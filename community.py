from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SelectField, SubmitField
from wtforms.validators import InputRequired, Length
from database import CommunityPost, CommunityPostLike, CommunityComment
from extensions import assignmenet_db
from datetime import datetime

community_bp = Blueprint('community', __name__)


# Forms
class CommunityPostForm(FlaskForm):
    content = TextAreaField(validators=[InputRequired(), Length(min=1, max=2000)], render_kw={"placeholder": "Share something with the community...", "rows": 3})
    post_type = SelectField('Post Type', choices=[('public', 'Public'), ('mmu', 'MMU Only')], default='public')
    submit = SubmitField('Post')

class CommunityCommentForm(FlaskForm):
    content = TextAreaField(validators=[InputRequired(), Length(min=1, max=500)], render_kw={"placeholder": "Write a comment...", "rows": 2})
    submit = SubmitField('Comment')


# Utility function for time formatting
def format_relative_time(post_time):
    # Show time as "5 minutes ago" or "2 days ago" etc
    now = datetime.utcnow()
    diff = now - post_time
    
    if diff.total_seconds() < 3600:
        minutes = int(diff.total_seconds() / 60)
        if minutes < 1:
            seconds = int(diff.total_seconds())
            return f"{seconds} second{'s' if seconds != 1 else ''} ago"
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    
    # hours
    elif diff.total_seconds() < 86400:
        hours = int(diff.total_seconds() / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    
    # days
    elif diff.days < 7:
        days = diff.days
        return f"{days} day{'s' if days != 1 else ''} ago"
    
    # weeks
    elif diff.days < 28:
        weeks = diff.days // 7
        return f"{weeks} week{'s' if weeks != 1 else ''} ago"
    
    # months
    elif diff.days < 365:
        months = diff.days // 30  # Approximate months
        return f"{months} month{'s' if months != 1 else ''} ago"
    
    # years
    else:
        if post_time.year == now.year:
            # day and month
            return post_time.strftime("%d %B")
        else:
            # day, month, and year
            return post_time.strftime("%d %B %Y")


# Routes
@community_bp.route('/community', methods=['GET', 'POST'])
def community():
    # Community page where users can post and see others' posts
    form = CommunityPostForm()
    if current_user.is_authenticated and form.validate_on_submit():
        post = CommunityPost(
            user_id=current_user.id, 
            content=form.content.data.strip(),
            post_type=form.post_type.data
        )
        assignmenet_db.session.add(post)
        assignmenet_db.session.commit()
        flash('Posted!', 'success')
        return redirect(url_for('community.community'))

    posts = CommunityPost.query.options(assignmenet_db.joinedload(CommunityPost.comments)).order_by(CommunityPost.created_at.desc()).limit(100).all()
    return render_template('community.html', form=form, posts=posts, format_relative_time=format_relative_time)


@community_bp.route('/community/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    # Add a comment to a community post
    post = CommunityPost.query.get_or_404(post_id)
    form = CommunityCommentForm()
    
    if form.validate_on_submit():
        comment = CommunityComment(
            user_id=current_user.id,
            post_id=post_id,
            content=form.content.data.strip()
        )
        assignmenet_db.session.add(comment)
        assignmenet_db.session.commit()
        flash('Comment added!', 'success')
    
    return redirect(url_for('community.community'))


@community_bp.route('/community/post/<int:post_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    # Delete a community post (only by author or admin)
    print(f"DEBUG: Delete route called for post {post_id}")
    print(f"DEBUG: Current user: {current_user.id}, is_admin: {current_user.is_admin}")
    
    try:
        post = CommunityPost.query.get(post_id)
        if not post:
            print(f"DEBUG: Post {post_id} not found")
            return '', 404
        print(f"DEBUG: Found post {post_id} by user {post.user_id}")
        if current_user.id != post.user_id and not current_user.is_admin:
            print(f"DEBUG: User {current_user.id} cannot delete post {post_id}")
            return '', 403
        print(f"DEBUG: User has permission to delete")
        comments_deleted = 0
        for comment in post.comments:
            assignmenet_db.session.delete(comment)
            comments_deleted += 1
        likes_deleted = 0
        for like in post.likes:
            assignmenet_db.session.delete(like)
            likes_deleted += 1                    
        print(f"DEBUG: Deleted {comments_deleted} comments and {likes_deleted} likes")
        assignmenet_db.session.delete(post)
        assignmenet_db.session.commit()       
        print(f"DEBUG: Successfully deleted post {post_id}")
        flash('Post deleted successfully!', 'success')
        return redirect(url_for('community.community'))
        
    except Exception as e:
        print(f"DEBUG: Error deleting post {post_id}: {str(e)}")
        assignmenet_db.session.rollback()
        return '', 500


@community_bp.route('/test-delete/<int:post_id>')
@login_required
def test_delete(post_id):
    # Test route to check if post exists and user permissions
    post = CommunityPost.query.get(post_id)
    if not post:
        return f"Post {post_id} not found", 404
    
    can_delete = current_user.id == post.user_id or current_user.is_admin
    return f"Post {post_id} exists. User {current_user.id} can delete: {can_delete}. Post author: {post.user_id}", 200


@community_bp.route('/community/post/<int:post_id>/like', methods=['POST'])
@login_required
def toggle_like(post_id):
    post = CommunityPost.query.get_or_404(post_id)
    existing_like = CommunityPostLike.query.filter_by(
        user_id=current_user.id, 
        post_id=post_id
    ).first()
    
    if existing_like:
        assignmenet_db.session.delete(existing_like)
        liked = False
    else:
        new_like = CommunityPostLike(user_id=current_user.id, post_id=post_id)
        assignmenet_db.session.add(new_like)
        liked = True
    
    assignmenet_db.session.commit()
    

    like_count = CommunityPostLike.query.filter_by(post_id=post_id).count()
    
    return jsonify({'liked': liked, 'count': like_count})


@community_bp.route('/community/post/<int:post_id>/comments')
def get_comments(post_id):
    # Get comments for a post
    post = CommunityPost.query.get_or_404(post_id)
    comments = CommunityComment.query.filter_by(post_id=post_id).order_by(CommunityComment.created_at.asc()).all()
    
    comments_data = []
    for comment in comments:
        comments_data.append({
            'id': comment.id,
            'content': comment.content,
            'username': comment.user.username,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M'),
            'user_id': comment.user_id
        })
    
    return jsonify({'comments': comments_data})


# Context processor to make functions available in templates
@community_bp.context_processor
def inject_community_helpers():
    return {
        'format_relative_time': format_relative_time,
    }


# Export the blueprint and forms
__all__ = [
    'community_bp',
    'CommunityPostForm',
    'CommunityCommentForm',
    'format_relative_time',
]
