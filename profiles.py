from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from sqlalchemy import func
import os


profiles_bp = Blueprint('profiles', __name__)


# Forms
class Loginform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=3, max=150)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class Registerform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    school_university = StringField(validators=[Length(min=0, max=200)])
    avatar = SelectField('Avatar', choices=[(str(i), f"#{i}") for i in range(1, 11)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        from app import User
        existing_user_username = User.query.filter(func.lower(User.username) == (username.data or '').strip().lower()).first()
        if existing_user_username:
            raise ValidationError("Username already exists")

    def validate_email(self, email):
        from app import User
        existing_user_email = User.query.filter(func.lower(User.email) == (email.data or '').strip().lower()).first()
        if existing_user_email:
            raise ValidationError("Email already exists")


class profileupdateform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
    school_university = StringField(validators=[Length(min=0, max=200)])
    avatar = SelectField('Avatar', choices=[(str(i), f"#{i}") for i in range(1, 11)])
    # Optional profile fields used in template
    bio = TextAreaField(validators=[Length(min=0, max=500)])
    github_username = StringField(validators=[Length(min=0, max=100)])
    instagram_username = StringField(validators=[Length(min=0, max=100)])
    twitter_username = StringField(validators=[Length(min=0, max=100)])
    youtube_username = StringField(validators=[Length(min=0, max=100)])
    linkedin_username = StringField(validators=[Length(min=0, max=100)])
    tiktok_username = StringField(validators=[Length(min=0, max=100)])
    discord_username = StringField(validators=[Length(min=0, max=100)])
    custom_website_url = StringField(validators=[Length(min=0, max=200)])
    custom_website_name = StringField(validators=[Length(min=0, max=100)])
    show_email = SelectField('Show Email', choices=[('True', 'Show'), ('False', 'Hide')])
    # Current password is no longer required to edit profile
    current_password = PasswordField(validators=[Length(min=0, max=20)])
    submit = SubmitField('Update')

    def validate_username(self, username):
        from app import User
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username and current_user and existing_user_username.id != current_user.id:
            raise ValidationError("Username already exists")

    def validate_email(self, email):
        from app import User
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email and current_user and existing_user_email.id != current_user.id:
            raise ValidationError("Email already exists")


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Enter your email address"})
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm New Password"})


# Routes
@profiles_bp.route('/login', methods=['GET', 'POST'])
def login():
    from app import User, bcrypt
    form = Loginform()
    error_message = None
    if form.validate_on_submit():
        identifier_raw = form.username.data.strip()
        identifier_lower = identifier_raw.lower()
        if '@' in identifier_raw:
            user = User.query.filter(func.lower(User.email) == identifier_lower).first()
        else:
            user = User.query.filter(func.lower(User.username) == identifier_lower).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_verified:
                login_user(user)
                return redirect(url_for('index'))
            else:
                error_message = "Your email is not verified yet. Please check your inbox and click the verification link."
        else:
            error_message = "Invalid username or password"
    return render_template('login.html', form=form, error_message=error_message)


@profiles_bp.route('/register', methods=['GET', 'POST'])
def register():
    from app import User, assignmenet_db, bcrypt, get_university_from_email
    from emails import generate_verification_token
    from app import send_verification_email
    form = Registerform()
    success_message = None
    if request.method == 'POST' and form.email.data:
        detected_university = get_university_from_email(form.email.data)
        if detected_university:
            form.school_university.data = detected_university
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                username=(form.username.data or '').strip().lower(),
                email=form.email.data,
                password=hashed_password,
                school_university=form.school_university.data,
                avatar=form.avatar.data
            )
            assignmenet_db.session.add(new_user)
            assignmenet_db.session.commit()

            try:
                send_verification_email(new_user.email, new_user.username)
                success_message = "Registration successful! Check your email for verification link."
            except Exception as email_error:
                print(f"DEBUG: Email sending failed: {email_error}")
                token = generate_verification_token(new_user.email)
                verification_url = url_for('emails.verify_email', token=token, _external=True)
                success_message = "Registration successful! Email failed - try resend verification."
        except Exception as e:
            print(f"DEBUG: Error during registration: {e}")
            success_message = "Registration failed. Please try again."
    return render_template('register.html', form=form, success_message=success_message)


@profiles_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('profiles.login'))


@profiles_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    from app import User
    from emails import generate_verification_token
    from app import send_password_reset_email
    form = ForgotPasswordForm()
    success_message = None
    error_message = None
    if form.validate_on_submit():
        email = form.email.data.strip()
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = generate_verification_token(email)
                reset_url = url_for('emails.reset_password', token=token, _external=True)
                send_password_reset_email(user.email, user.username, reset_url)
                success_message = "Password reset link has been sent to your email address."
            except Exception as e:
                print(f"DEBUG: Error sending password reset email: {e}")
                error_message = "Failed to send reset email. Please try again."
        else:
            success_message = "If an account with that email exists, a password reset link has been sent."
    return render_template('forgot_password.html', form=form, success_message=success_message, error_message=error_message)


@profiles_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    from app import assignmenet_db, bcrypt, User, is_mmu_email
    from emails import generate_verification_token
    form = profileupdateform()
    if form.validate_on_submit():
        # Allow editing without requiring current password
        if True:
            if form.email.data != current_user.email:
                existing_user = User.query.filter_by(email=form.email.data).first()
                if existing_user and existing_user.id != current_user.id:
                    flash('Email already exists')
                    return redirect(url_for('profiles.profile'))
                current_user.pending_email = form.email.data
                current_user.username = (form.username.data or '').strip().lower()
                assignmenet_db.session.commit()
                token = generate_verification_token(form.email.data)
                current_user.email_change_token = token
                assignmenet_db.session.commit()
                verification_url = url_for('emails.verify_email_change', token=token, _external=True)
                from app import send_email_change_verification
                send_email_change_verification(current_user.email, current_user.username, form.email.data, verification_url)
                flash('Email change requested! Please check your new email address for verification link.')
                return redirect(url_for('profiles.profile'))
            else:
                # Update core fields
                current_user.username = (form.username.data or '').strip().lower()
                current_user.avatar = form.avatar.data
                # Optional profile fields
                if hasattr(form, 'bio'):
                    current_user.bio = form.bio.data
                if hasattr(form, 'github_username'):
                    current_user.github_username = form.github_username.data
                if hasattr(form, 'instagram_username'):
                    current_user.instagram_username = form.instagram_username.data
                if hasattr(form, 'twitter_username'):
                    current_user.twitter_username = form.twitter_username.data
                if hasattr(form, 'youtube_username'):
                    current_user.youtube_username = form.youtube_username.data
                if hasattr(form, 'linkedin_username'):
                    current_user.linkedin_username = form.linkedin_username.data
                if hasattr(form, 'tiktok_username'):
                    current_user.tiktok_username = form.tiktok_username.data
                if hasattr(form, 'discord_username'):
                    current_user.discord_username = form.discord_username.data
                if hasattr(form, 'custom_website_url'):
                    current_user.custom_website_url = form.custom_website_url.data
                if hasattr(form, 'custom_website_name'):
                    current_user.custom_website_name = form.custom_website_name.data
                if hasattr(form, 'show_email'):
                    current_user.show_email = (form.show_email.data == 'True') if isinstance(form.show_email.data, str) else bool(form.show_email.data)
                # University rule: only allow change if not verified MMU
                if not (current_user.is_verified and is_mmu_email(current_user.email)):
                    if hasattr(form, 'school_university'):
                        current_user.school_university = form.school_university.data
                assignmenet_db.session.commit()
                flash('Profile updated successfully')
                return redirect(url_for('profiles.profile'))
        
    elif request.method == 'GET':
        # Pre-fill form from current_user
        if hasattr(form, 'username'):
            form.username.data = (current_user.username or '').lower()
        if hasattr(form, 'email'):
            form.email.data = current_user.email
        if hasattr(form, 'school_university'):
            form.school_university.data = current_user.school_university
        if hasattr(form, 'avatar'):
            form.avatar.data = current_user.avatar or '1'
        if hasattr(form, 'bio'):
            form.bio.data = getattr(current_user, 'bio', None)
        for fld in (
            'github_username','instagram_username','twitter_username','youtube_username',
            'linkedin_username','tiktok_username','discord_username',
            'custom_website_url','custom_website_name'
        ):
            if hasattr(form, fld):
                setattr(form, f"{fld}.data", getattr(current_user, fld, None))
        if hasattr(form, 'show_email'):
            form.show_email.data = str(getattr(current_user, 'show_email', False))
    return render_template('profile.html', form=form)


# Public profiles
@profiles_bp.route('/sd<string:code>')
def public_profile_by_public_code(code):
    from app import _decode_public_id, User, get_user_avatar_url
    numeric_id = _decode_public_id(f"sd{code}")
    if not numeric_id:
        return redirect(url_for('index'))
    user = User.query.get(numeric_id)
    if not user:
        return redirect(url_for('index'))
    return render_template('public_profile.html', user=user, profile_user=user, avatar_url=get_user_avatar_url(user))


@profiles_bp.route('/<username>')
def public_profile_by_username(username):
    if username.lower().startswith('sd') and len(username) > 2:
        return redirect(url_for('profiles.public_profile_by_public_code', code=username[2:]))
    from app import User, get_user_avatar_url
    user = User.query.filter(func.lower(User.username) == username.lower()).first()
    if not user:
        from flask import abort
        abort(404)
    return render_template('public_profile.html', user=user, profile_user=user, avatar_url=get_user_avatar_url(user))


__all__ = [
    'profiles_bp',
    'Loginform',
    'Registerform',
    'profileupdateform',
    'ForgotPasswordForm',
    'ResetPasswordForm',
]


# Account management actions
@profiles_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    from app import bcrypt, assignmenet_db
    if request.method == 'POST' and current_user.is_authenticated:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Invalid current password')
            return redirect(url_for('profiles.profile'))
        if new_password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            assignmenet_db.session.commit()
            flash('Password updated successfully')
            return redirect(url_for('profiles.profile'))
        else:
            flash('Passwords do not match')
            return redirect(url_for('profiles.profile'))
    return redirect(url_for('profiles.profile'))


@profiles_bp.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def delete_profile():
    from app import bcrypt, assignmenet_db, CommunityPost, CommunityPostLike
    if request.method == 'POST':
        if bcrypt.check_password_hash(current_user.password, request.form['confirm_password']):
            try:
                # Import models
                try:
                    from subject_enrollment.subject import Enrollment, PreviousSemester
                except Exception:
                    Enrollment = None
                    PreviousSemester = None
                
                try:
                    from class_schedule.schedule import ClassSchedule, ScheduleSubjectPref
                except Exception:
                    ClassSchedule = None
                    ScheduleSubjectPref = None

                # Delete assignments first (they depend on enrollments)
                if Enrollment:
                    enrollments = Enrollment.query.filter_by(user_id=current_user.id).all()
                    for enrollment in enrollments:
                        # Delete assignments for this enrollment
                        from tracker.task_tracker import Assignment
                        assignments = Assignment.query.filter_by(enrollment_id=enrollment.id).all()
                        for assignment in assignments:
                            assignmenet_db.session.delete(assignment)
                        # Delete the enrollment
                        assignmenet_db.session.delete(enrollment)

                # Delete previous semesters
                if PreviousSemester:
                    previous_semesters = PreviousSemester.query.filter_by(user_id=current_user.id).all()
                    for prev in previous_semesters:
                        assignmenet_db.session.delete(prev)

                # Delete schedule-related records
                if ClassSchedule:
                    schedules = ClassSchedule.query.filter_by(user_id=current_user.id).all()
                    for schedule in schedules:
                        assignmenet_db.session.delete(schedule)
                
                if ScheduleSubjectPref:
                    prefs = ScheduleSubjectPref.query.filter_by(user_id=current_user.id).all()
                    for pref in prefs:
                        assignmenet_db.session.delete(pref)

                # Delete community posts, likes, and comments explicitly
                # (SQLAlchemy doesn't handle ON DELETE CASCADE properly)
                from app import CommunityPost, CommunityPostLike, CommunityComment
                
                # First, delete all comments that reference posts by this user
                # (comments on posts by the user being deleted)
                posts_by_user = CommunityPost.query.filter_by(user_id=current_user.id).all()
                post_ids = [post.id for post in posts_by_user]
                
                if post_ids:
                    comments_on_user_posts = CommunityComment.query.filter(CommunityComment.post_id.in_(post_ids)).all()
                    for comment in comments_on_user_posts:
                        assignmenet_db.session.delete(comment)
                
                # Delete community post likes by this user
                likes = CommunityPostLike.query.filter_by(user_id=current_user.id).all()
                for like in likes:
                    assignmenet_db.session.delete(like)
                
                # Delete community comments by this user
                comments = CommunityComment.query.filter_by(user_id=current_user.id).all()
                for comment in comments:
                    assignmenet_db.session.delete(comment)
                
                # Finally, delete community posts by this user
                posts = CommunityPost.query.filter_by(user_id=current_user.id).all()
                for post in posts:
                    assignmenet_db.session.delete(post)
                
                # Flush to ensure all deletions are processed
                assignmenet_db.session.flush()

                # Delete quick links owned by the user
                from app import QuickLink
                quick_links = QuickLink.query.filter_by(user_id=current_user.id).all()
                for link in quick_links:
                    assignmenet_db.session.delete(link)

                # Note: Contact messages will have their user_id set to NULL automatically
                # by the database's ON DELETE SET NULL constraint when the user is deleted

                # Commit all deletions before deleting the user
                assignmenet_db.session.commit()
                
            except Exception as cleanup_err:
                print(f"DEBUG: Cleanup before user delete failed: {cleanup_err}")
                assignmenet_db.session.rollback()
                flash(f"Failed to delete profile: {str(cleanup_err)}")
                return redirect(url_for('profiles.profile'))

            # Now delete the user
            try:
                assignmenet_db.session.delete(current_user)
                assignmenet_db.session.commit()
                logout_user()
                flash('Profile deleted successfully')
                return redirect(url_for('profiles.login'))
            except Exception as delete_err:
                print(f"DEBUG: User delete failed: {delete_err}")
                assignmenet_db.session.rollback()
                flash(f"Failed to delete profile: {str(delete_err)}")
                return redirect(url_for('profiles.profile'))
        else:
            flash('Invalid current password')
            return redirect(url_for('profiles.profile'))
    return redirect(url_for('profiles.profile'))


# Avatar and profile helpers and routes (no Gravatar; only built-in 10 avatars)
def custom_avatar_url(avatar_id, size=96):
    return f"/avatar/{avatar_id}"

def get_user_avatar_url(user, size=96):
    if user.username == 'admin':
        return f"/static/images/fav.png"
    if hasattr(user, 'avatar') and user.avatar:
        return custom_avatar_url(user.avatar, size)
    # Fallback to avatar #1 if none selected
    return custom_avatar_url('1', size)


@profiles_bp.route('/avatar/<string:avatar_id>')
def serve_avatar(avatar_id):
    try:
        avatar_num = int(avatar_id)
        if 1 <= avatar_num <= 10:
            avatar_path = f"static/avatars/#{avatar_num}.JPG"
            if os.path.exists(avatar_path):
                return send_file(avatar_path)
    except ValueError:
        pass
    return send_file("static/avatars/#1.JPG")


@profiles_bp.context_processor
def inject_profile_helpers():
    return {
        'user_avatar_url': get_user_avatar_url,
        'custom_avatar_url': custom_avatar_url,
    }


