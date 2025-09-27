from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, abort, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import hashlib
import os
import requests
import json
from urllib.parse import urlparse
from flask_migrate import Migrate
from extensions import db
from database import User, QuickLink, ContactMessage, CommunityPost, CommunityPostLike, CommunityComment, EmailLog
from tracker.task_tracker import assignments_bp
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from functools import wraps
from sqlalchemy import or_, func
import threading
from gpa_calculator.gpa import gpa_bp
from datetime import datetime, timedelta
import calendar
from class_schedule.schedule import schedule_bp
from subject_enrollment.subject import enrollment_bp
from quicklinks import quicklinks_bp
from sqlalchemy import inspect, text
import time
import sys as _sys
from Pomodoro.backend import pomodoro_bp

_sys.modules['app'] = _sys.modules[__name__]

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


# Database configuration (PostgreSQL)
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is required. Set it to your Postgres connection string.")
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
app.config['BREVO_API_KEY'] = os.getenv('BREVO_API_KEY')
app.config['SENDER_EMAIL'] = os.getenv('SENDER_EMAIL')
app.config['SENDER_NAME'] = os.getenv('SENDER_NAME', 'StudyBox')
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')


server_name_env = os.getenv('SERVER_NAME')
if server_name_env and server_name_env.strip() and server_name_env != 'studybox.onrender.com':
    app.config['SERVER_NAME'] = server_name_env

# blueprints imported
app.register_blueprint(assignments_bp, url_prefix='/assignment_tracker')
app.register_blueprint(gpa_bp, url_prefix='/gpa_calculator')
app.register_blueprint(enrollment_bp, url_prefix='/enrollment')
app.register_blueprint(schedule_bp)
from emails import emails_bp
from profiles import profiles_bp, get_user_avatar_url, get_favicon_url, get_social_url, get_user_social_links
from community import community_bp, format_relative_time
app.register_blueprint(emails_bp)
app.register_blueprint(profiles_bp)
app.register_blueprint(community_bp)
app.register_blueprint(pomodoro_bp, url_prefix='/pomodoro')
app.register_blueprint(quicklinks_bp)
if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'dev-secret-key-change-me'

# Initialize database and security components
db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'profiles.login'


app.config['CACHE_BUST_VERSION'] = str(int(time.time())) 
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.route("/dev-login-admin")
def dev_login_admin():
    user = User.query.filter_by(username="admin").first()
    if user:
        user.is_verified = True
        db.session.commit()
        login_user(user)
        return "Logged in as admin"
    return "Admin user not found", 404

@login_manager.user_loader
def load_user(user_id):
    # Load user from database for Flask-Login
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# cache busting
def get_cache_bust_version():
    return app.config.get('CACHE_BUST_VERSION', str(int(time.time())))
def add_cache_bust_to_url(url):
    separator = '&' if '?' in url else '?'
    return f"{url}{separator}v={get_cache_bust_version()}"
@app.after_request
def add_cache_headers(response):
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    elif response.content_type and any(ext in response.content_type for ext in ['css', 'js', 'image']):
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        response.headers['ETag'] = get_cache_bust_version()
    return response


def admin_required(view_func):
    # making sure only admins can access admin pages
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('profiles.login'))
        if not getattr(current_user, 'is_admin', False):
            flash('You do not have permission to access that page.')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return wrapped_view



_default_admin_checked = False
_usernames_normalized = False

@app.before_request
def ensure_default_admin_exists_once():
    # @admin user exists default and usernames are lowercase
    global _default_admin_checked
    global _usernames_normalized
    if _default_admin_checked and _usernames_normalized:
        return
    if request.endpoint in ('page_not_found',) or (request.path or '').startswith(('/static/', '/favicon/')):
        return
    try:
        user = User.query.filter_by(username='admin').first()
        if user and not user.is_admin:
            user.is_admin = True
            db.session.commit()
            print("DEBUG: Ensured @admin has admin privileges")
        # Force-remove admin from any non-@admin users
        others = User.query.filter(User.username != 'admin', User.is_admin == True).all()
        changed = 0
        for u in others:
            u.is_admin = False
            changed += 1
        if changed:
            db.session.commit()
            print(f"DEBUG: Removed admin from {changed} non-@admin user(s)")
        if not _usernames_normalized:
            users = User.query.all()
            for u in users:
                original = (u.username or '').strip()
                if not original:
                    continue
                lower = original.lower()
                if lower == u.username:
                    continue
                candidate = lower
                suffix = 2
                while User.query.filter(func.lower(User.username) == candidate).filter(User.id != u.id).first():
                    candidate = f"{lower}{suffix}"
                    suffix += 1
                print(f"DEBUG: Normalizing username {original} -> {candidate}")
                u.username = candidate
            db.session.commit()
            _usernames_normalized = True
    except Exception as e:
        print(f"DEBUG: Failed to ensure default admin: {e}")
    finally:
        _default_admin_checked = True



class ContactForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Your name"})
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": "your.email@example.com"})
    subject = StringField('Subject', validators=[InputRequired(), Length(min=5, max=200)], render_kw={"placeholder": "Brief description of your issue"})
    message = TextAreaField('Message', validators=[InputRequired(), Length(min=10, max=2000)], render_kw={"placeholder": "Please describe your issue or question in detail...", "rows": 5})
    submit = SubmitField('Send Message')

from emails import (
    send_email_via_brevo_api,
    generate_verification_token,
    verify_token,
)

def is_mmu_email(email):
    """Check if the email belongs to MMU (Multimedia University Malaysia)"""
    return email.lower().endswith('@student.mmu.edu.my')

def get_university_from_email(email):
    """Get university name based on email domain"""
    if is_mmu_email(email):
        return "Multimedia University Malaysia"
    return ""




@app.context_processor 
def inject_helpers():
    return {
        'avatar_url': get_user_avatar_url,
        'user_avatar_url': get_user_avatar_url,
        'cache_bust_version': get_cache_bust_version,
        'add_cache_bust': add_cache_bust_to_url,
        'get_favicon_url': get_favicon_url,
        'get_social_url': get_social_url,
        'get_user_social_links': get_user_social_links,
    }



_BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

def _encode_base36(number):
    number = int(number)
    if number < 0:
        raise ValueError("number must be non-negative")
    if number == 0:
        return "0"
    digits = []
    while number:
        number, rem = divmod(number, 36)
        digits.append(_BASE36_ALPHABET[rem])
    return ''.join(reversed(digits))

_CODE_LENGTH = 6
_CODE_MODULUS = 36 ** _CODE_LENGTH
_CODE_MULTIPLIER = 48271
_CODE_INCREMENT = 12345
_CODE_MULTIPLIER_INV = pow(_CODE_MULTIPLIER, -1, _CODE_MODULUS)

def _encode_user_code(user_id):
    # Convert user ID to a short public code
    value = (int(user_id) * _CODE_MULTIPLIER + _CODE_INCREMENT) % _CODE_MODULUS
    return _encode_base36(value).zfill(_CODE_LENGTH)

def _decode_public_id(public_code):
    # Convert public code back to user ID
    if not public_code or len(public_code) < 3 or not public_code.startswith('sd'):
        return None
    base = public_code[2:]
    if any(ch.lower() not in _BASE36_ALPHABET for ch in base):
        return None
    try:
        value = 0
        for ch in base.lower():
            value = value * 36 + _BASE36_ALPHABET.index(ch)
        original = ((value - _CODE_INCREMENT) * _CODE_MULTIPLIER_INV) % _CODE_MODULUS
        if original <= 0:
            return None
        return original
    except Exception:
        return None


from emails import send_verification_email_async as _send_verification_email_async
def send_verification_email(user_email, username):
    # Send email verification link to new users
    try:
        token = generate_verification_token(user_email)
        verification_url = url_for('emails.verify_email', token=token, _external=True)
        _send_verification_email_async(app, user_email, username, verification_url)
    except Exception as e:
        print(f"DEBUG: Error generating token for {user_email}: {e}")
        raise e

from emails import send_password_reset_email_async as _send_password_reset_email_async
def send_password_reset_email(user_email, username, reset_url):
    _send_password_reset_email_async(app, user_email, username, reset_url)

from emails import send_email_change_verification_async as _send_email_change_verification_async
def send_email_change_verification(user_email, username, new_email, verification_url):
    _send_email_change_verification_async(app, user_email, username, new_email, verification_url)



@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    verified_users = User.query.filter_by(is_verified=True).count()
    unverified_users = User.query.filter_by(is_verified=False).count()
    admins = User.query.filter_by(is_admin=True).count()
    mmu_users = User.query.filter(User.email.ilike('%@student.mmu.edu.my')).count()
    contact_messages_count = ContactMessage.query.count()
    
    # Count emails sent in the last month
    from datetime import datetime, timedelta
    one_month_ago = datetime.utcnow() - timedelta(days=30)
    emails_last_month = EmailLog.query.filter(
        EmailLog.sent_at >= one_month_ago,
        EmailLog.success == True
    ).count()
    
    q = request.args.get('q', '').strip()
    active_filter = request.args.get('filter', 'all').strip() or 'all'

    query = User.query
    if active_filter == 'verified':
        query = query.filter_by(is_verified=True)
    elif active_filter == 'unverified':
        query = query.filter_by(is_verified=False)
    elif active_filter == 'admins':
        query = query.filter_by(is_admin=True)
    elif active_filter == 'mmu':
        query = query.filter(User.email.ilike('%@student.mmu.edu.my'))
    else:
        active_filter = 'all'

    if q:
        search_clause = or_(
            User.username.ilike(f"%{q}%"),
            User.email.ilike(f"%{q}%"),
            User.school_university.ilike(f"%{q}%")
        )
        query = query.filter(search_clause)

    users = query.order_by(User.id.desc()).limit(10).all()
    return render_template('admin.html',
                           page='dashboard',
                           total_users=total_users,
                           verified_users=verified_users,
                           unverified_users=unverified_users,
                           admins=admins,
                           mmu_users=mmu_users,
                           contact_messages_count=contact_messages_count,
                           emails_last_month=emails_last_month,
                           users=users,
                           q=q,
                           active_filter=active_filter)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    q = request.args.get('q', '').strip()
    active_filter = request.args.get('filter', 'all').strip() or 'all'

    query = User.query

    if active_filter == 'verified':
        query = query.filter_by(is_verified=True)
    elif active_filter == 'unverified':
        query = query.filter_by(is_verified=False)
    elif active_filter == 'admins':
        query = query.filter_by(is_admin=True)
    elif active_filter == 'mmu':
        query = query.filter(User.email.ilike('%@student.mmu.edu.my'))
    else:
        active_filter = 'all'

    if q:
        search_clause = or_(
            User.username.ilike(f"%{q}%"),
            User.email.ilike(f"%{q}%"),
            User.school_university.ilike(f"%{q}%")
        )
        query = query.filter(search_clause)

    users = query.order_by(User.id.desc()).all()

    return render_template('admin.html', page='users', users=users, q=q, active_filter=active_filter)

## Removed admin promotion/demotion endpoints to enforce @admin-only admin policy

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    # Delete user and all their data (assignments, posts, etc)
    user = User.query.get_or_404(user_id)
    if user.username.strip().lower() == 'admin':
        flash('You cannot delete @admin.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        return redirect(url_for('admin_users', filter=filt, q=q))
    if current_user.id == user_id:
        flash('You cannot delete yourself.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        return redirect(url_for('admin_users', filter=filt, q=q))
    username = user.username
    try:
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

        if Enrollment:
            enrollments = Enrollment.query.filter_by(user_id=user.id).all()
            for enrollment in enrollments:
                from tracker.task_tracker import Assignment
                assignments = Assignment.query.filter_by(enrollment_id=enrollment.id).all()
                for assignment in assignments:
                    db.session.delete(assignment)
                # Delete the enrollment
                db.session.delete(enrollment)

        if PreviousSemester:
            previous_semesters = PreviousSemester.query.filter_by(user_id=user.id).all()
            for prev in previous_semesters:
                db.session.delete(prev)

        if ClassSchedule:
            schedules = ClassSchedule.query.filter_by(user_id=user.id).all()
            for schedule in schedules:
                db.session.delete(schedule)
        
        if ScheduleSubjectPref:
            prefs = ScheduleSubjectPref.query.filter_by(user_id=user.id).all()
            for pref in prefs:
                db.session.delete(pref)

        from app import CommunityPost, CommunityPostLike, CommunityComment
        from Pomodoro.backend import TimeStudied

        posts_by_user = CommunityPost.query.filter_by(user_id=user.id).all()
        post_ids = [post.id for post in posts_by_user]
        
        if post_ids:
            comments_on_user_posts = CommunityComment.query.filter(CommunityComment.post_id.in_(post_ids)).all()
            for comment in comments_on_user_posts:
                db.session.delete(comment)
        
        likes = CommunityPostLike.query.filter_by(user_id=user.id).all()
        for like in likes:
            db.session.delete(like)
        
        # Delete community comments by this user
        comments = CommunityComment.query.filter_by(user_id=user.id).all()
        for comment in comments:
            db.session.delete(comment)
        
        # Finally, delete community posts by this user
        posts = CommunityPost.query.filter_by(user_id=user.id).all()
        for post in posts:
            db.session.delete(post)
        
        # Flush to ensure all deletions are processed
        db.session.flush()
        
        # Delete time studied records (Pomodoro timer data)
        time_studied_records = TimeStudied.query.filter_by(user_id=user.id).all()
        for record in time_studied_records:
            db.session.delete(record)
        
        # Note: Contact messages will have their user_id set to NULL automatically
        # by the database's ON DELETE SET NULL constraint when the user is deleted

        quick_links = QuickLink.query.filter_by(user_id=user.id).all()
        for link in quick_links:
            db.session.delete(link)

        # Commit all deletions before deleting the user
        db.session.commit()
        
    except Exception as cleanup_err:
        print(f"DEBUG: Cleanup before user delete failed: {cleanup_err}")
        db.session.rollback()
        flash(f"Failed to delete user {username}: {str(cleanup_err)}")
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        return redirect(url_for('admin_users', filter=filt, q=q))

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"Deleted user {username}")
    except Exception as delete_err:
        print(f"DEBUG: User delete failed: {delete_err}")
        db.session.rollback()
        flash(f"Failed to delete user {username}: {str(delete_err)}")
    
    filt = request.form.get('filter') or 'all'
    q = (request.form.get('q') or '').strip()
    page = request.form.get('page') or 'users'
    if page == 'dashboard':
        return redirect(url_for('admin_dashboard', filter=filt, q=q))
    else:
        return redirect(url_for('admin_users', filter=filt, q=q))

@app.route('/admin/bootstrap', methods=['POST'])
def admin_bootstrap():
    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin:
        return ("Admin already exists", 403)
    token = request.args.get('token') or request.form.get('token')
    expected = os.getenv('ADMIN_BOOTSTRAP_TOKEN')
    if not expected or not token or token != expected:
        return ("Forbidden", 403)
    username_or_email = request.args.get('user') or request.form.get('user')
    if not username_or_email:
        return ("Missing user", 400)
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
    if not user:
        return ("User not found", 404)
    user.is_admin = True
    db.session.commit()
    return ("Bootstrap complete", 200)



def get_dashboard_warnings(user):
    # Check for assignment deadlines, low GPA, and upcoming classes
    warnings = []
    today = datetime.now().date()
    now = datetime.now()
    
    # required models
    from tracker.task_tracker import Assignment
    from class_schedule.schedule import ClassSchedule
    from subject_enrollment.subject import Enrollment, sem_dic
    from gpa_calculator.gpa import calc_gpa
    
    if user.current_semester:
        current_semester_codes = sem_dic.get(user.current_semester, [])
        subjects = Enrollment.query.filter_by(user_id=user.id).filter(Enrollment.course_code.in_(current_semester_codes)).all()
        
        for subject in subjects:
            assignments = Assignment.query.filter(Assignment.enrollment_id == subject.id, Assignment.done == False).all()
            for assignment in assignments:
                if assignment.deadline:
                    days_remaining = (assignment.deadline - today).days
                    if 0 <= days_remaining <= 7:
                        warnings.append({
                            'type': 'assignment_deadline',
                            'title': f'Assignment Due Soon',
                            'message': f'{assignment.assignment} is due in {days_remaining} day{"s" if days_remaining != 1 else ""}',
                            'urgency': 'urgent' if days_remaining <= 3 else 'warning',
                            'icon': 'fas fa-exclamation-triangle',
                            'color': '#dc3545' if days_remaining <= 3 else '#fd7e14'
                        })
                    elif days_remaining < 0:
                        warnings.append({
                            'type': 'assignment_overdue',
                            'title': f'Assignment Overdue',
                            'message': f'{assignment.assignment} is {abs(days_remaining)} day{"s" if abs(days_remaining) != 1 else ""} overdue',
                            'urgency': 'critical',
                            'icon': 'fas fa-times-circle',
                            'color': '#dc3545'
                        })

    try:
        current_gpa = calc_gpa(user)
        if current_gpa > 0 and current_gpa < 2.0:  # Low GPA threshold
            warnings.append({
                'type': 'low_gpa',
                'title': 'Low GPA Alert',
                'message': f'Your current GPA is {current_gpa:.2f}. Consider focusing on improving your grades.',
                'urgency': 'warning',
                'icon': 'fas fa-chart-line',
                'color': '#ffc107'
            })
    except:
        pass

    if user.current_semester:
        current_semester_codes = sem_dic.get(user.current_semester, [])
        today_name = now.strftime("%A")
        upcoming_classes = ClassSchedule.query.filter_by(
            user_id=user.id, 
            day_of_week=today_name
        ).filter(ClassSchedule.course_code.in_(current_semester_codes)).all()
        
        for class_schedule in upcoming_classes:
            class_time = datetime.combine(today, class_schedule.start_time)
            time_diff = class_time - now
            
            if timedelta(minutes=0) <= time_diff <= timedelta(hours=1):
                minutes_remaining = int(time_diff.total_seconds() / 60)
                if minutes_remaining > 0:
                    if minutes_remaining <= 5:
                        urgency = 'critical'
                        color = '#dc3545'
                    elif minutes_remaining <= 15:
                        urgency = 'urgent'
                        color = '#fd7e14'
                    else:
                        urgency = 'warning'
                        color = '#ffc107'
                    
                    warnings.append({
                        'type': 'upcoming_class',
                        'title': 'Class Starting Soon',
                        'message': f'{class_schedule.subject_name()} starts in {minutes_remaining} minute{"s" if minutes_remaining != 1 else ""}',
                        'urgency': urgency,
                        'icon': 'fas fa-clock',
                        'color': color
                    })

    def get_sort_key(warning):
        urgency_order = {'critical': 0, 'urgent': 1, 'warning': 2, 'info': 3}
        base_urgency = urgency_order.get(warning['urgency'], 4)
        if warning['type'] == 'upcoming_class':
            import re
            time_match = re.search(r'starts in (\d+) minute', warning['message'])
            if time_match:
                minutes_remaining = int(time_match.group(1))
                return (base_urgency, -minutes_remaining)
        
        elif warning['type'] in ['assignment_deadline', 'assignment_overdue']:
            import re
            if 'overdue' in warning['message']:
                overdue_match = re.search(r'(\d+) day.*overdue', warning['message'])
                if overdue_match:
                    days_overdue = int(overdue_match.group(1))
                    return (base_urgency, -days_overdue)
            else:
                due_match = re.search(r'due in (\d+) day', warning['message'])
                if due_match:
                    days_remaining = int(due_match.group(1))
                    return (base_urgency, days_remaining)
        
        return (base_urgency, 0)
    
    warnings.sort(key=get_sort_key)
    
    return warnings

@app.route('/')
@app.route('/dashboard')
@app.route('/home')
@app.route('/index')
@login_required
def index():
    warnings = get_dashboard_warnings(current_user)
    return render_template('index.html', user=current_user, warnings=warnings)


@app.route('/help', methods=['GET'])
def help_page():
    return render_template('help.html')




@app.route('/task')
@login_required
def task():
    return render_template('task.html')

@app.route('/favicon/<string:code>.ico')
def dynamic_favicon(code):
    numeric_id = _decode_public_id(f"sd{code}")
    if not numeric_id:
        abort(404)
    user = User.query.get_or_404(numeric_id)
    

    avatar_url = get_user_avatar_url(user, size=32)
    return redirect(avatar_url)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Start the Flask app and set up database
    try:
        with app.app_context():
            print("Using local SQLite database. Initializing tables if needed...")
            db.create_all()
            print("Database initialized.")

            # class_schedule.class_type
            try:
                inspector = inspect(db.engine)
                tables = inspector.get_table_names()
                if 'class_schedule' in tables:
                    cols = {c['name'] for c in inspector.get_columns('class_schedule')}
                    if 'class_type' not in cols:
                        print("Adding missing column class_schedule.class_type ...")
                        db.session.execute(text("ALTER TABLE class_schedule ADD COLUMN IF NOT EXISTS class_type VARCHAR(20)"))
                        db.session.commit()
                        print("Added class_type column.")
                if 'schedule_subject_pref' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS schedule_subject_pref (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
                                course_code VARCHAR(100) NOT NULL,
                                short_name VARCHAR(100)
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created schedule_subject_pref table.")
                    except Exception as ce:
                        print(f"Could not create schedule_subject_pref: {ce}")
                
                # contact_message
                if 'contact_message' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS contact_message (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
                                name VARCHAR(100) NOT NULL,
                                email VARCHAR(150) NOT NULL,
                                subject VARCHAR(200) NOT NULL,
                                message TEXT NOT NULL,
                                is_read BOOLEAN DEFAULT FALSE,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created contact_message table.")
                    except Exception as ce:
                        print(f"Could not create contact_message: {ce}")

                # community_post
                if 'community_post' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS community_post (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
                                content TEXT NOT NULL,
                                post_type VARCHAR(20) NOT NULL DEFAULT 'public',
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created community_post table.")
                    except Exception as ce:
                        print(f"Could not create community_post: {ce}")
                else:
                    # post_type
                    cols = {c['name'] for c in inspector.get_columns('community_post')}
                    if 'post_type' not in cols:
                        print("Adding missing column community_post.post_type ...")
                        db.session.execute(text("ALTER TABLE community_post ADD COLUMN IF NOT EXISTS post_type VARCHAR(20) DEFAULT 'public'"))
                        db.session.commit()
                        print("Added post_type column.")
                
                # community_post_like
                if 'community_post_like' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS community_post_like (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
                                post_id INTEGER NOT NULL REFERENCES "community_post" (id) ON DELETE CASCADE,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                UNIQUE(user_id, post_id)
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created community_post_like table.")
                    except Exception as ce:
                        print(f"Could not create community_post_like: {ce}")
                
                # community_comment
                if 'community_comment' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS community_comment (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
                                post_id INTEGER NOT NULL REFERENCES "community_post" (id) ON DELETE CASCADE,
                                content TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created community_comment table.")
                    except Exception as ce:
                        print(f"Could not create community_comment: {ce}")
            except Exception as schema_err:
                print(f"Schema check failed or not needed: {schema_err}")
    except Exception as e:
        print(f"Database connection failed: {e}")
        print("This might be due to:")
        print("1. Network connectivity issues")
        print("2. Database server being down")
        print("3. Incorrect credentials")
        print("4. Firewall restrictions")
        print("\nFor local development, you might want to:")
        print("1. Use SQLite for development (default now)")
        print("2. Check file permissions/path for SQLite")



    # for local dev
    if os.getenv('FLASK_ENV') != 'production':
        app.run(debug=True, host='127.0.0.1', port=5000)
