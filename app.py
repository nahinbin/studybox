from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, abort, make_response, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
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
from database import User, QuickLink, ContactMessage, CommunityPost, CommunityPostLike, CommunityComment, HelpTicket, HelpReply, Institution
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
from werkzeug.utils import secure_filename

_sys.modules['app'] = _sys.modules[__name__]

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# Enable CSRF protection for forms
csrf = CSRFProtect(app)


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
app.config['HELP_UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'help')
app.config['INSTITUTION_UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'institutions')
app.config['NOTES_UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'notes')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

# Google OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv(
    'GOOGLE_CLIENT_ID',
    '563119109790-mkcatckbt0t7nml4puni6p8m5lieup6i.apps.googleusercontent.com',
)
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')


server_name_env = os.getenv('SERVER_NAME')
if server_name_env and server_name_env.strip() and server_name_env != 'studybox.onrender.com':
    app.config['SERVER_NAME'] = server_name_env

# blueprints imported
app.register_blueprint(assignments_bp, url_prefix='/assignment_tracker')
app.register_blueprint(gpa_bp, url_prefix='/gpa_calculator')
app.register_blueprint(enrollment_bp, url_prefix='/enrollment')
app.register_blueprint(schedule_bp)
from emails import emails_bp
from profiles import (
    profiles_bp,
    get_user_avatar_url,
    get_favicon_url,
    get_social_url,
    get_user_social_links,
    custom_avatar_url,
)
from community import community_bp, format_relative_time
from notes.notes import notes_bp
app.register_blueprint(emails_bp)
app.register_blueprint(profiles_bp)
app.register_blueprint(community_bp)
app.register_blueprint(pomodoro_bp, url_prefix='/pomodoro')
app.register_blueprint(quicklinks_bp)
app.register_blueprint(notes_bp)
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
login_manager.login_message = None


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


def _ensure_institution_schema_safe():
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        if 'institution' not in tables:
            try:
                db.create_all()
            except Exception:
                pass
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
        if 'institution' in tables:
            existing_cols = {c['name'] for c in inspector.get_columns('institution')}
            dialect = db.engine.dialect.name
            # Add image_data
            if 'image_data' not in existing_cols:
                try:
                    if dialect == 'postgresql':
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_data BYTEA"))
                    else:
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN image_data BLOB"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            # Add image_mime
            if 'image_mime' not in existing_cols:
                try:
                    if dialect == 'postgresql':
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_mime VARCHAR(100)"))
                    else:
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN image_mime VARCHAR(100)"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            # Add image_filename
            if 'image_filename' not in existing_cols:
                try:
                    if dialect == 'postgresql':
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_filename VARCHAR(255)"))
                    else:
                        db.session.execute(text("ALTER TABLE institution ADD COLUMN image_filename VARCHAR(255)"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
    except Exception as e:
        print(f"DEBUG: _ensure_institution_schema_safe failed: {e}")


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
_mmu_institution_ensured = False

@app.before_request
def ensure_default_admin_exists_once():
    # @admin user exists default and usernames are lowercase
    global _default_admin_checked
    global _usernames_normalized
    global _mmu_institution_ensured
    if _default_admin_checked and _usernames_normalized and _mmu_institution_ensured:
        return
    if request.endpoint in ('page_not_found',) or (request.path or '').startswith(('/static/', '/favicon/')):
        return
    try:
        # Ensure institution schema before any Institution queries
        _ensure_institution_schema_safe()
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
        # Ensure MMU institution exists and is system-locked
        if not _mmu_institution_ensured:
            mmu = Institution.query.filter(func.lower(Institution.name) == 'multimedia university malaysia').first()
            if not mmu:
                mmu = Institution(
                    name='Multimedia University Malaysia',
                    code='MMU',
                    domain='@student.mmu.edu.my',
                    logo_url='/static/images/mmu_fav.png',
                    is_system=True,
                )
                db.session.add(mmu)
                db.session.commit()
            else:
                # Make sure flags and logo are set
                changed = False
                if not mmu.is_system:
                    mmu.is_system = True
                    changed = True
                if not mmu.logo_url:
                    mmu.logo_url = '/static/images/mmu_fav.png'
                    changed = True
                if changed:
                    db.session.commit()
            _mmu_institution_ensured = True
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
        'custom_avatar_url': custom_avatar_url,
        'cache_bust_version': get_cache_bust_version,
        'add_cache_bust': add_cache_bust_to_url,
        'get_favicon_url': get_favicon_url,
        'get_social_url': get_social_url,
        'get_user_social_links': get_user_social_links,
        'get_institution_logo_for_user': get_institution_logo_for_user,
        'get_institution_logo_by_name': get_institution_logo_by_name,
    }



def get_institution_logo_by_name(name):
    if not name:
        return None
    inst = Institution.query.filter(func.lower(Institution.name) == (name or '').strip().lower()).first()
    if not inst:
        return None
    if getattr(inst, 'image_data', None):
        return f"/institutions/logo/{inst.id}"
    return inst.logo_url if inst.logo_url else None


def get_institution_logo_for_user(user):
    try:
        if getattr(user, 'is_verified', False) and getattr(user, 'email', '') and user.email.endswith('@student.mmu.edu.my'):
            return '/static/images/mmu_fav.png'
        if getattr(user, 'school_university', None):
            return get_institution_logo_by_name(user.school_university)
        return None
    except Exception:
        return None


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

from emails import send_password_reset_email_sync as _send_password_reset_email_sync

def send_password_reset_email(user_email, username, reset_url):
    # Send synchronously to avoid thread termination issues during deploys
    return _send_password_reset_email_sync(app, user_email, username, reset_url)

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
    show_profile_setup = session.pop('needs_profile_setup', False)
    return render_template('index.html', user=current_user, warnings=warnings, show_profile_setup=show_profile_setup)


def _ensure_help_upload_dir():
    try:
        os.makedirs(app.config['HELP_UPLOAD_FOLDER'], exist_ok=True)
    except Exception:
        pass


def _allowed_image(filename):
    allowed = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}
    ext = os.path.splitext(filename or '')[1].lower()
    return ext in allowed


def _ensure_institution_upload_dir():
    try:
        os.makedirs(app.config['INSTITUTION_UPLOAD_FOLDER'], exist_ok=True)
    except Exception:
        pass


@app.route('/help', methods=['GET', 'POST'])
@login_required
def help_page():
    if request.method == 'POST':
        subject = (request.form.get('subject') or '').strip()
        message = (request.form.get('message') or '').strip()
        add_to_faq = True if request.form.get('add_to_faq') == 'on' else False

        if not subject or not message:
            flash('Subject and message are required.')
            return redirect(url_for('help_page'))

        image_url = None
        image_mime = None
        image_filename = None

        file = request.files.get('image')
        if file and file.filename:
            if not _allowed_image(file.filename):
                flash('Unsupported image type. Allowed: png, jpg, jpeg, gif, webp')
                return redirect(url_for('help_page'))
            _ensure_help_upload_dir()
            original_name = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
            final_name = f"{current_user.id}_{timestamp}_{original_name}"
            save_path = os.path.join(app.config['HELP_UPLOAD_FOLDER'], final_name)
            try:
                file.save(save_path)
                image_filename = original_name
                image_url = f"/static/uploads/help/{final_name}"
                image_mime = file.mimetype
            except Exception as e:
                print(f"DEBUG: failed to save help image: {e}")
                flash('Failed to upload image; please try again.')
                return redirect(url_for('help_page'))

        ticket = HelpTicket(
            user_id=current_user.id,
            subject=subject,
            message=message,
            add_to_faq=add_to_faq,
            image_url=image_url,
            image_mime=image_mime,
            image_filename=image_filename,
        )
        db.session.add(ticket)
        db.session.commit()
        flash('Your help request has been submitted.')
        return redirect(url_for('help_page'))

    # GET: show user's tickets and searchable FAQs
    q = (request.args.get('q') or '').strip()
    try:
        faq_page_num = max(1, int(request.args.get('page') or 1))
    except Exception:
        faq_page_num = 1
    FAQ_PER_PAGE = 8
    tickets = HelpTicket.query.filter_by(user_id=current_user.id).order_by(HelpTicket.created_at.desc()).all()

    # FAQ: only those marked add_to_faq and having at least one reply
    faq_query = HelpTicket.query.filter_by(add_to_faq=True)
    # must have replies
    faq_query = faq_query.filter(HelpTicket.id.in_(db.session.query(HelpReply.ticket_id)))
    if q:
        like = f"%{q}%"
        # search in ticket subject/message OR any reply message
        faq_query = faq_query.filter(
            or_(
                HelpTicket.subject.ilike(like),
                HelpTicket.message.ilike(like),
                HelpTicket.id.in_(
                    db.session.query(HelpReply.ticket_id).filter(HelpReply.message.ilike(like))
                ),
            )
        )
    faq_query = faq_query.order_by(HelpTicket.created_at.desc())
    try:
        faq_total = faq_query.count()
    except Exception:
        faq_total = 0
    faq_pages = (faq_total + FAQ_PER_PAGE - 1) // FAQ_PER_PAGE if faq_total else 1
    if faq_page_num > faq_pages:
        faq_page_num = faq_pages
    faq_tickets = faq_query.offset((faq_page_num - 1) * FAQ_PER_PAGE).limit(FAQ_PER_PAGE).all()

    return render_template('help.html', tickets=tickets, faq_tickets=faq_tickets, q=q, faq_page_num=faq_page_num, faq_pages=faq_pages, faq_total=faq_total)




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

@app.route('/admin/help')
@login_required
@admin_required
def admin_help_list():
    status = (request.args.get('status') or 'all').strip()
    query = HelpTicket.query
    if status == 'unreplied':
        query = query.filter(~HelpTicket.id.in_(db.session.query(HelpReply.ticket_id)))
    elif status == 'faq':
        query = query.filter_by(add_to_faq=True)
    tickets = query.order_by(HelpTicket.created_at.desc()).all()
    return render_template('help_admin.html', tickets=tickets, status=status)


@app.route('/admin/tools', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_tools():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        code = (request.form.get('code') or '').strip() or None
        domain = (request.form.get('domain') or '').strip() or None
        if not name:
            flash('Institution name is required.')
            return redirect(url_for('admin_tools'))
        existing = Institution.query.filter(func.lower(Institution.name) == name.lower()).first()
        if existing:
            flash('Institution with this name already exists.')
            return redirect(url_for('admin_tools'))
        inst = Institution(name=name, code=code, domain=domain)
        db.session.add(inst)
        db.session.commit()
        # Optional logo upload on create
        file = request.files.get('logo')
        if file and file.filename:
            if not _allowed_image(file.filename):
                flash('Unsupported image type. Allowed: png, jpg, jpeg, gif, webp')
                return redirect(url_for('admin_tools'))
            try:
                original = secure_filename(file.filename)
                mime = file.mimetype
                data = file.read()
                inst.image_filename = original
                inst.image_mime = mime
                inst.image_data = data
                inst.logo_url = f"/institutions/logo/{inst.id}"
                db.session.commit()
            except Exception as e:
                print(f"DEBUG: failed to store institution logo on create: {e}")
                flash('Institution created but logo upload failed. You can upload it in Edit.')
        flash('Institution created.')
        return redirect(url_for('admin_tools'))
    institutions = Institution.query.order_by(Institution.is_system.desc(), Institution.name.asc()).all()
    return render_template('admin_tools.html', institutions=institutions)


@app.route('/admin/institutions/<int:inst_id>/update', methods=['POST'])
@login_required
@admin_required
def update_institution(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    name = (request.form.get('name') or '').strip()
    code = (request.form.get('code') or '').strip() or None
    domain = (request.form.get('domain') or '').strip() or None
    if inst.is_system:
        # Keep MMU permanent; only allow domain/logo update
        if domain is not None:
            inst.domain = domain
    else:
        if name:
            # Prevent duplicate name
            exists = Institution.query.filter(func.lower(Institution.name) == name.lower(), Institution.id != inst.id).first()
            if exists:
                flash('Another institution already uses this name.')
                return redirect(url_for('admin_tools'))
            inst.name = name
        inst.code = code
        inst.domain = domain
    db.session.commit()
    flash('Institution updated.')
    return redirect(url_for('admin_tools'))


@app.route('/admin/institutions/<int:inst_id>/logo', methods=['POST'])
@login_required
@admin_required
def upload_institution_logo(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    file = request.files.get('logo')
    if not file or not file.filename:
        flash('No logo selected.')
        return redirect(url_for('admin_tools'))
    if not _allowed_image(file.filename):
        flash('Unsupported image type. Allowed: png, jpg, jpeg, gif, webp')
        return redirect(url_for('admin_tools'))
    try:
        original = secure_filename(file.filename)
        mime = file.mimetype
        data = file.read()
        inst.image_filename = original
        inst.image_mime = mime
        inst.image_data = data
        inst.logo_url = f"/institutions/logo/{inst.id}"
        db.session.commit()
        flash('Logo updated.')
    except Exception as e:
        print(f"DEBUG: failed to store institution logo: {e}")
        flash('Failed to upload logo; please try again.')
    return redirect(url_for('admin_tools'))


@app.route('/institutions/logo/<int:inst_id>')
def serve_institution_logo(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    if not getattr(inst, 'image_data', None):
        abort(404)
    try:
        from io import BytesIO
        bio = BytesIO(inst.image_data)
        response = send_file(bio, mimetype=(inst.image_mime or 'image/png'), as_attachment=False, download_name=(inst.image_filename or 'logo'))
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        response.headers['ETag'] = get_cache_bust_version()
        return response
    except Exception as e:
        print(f"DEBUG: failed to serve institution logo: {e}")
        abort(500)


@app.route('/admin/institutions/<int:inst_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_institution(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    if inst.is_system:
        flash('System institution cannot be deleted.')
        return redirect(url_for('admin_tools'))
    # Optionally, unassign users by clearing school_university string
    users = User.query.filter(User.school_university == inst.name).all()
    for u in users:
        u.school_university = None
    db.session.delete(inst)
    db.session.commit()
    flash('Institution deleted.')
    return redirect(url_for('admin_tools'))


@app.route('/admin/institutions/<int:inst_id>/users', methods=['GET'])
@login_required
@admin_required
def institution_users(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    users = User.query.filter(User.school_university == inst.name).order_by(User.id.desc()).all()
    return render_template('admin_tools.html', institutions=Institution.query.order_by(Institution.is_system.desc(), Institution.name.asc()).all(), selected_institution=inst, institution_users=users)


@app.route('/admin/institutions/<int:inst_id>/assign', methods=['POST'])
@login_required
@admin_required
def assign_user_to_institution(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    identifier = (request.form.get('identifier') or '').strip()
    if not identifier:
        flash('Provide a username or email to assign.')
        return redirect(url_for('institution_users', inst_id=inst.id))
    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('institution_users', inst_id=inst.id))
    # Assign by setting school_university string (non-invasive)
    user.school_university = inst.name
    db.session.commit()
    flash(f"Assigned @{user.username} to {inst.name}.")
    return redirect(url_for('institution_users', inst_id=inst.id))


@app.route('/admin/institutions/<int:inst_id>/remove', methods=['POST'])
@login_required
@admin_required
def remove_user_from_institution(inst_id):
    inst = Institution.query.get_or_404(inst_id)
    user_id = request.form.get('user_id')
    try:
        user_id = int(user_id)
    except Exception:
        flash('Invalid user id.')
        return redirect(url_for('institution_users', inst_id=inst.id))
    user = User.query.get_or_404(user_id)
    if user.school_university == inst.name:
        user.school_university = None
        db.session.commit()
        flash(f"Removed @{user.username} from {inst.name}.")
    return redirect(url_for('institution_users', inst_id=inst.id))


@app.route('/admin/help/<int:ticket_id>/reply', methods=['POST'])
@login_required
@admin_required
def admin_help_reply(ticket_id):
    ticket = HelpTicket.query.get_or_404(ticket_id)
    message = (request.form.get('message') or '').strip()
    if not message:
        flash('Reply message is required.')
        return redirect(url_for('admin_help_list'))
    reply = HelpReply(ticket_id=ticket.id, admin_id=current_user.id, message=message)
    db.session.add(reply)
    db.session.commit()
    flash('Reply sent.')
    return redirect(url_for('admin_help_list'))


@app.route('/faq')
def faq_page():
    tickets = HelpTicket.query.filter_by(add_to_faq=True).order_by(HelpTicket.created_at.desc()).all()
    tickets = [t for t in tickets if t.replies]
    return render_template('faq.html', tickets=tickets)

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
                
                # help_ticket
                if 'help_ticket' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS help_ticket (
                                id SERIAL PRIMARY KEY,
                                user_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
                                subject VARCHAR(200) NOT NULL,
                                message TEXT NOT NULL,
                                add_to_faq BOOLEAN DEFAULT FALSE,
                                image_url VARCHAR(300),
                                image_mime VARCHAR(100),
                                image_filename VARCHAR(255),
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created help_ticket table.")
                    except Exception as ce:
                        print(f"Could not create help_ticket: {ce}")

                # help_reply
                if 'help_reply' not in tables:
                    try:
                        db.session.execute(text(
                            """
                            CREATE TABLE IF NOT EXISTS help_reply (
                                id SERIAL PRIMARY KEY,
                                ticket_id INTEGER NOT NULL REFERENCES "help_ticket" (id) ON DELETE CASCADE,
                                admin_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
                                message TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        ))
                        db.session.commit()
                        print("Created help_reply table.")
                    except Exception as ce:
                        print(f"Could not create help_reply: {ce}")
                # institution columns
                if 'institution' in tables:
                    cols = {c['name'] for c in inspector.get_columns('institution')}
                    dialect = db.engine.dialect.name
                    if 'image_data' not in cols:
                        try:
                            if dialect == 'postgresql':
                                db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_data BYTEA"))
                            else:
                                db.session.execute(text("ALTER TABLE institution ADD COLUMN image_data BLOB"))
                            db.session.commit()
                            print("Added institution.image_data column.")
                        except Exception as ce:
                            print(f"Could not add institution.image_data: {ce}")
                            db.session.rollback()
                    if 'image_mime' not in cols:
                        try:
                            db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_mime VARCHAR(100)"))
                            db.session.commit()
                            print("Added institution.image_mime column.")
                        except Exception as ce:
                            print(f"Could not add institution.image_mime: {ce}")
                            db.session.rollback()
                    if 'image_filename' not in cols:
                        try:
                            db.session.execute(text("ALTER TABLE institution ADD COLUMN IF NOT EXISTS image_filename VARCHAR(255)"))
                            db.session.commit()
                            print("Added institution.image_filename column.")
                        except Exception as ce:
                            print(f"Could not add institution.image_filename: {ce}")
                            db.session.rollback()
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
