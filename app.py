from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import hashlib
import os
import requests
import json
from flask_migrate import Migrate
from tracker.task_tracker import assignments_bp, assignmenet_db
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from functools import wraps
from sqlalchemy import or_, func
import threading
from gpa_calculator.gpa import gpa_bp

load_dotenv()

app = Flask(__name__)


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


database_url = os.getenv('DATABASE_URL', 'postgresql://studybox_db_user:VVb2l5baXEXnAIEYQDDwBKfmux7XaDE0@dpg-d2kjiqjipnbc73f69d0g-a.singapore-postgres.render.com/studybox_db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Brevo API
app.config['BREVO_API_KEY'] = os.getenv('BREVO_API_KEY')
app.config['SENDER_EMAIL'] = os.getenv('SENDER_EMAIL')
app.config['SENDER_NAME'] = os.getenv('SENDER_NAME', 'StudyBox')


app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')

# Remove SERVER_NAME configuration to allow multiple domains
# This allows the app to work with both studybox.onrender.com and custom domains
server_name_env = os.getenv('SERVER_NAME')
if server_name_env and server_name_env.strip() and server_name_env != 'studybox.onrender.com':
    app.config['SERVER_NAME'] = server_name_env

app.register_blueprint(assignments_bp, url_prefix='/assignment_tracker')
app.register_blueprint(gpa_bp, url_prefix='/gpa_calculator')


if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'dev-secret-key-change-me'

assignmenet_db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, assignmenet_db)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        # Handle cases where user_id is not a valid integer
        return None



class User(UserMixin, assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    username = assignmenet_db.Column(assignmenet_db.String(150), unique=True, nullable=False)
    password = assignmenet_db.Column(assignmenet_db.String(150), nullable=False)
    email = assignmenet_db.Column(assignmenet_db.String(150), unique=True, nullable=False)
    is_verified = assignmenet_db.Column(assignmenet_db.Boolean, default=False)
    verification_token = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    is_admin = assignmenet_db.Column(assignmenet_db.Boolean, default=False, nullable=False)
    pending_email = assignmenet_db.Column(assignmenet_db.String(150), nullable=True)
    email_change_token = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    school_university = assignmenet_db.Column(assignmenet_db.String(200), nullable=True)

    @property
    def public_id(self):
        return f"sd{_encode_user_code(self.id)}"


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not getattr(current_user, 'is_admin', False):
            flash('You do not have permission to access that page.')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return wrapped_view



_default_admin_checked = False
_usernames_normalized = False

@app.before_request
def ensure_default_admin_exists_once():
    global _default_admin_checked
    global _usernames_normalized
    if _default_admin_checked and _usernames_normalized:
        return
    try:
        # Ensure the username 'admin' is always an admin if present
        user = User.query.filter_by(username='admin').first()
        if user and not user.is_admin:
            user.is_admin = True
            assignmenet_db.session.commit()
            print("DEBUG: Ensured @admin has admin privileges")
        # One-time normalization: force all usernames to lowercase, resolving conflicts
        if not _usernames_normalized:
            users = User.query.all()
            for u in users:
                original = (u.username or '').strip()
                if not original:
                    continue
                lower = original.lower()
                if lower == u.username:
                    continue
                # Ensure unique by appending numeric suffix if necessary
                candidate = lower
                suffix = 2
                while User.query.filter(func.lower(User.username) == candidate).filter(User.id != u.id).first():
                    candidate = f"{lower}{suffix}"
                    suffix += 1
                print(f"DEBUG: Normalizing username {original} -> {candidate}")
                u.username = candidate
            assignmenet_db.session.commit()
            _usernames_normalized = True
    except Exception as e:
        print(f"DEBUG: Failed to ensure default admin: {e}")
    finally:
        _default_admin_checked = True

class Registerform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    school_university = StringField(validators=[Length(max=200)], render_kw={"placeholder": "Enter your school or university name"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        desired = (username.data or '').strip().lower()
        existing_user_username = User.query.filter(func.lower(User.username) == desired).first()
        if existing_user_username:
            raise ValidationError("Username already exists")
        
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("Email already exists")

class Loginform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=3, max=150)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Enter your email address"})
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm New Password"})
    submit = SubmitField('Reset Password')
    
    def validate_confirm_password(self, confirm_password):
        if self.password.data != confirm_password.data:
            raise ValidationError("Passwords do not match")

class profileupdateform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
    school_university = StringField(validators=[Length(max=200)], render_kw={"placeholder": "Enter your school or university name"})
    current_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Current Password"})
    submit = SubmitField('Update')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username and existing_user_username.id != current_user.id:
            raise ValidationError("Username already exists")
        
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email and existing_user_email.id != current_user.id:
            raise ValidationError("Email already exists")

def send_email_via_brevo_api(to_email, to_name, subject, html_content, text_content=None):
    """
    Send email using Brevo API
    
    Args:
        to_email (str): Recipient email address
        to_name (str): Recipient name
        subject (str): Email subject
        html_content (str): HTML email content
        text_content (str): Plain text email content (optional)
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    
    # Get Brevo API configuration
    api_key = os.getenv('BREVO_API_KEY')
    sender_email = os.getenv('SENDER_EMAIL')
    sender_name = os.getenv('SENDER_NAME', 'StudyBox')
    
    if not api_key or not sender_email:
        print("❌ Missing BREVO_API_KEY or SENDER_EMAIL in environment variables")
        return False
    
    # Brevo API endpoint
    url = "https://api.brevo.com/v3/smtp/email"
    
    # Prepare headers
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    
    # Prepare email data
    email_data = {
        "sender": {
            "name": sender_name,
            "email": sender_email
        },
        "to": [
            {
                "email": to_email,
                "name": to_name
            }
        ],
        "subject": subject,
        "htmlContent": html_content
    }
    
    # Add text content if provided
    if text_content:
        email_data["textContent"] = text_content
    
    try:
        print(f"📤 Sending email via Brevo API to {to_email}...")
        
        # Make API request
        response = requests.post(url, headers=headers, data=json.dumps(email_data))
        
        if response.status_code == 201:
            print(f"✅ Email sent successfully to {to_email}")
            return True
        else:
            print(f"❌ Failed to send email. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error sending email via Brevo API: {str(e)}")
        return False

def generate_verification_token(email):
    return serializer.dumps(email, salt='email-verification')

def is_mmu_email(email):
    """Check if the email belongs to MMU (Multimedia University Malaysia)"""
    return email.lower().endswith('@student.mmu.edu.my')

def get_university_from_email(email):
    """Get university name based on email domain"""
    if is_mmu_email(email):
        return "Multimedia University Malaysia"
    return ""


def gravatar_url(email, size=96):
    try:
        normalized = (email or '').strip().lower().encode('utf-8')
        email_hash = hashlib.md5(normalized).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?d=identicon&s={int(size)}"
    except Exception:
        # Fallback to identicon without hash if anything goes wrong
        return f"https://www.gravatar.com/avatar/?d=identicon&s={int(size)}"


@app.context_processor
def inject_helpers():
    return {
        'avatar_url': gravatar_url,
    }


# Public ID helpers (base36 with "sd" prefix)
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
# Choose constants coprime to modulus for bijective mapping
_CODE_MULTIPLIER = 48271  # not divisible by 2 or 3
_CODE_INCREMENT = 12345
_CODE_MULTIPLIER_INV = pow(_CODE_MULTIPLIER, -1, _CODE_MODULUS)

def _encode_user_code(user_id):
    value = (int(user_id) * _CODE_MULTIPLIER + _CODE_INCREMENT) % _CODE_MODULUS
    return _encode_base36(value).zfill(_CODE_LENGTH)

def _decode_public_id(public_code):
    # Accept strings that start with 'sd' followed by base36 (fixed length)
    if not public_code or len(public_code) < 3 or not public_code.startswith('sd'):
        return None
    base = public_code[2:]
    # validate characters
    if any(ch.lower() not in _BASE36_ALPHABET for ch in base):
        return None
    try:
        # parse base36
        value = 0
        for ch in base.lower():
            value = value * 36 + _BASE36_ALPHABET.index(ch)
        original = ((value - _CODE_INCREMENT) * _CODE_MULTIPLIER_INV) % _CODE_MODULUS
        # Only accept realistic small IDs to avoid collisions from modulus wrap
        if original <= 0:
            return None
        return original
    except Exception:
        return None

def verify_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
        return email
    except:
        return None

def send_email_async(user_email, username, verification_url):
    """Send email in a separate thread to avoid blocking the main request"""
    def _send():
        with app.app_context():
            try:
                print(f"DEBUG: Starting email send to {user_email}")
                
                # HTML content
                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: white;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://studybox.onrender.com/static/images/nav.png" alt="StudyBox Logo" style="max-width: 150px; height: auto;">
                    </div>
                    <h2 style="color: #000000; text-align: center;">Welcome to StudyBox!</h2>
                    <p style="color: #000000;">Hello {username},</p>
                    <p style="color: #000000;">Thank you for registering with StudyBox. Please click the button below to verify your email address:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{verification_url}" style="background-color: #000000; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email Address</a>
                    </p>
                    <p style="color: #000000;">This link will expire in 1 hour.</p>
                    <p style="color: #000000;">If you didn't create this account, please ignore this email.</p>
                    <br>
                    <p style="color: #000000;">Best regards,<br>StudyBox Team</p>
                </body>
                </html>
                """

                # Create plain text content
                text_content = f"""
                Welcome to StudyBox!
                
                Hello {username},
                
                Thank you for registering with StudyBox. Please click the link below to verify your email address:
                
                {verification_url}
                
                This link will expire in 1 hour.
                
                If you didn't create this account, please ignore this email.
                
                Best regards,
                StudyBox Team
                """

                success = send_email_via_brevo_api(
                    to_email=user_email,
                    to_name=username,
                    subject="Verify Your Email - StudyBox",
                    html_content=html_content,
                    text_content=text_content
                )
                
                if success:
                    print(f"DEBUG: Brevo API email sent successfully to {user_email}")
                else:
                    print(f"DEBUG: Failed to send email to {user_email}")
                
            except Exception as e:
                print(f"DEBUG: Error sending email to {user_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


def send_verification_email(user_email, username):
    try:
        token = generate_verification_token(user_email)
        # Build absolute URL while we are still in a request context
        verification_url = url_for('verify_email', token=token, _external=True)
        send_email_async(user_email, username, verification_url)
    except Exception as e:
        print(f"DEBUG: Error generating token for {user_email}: {e}")
        raise e

def send_password_reset_email(user_email, username, reset_url):
    """Send password reset email via Brevo API"""
    def _send_reset():
        with app.app_context():
            try:
                print(f"DEBUG: Starting password reset email send to {user_email}")
                
                # HTML content
                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: white;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://studybox.onrender.com/static/images/nav.png" alt="StudyBox Logo" style="max-width: 150px; height: auto;">
                    </div>
                    <h2 style="color: #000000; text-align: center;">Password Reset Request</h2>
                    <p style="color: #000000;">Hello {username},</p>
                    <p style="color: #000000;">You requested to reset your password for your StudyBox account. Click the button below to reset your password:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{reset_url}" style="background-color: #000000; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
                    </p>
                    <p style="color: #000000;">This link will expire in 1 hour.</p>
                    <p style="color: #000000;">If you didn't request this password reset, please ignore this email.</p>
                    <br>
                    <p style="color: #000000;">Best regards,<br>StudyBox Team</p>
                </body>
                </html>
                """

                # Create plain text content
                text_content = f"""
                Password Reset Request
                
                Hello {username},
                
                You requested to reset your password for your StudyBox account. Click the link below to reset your password:
                
                {reset_url}
                
                This link will expire in 1 hour.
                
                If you didn't request this password reset, please ignore this email.
                
                Best regards,
                StudyBox Team
                """

                # Send email via Brevo API
                success = send_email_via_brevo_api(
                    to_email=user_email,
                    to_name=username,
                    subject="Reset Your Password - StudyBox",
                    html_content=html_content,
                    text_content=text_content
                )
                
                if success:
                    print(f"DEBUG: Password reset email sent successfully to {user_email}")
                else:
                    print(f"DEBUG: Failed to send password reset email to {user_email}")
                
            except Exception as e:
                print(f"DEBUG: Error sending password reset email to {user_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    thread = threading.Thread(target=_send_reset)
    thread.daemon = True
    thread.start()

def send_email_change_verification(user_email, username, new_email, verification_url):
    """Send email change verification email via Brevo API"""
    def _send_email_change():
        with app.app_context():
            try:
                print(f"DEBUG: Starting email change verification send to {new_email}")
                
                # HTML content
                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: white;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://studybox.onrender.com/static/images/nav.png" alt="StudyBox Logo" style="max-width: 150px; height: auto;">
                    </div>
                    <h2 style="color: #000000; text-align: center;">Email Change Verification</h2>
                    <p style="color: #000000;">Hello {username},</p>
                    <p style="color: #000000;">You requested to change your email address from <strong>{user_email}</strong> to <strong>{new_email}</strong>.</p>
                    <p style="color: #000000;">Click the button below to verify this email change:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{verification_url}" style="background-color: #000000; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email Change</a>
                    </p>
                    <p style="color: #000000;">This link will expire in 1 hour.</p>
                    <p style="color: #000000;">If you didn't request this email change, please ignore this email and contact support.</p>
                    <br>
                    <p style="color: #000000;">Best regards,<br>StudyBox Team</p>
                </body>
                </html>
                """

                # Create plain text content
                text_content = f"""
                Email Change Verification
                
                Hello {username},
                
                You requested to change your email address from {user_email} to {new_email}.
                
                Click the link below to verify this email change:
                
                {verification_url}
                
                This link will expire in 1 hour.
                
                If you didn't request this email change, please ignore this email and contact support.
                
                Best regards,
                StudyBox Team
                """

                # Send email via Brevo API
                success = send_email_via_brevo_api(
                    to_email=new_email,
                    to_name=username,
                    subject="Verify Your Email Change - StudyBox",
                    html_content=html_content,
                    text_content=text_content
                )
                
                if success:
                    print(f"DEBUG: Email change verification sent successfully to {new_email}")
                else:
                    print(f"DEBUG: Failed to send email change verification to {new_email}")
                
            except Exception as e:
                print(f"DEBUG: Error sending email change verification to {new_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    thread = threading.Thread(target=_send_email_change)
    thread.daemon = True
    thread.start()

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            user = User.query.filter_by(email=email).first()
            if user and not user.is_verified:
                try:
                    token = generate_verification_token(user.email)
                    send_verification_email(user.email, user.username)
                    verification_url = url_for('verify_email', token=token, _external=True)
                    flash('Email sent successfully!')
                except Exception as e:
                    print(f"DEBUG: Error resending verification: {e}")
                    # Generate fallback link
                    token = generate_verification_token(user.email)
                    verification_url = url_for('verify_email', token=token, _external=True)
                    flash('Email failed. Try again.')


            else:
                flash('Email not found or already verified.')
        else:
            flash('Please enter your email address.')
    return render_template('resend_verification.html')

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    verified_users = User.query.filter_by(is_verified=True).count()
    admins = User.query.filter_by(is_admin=True).count()
    # Optional quick search and filter on dashboard
    q = request.args.get('q', '').strip()
    active_filter = request.args.get('filter', 'all').strip() or 'all'

    query = User.query
    if active_filter == 'verified':
        query = query.filter_by(is_verified=True)
    elif active_filter == 'admins':
        query = query.filter_by(is_admin=True)
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
                           admins=admins,
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
    elif active_filter == 'admins':
        query = query.filter_by(is_admin=True)
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

@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_promote(user_id):
    # Only @admin can promote
    if current_user.username.strip().lower() != 'admin':
        flash('Only @admin can promote users to admin.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    user = User.query.get_or_404(user_id)
    if user.username.strip().lower() == 'admin':
        flash('Cannot change admin status of @admin.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    user.is_admin = True
    assignmenet_db.session.commit()
    flash(f"Promoted {user.username} to admin")
    # Preserve current view parameters
    filt = request.form.get('filter') or 'all'
    q = (request.form.get('q') or '').strip()
    open_id = request.form.get('open_id') or str(user_id)
    page = request.form.get('page') or 'users'
    if page == 'dashboard':
        return redirect(url_for('admin_dashboard', filter=filt, q=q, open_id=open_id))
    else:
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_demote(user_id):
    # Only @admin can demote
    if current_user.username.strip().lower() != 'admin':
        flash('Only @admin can demote admins.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    if current_user.id == user_id:
        flash('You cannot demote yourself.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    user = User.query.get_or_404(user_id)
    if user.username.strip().lower() == 'admin':
        flash('You cannot demote @admin.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    user.is_admin = False
    assignmenet_db.session.commit()
    flash(f"Demoted {user.username} from admin")
    filt = request.form.get('filter') or 'all'
    q = (request.form.get('q') or '').strip()
    open_id = request.form.get('open_id') or str(user_id)
    page = request.form.get('page') or 'users'
    if page == 'dashboard':
        return redirect(url_for('admin_dashboard', filter=filt, q=q, open_id=open_id))
    else:
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
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
    assignmenet_db.session.delete(user)
    assignmenet_db.session.commit()
    flash(f"Deleted user {username}")
    filt = request.form.get('filter') or 'all'
    q = (request.form.get('q') or '').strip()
    page = request.form.get('page') or 'users'
    if page == 'dashboard':
        return redirect(url_for('admin_dashboard', filter=filt, q=q))
    else:
        return redirect(url_for('admin_users', filter=filt, q=q))

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_verified:
        flash('User is already verified.')
        filt = request.form.get('filter') or 'all'
        q = (request.form.get('q') or '').strip()
        open_id = request.form.get('open_id') or str(user_id)
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))
    user.is_verified = True
    assignmenet_db.session.commit()
    flash(f"Verified user {user.username}")
    filt = request.form.get('filter') or 'all'
    q = (request.form.get('q') or '').strip()
    open_id = request.form.get('open_id') or str(user_id)
    page = request.form.get('page') or 'users'
    if page == 'dashboard':
        return redirect(url_for('admin_dashboard', filter=filt, q=q, open_id=open_id))
    else:
        return redirect(url_for('admin_users', filter=filt, q=q, open_id=open_id))

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
    assignmenet_db.session.commit()
    return ("Bootstrap complete", 200)

@app.route('/verify/<token>')
def verify_email(token):
    email = verify_token(token)
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            
            # Update university if it's an MMU email
            if is_mmu_email(user.email) and user.school_university != "Multimedia University Malaysia":
                user.school_university = "Multimedia University Malaysia"
            
            assignmenet_db.session.commit()
            flash('Email verified successfully! You can now login to your account.')
            return redirect(url_for('login'))
    flash('Invalid or expired verification link. Please try registering again or resend verification email.')
    return redirect(url_for('login'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if not email:
        flash('Invalid or expired reset link. Please request a new password reset.')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please request a new password reset.')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Update user password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        assignmenet_db.session.commit()
        
        flash('Password reset successfully! You can now login with your new password.')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form, token=token)

@app.route('/verify-email-change/<token>')
def verify_email_change(token):
    email = verify_token(token)
    if not email:
        flash('Invalid or expired verification link.')
        return redirect(url_for('profile'))
    
    # Find user with this email change token
    user = User.query.filter_by(email_change_token=token).first()
    if not user:
        flash('Invalid verification link.')
        return redirect(url_for('profile'))
    
    # Check if the token matches the pending email
    if user.pending_email != email:
        flash('Invalid verification link.')
        return redirect(url_for('profile'))
    
    # Update user email
    old_email = user.email
    user.email = user.pending_email
    user.pending_email = None
    user.email_change_token = None
    
    # Update university if the new email is an MMU email
    if is_mmu_email(user.email):
        user.school_university = "Multimedia University Malaysia"
    
    assignmenet_db.session.commit()
    
    flash(f'Email successfully changed from {old_email} to {user.email}!')
    return redirect(url_for('profile'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    error_message = None
    if form.validate_on_submit():
        identifier_raw = form.username.data.strip()
        identifier_lower = identifier_raw.lower()
        if '@' in identifier_raw:
            user = User.query.filter(func.lower(User.email) == identifier_lower).first()
        else:
            user = User.query.filter(func.lower(User.username) == identifier_lower).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                if user.is_verified:
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    error_message = "Your email is not verified yet. Please check your inbox and click the verification link."
            else:
                error_message = "Invalid username or password"
        else:
            error_message = "Invalid username or password"
    return render_template('login.html', form=form, error_message=error_message)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    success_message = None
    error_message = None
    
    if form.validate_on_submit():
        email = form.email.data.strip()
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                # Generate password reset token
                token = generate_verification_token(email)
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # Send password reset email
                send_password_reset_email(user.email, user.username, reset_url)
                success_message = "Password reset link has been sent to your email address."
            except Exception as e:
                print(f"DEBUG: Error sending password reset email: {e}")
                error_message = "Failed to send reset email. Please try again."
        else:
            # Don't reveal if email exists or not for security
            success_message = "If an account with that email exists, a password reset link has been sent."
    
    return render_template('forgot_password.html', form=form, success_message=success_message, error_message=error_message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()
    success_message = None
    
    # Auto-detect university from email if it's an MMU email
    if request.method == 'GET':
        # Pre-fill university if it's an MMU email (for display purposes)
        pass
    elif request.method == 'POST' and form.email.data:
        # Auto-detect university from email
        detected_university = get_university_from_email(form.email.data)
        if detected_university:
            form.school_university.data = detected_university
    
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Get university - either from form or auto-detected
            university = form.school_university.data
            if not university and form.email.data:
                university = get_university_from_email(form.email.data)
            
            new_user = User(
                username=(form.username.data or '').strip().lower(), 
                email=form.email.data, 
                password=hashed_password,
                school_university=university
            )
            assignmenet_db.session.add(new_user)
            assignmenet_db.session.commit()
            # Auto-promote if username is 'admin'
            try:
                if new_user.username.strip().lower() == 'admin' and not new_user.is_admin:
                    new_user.is_admin = True
                    assignmenet_db.session.commit()
                    print("DEBUG: Auto-promoted @admin to admin on registration")
            except Exception as _e:
                print(f"DEBUG: Error while auto-promoting default admin: {_e}")
            
            print(f"DEBUG: Sending verification email to {new_user.email}")
            try:
                send_verification_email(new_user.email, new_user.username)
                print(f"DEBUG: Verification email sent successfully")
                success_message = "Registration successful! Check your email for verification link."
            except Exception as email_error:
                print(f"DEBUG: Email sending failed: {email_error}")
                token = generate_verification_token(new_user.email)
                verification_url = url_for('verify_email', token=token, _external=True)
                success_message = "Registration successful! Email failed - try resend verification."
        except Exception as e:
            print(f"DEBUG: Error during registration: {e}")
            success_message = "Registration failed. Please try again."
    return render_template('register.html', form=form, success_message=success_message)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = profileupdateform()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            # Check if email is being changed
            if form.email.data != current_user.email:
                # Check if new email already exists
                existing_user = User.query.filter_by(email=form.email.data).first()
                if existing_user and existing_user.id != current_user.id:
                    flash('Email already exists')
                    return redirect(url_for('profile'))
                
                # Store pending email change
                current_user.pending_email = form.email.data
                current_user.username = (form.username.data or '').strip().lower()
                assignmenet_db.session.commit()
                
                # Generate email change verification token
                token = generate_verification_token(form.email.data)
                current_user.email_change_token = token
                assignmenet_db.session.commit()
                
                # Send verification email to new email address
                verification_url = url_for('verify_email_change', token=token, _external=True)
                send_email_change_verification(current_user.email, current_user.username, form.email.data, verification_url)
                
                flash('Email change requested! Please check your new email address for verification link.')
                return redirect(url_for('profile'))
            else:
                # No email change, just update username and school
                current_user.username = (form.username.data or '').strip().lower()
                
                # Only allow school/university change if not MMU student
                if not is_mmu_email(current_user.email):
                    current_user.school_university = form.school_university.data
                # For MMU students, keep their university unchangeable
                
                assignmenet_db.session.commit()
                flash('Profile updated successfully')
                return redirect(url_for('profile'))
        else:
            flash('Invalid current password')
            return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = (current_user.username or '').lower()
        form.email.data = current_user.email
        form.school_university.data = current_user.school_university
    return render_template('profile.html', form=form)

@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST' and current_user.is_authenticated:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Invalid current password')
            return redirect(url_for('profile'))
        if new_password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            assignmenet_db.session.commit()
            flash('Password updated successfully')
            return redirect(url_for('profile'))
        else:
            flash('Passwords do not match')
            return redirect(url_for('profile'))
    return redirect(url_for('profile'))

@app.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def delete_profile():
    if request.method == 'POST':
        if bcrypt.check_password_hash(current_user.password, request.form['confirm_password']):
            assignmenet_db.session.delete(current_user)
            assignmenet_db.session.commit()
            logout_user()
            flash('Profile deleted successfully')
            return redirect(url_for('login'))
        else:
            flash('Invalid current password')
            return redirect(url_for('profile'))
    return redirect(url_for('profile'))

@app.route('/task')
@login_required
def task():
    return render_template('task.html')



@app.route('/sd<string:code>')
def public_profile_by_public_code(code):
    # Handle paths like /sd60bx8
    numeric_id = _decode_public_id(f"sd{code}")
    if not numeric_id:
        abort(404)
    user = User.query.get_or_404(numeric_id)
    return render_template('public_profile.html', user=user)


@app.route('/<username>')
def public_profile_by_username(username):
    # If someone enters an sd-code at root, redirect to the sd route
    if username.lower().startswith('sd') and len(username) > 2:
        return redirect(url_for('public_profile_by_public_code', code=username[2:]))
    # Case-insensitive match for username
    user = User.query.filter(func.lower(User.username) == username.strip().lower()).first()
    if not user:
        abort(404)
    return render_template('public_profile.html', user=user)


@app.errorhandler(404)
def page_not_found(e):
    print(e.code)
    print(e.description)
    return "sorry, the page you are looking for does not exist :(", 404
if __name__ == '__main__':
    try:
        with app.app_context():
            print("Attempting to connect to PostgreSQL database...")
            assignmenet_db.create_all()
            print("✅ Database connection successful!")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("This might be due to:")
        print("1. Network connectivity issues")
        print("2. Database server being down")
        print("3. Incorrect credentials")
        print("4. Firewall restrictions")
        print("\nFor local development, you might want to:")
        print("1. Use a local PostgreSQL instance")
        print("2. Use SQLite for development")
        print("3. Check your network connection to the database server")
    
    # Only run Flask development server locally
    if os.getenv('FLASK_ENV') != 'production':
        app.run(debug=True, host='127.0.0.1', port=5000)
