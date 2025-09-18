from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_migrate import Migrate
from tracker.task_tracker import assignments_bp, assignmenet_db
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from functools import wraps
from sqlalchemy import or_
import threading
import time
from gpa_calculator.gpa import gpa_bp

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
 

# Brevo SMTP configuration
app.config['BREVO_EMAIL'] = os.getenv('BREVO_LOGIN') or os.getenv('SENDER_EMAIL') or os.getenv('BREVO_EMAIL')
app.config['BREVO_PASSWORD'] = os.getenv('BREVO_PASSWORD')
app.config['BREVO_SERVER'] = os.getenv('BREVO_SMTP_SERVER') or os.getenv('BREVO_SERVER', 'smtp-relay.brevo.com')
app.config['BREVO_PORT'] = int(os.getenv('BREVO_SMTP_PORT') or os.getenv('BREVO_PORT', '587'))

# Required for generating absolute URLs in emails
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')
# Prefer explicit SERVER_NAME from environment for production deployments
server_name_env = os.getenv('SERVER_NAME')
if server_name_env:
    app.config['SERVER_NAME'] = server_name_env


app.register_blueprint(assignments_bp, url_prefix='/assignment_tracker')
app.register_blueprint(gpa_bp, url_prefix='/gpa_calculator')

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://studybox_db_user:VVb2l5baXEXnAIEYQDDwBKfmux7XaDE0@dpg-d2kjiqjipnbc73f69d0g-a.singapore-postgres.render.com/studybox_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


if Config.DATABASE_URL.startswith('postgres://'):
    Config.DATABASE_URL = Config.DATABASE_URL.replace('postgres://', 'postgresql://', 1)

Config.SQLALCHEMY_DATABASE_URI = Config.DATABASE_URL


app.config.from_object(Config)
if not app.config.get('SECRET_KEY'):
    # Fallback to a deterministic dev key if not provided via environment/config
    # This avoids runtime errors in itsdangerous when SECRET_KEY is None
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'dev-secret-key-change-me'
assignmenet_db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, assignmenet_db)

# Initialize token serializer after SECRET_KEY is confirmed
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(UserMixin, assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    username = assignmenet_db.Column(assignmenet_db.String(150), unique=True, nullable=False)
    password = assignmenet_db.Column(assignmenet_db.String(150), nullable=False)
    email = assignmenet_db.Column(assignmenet_db.String(150), unique=True, nullable=False)
    is_verified = assignmenet_db.Column(assignmenet_db.Boolean, default=False)
    verification_token = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    is_admin = assignmenet_db.Column(assignmenet_db.Boolean, default=False, nullable=False)


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


def _get_default_admin_email():
    return os.getenv('DEFAULT_ADMIN_EMAIL', 'nahin1234@gmail.com').strip().lower()


_default_admin_checked = False

@app.before_request
def ensure_default_admin_exists_once():
    global _default_admin_checked
    if _default_admin_checked:
        return
    try:
        target_email = _get_default_admin_email()
        if target_email:
            user = User.query.filter_by(email=target_email).first()
            if user and not user.is_admin:
                user.is_admin = True
                assignmenet_db.session.commit()
                print(f"DEBUG: Promoted default admin {target_email}")
    except Exception as e:
        print(f"DEBUG: Failed to ensure default admin: {e}")
    finally:
        _default_admin_checked = True

class Registerform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
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

class profileupdateform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[InputRequired(), Email()])
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

def generate_verification_token(email):
    return serializer.dumps(email, salt='email-verification')

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
                
                # Get Brevo SMTP configuration
                brevo_email = app.config.get('BREVO_EMAIL')
                brevo_password = app.config.get('BREVO_PASSWORD')
                brevo_server = app.config.get('BREVO_SERVER')
                brevo_port = app.config.get('BREVO_PORT')

                if not (brevo_email and brevo_password):
                    print("DEBUG: Brevo SMTP not configured. Logging verification URL instead of sending.")
                    print(f"DEBUG: Verification URL for {username} <{user_email}> -> {verification_url}")
                    return

                print("DEBUG: Sending via Brevo SMTP")
                
                # Create message
                msg = MIMEMultipart('alternative')
                msg['Subject'] = 'Verify Your Email - StudyBox'
                msg['From'] = brevo_email
                msg['To'] = user_email

                # Create HTML content
                html_body = f"""
                <html>
                <body>
                    <p>Hello {username},</p>
                    <p>Please click the following link to verify your email:</p>
                    <p><a href="{verification_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't create this account, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>StudyBox Team</p>
                </body>
                </html>
                """

                # Create plain text content
                text_body = f"""
                Hello {username},
                
                Please click the following link to verify your email:
                {verification_url}
                
                This link will expire in 1 hour.
                
                If you didn't create this account, please ignore this email.
                
                Best regards,
                StudyBox Team
                """

                # Attach parts
                part1 = MIMEText(text_body, 'plain')
                part2 = MIMEText(html_body, 'html')
                
                msg.attach(part1)
                msg.attach(part2)

                # Send email via SMTP
                with smtplib.SMTP(brevo_server, brevo_port) as server:
                    server.starttls()  # Enable TLS encryption
                    # Use BREVO_LOGIN for authentication, SENDER_EMAIL for From field
                    brevo_login = os.getenv('BREVO_LOGIN')
                    auth_email = brevo_login if brevo_login else brevo_email
                    server.login(auth_email, brevo_password)
                    server.sendmail(brevo_email, [user_email], msg.as_string())
                
                print(f"DEBUG: Brevo email sent successfully to {user_email}")
                
            except Exception as e:
                print(f"DEBUG: Error sending email to {user_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()

def send_otp_email(user_email, username, otp_code):
    """Send OTP email via Brevo SMTP"""
    def _send_otp():
        with app.app_context():
            try:
                print(f"DEBUG: Starting OTP email send to {user_email}")
                
                # Get Brevo SMTP configuration
                brevo_email = app.config.get('BREVO_EMAIL')
                brevo_password = app.config.get('BREVO_PASSWORD')
                brevo_server = app.config.get('BREVO_SERVER')
                brevo_port = app.config.get('BREVO_PORT')

                if not (brevo_email and brevo_password):
                    print("DEBUG: Brevo SMTP not configured. Logging OTP instead of sending.")
                    print(f"DEBUG: OTP for {username} <{user_email}> -> {otp_code}")
                    return

                print("DEBUG: Sending OTP via Brevo SMTP")
                
                # Create message
                msg = MIMEMultipart('alternative')
                msg['Subject'] = 'Your StudyBox OTP Code'
                msg['From'] = brevo_email
                msg['To'] = user_email

                # Create HTML content
                html_body = f"""
                <html>
                <body>
                    <h2>Your StudyBox OTP Code</h2>
                    <p>Hello {username},</p>
                    <p>Your OTP code is:</p>
                    <div style="background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
                        <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">{otp_code}</h1>
                    </div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>StudyBox Team</p>
                </body>
                </html>
                """

                # Create plain text content
                text_body = f"""
                Your StudyBox OTP Code
                
                Hello {username},
                
                Your OTP code is: {otp_code}
                
                This code will expire in 10 minutes.
                
                If you didn't request this code, please ignore this email.
                
                Best regards,
                StudyBox Team
                """

                # Attach parts
                part1 = MIMEText(text_body, 'plain')
                part2 = MIMEText(html_body, 'html')
                
                msg.attach(part1)
                msg.attach(part2)

                # Send email via SMTP
                with smtplib.SMTP(brevo_server, brevo_port) as server:
                    server.starttls()  # Enable TLS encryption
                    # Use BREVO_LOGIN for authentication, SENDER_EMAIL for From field
                    brevo_login = os.getenv('BREVO_LOGIN')
                    auth_email = brevo_login if brevo_login else brevo_email
                    server.login(auth_email, brevo_password)
                    server.sendmail(brevo_email, [user_email], msg.as_string())
                
                print(f"DEBUG: OTP email sent successfully to {user_email}")
                
            except Exception as e:
                print(f"DEBUG: Error sending OTP email to {user_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    thread = threading.Thread(target=_send_otp)
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
    users = User.query.order_by(User.id.desc()).limit(10).all()
    return render_template('admin.html',
                           page='dashboard',
                           total_users=total_users,
                           verified_users=verified_users,
                           admins=admins,
                           users=users)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin.html', page='users', users=users)

@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_promote(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    assignmenet_db.session.commit()
    flash(f"Promoted {user.username} to admin")
    return redirect(url_for('admin_users'))

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_demote(user_id):
    if current_user.id == user_id:
        flash('You cannot demote yourself.')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    user.is_admin = False
    assignmenet_db.session.commit()
    flash(f"Demoted {user.username} from admin")
    return redirect(url_for('admin_users'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if current_user.id == user_id:
        flash('You cannot delete yourself.')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    username = user.username
    assignmenet_db.session.delete(user)
    assignmenet_db.session.commit()
    flash(f"Deleted user {username}")
    return redirect(url_for('admin_users'))

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_verified:
        flash('User is already verified.')
        return redirect(url_for('admin_users'))
    user.is_verified = True
    assignmenet_db.session.commit()
    flash(f"Verified user {user.username}")
    return redirect(url_for('admin_users'))

@app.route('/admin/bootstrap', methods=['POST'])
def admin_bootstrap():
    # One-time bootstrap: if no admins exist, allow promoting by secret token
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
            assignmenet_db.session.commit()
            flash('Email verified successfully! You can now login to your account.')
            return redirect(url_for('login'))
    flash('Invalid or expired verification link. Please try registering again or resend verification email.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    error_message = None
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        user = User.query.filter(or_(User.username == identifier, User.email == identifier)).first()
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


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()
    success_message = None
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            assignmenet_db.session.add(new_user)
            assignmenet_db.session.commit()
            # Auto-promote default admin email if it matches
            try:
                if new_user.email.strip().lower() == _get_default_admin_email():
                    if not new_user.is_admin:
                        new_user.is_admin = True
                        assignmenet_db.session.commit()
                        print(f"DEBUG: Auto-promoted {new_user.email} to admin on registration")
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
            current_user.username = form.username.data
            current_user.email = form.email.data
            assignmenet_db.session.commit()
            flash('Profile updated successfully')
            return redirect(url_for('profile'))
        else:
            flash('Invalid current password')
            return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
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

@app.route('/send-otp', methods=['POST'])
def send_otp_route():
    """API endpoint to send OTP emails"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
        
        email = data.get('email')
        otp = data.get('otp')
        username = data.get('username', 'User')  # Default username if not provided
        
        if not email or not otp:
            return jsonify({"status": "error", "message": "Email and OTP are required"}), 400
        
        # Send OTP email
        send_otp_email(email, username, otp)
        
        return jsonify({"status": "success", "message": "OTP sent successfully!"}), 200
        
    except Exception as e:
        print(f"DEBUG: Error in send_otp_route: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500


@app.errorhandler(404)
def page_not_found(e):
    print(e.code)
    print(e.description)
    return "sorry, the page you are looking for does not exist :(", 404
if __name__ == '__main__':
    with app.app_context():
        assignmenet_db.create_all()
    app.run(debug=True)
