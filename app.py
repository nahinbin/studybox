from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from tracker.task_tracker import assignments_bp, database
from flask_mail import Mail, Message
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
import requests
import threading
import time

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_TIMEOUT'] = 10
app.config['MAIL_CONNECT_TIMEOUT'] = 10

# Required for generating absolute URLs in emails
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SERVER_NAME'] = 'studybox.onrender.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.register_blueprint(assignments_bp, url_prefix='/assignment_tracker')

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://studybox_db_user:VVb2l5baXEXnAIEYQDDwBKfmux7XaDE0@dpg-d2kjiqjipnbc73f69d0g-a.singapore-postgres.render.com/studybox_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


if Config.DATABASE_URL.startswith('postgres://'):
    Config.DATABASE_URL = Config.DATABASE_URL.replace('postgres://', 'postgresql://', 1)

Config.SQLALCHEMY_DATABASE_URI = Config.DATABASE_URL


app.config.from_object(Config)
database.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, database)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(UserMixin, database.Model):
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String(150), unique=True, nullable=False)
    password = database.Column(database.String(150), nullable=False)
    email = database.Column(database.String(150), unique=True, nullable=False)
    is_verified = database.Column(database.Boolean, default=False)
    verification_token = database.Column(database.String(100), nullable=True)

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
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
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

def send_email_async(user_email, username, token):
    """Send email in a separate thread to avoid blocking the main request"""
    def _send():
        with app.app_context():
            try:
                print(f"DEBUG: Starting email send to {user_email}")
                print(f"DEBUG: Mail server: {app.config.get('MAIL_SERVER')}")
                print(f"DEBUG: Mail username: {app.config.get('MAIL_USERNAME')}")
                
                msg = Message('Verify Your Email - StudyBox',
                              recipients=[user_email])
                msg.body = f'''
                Hello {username},
                
                Please click the following link to verify your email:
                {url_for('verify_email', token=token, _external=True)}
                
                This link will expire in 1 hour.
                
                If you didn't create this account, please ignore this email.
                '''
                print(f"DEBUG: About to send email to {user_email}")
                mail.send(msg)
                print(f"DEBUG: Email sent successfully to {user_email}")
            except Exception as e:
                print(f"DEBUG: Error sending email to {user_email}: {str(e)}")
                print(f"DEBUG: Error type: {type(e).__name__}")
                import traceback
                print(f"DEBUG: Traceback: {traceback.format_exc()}")
                # Fallback: try Mailgun HTTP API
                try:
                    subject = 'Verify Your Email - StudyBox'
                    text_body = (
                        f"Hello {username},\n\n"
                        f"Please click the following link to verify your email:\n"
                        f"{url_for('verify_email', token=token, _external=True)}\n\n"
                        "This link will expire in 1 hour.\n\n"
                        "If you didn't create this account, please ignore this email."
                    )
                    send_email_via_mailgun(user_email, subject, text_body)
                    print(f"DEBUG: Mailgun fallback sent successfully to {user_email}")
                except Exception as mg_err:
                    print(f"DEBUG: Mailgun fallback failed for {user_email}: {mg_err}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()

def send_email_via_mailgun(recipient_email: str, subject: str, text: str) -> None:
    """Send email using Mailgun HTTP API. Requires MAILGUN_DOMAIN, MAILGUN_API_KEY, MAIL_FROM env vars."""
    domain = os.getenv('MAILGUN_DOMAIN')
    # Support either MAILGUN_API_KEY or generic API_KEY (as shown in Mailgun docs)
    api_key = os.getenv('MAILGUN_API_KEY') or os.getenv('API_KEY')
    default_from = f"postmaster@{domain}" if domain else None
    mail_from = os.getenv('MAIL_FROM', app.config.get('MAIL_DEFAULT_SENDER') or default_from)
    if not domain or not api_key or not mail_from:
        raise RuntimeError('Mailgun is not configured (MAILGUN_DOMAIN, MAILGUN_API_KEY, MAIL_FROM).')

    url = f"https://api.mailgun.net/v3/{domain}/messages"
    data = {
        'from': mail_from,
        'to': recipient_email,
        'subject': subject,
        'text': text,
    }
    resp = requests.post(url, auth=('api', api_key), data=data, timeout=10)
    if resp.status_code >= 300:
        raise RuntimeError(f"Mailgun API error: {resp.status_code} {resp.text}")

def send_verification_email(user_email, username):
    try:
        token = generate_verification_token(user_email)
        send_email_async(user_email, username, token)
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

@app.route('/verify/<token>')
def verify_email(token):
    email = verify_token(token)
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            database.session.commit()
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
        user = User.query.filter_by(username=form.username.data).first()
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
            database.session.add(new_user)
            database.session.commit()
            
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
            database.session.commit()
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
            database.session.commit()
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
            database.session.delete(current_user)
            database.session.commit()
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


@app.errorhandler(404)
def page_not_found(e):
    print(e.code)
    print(e.description)
    return "sorry, the page you are looking for does not exist :(", 404
if __name__ == '__main__':
    with app.app_context():
        database.create_all()
    app.run(debug=True)