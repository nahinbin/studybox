from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from tracker.task_tracker import assignments_bp, assignmenet_db
from flask_mail import Mail, Message
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
import threading
import time
from gpa_calculator.gpa import gpa_bp
import jwt
from jwt import PyJWKClient

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.sendgrid.net')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # For SendGrid, use 'apikey'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # For SendGrid, use the API key
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['MAIL_TIMEOUT'] = 10
app.config['MAIL_CONNECT_TIMEOUT'] = 10

# Required for generating absolute URLs in emails
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')
# Prefer explicit SERVER_NAME from environment for production deployments
server_name_env = os.getenv('SERVER_NAME')
if server_name_env:
    app.config['SERVER_NAME'] = server_name_env

mail = Mail(app)

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

# Clerk configuration
CLERK_JWKS_URL = os.getenv('CLERK_JWKS_URL')  # e.g. https://your-domain.clerk.accounts.dev/.well-known/jwks.json
CLERK_ISSUER = os.getenv('CLERK_ISSUER')      # e.g. https://your-domain.clerk.accounts.dev
CLERK_AUDIENCE = os.getenv('CLERK_AUDIENCE')  # optional: your frontend domain or API identifier
CLERK_ENFORCE = os.getenv('CLERK_ENFORCE', 'true').lower() == 'true'

_clerk_jwk_client = PyJWKClient(CLERK_JWKS_URL) if CLERK_JWKS_URL else None

def _get_bearer_token_from_header(auth_header: str):
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    return None

def verify_clerk_jwt(auth_header: str):
    if not _clerk_jwk_client:
        raise RuntimeError('CLERK_JWKS_URL is not configured')
    token = _get_bearer_token_from_header(auth_header)
    if not token:
        raise PermissionError('Missing Bearer token')
    signing_key = _clerk_jwk_client.get_signing_key_from_jwt(token).key
    options = {"verify_aud": bool(CLERK_AUDIENCE)}
    claims = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        audience=CLERK_AUDIENCE if CLERK_AUDIENCE else None,
        issuer=CLERK_ISSUER if CLERK_ISSUER else None,
        options=options,
    )
    return claims

def clerk_required(view_func):
    def wrapper(*args, **kwargs):
        if not CLERK_ENFORCE:
            return view_func(*args, **kwargs)
        try:
            claims = verify_clerk_jwt(request.headers.get('Authorization'))
            g.clerk_claims = claims
        except Exception as e:
            return jsonify({"error": "unauthorized", "message": str(e)}), 401
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

def send_email_async(user_email, username, verification_url):
    """Send email in a separate thread to avoid blocking the main request"""
    def _send():
        with app.app_context():
            try:
                print(f"DEBUG: Starting email send to {user_email}")
                print(f"DEBUG: Mail server: {app.config.get('MAIL_SERVER')}")
                print(f"DEBUG: Mail username: {app.config.get('MAIL_USERNAME')}")
                print(f"DEBUG: Mail default sender: {app.config.get('MAIL_DEFAULT_SENDER')}")
                
                msg = Message('Verify Your Email - StudyBox',
                              recipients=[user_email])
                # Ensure a verified sender is used (required by SendGrid)
                if app.config.get('MAIL_DEFAULT_SENDER'):
                    msg.sender = app.config.get('MAIL_DEFAULT_SENDER')
                msg.body = f'''
                Hello {username},
                
                Please click the following link to verify your email:
                {verification_url}
                
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

@app.route('/whoami')
@clerk_required
def whoami():
    claims = getattr(g, 'clerk_claims', {})
    return jsonify({
        "sub": claims.get('sub'),
        "email": claims.get('email'),
        "claims": claims
    })

@app.route('/')
@clerk_required
def index():
    return render_template('index.html')

@app.route('/logout', methods=['GET'])
def logout():
    # With Clerk, frontend should clear session; backend is stateless JWT.
    return redirect(url_for('index'))

# Serve existing login/register pages (frontend handles Clerk auth on these pages)
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

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
@clerk_required
def task():
    return render_template('task.html')


@app.errorhandler(404)
def page_not_found(e):
    print(e.code)
    print(e.description)
    return "sorry, the page you are looking for does not exist :(", 404
if __name__ == '__main__':
    with app.app_context():
        assignmenet_db.create_all()
    app.run(debug=True)
