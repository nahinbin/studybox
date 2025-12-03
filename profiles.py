from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort, current_app, session
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from sqlalchemy import func
from urllib.parse import urlparse
import os
import secrets
import requests


profiles_bp = Blueprint('profiles', __name__)


# Social media and profile utility functions
def get_favicon_url(url):
    # Get the favicon icon for social media links in profiles
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            return None
        if 'github.com' in domain:
            return "https://github.com/favicon.ico"
        elif 'instagram.com' in domain:
            return "https://instagram.com/static/images/ico/favicon.ico/6b1a3f7a0c4f.png"
        elif 'twitter.com' in domain or 'x.com' in domain:
            return "https://abs.twimg.com/favicons/twitter.ico"
        elif 'youtube.com' in domain:
            return "https://www.youtube.com/favicon.ico"
        elif 'linkedin.com' in domain:
            return "https://www.linkedin.com/favicon.ico"
        elif 'tiktok.com' in domain:
            return "https://www.tiktok.com/favicon.ico"
        elif 'discord.com' in domain:
            return "https://discord.com/favicon.ico"
        return f"https://www.google.com/s2/favicons?domain={domain}&sz=32"
    except:
        return None

def get_social_url(platform, username):
    # Convert username to full social media URL
    if not username:
        return None
    
    username = username.strip()
    if not username:
        return None

    if username.startswith('@'):
        username = username[1:]
    
    url_mapping = {
        'github': f"https://github.com/{username}",
        'instagram': f"https://instagram.com/{username}",
        'twitter': f"https://twitter.com/{username}",
        'youtube': f"https://youtube.com/@{username}",
        'linkedin': f"https://linkedin.com/in/{username}",
        'tiktok': f"https://tiktok.com/@{username}",
        'discord': f"https://discord.com/users/{username}"
    }
    
    return url_mapping.get(platform)

def get_user_social_links(user):
    # Collect all social media links for a user's profile
    links = []
    
    platforms = [
        ('github', user.github_username),
        ('instagram', user.instagram_username),
        ('twitter', user.twitter_username),
        ('youtube', user.youtube_username),
        ('linkedin', user.linkedin_username),
        ('tiktok', user.tiktok_username),
        ('discord', user.discord_username)
    ]
    
    for platform, username in platforms:
        if username:
            url = get_social_url(platform, username)
            if url:
                links.append({
                    'platform': platform,
                    'username': username,
                    'url': url,
                    'favicon': get_favicon_url(url)
                })
    
    if user.custom_website_url:
        links.append({
            'platform': 'custom',
            'name': user.custom_website_name or 'Website',
            'url': user.custom_website_url,
            'favicon': get_favicon_url(user.custom_website_url)
        })
    
    return links


# Forms
class Loginform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=3, max=150)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class Registerform(FlaskForm):
    username = StringField(validators=[InputRequired(message="Username is required"), Length(min=4, max=20, message="Username must be between 4 and 20 characters")])
    email = StringField(validators=[InputRequired(message="Email is required"), Email(message="Please enter a valid email address")])
    password = PasswordField(validators=[InputRequired(message="Password is required"), Length(min=8, max=20, message="Password must be between 8 and 20 characters")], render_kw={"placeholder": "Password"})
    school_university = StringField(validators=[Length(min=0, max=200)])
    avatar = SelectField('Avatar', choices=[(str(i), f"#{i}") for i in range(1, 11)], validators=[InputRequired(message="Avatar is required")])
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


@profiles_bp.route('/login/google')
def google_login():
    # Start Google OAuth2 flow (used for both login and signup)
    from urllib.parse import urlencode

    client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    redirect_uri = url_for('profiles.google_callback', _external=True)

    if not client_id or not redirect_uri:
        flash('Google login is not configured.')
        return redirect(url_for('profiles.login'))

    state = secrets.token_urlsafe(16)
    session['google_oauth_state'] = state

    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': redirect_uri,
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent',
    }
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)
    return redirect(auth_url)


@profiles_bp.route('/auth/google/callback')
def google_callback():
    # Handle Google's OAuth2 callback
    from app import User, db, bcrypt, get_university_from_email

    error = request.args.get('error')
    if error:
        flash('Google sign-in was cancelled or failed.')
        return redirect(url_for('profiles.login'))

    state = request.args.get('state')
    code = request.args.get('code')
    if not state or state != session.get('google_oauth_state'):
        flash('Invalid Google login state. Please try again.')
        return redirect(url_for('profiles.login'))

    if not code:
        flash('Missing authorization code from Google.')
        return redirect(url_for('profiles.login'))

    session.pop('google_oauth_state', None)

    token_endpoint = 'https://oauth2.googleapis.com/token'
    redirect_uri = url_for('profiles.google_callback', _external=True)

    data = {
        'code': code,
        'client_id': current_app.config.get('GOOGLE_CLIENT_ID'),
        'client_secret': current_app.config.get('GOOGLE_CLIENT_SECRET'),
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }

    try:
        token_resp = requests.post(token_endpoint, data=data, timeout=10)
        if not token_resp.ok:
            # Log full response body for easier debugging in deploy logs
            try:
                print(f"DEBUG: Google token exchange body: {token_resp.text}")
            except Exception:
                pass
            token_resp.raise_for_status()
        token_data = token_resp.json()
    except Exception as e:
        print(f"DEBUG: Google token exchange failed: {e}")
        flash('Failed to sign in with Google. Please try again.')
        return redirect(url_for('profiles.login'))

    access_token = token_data.get('access_token')
    if not access_token:
        flash('Failed to obtain access token from Google.')
        return redirect(url_for('profiles.login'))

    try:
        userinfo_resp = requests.get(
            'https://openidconnect.googleapis.com/v1/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except Exception as e:
        print(f"DEBUG: Google userinfo fetch failed: {e}")
        flash('Failed to fetch Google profile information.')
        return redirect(url_for('profiles.login'))

    email = (userinfo.get('email') or '').strip().lower()
    full_name = (userinfo.get('name') or userinfo.get('given_name') or '').strip()

    if not email:
        flash('Your Google account has no email address available.')
        return redirect(url_for('profiles.login'))

    # Try to find existing user by email
    user = User.query.filter(func.lower(User.email) == email).first()

    if not user:
        # Create a new user account (acts as "Sign up with Google")
        raw_base = full_name or email.split('@', 1)[0] or 'user'
        # Keep only safe characters for username
        base_username = ''.join(
            ch.lower() for ch in raw_base if ch.isalnum() or ch in ['.', '_']
        ) or 'user'
        username_candidate = base_username
        suffix = 2
        while User.query.filter(func.lower(User.username) == username_candidate).first():
            username_candidate = f"{base_username}{suffix}"
            suffix += 1

        detected_university = get_university_from_email(email)

        # Generate a random password (not used, but required by schema)
        random_password = secrets.token_urlsafe(32)
        hashed_password = bcrypt.generate_password_hash(random_password).decode('utf-8')

        user = User(
            username=username_candidate,
            email=email,
            password=hashed_password,
            school_university=detected_university,
            avatar='1',
            is_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        # Ask user to confirm username and avatar on first dashboard load
        session['needs_profile_setup'] = True
    else:
        # Mark existing user as verified if they sign in with Google
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()

    login_user(user)
    return redirect(url_for('index'))


@profiles_bp.route('/register', methods=['GET', 'POST'])
def register():
    from app import User, db, bcrypt, get_university_from_email
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
            db.session.add(new_user)
            db.session.commit()

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
    from app import db, bcrypt, User, is_mmu_email
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
                db.session.commit()
                token = generate_verification_token(form.email.data)
                current_user.email_change_token = token
                db.session.commit()
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
                # only allow change if not verified university email
                if not (current_user.is_verified and is_mmu_email(current_user.email)):
                    if hasattr(form, 'school_university'):
                        current_user.school_university = form.school_university.data
                db.session.commit()
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


@profiles_bp.route('/profile/setup', methods=['POST'])
@login_required
def profile_setup():
    from app import db, User

    desired_username = (request.form.get('username') or '').strip().lower()
    selected_avatar = (request.form.get('avatar') or '').strip() or '1'

    # Fallback username based on Google name/email/current username
    if not desired_username:
        base_source = (
            (current_user.username or '').strip()
            or (current_user.email.split('@', 1)[0] if current_user.email else 'user')
        )
        base_username = ''.join(
            ch.lower() for ch in base_source if ch.isalnum() or ch in ['.', '_']
        ) or 'user'
    else:
        base_username = desired_username

    username_candidate = base_username
    suffix = 2
    while (
        User.query.filter(func.lower(User.username) == username_candidate)
        .filter(User.id != current_user.id)
        .first()
    ):
        username_candidate = f"{base_username}{suffix}"
        suffix += 1

    # Clamp avatar to valid range 1-10
    try:
        avatar_num = int(selected_avatar)
        if avatar_num < 1 or avatar_num > 10:
            avatar_num = 1
    except ValueError:
        avatar_num = 1

    current_user.username = username_candidate
    current_user.avatar = str(avatar_num)
    db.session.commit()

    # Do not show setup box again
    session.pop('needs_profile_setup', None)

    flash('Profile updated. You can change these anytime from your profile page.')
    return redirect(url_for('index'))


# Public profiles
@profiles_bp.route('/sd<string:code>')
def public_profile_by_public_code(code):
    from app import _decode_public_id, User, get_user_avatar_url, CommunityPost
    numeric_id = _decode_public_id(f"sd{code}")
    if not numeric_id:
        return redirect(url_for('index'))
    user = User.query.get(numeric_id)
    if not user:
        return redirect(url_for('index'))
    if user.username == 'admin':
        return redirect(url_for('index'))
    
    # Fetch recent community posts
    user_posts = CommunityPost.query.filter_by(user_id=user.id).order_by(CommunityPost.created_at.desc()).limit(10).all()
    
    return render_template('public_profile.html', user=user, profile_user=user, avatar_url=get_user_avatar_url(user), user_posts=user_posts)


@profiles_bp.route('/<username>')
def public_profile_by_username(username):
    if username.lower().startswith('sd') and len(username) > 2:
        return redirect(url_for('profiles.public_profile_by_public_code', code=username[2:]))
    from app import User, get_user_avatar_url, CommunityPost
    user = User.query.filter(func.lower(User.username) == username.lower()).first()
    if not user:
        from flask import abort
        abort(404)
    if user.username == 'admin':
        return redirect(url_for('index'))
    
    # community posts
    user_posts = CommunityPost.query.filter_by(user_id=user.id).order_by(CommunityPost.created_at.desc()).limit(10).all()
    
    return render_template('public_profile.html', user=user, profile_user=user, avatar_url=get_user_avatar_url(user), user_posts=user_posts)


__all__ = [
    'profiles_bp',
    'Loginform',
    'Registerform',
    'profileupdateform',
    'ForgotPasswordForm',
    'ResetPasswordForm',
    'get_favicon_url',
    'get_social_url',
    'get_user_social_links',
]


@profiles_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    from app import bcrypt, db
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
            db.session.commit()
            flash('Password updated successfully')
            return redirect(url_for('profiles.profile'))
        else:
            flash('Passwords do not match')
            return redirect(url_for('profiles.profile'))
    return redirect(url_for('profiles.profile'))


@profiles_bp.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def delete_profile():
    from app import bcrypt, db, CommunityPost, CommunityPostLike
    if request.method == 'POST':
        if bcrypt.check_password_hash(current_user.password, request.form['confirm_password']):
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

                # assignments
                if Enrollment:
                    enrollments = Enrollment.query.filter_by(user_id=current_user.id).all()
                    for enrollment in enrollments:
                        # assignments for this enrollment
                        from tracker.task_tracker import Assignment
                        assignments = Assignment.query.filter_by(enrollment_id=enrollment.id).all()
                        for assignment in assignments:
                            db.session.delete(assignment)
                        # Delete the enrollment
                        db.session.delete(enrollment)

                # previous semesters
                if PreviousSemester:
                    previous_semesters = PreviousSemester.query.filter_by(user_id=current_user.id).all()
                    for prev in previous_semesters:
                        db.session.delete(prev)

                # schedule-related records
                if ClassSchedule:
                    schedules = ClassSchedule.query.filter_by(user_id=current_user.id).all()
                    for schedule in schedules:
                        db.session.delete(schedule)
                
                if ScheduleSubjectPref:
                    prefs = ScheduleSubjectPref.query.filter_by(user_id=current_user.id).all()
                    for pref in prefs:
                        db.session.delete(pref)

                # Delete community posts, likes, and comments explicitly
                # (SQLAlchemy doesn't handle ON DELETE CASCADE properly)
                from app import CommunityPost, CommunityPostLike, CommunityComment
                from Pomodoro.backend import TimeStudied
                posts_by_user = CommunityPost.query.filter_by(user_id=current_user.id).all()
                post_ids = [post.id for post in posts_by_user]
                
                if post_ids:
                    comments_on_user_posts = CommunityComment.query.filter(CommunityComment.post_id.in_(post_ids)).all()
                    for comment in comments_on_user_posts:
                        db.session.delete(comment)
                
                likes = CommunityPostLike.query.filter_by(user_id=current_user.id).all()
                for like in likes:
                    db.session.delete(like)
                
                # Delete community comments by this user
                comments = CommunityComment.query.filter_by(user_id=current_user.id).all()

                for comment in comments:
                    db.session.delete(comment)
                
                posts = CommunityPost.query.filter_by(user_id=current_user.id).all()
                for post in posts:
                    db.session.delete(post)
                
                # Flush to ensure all deletions are processed
                db.session.flush()
                
                # Delete time studied records (Pomodoro timer data)
                time_studied_records = TimeStudied.query.filter_by(user_id=current_user.id).all()
                for record in time_studied_records:
                    db.session.delete(record)

                # Delete quick links owned by the user
                from app import QuickLink
                quick_links = QuickLink.query.filter_by(user_id=current_user.id).all()
                for link in quick_links:
                    db.session.delete(link)

                # Note: Contact messages will have their user_id set to NULL automatically
                # by the database's ON DELETE SET NULL constraint when the user is deleted

                # Commit all deletions before deleting the user
                db.session.commit()
                
            except Exception as cleanup_err:
                print(f"DEBUG: Cleanup before user delete failed: {cleanup_err}")
                db.session.rollback()
                flash(f"Failed to delete profile: {str(cleanup_err)}")
                return redirect(url_for('profiles.profile'))

            try:
                db.session.delete(current_user)
                db.session.commit()
                logout_user()
                flash('Profile deleted successfully')
                return redirect(url_for('profiles.login'))
            except Exception as delete_err:
                print(f"DEBUG: User delete failed: {delete_err}")
                db.session.rollback()
                flash(f"Failed to delete profile: {str(delete_err)}")
                return redirect(url_for('profiles.profile'))
        else:
            flash('Invalid current password')
            return redirect(url_for('profiles.profile'))
    return redirect(url_for('profiles.profile'))


def custom_avatar_url(avatar_id, size=96):
    return f"/avatar/{avatar_id}"

def get_user_avatar_url(user, size=96):
    if user.username == 'admin':
        return f"/static/images/fav.png"
    if hasattr(user, 'avatar') and user.avatar:
        return custom_avatar_url(user.avatar, size)
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
    # Import format_relative_time from community module
    from community import format_relative_time
    return {
        'user_avatar_url': get_user_avatar_url,
        'custom_avatar_url': custom_avatar_url,
        'get_favicon_url': get_favicon_url,
        'get_social_url': get_social_url,
        'get_user_social_links': get_user_social_links,
        'format_relative_time': format_relative_time,
    }


