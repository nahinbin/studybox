import os
import base64
import json
import threading
import requests
from flask import Blueprint, render_template, request, flash, url_for, redirect, current_app


emails_bp = Blueprint('emails', __name__)

# Cache for base64 inlined logo to avoid repeated disk/network reads
_INLINED_LOGO_CACHE = None

#verification link expires in 1 hour
def _get_serializer():
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(current_app.config.get('SECRET_KEY'))

#generate verification token
def generate_verification_token(email):
    return _get_serializer().dumps(email, salt='email-verification')


def verify_token(token, expiration=3600):
    try:
        email = _get_serializer().loads(token, salt='email-verification', max_age=expiration)
        return email
    except Exception:
        return None


def send_email_via_brevo_api(to_email, to_name, subject, html_content, text_content=None, email_type='general'):
    api_key = os.getenv('BREVO_API_KEY') or (current_app and current_app.config.get('BREVO_API_KEY'))
    sender_email = os.getenv('SENDER_EMAIL') or (current_app and current_app.config.get('SENDER_EMAIL'))
    sender_name = os.getenv('SENDER_NAME') or (current_app and current_app.config.get('SENDER_NAME', 'StudyBox'))

    if not api_key or not sender_email:
        print("Missing BREVO_API_KEY or SENDER_EMAIL in environment variables")
        return False

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {"accept": "application/json", "api-key": api_key, "content-type": "application/json"}
    email_data = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email, "name": to_name}],
        "subject": subject,
        "htmlContent": html_content,
        "headers": {
            "X-Mailer": "StudyBox Verification System",
            "X-Priority": "1",  # High priority
            "X-MSMail-Priority": "High",
            "Importance": "high",
            "X-Entity-Ref-ID": "StudyBox-Verification",  # Helps with spam filtering
            "List-Unsubscribe": "<mailto:support@studybox.com>"  # Shows legitimate intent
        }
    }
    if text_content:
        email_data["textContent"] = text_content

    try:
        response = requests.post(url, headers=headers, data=json.dumps(email_data))
        success = response.status_code == 201
        
        # Log the email attempt to database
        try:
            from database import EmailLog
            from extensions import db
            email_log = EmailLog(
                recipient_email=to_email,
                recipient_name=to_name,
                subject=subject,
                email_type=email_type,
                success=success
            )
            db.session.add(email_log)
            db.session.commit()
        except Exception as e:
            print(f"Failed to log email to database: {e}")
        
        if success:
            return True
        else:
            print(f"Failed to send email. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending email via Brevo API: {str(e)}")
        
        # Log failed email attempt
        try:
            from database import EmailLog
            from extensions import db
            email_log = EmailLog(
                recipient_email=to_email,
                recipient_name=to_name,
                subject=subject,
                email_type=email_type,
                success=False
            )
            db.session.add(email_log)
            db.session.commit()
        except Exception as db_e:
            print(f"Failed to log failed email to database: {db_e}")
        
        return False


def send_verification_email_async(app, user_email, username, verification_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1c1828; color: #e6e6ea;\">
                <div style=\"background-color: #1c1828; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border: 1px solid #2a243a;\">
                    <div style=\"text-align: center; margin-bottom: 24px;\">
                        <img src=\"{_get_logo_data_uri()}\" alt=\"StudyBox\" style=\"max-width: 160px; height: auto; margin-bottom: 6px;\">
                        <p style=\"color: #b0abc0; margin: 0; font-size: 12px; letter-spacing: 0.5px;\">ACADEMIC MANAGEMENT PLATFORM</p>
                    </div>
                    <h2 style=\"color: #f5f5f7; text-align: center; margin: 16px 0 18px; font-weight: 600; font-size: 22px;\">Welcome to StudyBox</h2>
                    <p style=\"color: #d7d7de; font-size: 15px; line-height: 1.7; margin: 0 0 12px;\">Hello <strong style=\"color:#ffffff;\">{username}</strong>,</p>
                    <p style=\"color: #c9c9d3; font-size: 15px; line-height: 1.7; margin: 0 0 12px;\">Thank you for registering with StudyBox. We're excited to help you organize your academic journey and achieve your educational goals.</p>
                    <p style=\"color: #c9c9d3; font-size: 15px; line-height: 1.7; margin: 0 0 24px;\">To complete your registration and access all features, please verify your email address by clicking the button below:</p>
                    <div style=\"text-align: center; margin: 28px 0;\">
                        <a href=\"{verification_url}\" style=\"background-color: #3b82f6; color: #ffffff; padding: 14px 26px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 15px;\">Verify Email Address</a>
                    </div>
                </div>
            </body>
            </html>
            """
            text_content = f"""
            Welcome to StudyBox!
            
            Hello {username},
            
            Please verify your email address:
            {verification_url}
            """
            send_email_via_brevo_api(
                to_email=user_email,
                to_name=username,
                subject="[URGENT] Verify Your Email - StudyBox",
                html_content=html_content,
                text_content=text_content,
                email_type='verification'
            )

    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


def send_password_reset_email_async(app, user_email, username, reset_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1c1828; color: #e6e6ea;\">
                <div style=\"background-color: #1c1828; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border: 1px solid #2a243a;\">
                    <div style=\"text-align: center; margin-bottom: 24px;\">
                        <img src=\"{_get_logo_data_uri()}\" alt=\"StudyBox\" style=\"max-width: 160px; height: auto; margin-bottom: 6px;\">
                        <p style=\"color: #b0abc0; margin: 0; font-size: 12px; letter-spacing: 0.5px;\">PASSWORD RESET</p>
                    </div>
                    <h2 style=\"color: #f5f5f7; text-align: center; margin: 16px 0 18px; font-weight: 600; font-size: 22px;\">Reset Your Password</h2>
                    <p style=\"color: #d7d7de; font-size: 15px; line-height: 1.7; margin: 0 0 18px;\">Hello <strong style=\"color:#ffffff;\">{username}</strong>,</p>
                    <div style=\"text-align: center; margin: 28px 0;\">
                        <a href=\"{reset_url}\" style=\"background-color: #f59e0b; color: #1c1828; padding: 14px 26px; text-decoration: none; border-radius: 6px; font-weight: 700; display: inline-block; font-size: 15px;\">Reset Password</a>
                    </div>
                </div>
            </body>
            </html>
            """
            text_content = f"""
            Password Reset
            
            Hello {username},
            
            Click the link below to reset your password:
            {reset_url}
            """
            send_email_via_brevo_api(
                to_email=user_email,
                to_name=username,
                subject="[URGENT] Reset Your Password - StudyBox",
                html_content=html_content,
                text_content=text_content,
                email_type='password_reset'
            )

    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


def send_email_change_verification_async(app, user_email, username, new_email, verification_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #1c1828; color: #e6e6ea;\">
                <div style=\"background-color: #1c1828; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border: 1px solid #2a243a;\">
                    <div style=\"text-align: center; margin-bottom: 24px;\">
                        <img src=\"{_get_logo_data_uri()}\" alt=\"StudyBox\" style=\"max-width: 160px; height: auto; margin-bottom: 6px;\">
                        <p style=\"color: #b0abc0; margin: 0; font-size: 12px; letter-spacing: 0.5px;\">EMAIL CHANGE VERIFICATION</p>
                    </div>
                    <h2 style=\"color: #f5f5f7; text-align: center; margin: 16px 0 18px; font-weight: 600; font-size: 22px;\">Verify Email Change</h2>
                    <p style=\"color: #d7d7de; font-size: 15px; line-height: 1.7; margin: 0 0 18px;\">Hello <strong style=\"color:#ffffff;\">{username}</strong>,</p>
                    <div style=\"text-align: center; margin: 28px 0;\">
                        <a href=\"{verification_url}\" style=\"background-color: #22c55e; color: #1c1828; padding: 14px 26px; text-decoration: none; border-radius: 6px; font-weight: 700; display: inline-block; font-size: 15px;\">Verify Email Change</a>
                    </div>
                </div>
            </body>
            </html>
            """
            text_content = f"""
            Email Change Verification
            
            Hello {username},
            You requested to change your email from {user_email} to {new_email}.
            Verify here:
            {verification_url}
            """
            send_email_via_brevo_api(
                to_email=new_email,
                to_name=username,
                subject="[URGENT] Verify Your Email Change - StudyBox",
                html_content=html_content,
                text_content=text_content,
                email_type='email_change'
            )

    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


@emails_bp.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    from app import User  # lazy import to avoid cycles
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            user = User.query.filter_by(email=email).first()
            if user and not user.is_verified:
                try:
                    token = generate_verification_token(user.email)
                    verification_url = url_for('emails.verify_email', token=token, _external=True)
                    send_verification_email_async(current_app._get_current_object(), user.email, user.username, verification_url)
                    flash('Email sent successfully!')
                except Exception as e:
                    print(f"DEBUG: Error resending verification: {e}")
                    token = generate_verification_token(user.email)
                    verification_url = url_for('emails.verify_email', token=token, _external=True)
                    flash('Email failed. Try again.')
            else:
                flash('Email not found or already verified.')
        else:
            flash('Please enter your email address.')
    return render_template('resend_verification.html')


@emails_bp.route('/verify/<token>')
def verify_email(token):
    from app import User  # lazy import
    email = verify_token(token)
    if not email:
        flash('Invalid or expired verification link.')
        return redirect(url_for('profiles.login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('profiles.login'))

    user.is_verified = True
    user.email_change_token = None
    from extensions import db
    db.session.commit()
    
    # Automatically log in the user after verification
    from flask_login import login_user
    login_user(user)
    flash('Email verified successfully! You are now logged in.')
    return redirect(url_for('index'))


@emails_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    from app import ResetPasswordForm, User, bcrypt  # lazy import
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
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        from extensions import db
        db.session.commit()
        flash('Password reset successfully! You can now login with your new password.')
        return redirect(url_for('profiles.login'))

    return render_template('reset_password.html', form=form, token=token)


@emails_bp.route('/verify-email-change/<token>')
def verify_email_change(token):
    from app import User  # lazy import
    email = verify_token(token)
    if not email:
        flash('Invalid or expired email change verification link.')
        return redirect(url_for('profile'))

    user = User.query.filter_by(pending_email=email).first()
    if not user:
        flash('Invalid email change request or user not found.')
        return redirect(url_for('profile'))

    user.email = user.pending_email
    user.pending_email = None
    user.email_change_token = None
    from extensions import db
    db.session.commit()
    flash('Email address updated successfully!')
    return redirect(url_for('profile'))


def _get_logo_data_uri():
    global _INLINED_LOGO_CACHE
    if _INLINED_LOGO_CACHE:
        return _INLINED_LOGO_CACHE
    try:
        # 1) Try local static logo first
        from pathlib import Path
        logo_path = Path(current_app.root_path) / 'static' / 'images' / 'nav.png'
        if logo_path.is_file():
            with open(logo_path, 'rb') as f:
                data = f.read()
                b64 = base64.b64encode(data).decode('ascii')
                _INLINED_LOGO_CACHE = f"data:image/png;base64,{b64}"
                return _INLINED_LOGO_CACHE
    except Exception as e:
        print(f"DEBUG: Failed to inline local logo: {e}")

    # 2) Try fetching the provided remote logo and inline it
    try:
        remote_url = "https://www.study-box.site/static/images/nav.png?v=1759213725"
        resp = requests.get(remote_url, timeout=5)
        if resp.status_code == 200 and resp.content:
            b64 = base64.b64encode(resp.content).decode('ascii')
            _INLINED_LOGO_CACHE = f"data:image/png;base64,{b64}"
            return _INLINED_LOGO_CACHE
        else:
            print(f"DEBUG: Remote logo fetch failed, status={resp.status_code}")
    except Exception as e:
        print(f"DEBUG: Failed to fetch remote logo: {e}")

    # 3) Final fallback to hosted image URL (may be blocked by some clients)
    return "https://studybox.vercel.app/static/images/nav.png"


__all__ = [
    'emails_bp',
    'generate_verification_token',
    'verify_token',
    'send_email_via_brevo_api',
    'send_verification_email_async',
    'send_password_reset_email_async',
    'send_email_change_verification_async',
]


