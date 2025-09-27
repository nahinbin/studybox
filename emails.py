import os
import json
import threading
import requests
from flask import Blueprint, render_template, request, flash, url_for, redirect, current_app


emails_bp = Blueprint('emails', __name__)


def _get_serializer():
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(current_app.config.get('SECRET_KEY'))


def generate_verification_token(email):
    return _get_serializer().dumps(email, salt='email-verification')


def verify_token(token, expiration=3600):
    try:
        email = _get_serializer().loads(token, salt='email-verification', max_age=expiration)
        return email
    except Exception:
        return None


def send_email_via_brevo_api(to_email, to_name, subject, html_content, text_content=None):
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
    }
    if text_content:
        email_data["textContent"] = text_content

    try:
        response = requests.post(url, headers=headers, data=json.dumps(email_data))
        if response.status_code == 201:
            return True
        else:
            print(f"Failed to send email. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending email via Brevo API: {str(e)}")
        return False


def send_verification_email_async(app, user_email, username, verification_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;\">
                <div style=\"background-color: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);\">
                    <div style=\"text-align: center; margin-bottom: 40px;\">
                        <h1 style=\"color: #2c3e50; margin: 0; font-size: 32px; font-weight: 300; letter-spacing: 1px;\">StudyBox</h1>
                        <p style=\"color: #7f8c8d; margin: 8px 0 0 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;\">Academic Management Platform</p>
                    </div>
                    <h2 style=\"color: #2c3e50; text-align: center; margin-bottom: 30px; font-weight: 400; font-size: 24px;\">Welcome to StudyBox</h2>
                    <p style=\"color: #34495e; font-size: 16px; line-height: 1.6; margin-bottom: 20px;\">Hello <strong>{username}</strong>,</p>
                    <p style=\"color: #34495e; font-size: 16px; line-height: 1.6; margin-bottom: 20px;\">Thank you for registering with StudyBox. We're excited to help you organize your academic journey and achieve your educational goals.</p>
                    <p style=\"color: #34495e; font-size: 16px; line-height: 1.6; margin-bottom: 30px;\">To complete your registration and access all features, please verify your email address by clicking the button below:</p>
                    <div style=\"text-align: center; margin: 50px 0;\">
                        <a href=\"{verification_url}\" style=\"background-color: #3498db; color: white; padding: 16px 32px; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block; font-size: 16px; box-shadow: 0 3px 6px rgba(52,152,219,0.3); transition: all 0.3s ease;\">Verify Email Address</a>
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
                subject="Verify Your Email - StudyBox",
                html_content=html_content,
                text_content=text_content,
            )

    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


def send_password_reset_email_async(app, user_email, username, reset_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;\">
                <div style=\"background-color: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);\">
                    <div style=\"text-align: center; margin-bottom: 40px;\">
                        <h1 style=\"color: #2c3e50; margin: 0; font-size: 32px; font-weight: 300; letter-spacing: 1px;\">StudyBox</h1>
                        <p style=\"color: #7f8c8d; margin: 8px 0 0 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;\">Password Reset</p>
                    </div>
                    <h2 style=\"color: #2c3e50; text-align: center; margin-bottom: 30px; font-weight: 400; font-size: 24px;\">Reset Your Password</h2>
                    <p style=\"color: #34495e; font-size: 16px; line-height: 1.6; margin-bottom: 20px;\">Hello <strong>{username}</strong>,</p>
                    <div style=\"text-align: center; margin: 50px 0;\">
                        <a href=\"{reset_url}\" style=\"background-color: #e67e22; color: white; padding: 16px 32px; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block; font-size: 16px; box-shadow: 0 3px 6px rgba(230,126,34,0.3); transition: all 0.3s ease;\">Reset Password</a>
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
                subject="Reset Your Password - StudyBox",
                html_content=html_content,
                text_content=text_content,
            )

    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()


def send_email_change_verification_async(app, user_email, username, new_email, verification_url):
    def _send():
        with app.app_context():
            html_content = f"""
            <html>
            <body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;\">
                <div style=\"background-color: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);\">
                    <div style=\"text-align: center; margin-bottom: 40px;\">
                        <h1 style=\"color: #2c3e50; margin: 0; font-size: 32px; font-weight: 300; letter-spacing: 1px;\">StudyBox</h1>
                        <p style=\"color: #7f8c8d; margin: 8px 0 0 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;\">Email Change Verification</p>
                    </div>
                    <h2 style=\"color: #2c3e50; text-align: center; margin-bottom: 30px; font-weight: 400; font-size: 24px;\">Verify Email Change</h2>
                    <p style=\"color: #34495e; font-size: 16px; line-height: 1.6; margin-bottom: 20px;\">Hello <strong>{username}</strong>,</p>
                    <div style=\"text-align: center; margin: 50px 0;\">
                        <a href=\"{verification_url}\" style=\"background-color: #27ae60; color: white; padding: 16px 32px; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block; font-size: 16px; box-shadow: 0 3px 6px rgba(39,174,96,0.3); transition: all 0.3s ease;\">Verify Email Change</a>
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
                subject="Verify Your Email Change - StudyBox",
                html_content=html_content,
                text_content=text_content,
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


__all__ = [
    'emails_bp',
    'generate_verification_token',
    'verify_token',
    'send_email_via_brevo_api',
    'send_verification_email_async',
    'send_password_reset_email_async',
    'send_email_change_verification_async',
]


