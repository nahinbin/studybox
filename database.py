from flask_login import UserMixin
from extensions import db


_BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
_CODE_LENGTH = 6
_CODE_MODULUS = 36 ** _CODE_LENGTH
_CODE_MULTIPLIER = 48271
_CODE_INCREMENT = 12345
_CODE_MULTIPLIER_INV = pow(_CODE_MULTIPLIER, -1, _CODE_MODULUS)


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


def _encode_user_code(user_id):
    value = (int(user_id) * _CODE_MULTIPLIER + _CODE_INCREMENT) % _CODE_MODULUS
    return _encode_base36(value).zfill(_CODE_LENGTH)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    pending_email = db.Column(db.String(150), nullable=True)
    email_change_token = db.Column(db.String(100), nullable=True)
    school_university = db.Column(db.String(200), nullable=True)
    avatar = db.Column(db.String(20), nullable=True, default='1')
    bio = db.Column(db.Text, nullable=True)
    github_username = db.Column(db.String(100), nullable=True)
    instagram_username = db.Column(db.String(100), nullable=True)
    twitter_username = db.Column(db.String(100), nullable=True)
    youtube_username = db.Column(db.String(100), nullable=True)
    linkedin_username = db.Column(db.String(100), nullable=True)
    tiktok_username = db.Column(db.String(100), nullable=True)
    discord_username = db.Column(db.String(100), nullable=True)
    custom_website_url = db.Column(db.String(200), nullable=True)
    custom_website_name = db.Column(db.String(100), nullable=True)
    show_email = db.Column(db.Boolean, default=False, nullable=False)
    current_semester = db.Column(db.String(100), nullable=True)
    enrollments = db.relationship('Enrollment', backref='user', lazy=True)
    graduated = db.Column(db.Boolean, default=False)
    previous_semesters = db.relationship('PreviousSemester', backref='user', lazy=True)

    @property
    def public_id(self):
        return f"sd{_encode_user_code(self.id)}"


class QuickLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    favicon_url = db.Column(db.String(500), nullable=True)
    description = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    @property
    def public_id(self):
        return f"sd{_encode_user_code(self.id)}"


## MMULink model removed; MMU links are hard-coded in app logic


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='contact_messages')


class CommunityPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(20), nullable=False, default='public')
    image_url = db.Column(db.String(300))
    image_data = db.Column(db.LargeBinary)
    image_mime = db.Column(db.String(100))
    image_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='community_posts')
    likes = db.relationship('CommunityPostLike', backref='post', lazy=True, cascade='all, delete-orphan')


class CommunityPostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='community_post_likes')
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)


class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_email = db.Column(db.String(150), nullable=False)
    recipient_name = db.Column(db.String(150), nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    email_type = db.Column(db.String(50), nullable=False)  # 'verification', 'password_reset', 'email_change'
    sent_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    success = db.Column(db.Boolean, default=True)


class CommunityComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='community_comments')
    post = db.relationship('CommunityPost', backref='comments')


class HelpTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    add_to_faq = db.Column(db.Boolean, default=False, nullable=False)
    image_url = db.Column(db.String(300))
    image_mime = db.Column(db.String(100))
    image_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='help_tickets')


class HelpReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('help_ticket.id', ondelete='CASCADE'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    ticket = db.relationship('HelpTicket', backref='replies')
    admin = db.relationship('User', backref='help_replies')


class Institution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=True)
    domain = db.Column(db.String(150), nullable=True)
    logo_url = db.Column(db.String(300), nullable=True)
    image_data = db.Column(db.LargeBinary)
    image_mime = db.Column(db.String(100))
    image_filename = db.Column(db.String(255))
    is_system = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<Institution {self.name}>"


__all__ = [
    'User',
    'QuickLink',
    'ContactMessage',
    'CommunityPost',
    'CommunityPostLike',
    'CommunityComment',
    'HelpTicket',
    'HelpReply',
    'Institution',
    'EmailLog',
]


