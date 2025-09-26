from flask_login import UserMixin
from extensions import assignmenet_db


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
    avatar = assignmenet_db.Column(assignmenet_db.String(20), nullable=True, default='1')
    bio = assignmenet_db.Column(assignmenet_db.Text, nullable=True)
    github_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    instagram_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    twitter_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    youtube_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    linkedin_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    tiktok_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    discord_username = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    custom_website_url = assignmenet_db.Column(assignmenet_db.String(200), nullable=True)
    custom_website_name = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    show_email = assignmenet_db.Column(assignmenet_db.Boolean, default=False, nullable=False)
    current_semester = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)
    enrollments = assignmenet_db.relationship('Enrollment', backref='user', lazy=True)
    graduated = assignmenet_db.Column(assignmenet_db.Boolean, default=False)
    previous_semesters = assignmenet_db.relationship('PreviousSemester', backref='user', lazy=True)

    @property
    def public_id(self):
        return f"sd{_encode_user_code(self.id)}"


class QuickLink(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    title = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    url = assignmenet_db.Column(assignmenet_db.String(500), nullable=False)
    favicon_url = assignmenet_db.Column(assignmenet_db.String(500), nullable=True)
    description = assignmenet_db.Column(assignmenet_db.String(200), nullable=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable=False)
    created_at = assignmenet_db.Column(assignmenet_db.DateTime, default=assignmenet_db.func.current_timestamp())

    @property
    def public_id(self):
        return f"sd{_encode_user_code(self.id)}"


## MMULink model removed; MMU links are hard-coded in app logic


class ContactMessage(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable=True)
    name = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    email = assignmenet_db.Column(assignmenet_db.String(150), nullable=False)
    subject = assignmenet_db.Column(assignmenet_db.String(200), nullable=False)
    message = assignmenet_db.Column(assignmenet_db.Text, nullable=False)
    is_read = assignmenet_db.Column(assignmenet_db.Boolean, default=False)
    created_at = assignmenet_db.Column(assignmenet_db.DateTime, default=assignmenet_db.func.current_timestamp())

    user = assignmenet_db.relationship('User', backref='contact_messages')


class CommunityPost(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable=False)
    content = assignmenet_db.Column(assignmenet_db.Text, nullable=False)
    post_type = assignmenet_db.Column(assignmenet_db.String(20), nullable=False, default='public')
    created_at = assignmenet_db.Column(assignmenet_db.DateTime, default=assignmenet_db.func.current_timestamp())

    user = assignmenet_db.relationship('User', backref='community_posts')
    likes = assignmenet_db.relationship('CommunityPostLike', backref='post', lazy=True, cascade='all, delete-orphan')


class CommunityPostLike(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable=False)
    post_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('community_post.id'), nullable=False)
    created_at = assignmenet_db.Column(assignmenet_db.DateTime, default=assignmenet_db.func.current_timestamp())

    user = assignmenet_db.relationship('User', backref='community_post_likes')
    __table_args__ = (assignmenet_db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)


class CommunityComment(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable=False)
    post_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('community_post.id'), nullable=False)
    content = assignmenet_db.Column(assignmenet_db.Text, nullable=False)
    created_at = assignmenet_db.Column(assignmenet_db.DateTime, default=assignmenet_db.func.current_timestamp())

    user = assignmenet_db.relationship('User', backref='community_comments')
    post = assignmenet_db.relationship('CommunityPost', backref='comments')


__all__ = [
    'User',
    'QuickLink',
    'ContactMessage',
    'CommunityPost',
    'CommunityPostLike',
    'CommunityComment',
]


