"""merge heads

Revision ID: b82e9dc57b35
Revises: 3d2f2aa24ec6, add_image_url_to_community_post
Create Date: 2025-10-10 16:57:22.726740

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b82e9dc57b35'
down_revision = ('3d2f2aa24ec6', 'add_image_url_to_community_post')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
