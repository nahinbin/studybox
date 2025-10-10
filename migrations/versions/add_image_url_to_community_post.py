from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_image_url_to_community_post'
down_revision = 'f2bc06494590'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('community_post', sa.Column('image_url', sa.String(length=300), nullable=True))


def downgrade():
    op.drop_column('community_post', 'image_url')
