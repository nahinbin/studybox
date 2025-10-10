from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_post_image_bytes'
down_revision = 'b82e9dc57b35'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('community_post', sa.Column('image_data', sa.LargeBinary(), nullable=True))
    op.add_column('community_post', sa.Column('image_mime', sa.String(length=100), nullable=True))
    op.add_column('community_post', sa.Column('image_filename', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('community_post', 'image_filename')
    op.drop_column('community_post', 'image_mime')
    op.drop_column('community_post', 'image_data')


