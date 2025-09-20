"""update_existing_mmu_users_university

Revision ID: 1ac5026de973
Revises: f2bc06494590
Create Date: 2025-09-20 21:37:38.229608

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1ac5026de973'
down_revision = 'f2bc06494590'
branch_labels = None
depends_on = None


def upgrade():
    # Update existing MMU users to have correct university name
    connection = op.get_bind()
    
    # Update users with MMU email addresses to have "Multimedia University Malaysia" as their university
    connection.execute(
        sa.text("""
            UPDATE "user" 
            SET school_university = 'Multimedia University Malaysia' 
            WHERE email LIKE '%@student.mmu.edu.my' 
            AND (school_university IS NULL OR school_university != 'Multimedia University Malaysia')
        """)
    )


def downgrade():
    # This migration cannot be easily reversed as we don't know what the original university names were
    pass
