"""empty message

Revision ID: 40e99ddc0100
Revises: e64726fee83c
Create Date: 2025-03-22 17:04:00.728385

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '40e99ddc0100'
down_revision = 'e64726fee83c'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add columns with default value 0.0 for existing rows
    op.add_column('user', sa.Column('available_balance', sa.Float(), nullable=False, server_default='0.0'))
    op.add_column('user', sa.Column('remaining_balance', sa.Float(), nullable=False, server_default='0.0'))
    op.add_column('user', sa.Column('used_balance', sa.Float(), nullable=False, server_default='0.0'))

def downgrade():
    op.drop_column('user', 'used_balance')
    op.drop_column('user', 'remaining_balance')
    op.drop_column('user', 'available_balance')

    # ### end Alembic commands ###
