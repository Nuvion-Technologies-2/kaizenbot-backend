"""empty message

Revision ID: 2144d516d689
Revises: 5c3e7140ef39
Create Date: 2025-03-20 17:42:04.086161

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2144d516d689'
down_revision = '5c3e7140ef39'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stock', schema=None) as batch_op:
        batch_op.drop_column('trading_status')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('stock', schema=None) as batch_op:
        batch_op.add_column(sa.Column('trading_status', sa.BOOLEAN(), autoincrement=False, nullable=False))

    # ### end Alembic commands ###
