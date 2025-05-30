"""bye bytes

Revision ID: b1f2ff5835f8
Revises: 
Create Date: 2025-05-29 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = 'b1f2ff5835f8'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Get the connection and inspector
    conn = op.get_bind()
    inspector = inspect(conn)
    
    # Get the actual constraint name
    constraints = inspector.get_unique_constraints('users')
    public_key_constraint = next((c for c in constraints if 'public_key' in c['column_names']), None)
    
    if public_key_constraint:
        # Drop the existing constraint using its actual name
        op.drop_constraint(public_key_constraint['name'], 'users', type_='unique')
    
    # Then modify the column
    op.alter_column('users', 'public_key',
        existing_type=sa.VARBINARY(2048),
        type_=sa.String(2048),
        existing_nullable=False)
    
    # Create the unique constraint using raw SQL to specify the index length
    op.execute('CREATE UNIQUE INDEX users_public_key_key ON users (public_key(767))')


def downgrade() -> None:
    # Get the connection and inspector
    conn = op.get_bind()
    inspector = inspect(conn)
    
    # Get the actual constraint name
    constraints = inspector.get_unique_constraints('users')
    public_key_constraint = next((c for c in constraints if 'public_key' in c['column_names']), None)
    
    if public_key_constraint:
        # Drop the existing constraint using its actual name
        op.drop_constraint(public_key_constraint['name'], 'users', type_='unique')
    
    # Change back to VARBINARY
    op.alter_column('users', 'public_key',
        existing_type=sa.String(2048),
        type_=sa.VARBINARY(2048),
        existing_nullable=False)
    
    # Add back the original unique constraint
    op.create_unique_constraint('users_public_key_key', 'users', ['public_key'])
