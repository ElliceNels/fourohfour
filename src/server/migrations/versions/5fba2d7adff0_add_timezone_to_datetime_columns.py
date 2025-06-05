"""add_timezone_to_datetime_columns

Revision ID: 5fba2d7adff0
Revises: 506c46e6d55c
Create Date: 2025-06-04 00:32:19.514619

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5fba2d7adff0'
down_revision: Union[str, None] = '506c46e6d55c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
