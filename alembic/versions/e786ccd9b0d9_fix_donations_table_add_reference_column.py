"""Fix donations table - add reference column

Revision ID: e786ccd9b0d9
Revises: 
Create Date: 2025-02-14 14:39:23.746035

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision: str = 'e786ccd9b0d9'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add the 'reference' column as nullable first
    op.add_column('donations', sa.Column('reference', sa.String(length=100), nullable=True))

    # Assign a default value to existing records
    op.execute("UPDATE donations SET reference = 'default_ref' WHERE reference IS NULL")

    # Alter the column to make it NOT NULL after populating data
    op.alter_column('donations', 'reference', nullable=False)

    # Ensure the reference column has unique values
    op.create_unique_constraint("uq_donations_reference", 'donations', ['reference'])

    # Modify 'paid_status' column
    op.alter_column('donations', 'paid_status',
               existing_type=sa.BOOLEAN(),
               server_default=None,
               existing_nullable=True)

    # Modify 'donation_date' in 'user' table
    op.alter_column('user', 'donation_date',
               existing_type=sa.DATE(),
               server_default=None,
               existing_nullable=False)

    # Drop unique constraints on 'user.phone'
    op.drop_constraint('user_phone_key', 'user', type_='unique')
    op.drop_constraint('user_phone_key1', 'user', type_='unique')

    # Drop old password hash columns
    op.drop_column('user', 'phone_password_hash')
    op.drop_column('user', 'email_password_hash')


def downgrade() -> None:
    # Restore dropped password hash columns
    op.add_column('user', sa.Column('email_password_hash', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
    op.add_column('user', sa.Column('phone_password_hash', sa.VARCHAR(length=255), autoincrement=False, nullable=True))

    # Restore unique constraints on 'user.phone'
    op.create_unique_constraint('user_phone_key1', 'user', ['phone'])
    op.create_unique_constraint('user_phone_key', 'user', ['phone'])

    # Restore 'donation_date' default
    op.alter_column('user', 'donation_date',
               existing_type=sa.DATE(),
               server_default=sa.text('now()'),
               existing_nullable=False)

    # Remove the unique constraint on 'reference'
    op.drop_constraint("uq_donations_reference", 'donations', type_='unique')

    # Modify 'paid_status' column back to original state
    op.alter_column('donations', 'paid_status',
               existing_type=sa.BOOLEAN(),
               server_default=sa.text('false'),
               existing_nullable=True)

    # Drop 'reference' column
    op.drop_column('donations', 'reference')
