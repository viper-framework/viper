"""initial alembic migration

Revision ID: 74c7becae858
Revises:
Create Date: 2017-05-09 20:52:15.401889

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '74c7becae858'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### Viper Database on 2017-10-30 ###
    op.create_table('analysis',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cmd_line', sa.String(length=255), nullable=True),
    sa.Column('results', sa.Text(), nullable=False),
    sa.Column('stored_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('malware',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('size', sa.Integer(), nullable=False),
    sa.Column('type', sa.Text(), nullable=True),
    sa.Column('mime', sa.String(length=255), nullable=True),
    sa.Column('md5', sa.String(length=32), nullable=False),
    sa.Column('crc32', sa.String(length=8), nullable=False),
    sa.Column('sha1', sa.String(length=40), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('sha512', sa.String(length=128), nullable=False),
    sa.Column('ssdeep', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['parent_id'], ['malware.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('malware', schema=None) as batch_op:
        batch_op.create_index('hash_index', ['md5', 'crc32', 'sha1', 'sha256', 'sha512'], unique=True)
        batch_op.create_index(batch_op.f('ix_malware_md5'), ['md5'], unique=False)
        batch_op.create_index(batch_op.f('ix_malware_sha256'), ['sha256'], unique=False)

    op.create_table('note',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=True),
    sa.Column('body', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tag',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tag', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('tag', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tag_tag'), ['tag'], unique=True)

    op.create_table('association',
    sa.Column('tag_id', sa.Integer(), nullable=True),
    sa.Column('note_id', sa.Integer(), nullable=True),
    sa.Column('malware_id', sa.Integer(), nullable=True),
    sa.Column('analysis_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_id'], ['analysis.id'], ),
    sa.ForeignKeyConstraint(['malware_id'], ['malware.id'], ),
    sa.ForeignKeyConstraint(['note_id'], ['note.id'], ),
    sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### there is no downgrade from here ###
    pass
    # ### end Alembic commands ###
