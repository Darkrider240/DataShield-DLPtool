"""Initial schema — all DataShield Enterprise tables.

Revision ID: 001_initial
Revises:
Create Date: 2026-06-20
"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ── admin_users ───────────────────────────────────────────────────────────
    op.create_table(
        'admin_users',
        sa.Column('id',               sa.String,  primary_key=True),
        sa.Column('email',            sa.String,  nullable=False, unique=True, index=True),
        sa.Column('hashed_password',  sa.String,  nullable=False),
        sa.Column('full_name',        sa.String,  nullable=False, server_default=''),
        sa.Column('role',             sa.String,  nullable=False, server_default='analyst'),
        sa.Column('is_active',        sa.Boolean, server_default='true'),
        sa.Column('created_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_login',       sa.DateTime(timezone=True), nullable=True),
    )

    # ── employees ─────────────────────────────────────────────────────────────
    op.create_table(
        'employees',
        sa.Column('id',                    sa.String,  primary_key=True),
        sa.Column('email',                 sa.String,  nullable=False, unique=True, index=True),
        sa.Column('full_name',             sa.String,  server_default=''),
        sa.Column('department',            sa.String,  server_default=''),
        sa.Column('job_title',             sa.String,  server_default=''),
        sa.Column('encrypted_dek',         sa.Text,    nullable=False),
        sa.Column('pin_hash',              sa.String,  nullable=True),
        sa.Column('pin_set',               sa.Boolean, server_default='false'),
        sa.Column('risk_score',            sa.Float,   server_default='0.0'),
        sa.Column('risk_level',            sa.String,  server_default='CLEAN'),
        sa.Column('high_violations_7d',    sa.Integer, server_default='0'),
        sa.Column('medium_violations_7d',  sa.Integer, server_default='0'),
        sa.Column('total_events_30d',      sa.Integer, server_default='0'),
        sa.Column('average_volume_30d',    sa.Float,   server_default='0.0'),
        sa.Column('is_flagged',            sa.Boolean, server_default='false'),
        sa.Column('flag_reason',           sa.String,  server_default=''),
        sa.Column('flagged_at',            sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active',             sa.Boolean, server_default='true'),
        # Per-employee monitoring channel controls
        sa.Column('monitor_clipboard',     sa.Boolean, server_default='true'),
        sa.Column('monitor_usb',           sa.Boolean, server_default='true'),
        sa.Column('monitor_webmail',       sa.Boolean, server_default='true'),
        sa.Column('monitor_file_scan',     sa.Boolean, server_default='true'),
        sa.Column('created_at',            sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── agents ────────────────────────────────────────────────────────────────
    op.create_table(
        'agents',
        sa.Column('id',                      sa.String,  primary_key=True),
        sa.Column('hostname',                sa.String,  nullable=False),
        sa.Column('employee_id',             sa.String,  nullable=False, index=True),
        sa.Column('employee_email',          sa.String,  nullable=False),
        sa.Column('platform',                sa.String,  server_default=''),
        sa.Column('agent_version',           sa.String,  server_default=''),
        sa.Column('is_active',               sa.Boolean, server_default='true'),
        sa.Column('policy_update_available', sa.Boolean, server_default='false'),
        sa.Column('last_heartbeat',          sa.DateTime(timezone=True), nullable=True),
        sa.Column('registered_at',           sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── dlp_events ────────────────────────────────────────────────────────────
    op.create_table(
        'dlp_events',
        sa.Column('id',                       sa.String,  primary_key=True),
        sa.Column('employee_id',              sa.String,  nullable=False, index=True),
        sa.Column('agent_id',                 sa.String,  server_default=''),
        sa.Column('channel',                  sa.String,  nullable=False),
        sa.Column('action_taken',             sa.String,  nullable=False),
        sa.Column('justification',            sa.Text,    server_default=''),
        sa.Column('risk_level',               sa.String,  nullable=False),
        sa.Column('risk_score',               sa.Float,   server_default='0.0'),
        sa.Column('file_path_encrypted',      sa.Text,    server_default=''),
        sa.Column('ai_explanation_encrypted', sa.Text,    server_default=''),
        sa.Column('matched_value_redacted',   sa.Text,    server_default=''),
        sa.Column('pattern_names',            sa.JSON,    server_default='[]'),
        sa.Column('regulation_tags',          sa.JSON,    server_default='[]'),
        sa.Column('occurred_at',              sa.DateTime(timezone=True), nullable=False),
        sa.Column('ingested_at',              sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── policies ──────────────────────────────────────────────────────────────
    op.create_table(
        'policies',
        sa.Column('id',              sa.String,  primary_key=True),
        sa.Column('name',            sa.String,  nullable=False, unique=True),
        sa.Column('category',        sa.String,  nullable=False),
        sa.Column('pattern',         sa.Text,    nullable=False),
        sa.Column('base_weight',     sa.Float,   server_default='1.0'),
        sa.Column('regulation_tags', sa.JSON,    server_default='[]'),
        sa.Column('description',     sa.Text,    server_default=''),
        sa.Column('is_active',       sa.Boolean, server_default='true'),
        sa.Column('version',         sa.String,  server_default='1'),
        sa.Column('created_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── alerts ────────────────────────────────────────────────────────────────
    op.create_table(
        'alerts',
        sa.Column('id',               sa.String,  primary_key=True),
        sa.Column('employee_id',      sa.String,  nullable=False, index=True),
        sa.Column('event_id',         sa.String,  nullable=True),
        sa.Column('title',            sa.String,  nullable=False),
        sa.Column('description',      sa.Text,    server_default=''),
        sa.Column('severity',         sa.String,  nullable=False),
        sa.Column('status',           sa.String,  nullable=False, server_default='OPEN'),
        sa.Column('top_pattern',      sa.String,  server_default=''),
        sa.Column('escalation_count', sa.Integer, server_default='1'),
        sa.Column('acknowledged_by',  sa.String,  server_default=''),
        sa.Column('acknowledged_at',  sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at',      sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── server_settings ───────────────────────────────────────────────────────
    op.create_table(
        'server_settings',
        sa.Column('key',        sa.String, primary_key=True),
        sa.Column('value',      sa.String, nullable=False, server_default=''),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table('server_settings')
    op.drop_table('alerts')
    op.drop_table('policies')
    op.drop_table('dlp_events')
    op.drop_table('agents')
    op.drop_table('employees')
    op.drop_table('admin_users')
