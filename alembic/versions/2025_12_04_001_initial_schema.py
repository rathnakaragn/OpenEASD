"""Initial schema baseline

Revision ID: 001
Revises: None
Create Date: 2025-12-04

This is a baseline migration that represents the current schema state.
All existing tables are treated as already created.

To use with an existing database:
    alembic stamp head

To create tables in a fresh database:
    alembic upgrade head
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""
    # Domain table
    op.create_table(
        'domain',
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('contact_email', sa.String(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('tags', sa.String(), nullable=True),
        sa.Column('scan_frequency', sa.String(), nullable=True, server_default='weekly'),
        sa.Column('active_scan_enabled', sa.Boolean(), nullable=True, server_default='1'),
        sa.Column('scan_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_scanned_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('domain')
    )

    # ScanSession table
    op.create_table(
        'scansession',
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('scan_type', sa.String(), nullable=False),
        sa.Column('tool_name', sa.String(), nullable=True),
        sa.Column('apex_domain', sa.String(), nullable=True),
        sa.Column('domains_scanned', sa.String(), nullable=True),
        sa.Column('start_time', sa.DateTime(), nullable=True),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='running'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('metadata', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('scan_id')
    )

    # Job table
    op.create_table(
        'job',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('job_type', sa.String(), nullable=False),
        sa.Column('payload', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('scan_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('queued_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('worker_id', sa.String(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_job_status', 'job', ['status'], unique=False)
    op.create_index('ix_job_scan_id', 'job', ['scan_id'], unique=False)

    # SubdomainHistory table
    op.create_table(
        'subdomainhistory',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('apex_domain', sa.String(), nullable=False),
        sa.Column('subdomain', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='new'),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('tool_source', sa.String(), nullable=True),
        sa.Column('meta_data', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_subdomainhistory_apex_domain', 'subdomainhistory', ['apex_domain'], unique=False)
    op.create_index('ix_subdomainhistory_subdomain', 'subdomainhistory', ['subdomain'], unique=False)

    # Finding table
    op.create_table(
        'finding',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('finding_type', sa.String(), nullable=False),
        sa.Column('affected_asset', sa.String(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(), nullable=False, server_default='medium'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('status', sa.String(), nullable=False, server_default='new'),
        sa.Column('detector', sa.String(), nullable=True),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('score_breakdown_json', sa.Text(), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_finding_scan_id', 'finding', ['scan_id'], unique=False)
    op.create_index('ix_finding_affected_asset', 'finding', ['affected_asset'], unique=False)
    op.create_index('ix_finding_severity', 'finding', ['severity'], unique=False)

    # Tool result tables
    op.create_table(
        'subfinderresult',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('apex_domain', sa.String(), nullable=False),
        sa.Column('subdomain', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'amassresult',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('apex_domain', sa.String(), nullable=False),
        sa.Column('subdomain', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('tag', sa.String(), nullable=True),
        sa.Column('sources', sa.Text(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'naaburesult',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('target_host', sa.String(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(), nullable=False, server_default='tcp'),
        sa.Column('scanned_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'nmapresult',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('target_host', sa.String(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(), nullable=False, server_default='tcp'),
        sa.Column('service_name', sa.String(), nullable=True),
        sa.Column('service_version', sa.String(), nullable=True),
        sa.Column('service_product', sa.String(), nullable=True),
        sa.Column('service_info', sa.Text(), nullable=True),
        sa.Column('os_info', sa.Text(), nullable=True),
        sa.Column('scripts_output', sa.Text(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('nmapresult')
    op.drop_table('naaburesult')
    op.drop_table('amassresult')
    op.drop_table('subfinderresult')
    op.drop_index('ix_finding_severity', 'finding')
    op.drop_index('ix_finding_affected_asset', 'finding')
    op.drop_index('ix_finding_scan_id', 'finding')
    op.drop_table('finding')
    op.drop_index('ix_subdomainhistory_subdomain', 'subdomainhistory')
    op.drop_index('ix_subdomainhistory_apex_domain', 'subdomainhistory')
    op.drop_table('subdomainhistory')
    op.drop_index('ix_job_scan_id', 'job')
    op.drop_index('ix_job_status', 'job')
    op.drop_table('job')
    op.drop_table('scansession')
    op.drop_table('domain')
