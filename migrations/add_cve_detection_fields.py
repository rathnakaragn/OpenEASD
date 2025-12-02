"""
Migration: Add CVE detection fields to security_alerts table

This migration adds fields for storing CVE and vulnerability detection results:
- cve_ids: JSON list of CVE IDs found
- cvss_score: Highest CVSS score (0-10)
- cvss_vector: CVSS vector string
- vulnerability_description: Details of vulnerabilities
- remediation_steps: Steps to fix the vulnerabilities

Created: 2025-12-02
Updated: 2025-12-02 (Fixed idempotency)

Idempotent: YES - Safe to run multiple times
"""

import sqlite3
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def migrate_up(db_path: str) -> None:
    """
    Apply migration - add CVE detection fields.

    Fully idempotent: Safe to run multiple times.
    - Checks if column exists before adding
    - Uses CREATE INDEX IF NOT EXISTS for indices
    - Logs skipped steps without errors
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    columns_added = []
    columns_skipped = []

    try:
        # Define columns to add
        columns_to_add = [
            ("cve_ids", "TEXT DEFAULT NULL",
             "JSON list of CVE IDs found"),
            ("cvss_score", "REAL DEFAULT NULL",
             "Highest CVSS score (0-10)"),
            ("cvss_vector", "VARCHAR(255) DEFAULT NULL",
             "CVSS vector string"),
            ("vulnerability_description", "TEXT DEFAULT NULL",
             "Details of vulnerabilities"),
            ("remediation_steps", "TEXT DEFAULT NULL",
             "Steps to fix the vulnerabilities"),
        ]

        # Add each column individually (per-column error handling)
        for col_name, col_type, col_description in columns_to_add:
            try:
                cursor.execute(f"""
                    ALTER TABLE security_alerts
                    ADD COLUMN {col_name} {col_type}
                """)
                columns_added.append(col_name)
                print(f"✓ Added {col_name} column - {col_description}")
            except sqlite3.OperationalError as e:
                error_msg = str(e).lower()
                if "duplicate column name" in error_msg:
                    columns_skipped.append(col_name)
                    print(f"⊘ Column {col_name} already exists (skipped)")
                elif "already exists" in error_msg:
                    columns_skipped.append(col_name)
                    print(f"⊘ Column {col_name} already exists (skipped)")
                else:
                    # Re-raise if it's a different error
                    print(f"✗ Error adding {col_name}: {e}")
                    raise

        # Create indices (using IF NOT EXISTS to be idempotent)
        indices_to_create = [
            ("idx_cvss_score",
             "CREATE INDEX IF NOT EXISTS idx_cvss_score "
             "ON security_alerts(cvss_score) "
             "WHERE cvss_score IS NOT NULL",
             "Fast sorting by CVSS score"),
            ("idx_cve_severity",
             "CREATE INDEX IF NOT EXISTS idx_cve_severity "
             "ON security_alerts(severity, cvss_score DESC) "
             "WHERE cvss_score IS NOT NULL",
             "Fast filtering by severity + sorting"),
        ]

        indices_created = []
        for idx_name, idx_sql, idx_description in indices_to_create:
            try:
                cursor.execute(idx_sql)
                indices_created.append(idx_name)
                print(f"✓ Created/verified index {idx_name} - {idx_description}")
            except sqlite3.OperationalError as e:
                if "already exists" in str(e).lower():
                    print(f"⊘ Index {idx_name} already exists (skipped)")
                else:
                    print(f"✗ Error creating index {idx_name}: {e}")
                    # Don't raise - indices are optimizations, not required

        # Commit changes
        conn.commit()

        # Summary
        print("\n" + "="*60)
        print("Migration Summary:")
        print("="*60)
        print(f"✓ Columns added: {len(columns_added)}")
        for col in columns_added:
            print(f"  - {col}")

        if columns_skipped:
            print(f"⊘ Columns skipped (already exist): {len(columns_skipped)}")
            for col in columns_skipped:
                print(f"  - {col}")

        print(f"✓ Indices created/verified: {len(indices_created)}")
        for idx in indices_created:
            print(f"  - {idx}")

        print("\n✓ Migration completed successfully!")
        print("="*60)

    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def migrate_down(db_path: str) -> None:
    """
    Rollback migration - remove CVE detection fields.

    Note: SQLite has limited ALTER TABLE support.
    For SQLite 3.35.0+, we can drop columns.
    For earlier versions, manual intervention required.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check SQLite version
        cursor.execute("SELECT sqlite_version()")
        version_str = cursor.fetchone()[0]
        major, minor, patch = version_str.split('.')
        major, minor = int(major), int(minor)

        print(f"SQLite version: {version_str}")

        if major > 3 or (major == 3 and minor >= 35):
            # SQLite 3.35+ supports DROP COLUMN
            print("SQLite 3.35+ detected - DROP COLUMN supported")

            columns_to_drop = [
                'cve_ids',
                'cvss_score',
                'cvss_vector',
                'vulnerability_description',
                'remediation_steps'
            ]

            columns_dropped = []
            for col in columns_to_drop:
                try:
                    cursor.execute(f"ALTER TABLE security_alerts DROP COLUMN {col}")
                    columns_dropped.append(col)
                    print(f"✓ Dropped column {col}")
                except sqlite3.OperationalError as e:
                    if "no such column" in str(e).lower():
                        print(f"⊘ Column {col} doesn't exist (skipped)")
                    else:
                        print(f"✗ Error dropping {col}: {e}")

            if columns_dropped:
                conn.commit()
                print(f"\n✓ Rollback completed - {len(columns_dropped)} columns dropped")
            else:
                print("\n⊘ No columns to drop - migration appears to be already rolled back")

        else:
            # Older SQLite versions don't support DROP COLUMN
            print(f"\nSQLite {major}.{minor} detected - DROP COLUMN not supported")
            print("\nManual rollback required. To remove CVE columns:")
            print("""
1. Backup your database:
   cp openeasd.db openeasd.db.backup

2. Download recent SQLite (3.35+) or use this Python script:
   import sqlite3
   conn = sqlite3.connect('openeasd.db')
   cursor = conn.cursor()

   # Create new table without CVE columns
   cursor.execute('''
       CREATE TABLE security_alerts_new AS
       SELECT id, domain, scan_id, vulnerability_type, severity,
              description, remediation, tool_source, service_type,
              service_version, service_confidence, detection_method,
              discovered_at
       FROM security_alerts
   ''')

   # Drop old table and rename
   cursor.execute('DROP TABLE security_alerts')
   cursor.execute('ALTER TABLE security_alerts_new RENAME TO security_alerts')
   conn.commit()

3. Or contact your database administrator for manual rollback
            """)

    except Exception as e:
        print(f"Error during rollback: {e}")
        logger.error(f"Migration rollback failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    # Find database file
    project_root = Path(__file__).parent.parent
    db_path = project_root / "openeasd.db"

    if not db_path.exists():
        print(f"✗ Database not found at {db_path}")
        exit(1)

    print(f"Migrating database: {db_path}\n")
    migrate_up(str(db_path))
