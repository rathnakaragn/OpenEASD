"""
Migration: Add service detection fields to security_alerts table

This migration adds fields for storing nmap service detection results:
- service_type: Detected service name (mysql, ssh, ftp, etc.)
- service_version: Service version string
- service_confidence: Nmap confidence level (0-100)
- detection_method: Detection method used (httpx, nmap, banner)

Created: 2025-12-02
"""

import sqlite3
from pathlib import Path


def migrate_up(db_path: str) -> None:
    """Apply migration - add service detection fields."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Add service_type column
        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN service_type VARCHAR(50) DEFAULT NULL
        """)
        print("✓ Added service_type column")

        # Add service_version column
        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN service_version VARCHAR(100) DEFAULT NULL
        """)
        print("✓ Added service_version column")

        # Add service_confidence column
        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN service_confidence INTEGER DEFAULT NULL
        """)
        print("✓ Added service_confidence column")

        # Add detection_method column
        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN detection_method VARCHAR(50) DEFAULT 'httpx'
        """)
        print("✓ Added detection_method column")

        # Create index on service_type for faster filtering
        cursor.execute("""
            CREATE INDEX idx_service_type
            ON security_alerts(service_type)
        """)
        print("✓ Created index on service_type")

        conn.commit()
        print("\n✓ Migration completed successfully!")

    except sqlite3.OperationalError as e:
        if "already exists" in str(e):
            print(f"⚠ Column already exists: {e}")
            conn.rollback()
        else:
            print(f"✗ Error: {e}")
            conn.rollback()
            raise
    finally:
        conn.close()


def migrate_down(db_path: str) -> None:
    """Rollback migration - remove service detection fields."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # SQLite doesn't support DROP COLUMN easily, so we use a workaround
        # Create a new table without the new columns, then swap

        print("Note: SQLite doesn't support DROP COLUMN directly.")
        print("Manual rollback required. Contact database administrator.")
        print("\nThe columns added are:")
        print("  - service_type")
        print("  - service_version")
        print("  - service_confidence")
        print("  - detection_method")

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
