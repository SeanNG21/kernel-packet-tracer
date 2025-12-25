#!/usr/bin/env python3
"""
Migration script to create time-series metrics tables
Run this script to add packet_metrics_10m, verdict_metrics_10m, and raw_packet_events tables
"""

import os
import sys
from flask import Flask
from models import db
from metrics_models import PacketMetrics10m, VerdictMetrics10m, RawPacketEvent


def create_app():
    """Create Flask app with database configuration"""
    app = Flask(__name__)

    # Database configuration (same as in app.py)
    DB_PATH = os.path.join(os.path.dirname(__file__), "nft_tracer.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize database
    db.init_app(app)

    return app


def run_migration():
    """Run database migration to create metrics tables"""
    print("=" * 70)
    print("MIGRATION: Creating Time-Series Metrics Tables")
    print("=" * 70)

    app = create_app()

    with app.app_context():
        print("\n[*] Creating tables...")

        # Create all tables defined in metrics_models
        db.create_all()

        print("[✓] Successfully created tables:")
        print("    • packet_metrics_10m")
        print("    • verdict_metrics_10m")
        print("    • raw_packet_events")

        # Verify tables were created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        print(f"\n[*] All tables in database:")
        for table in tables:
            print(f"    • {table}")

        print("\n[✓] Migration completed successfully!")
        print("=" * 70)


if __name__ == '__main__':
    try:
        run_migration()
    except Exception as e:
        print(f"\n[✗] Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
