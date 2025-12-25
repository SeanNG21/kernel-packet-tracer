#!/usr/bin/env python3
"""
Migration script for realtime timeseries metrics table

Run this to create the realtime_timeseries_metrics table
"""

import os
import sys
from flask import Flask
from models import db
from realtime_timeseries_models import RealtimeTimeseriesMetric


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
    """Run database migration"""
    print("=" * 70)
    print("MIGRATION: Creating Realtime Timeseries Metrics Table")
    print("=" * 70)

    app = create_app()

    with app.app_context():
        print("\n[*] Creating table: realtime_timeseries_metrics...")

        # Create table
        db.create_all()

        print("[✓] Successfully created table: realtime_timeseries_metrics")

        # Verify table
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        print(f"\n[*] All tables in database:")
        for table in sorted(tables):
            print(f"    • {table}")

        # Show columns for new table
        if 'realtime_timeseries_metrics' in tables:
            columns = [col['name'] for col in inspector.get_columns('realtime_timeseries_metrics')]
            print(f"\n[*] Columns in realtime_timeseries_metrics:")
            for col in columns:
                print(f"    • {col}")

        print("\n" + "=" * 70)
        print("✨ Migration completed successfully!")
        print("=" * 70)
        print("\nNext steps:")
        print("1. Enable realtime trace: POST /api/realtime/enable")
        print("2. Let it run for 10+ minutes (auto-flush buckets)")
        print("3. Check metrics: GET /api/metrics/realtime/packets")
        print("4. View in dashboard: Navigate to Metrics tab")
        print("=" * 70)


if __name__ == '__main__':
    try:
        run_migration()
    except Exception as e:
        print(f"\n[✗] Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
