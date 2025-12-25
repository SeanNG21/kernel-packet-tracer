#!/usr/bin/env python3
"""
Test Report Generator with Sample Data
=======================================

This script tests the report generator without running actual network tests.
It creates sample data to verify all report formats work correctly.
"""

import sys
import os
from datetime import datetime
from dataclasses import dataclass, asdict

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from helpers.report_generator import ReportGenerator

@dataclass
class TestResult:
    """Sample test result for testing report generator"""
    test_case: str
    tool: str
    packets_sent: int
    packets_detected: int
    drops_detected: int
    drops_expected: int
    accepts_detected: int
    accepts_expected: int
    detection_accuracy: float
    cpu_usage_avg: float
    cpu_usage_max: float
    memory_mb: float
    execution_time_sec: float
    unique_source_ips: int
    timestamp: str
    verdict_breakdown: dict
    nftables_counter_drop: int
    nftables_counter_accept: int
    detection_latency_ms: float
    spike_false_positive: bool
    drop_record_completeness: float


def create_sample_data():
    """Create sample test data"""

    # Sample configuration
    config = {
        'db_server_ip': '10.10.0.1',
        'db_port': 5432,
        'whitelist_ip': '10.10.0.2',
        'namespace_db': 'dbns',
        'namespace_attacker': 'attns'
    }

    # Sample test result with good metrics
    result = TestResult(
        test_case="DB_Server_Monitoring",
        tool="NFT Tracer Realtime",
        packets_sent=650,  # 50 baseline + 100 legit spike + 500 attack
        packets_detected=150,  # Only baseline + legit spike detected (attack in namespace)
        drops_detected=0,  # eBPF can't see namespace traffic
        drops_expected=500,
        accepts_detected=150,
        accepts_expected=150,
        detection_accuracy=23.08,  # 150/650
        cpu_usage_avg=45.5,
        cpu_usage_max=68.3,
        memory_mb=125.4,
        execution_time_sec=28.45,
        unique_source_ips=342,  # Random IPs in attack phase
        timestamp=datetime.now().isoformat(),
        verdict_breakdown={
            'ACCEPT': 150,
            'DROP': 0  # Using nftables counters as fallback
        },
        nftables_counter_drop=478,  # ~95% of attack packets
        nftables_counter_accept=152,  # Baseline + legit spike
        detection_latency_ms=45.2,  # Very fast
        spike_false_positive=False,  # Good - no false positive
        drop_record_completeness=0.0  # No DROP events from eBPF (namespace isolation)
    )

    # Sample analysis
    analysis = {
        'total_packets': 150,
        'unique_ips': 342,
        'verdict_counts': {
            'ACCEPT': 150,
            'DROP': 0
        },
        'drops': 0,
        'accepts': 150,
        'source': 'nftables_counters',  # Fallback due to namespace
        'detection_latency_ms': 45.2,
        'drop_record_completeness': 0.0,
        'spike_false_positive': False
    }

    return config, [result], analysis


def main():
    """Test report generator with sample data"""

    print("=" * 80)
    print("TESTING REPORT GENERATOR WITH SAMPLE DATA")
    print("=" * 80)

    # Get test directory
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(tests_dir, "results", "test_reports")

    # Create test results directory
    os.makedirs(results_dir, exist_ok=True)

    print(f"\n📁 Output directory: {results_dir}")

    # Create sample data
    print("\n[1/3] Creating sample data...")
    config, results, analysis = create_sample_data()
    print(f"  ✓ Created sample test result")

    # Initialize report generator
    print("\n[2/3] Initializing report generator...")
    report_gen = ReportGenerator(results_dir)
    print(f"  ✓ Report generator initialized")

    # Generate all reports
    print("\n[3/3] Generating reports...")

    try:
        # 1. CSV export
        report_gen.export_to_csv(
            results,
            "test_metrics.csv",
            "Test Scenario"
        )

        # 2. Statistics CSV
        report_gen.generate_statistics_table_csv(
            results,
            "test_statistics.csv"
        )

        # 3. HTML report
        report_gen.generate_html_report(
            results,
            config,
            analysis,
            "Test Scenario - DB Server Monitoring",
            "test_report.html"
        )

        # 4. Markdown summary
        report_gen.generate_markdown_summary(
            results,
            config,
            "Test Scenario - DB Server Monitoring",
            "test_summary.md"
        )

        # 5. Detailed JSON
        detailed_data = {
            'scenario': 'Test Scenario - DB Server Monitoring',
            'timestamp': datetime.now().isoformat(),
            'configuration': config,
            'results': [asdict(r) for r in results],
            'analysis': analysis
        }

        report_gen.export_detailed_json(
            detailed_data,
            "test_detailed.json"
        )

        print("\n" + "=" * 80)
        print("✅ REPORT GENERATION SUCCESSFUL")
        print("=" * 80)

        print(f"\n📊 Generated files in: {results_dir}")
        print("\n  ✓ test_metrics.csv        - CSV for Excel/Google Sheets")
        print("  ✓ test_statistics.csv     - Detailed statistics table")
        print("  ✓ test_report.html        - Interactive HTML report with charts")
        print("  ✓ test_summary.md         - Markdown summary")
        print("  ✓ test_detailed.json      - Complete data in JSON")

        print("\n🌐 To view HTML report:")
        print(f"  firefox {os.path.join(results_dir, 'test_report.html')}")
        print("  # or")
        print(f"  google-chrome {os.path.join(results_dir, 'test_report.html')}")

        print("\n✅ All report formats working correctly!")
        print("\nYou can now run the actual test:")
        print("  cd tests/scenarios")
        print("  sudo python3 scenario_1_drop_detection.py")

        return 0

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
