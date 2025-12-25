#!/usr/bin/env python3
"""
Master Test Runner - Execute All Test Scenarios
================================================

This script runs all three test scenarios in sequence and generates
a comprehensive comparison report.

Author: NFT Tracer Development Team
Date: 2025-11-24
"""

import os
import sys
import subprocess
import time
from datetime import datetime

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(text.center(80))
    print("=" * 80 + "\n")

def run_scenario(scenario_name, script_path):
    """Run a single test scenario"""
    print_header(f"RUNNING {scenario_name}")

    print(f"Script: {script_path}")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    start_time = time.time()

    try:
        # Run the scenario script
        result = subprocess.run(
            ["sudo", "python3", script_path],
            cwd=os.path.dirname(script_path)
        )

        duration = time.time() - start_time

        if result.returncode == 0:
            print(f"\n✓ {scenario_name} completed successfully")
        else:
            print(f"\n✗ {scenario_name} failed with exit code {result.returncode}")

        print(f"Duration: {duration:.2f} seconds")

        return result.returncode == 0

    except KeyboardInterrupt:
        print(f"\n⚠ {scenario_name} interrupted by user")
        return False

    except Exception as e:
        print(f"\n✗ Error running {scenario_name}: {e}")
        return False

def check_prerequisites():
    """Check if all prerequisites are installed"""
    print_header("CHECKING PREREQUISITES")

    prerequisites = {
        "nft": "nftables (sudo apt-get install nftables)",
        "iperf3": "iperf3 (sudo apt-get install iperf3)",
        "hping3": "hping3 (sudo apt-get install hping3)",
        "python3": "Python 3",
    }

    all_ok = True

    for cmd, description in prerequisites.items():
        result = subprocess.run(
            ["which", cmd],
            capture_output=True
        )

        if result.returncode == 0:
            print(f"  ✓ {description}")
        else:
            print(f"  ✗ {description} - NOT FOUND")
            all_ok = False

    # Check Python packages
    python_packages = [
        "requests",
        "psutil",
        "socketio",
        "matplotlib",
        "numpy"
    ]

    print("\nChecking Python packages:")
    for package in python_packages:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} - NOT INSTALLED (pip install {package})")
            all_ok = False

    if not all_ok:
        print("\n⚠ Some prerequisites are missing. Please install them before running tests.")
        print("Run: sudo ./tests/setup_test_environment.sh")
        return False

    print("\n✓ All prerequisites satisfied\n")
    return True

def check_nft_tracer_running():
    """Check if NFT Tracer backend is running"""
    print_header("CHECKING NFT TRACER STATUS")

    try:
        import requests
        response = requests.get("http://localhost:5000/api/health", timeout=2)

        if response.status_code == 200:
            print("  ✓ NFT Tracer backend is running")
            return True
        else:
            print("  ✗ NFT Tracer backend returned error")
            return False

    except Exception as e:
        print("  ✗ NFT Tracer backend is not running")
        print(f"     Error: {e}")
        print("\n  Please start the NFT Tracer backend:")
        print("    cd /home/sean/Downloads/nft-tracer-app/backend")
        print("    sudo python3 app.py")
        return False

def main():
    """Main entry point"""
    print_header("NFT TRACER - COMPREHENSIVE TEST SUITE")
    print("This will run all three test scenarios:")
    print("  1. Packet Drop Detection and Analysis")
    print("  2. Firewall Rule Performance Impact")
    print("  3. Real-time Monitoring Performance Under Load")
    print("\nEstimated total time: 20-30 minutes")
    print("Make sure you have sudo privileges and all prerequisites installed.")

    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠ This script requires sudo privileges.")
        print("Please run: sudo python3 run_all_scenarios.py")
        sys.exit(1)

    # Wait for user confirmation
    try:
        input("\nPress Enter to continue or Ctrl+C to cancel...")
    except KeyboardInterrupt:
        print("\n\nTest suite cancelled by user")
        sys.exit(0)

    # Check prerequisites
    if not check_prerequisites():
        print("\n⚠ Prerequisites check failed. Please install missing components.")
        sys.exit(1)

    # Check NFT Tracer
    if not check_nft_tracer_running():
        print("\n⚠ NFT Tracer backend must be running. Please start it first.")
        sys.exit(1)

    # Test scenarios
    scenarios = [
        ("Scenario 1: Packet Drop Detection",
         "/home/sean/Downloads/nft-tracer-app/tests/scenarios/scenario_1_drop_detection.py"),
        ("Scenario 2: Performance Impact",
         "/home/sean/Downloads/nft-tracer-app/tests/scenarios/scenario_2_performance_impact.py"),
        ("Scenario 3: Real-time Performance",
         "/home/sean/Downloads/nft-tracer-app/tests/scenarios/scenario_3_realtime_performance.py"),
    ]

    # Track results
    results = {}
    overall_start = time.time()

    # Run all scenarios
    for scenario_name, script_path in scenarios:
        success = run_scenario(scenario_name, script_path)
        results[scenario_name] = success

        # Wait between scenarios
        if scenario_name != scenarios[-1][0]:
            print("\nWaiting 30 seconds before next scenario...")
            time.sleep(30)

    overall_duration = time.time() - overall_start

    # Print final summary
    print_header("TEST SUITE COMPLETE")

    print("Results:")
    for scenario_name, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {scenario_name}")

    print(f"\nTotal duration: {overall_duration/60:.2f} minutes")

    # Count successes
    passed = sum(1 for s in results.values() if s)
    total = len(results)

    print(f"\nOverall: {passed}/{total} scenarios passed")

    # Generate report
    print_header("GENERATING COMPARISON REPORT")

    report_script = "/home/sean/Downloads/nft-tracer-app/tests/generate_comparison_report.py"

    if os.path.exists(report_script):
        print("Running report generator...")
        result = subprocess.run(["python3", report_script])

        if result.returncode == 0:
            print("\n✓ Report generated successfully")
            print("\nView report at:")
            print("  /home/sean/Downloads/nft-tracer-app/tests/results/comparison_report.html")
        else:
            print("\n⚠ Report generation failed")
    else:
        print("⚠ Report generator not found, skipping...")

    print("\n" + "=" * 80)
    print("\nNext steps:")
    print("  1. Review individual results in tests/results/")
    print("  2. Open comparison_report.html in a browser")
    print("  3. Check generated charts in tests/results/charts/")

    # Exit with appropriate code
    if passed == total:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Test suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
