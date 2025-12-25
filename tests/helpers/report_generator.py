#!/usr/bin/env python3
"""
Report Generator for NFT Tracer Test Scenarios
===============================================

Generates comprehensive reports with:
- JSON/CSV exports for data analysis
- HTML reports with interactive charts
- Statistical tables and summaries
- Performance visualizations
- Timeline analysis

Author: NFT Tracer Development Team
Date: 2025-11-30
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import asdict


class ReportGenerator:
    """Generate comprehensive test reports with charts and tables"""

    def __init__(self, results_dir: str = None):
        """Initialize report generator

        Args:
            results_dir: Directory to save reports (default: tests/results)
        """
        if results_dir is None:
            tests_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            results_dir = os.path.join(tests_dir, "results")

        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(os.path.join(self.results_dir, "charts"), exist_ok=True)

    def export_to_csv(self, results: List[Any], filename: str, scenario_name: str = ""):
        """Export results to CSV for Excel/Google Sheets

        Args:
            results: List of TestResult objects
            filename: Output filename (e.g., "scenario_1_metrics.csv")
            scenario_name: Name of the scenario
        """
        csv_path = os.path.join(self.results_dir, filename)

        # Convert dataclass to dict
        if not results:
            print(f"  ⚠ No results to export to CSV")
            return None

        result_dicts = [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in results]

        # Write CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            if result_dicts:
                # Get all unique keys from all results
                all_keys = set()
                for r in result_dicts:
                    all_keys.update(r.keys())

                # Sort keys for consistent column order
                fieldnames = sorted(all_keys)

                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for result in result_dicts:
                    # Handle nested dicts by converting to JSON string
                    row = {}
                    for key, value in result.items():
                        if isinstance(value, (dict, list)):
                            row[key] = json.dumps(value)
                        else:
                            row[key] = value
                    writer.writerow(row)

        print(f"  ✓ CSV exported to: {csv_path}")
        return csv_path

    def export_detailed_json(self, data: Dict, filename: str):
        """Export detailed JSON with all metrics

        Args:
            data: Complete test data including config, results, events
            filename: Output filename (e.g., "scenario_1_detailed.json")
        """
        json_path = os.path.join(self.results_dir, filename)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"  ✓ Detailed JSON exported to: {json_path}")
        return json_path

    def generate_html_report(
        self,
        results: List[Any],
        config: Dict,
        analysis: Dict,
        scenario_name: str,
        filename: str
    ):
        """Generate interactive HTML report with charts

        Args:
            results: List of TestResult objects
            config: Test configuration
            analysis: Analysis results (from analyze_realtime_events)
            scenario_name: Name of the scenario
            filename: Output filename (e.g., "scenario_1_report.html")
        """
        html_path = os.path.join(self.results_dir, filename)

        # Convert results to dicts
        result_dicts = [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in results]

        # Get primary result
        result = result_dicts[0] if result_dicts else {}

        # Calculate additional metrics
        drop_accuracy = 0.0
        accept_accuracy = 0.0

        if result.get('drops_expected', 0) > 0:
            drop_accuracy = (result.get('drops_detected', 0) / result['drops_expected']) * 100.0

        if result.get('accepts_expected', 0) > 0:
            accept_accuracy = (result.get('accepts_detected', 0) / result['accepts_expected']) * 100.0

        # Verdict breakdown for pie chart
        verdict_breakdown = result.get('verdict_breakdown', {})

        # Generate HTML
        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{scenario_name} - Test Report</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 15px;
            margin-bottom: 30px;
            font-size: 2.5em;
        }}

        h2 {{
            color: #2c3e50;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-left: 10px;
            border-left: 4px solid #3498db;
            font-size: 1.8em;
        }}

        h3 {{
            color: #34495e;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}

        .metadata {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
            font-size: 0.95em;
        }}

        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .metric-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .metric-card.success {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}

        .metric-card.warning {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}

        .metric-card.info {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}

        .metric-label {{
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 5px;
        }}

        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .metric-unit {{
            font-size: 0.85em;
            opacity: 0.8;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        th {{
            background: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}

        td {{
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        .status-good {{
            color: #27ae60;
            font-weight: bold;
        }}

        .status-bad {{
            color: #e74c3c;
            font-weight: bold;
        }}

        .status-warning {{
            color: #f39c12;
            font-weight: bold;
        }}

        .alert {{
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }}

        .alert-info {{
            background: #d1ecf1;
            border-color: #0c5460;
            color: #0c5460;
        }}

        .alert-success {{
            background: #d4edda;
            border-color: #155724;
            color: #155724;
        }}

        .alert-warning {{
            background: #fff3cd;
            border-color: #856404;
            color: #856404;
        }}

        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}

        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}

        .phase-table {{
            margin: 20px 0;
        }}

        .phase-table th {{
            background: #34495e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 {scenario_name}</h1>

        <div class="metadata">
            <strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Test Duration:</strong> {result.get('execution_time_sec', 0):.2f} seconds<br>
            <strong>Tool:</strong> {result.get('tool', 'NFT Tracer')}
        </div>

        <h2>📈 Key Performance Metrics</h2>

        <div class="metric-grid">
            <div class="metric-card success">
                <div class="metric-label">Detection Accuracy</div>
                <div class="metric-value">{result.get('detection_accuracy', 0):.1f}%</div>
                <div class="metric-unit">Overall Detection Rate</div>
            </div>

            <div class="metric-card info">
                <div class="metric-label">Detection Latency</div>
                <div class="metric-value">{result.get('detection_latency_ms', 0):.1f}</div>
                <div class="metric-unit">milliseconds</div>
            </div>

            <div class="metric-card {'success' if not result.get('spike_false_positive', False) else 'warning'}">
                <div class="metric-label">False Positives</div>
                <div class="metric-value">{'NO ✓' if not result.get('spike_false_positive', False) else 'YES ✗'}</div>
                <div class="metric-unit">Legitimate traffic flagged</div>
            </div>

            <div class="metric-card info">
                <div class="metric-label">DROP Completeness</div>
                <div class="metric-value">{result.get('drop_record_completeness', 0):.1f}%</div>
                <div class="metric-unit">Records with full info</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">CPU Usage (Avg)</div>
                <div class="metric-value">{result.get('cpu_usage_avg', 0):.1f}%</div>
                <div class="metric-unit">System load</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">Unique Source IPs</div>
                <div class="metric-value">{result.get('unique_source_ips', 0)}</div>
                <div class="metric-unit">Distinct attackers</div>
            </div>
        </div>

        <h2>🎯 Test Configuration</h2>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>DB Server IP</td>
                <td><code>{config.get('db_server_ip', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>DB Port</td>
                <td><code>{config.get('db_port', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>Whitelist IP</td>
                <td><code>{config.get('whitelist_ip', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>DB Namespace</td>
                <td><code>{config.get('namespace_db', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>Attacker Namespace</td>
                <td><code>{config.get('namespace_attacker', 'N/A')}</code></td>
            </tr>
        </table>

        <h2>📦 Traffic Summary</h2>

        <div class="chart-container">
            <h3>Packet Distribution by Verdict</h3>
            <div id="verdictPieChart"></div>
        </div>

        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Total Packets Sent</td>
                <td>{result.get('packets_sent', 0)}</td>
                <td>-</td>
            </tr>
            <tr>
                <td>Packets Detected</td>
                <td>{result.get('packets_detected', 0)}</td>
                <td>-</td>
            </tr>
            <tr>
                <td>Drops Detected / Expected</td>
                <td>{result.get('drops_detected', 0)} / {result.get('drops_expected', 0)}</td>
                <td class="{'status-good' if drop_accuracy >= 90 else 'status-warning' if drop_accuracy >= 70 else 'status-bad'}">{drop_accuracy:.1f}%</td>
            </tr>
            <tr>
                <td>Accepts Detected / Expected</td>
                <td>{result.get('accepts_detected', 0)} / {result.get('accepts_expected', 0)}</td>
                <td class="{'status-good' if accept_accuracy >= 90 else 'status-warning' if accept_accuracy >= 70 else 'status-bad'}">{accept_accuracy:.1f}%</td>
            </tr>
        </table>

        <h2>📊 Three-Phase Traffic Pattern</h2>

        <div class="alert alert-info">
            <strong>ℹ️ Test Methodology:</strong><br>
            • <strong>Phase 1 - Baseline:</strong> Normal traffic from whitelist IP to establish baseline<br>
            • <strong>Phase 2 - Legitimate Spike:</strong> High traffic from whitelist IP to test false positive detection<br>
            • <strong>Phase 3 - Attack Spike:</strong> Traffic from random IPs to simulate distributed attack
        </div>

        <div class="chart-container">
            <h3>Detection Accuracy Breakdown</h3>
            <div id="accuracyBarChart"></div>
        </div>

        <h2>🔍 Scenario 4.3.1 - Đánh Giá Chi Tiết</h2>

        <h3>1. Khả Năng Phát Hiện Lưu Lượng</h3>

        <table>
            <tr>
                <th>Chỉ Số</th>
                <th>Giá Trị</th>
                <th>Đánh Giá</th>
            </tr>
            <tr>
                <td><strong>Detection Latency</strong><br><small>Thời gian từ attack start → first DROP detection</small></td>
                <td>{result.get('detection_latency_ms', 0):.2f} ms</td>
                <td class="{'status-good' if result.get('detection_latency_ms', 0) < 100 else 'status-warning' if result.get('detection_latency_ms', 0) < 500 else 'status-bad'}">
                    {'✓ Excellent' if result.get('detection_latency_ms', 0) < 100 else '✓ Good' if result.get('detection_latency_ms', 0) < 500 else '⚠ Needs Improvement'}
                </td>
            </tr>
            <tr>
                <td><strong>Spike False Positive</strong><br><small>Hệ thống có flag nhầm legitimate spike không?</small></td>
                <td>{'YES ✗' if result.get('spike_false_positive', False) else 'NO ✓'}</td>
                <td class="{'status-bad' if result.get('spike_false_positive', False) else 'status-good'}">
                    {'❌ FAILED' if result.get('spike_false_positive', False) else '✓ PASSED'}
                </td>
            </tr>
        </table>

        <h3>2. Khả Năng Ghi Nhận và Truy Vết Packet Drop</h3>

        <table>
            <tr>
                <th>Chỉ Số</th>
                <th>Giá Trị</th>
                <th>Đánh Giá</th>
            </tr>
            <tr>
                <td><strong>DROP Record Completeness</strong><br><small>% records có đủ: src_ip, dst_ip, ports, comm</small></td>
                <td>{result.get('drop_record_completeness', 0):.2f}%</td>
                <td class="{'status-good' if result.get('drop_record_completeness', 0) == 100 else 'status-warning' if result.get('drop_record_completeness', 0) >= 90 else 'status-bad'}">
                    {'✓ Excellent' if result.get('drop_record_completeness', 0) == 100 else '✓ Good' if result.get('drop_record_completeness', 0) >= 90 else '⚠ Needs Improvement'}
                </td>
            </tr>
            <tr>
                <td><strong>Unique Source IPs Tracked</strong><br><small>Khả năng track nhiều nguồn tấn công</small></td>
                <td>{result.get('unique_source_ips', 0)} IPs</td>
                <td class="status-good">✓ Tracked</td>
            </tr>
        </table>

        <h2>⚡ Performance Metrics</h2>

        <div class="chart-container">
            <h3>Resource Usage</h3>
            <div id="performanceChart"></div>
        </div>

        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>CPU Usage (Average)</td>
                <td>{result.get('cpu_usage_avg', 0):.2f}%</td>
            </tr>
            <tr>
                <td>CPU Usage (Maximum)</td>
                <td>{result.get('cpu_usage_max', 0):.2f}%</td>
            </tr>
            <tr>
                <td>Execution Time</td>
                <td>{result.get('execution_time_sec', 0):.2f} seconds</td>
            </tr>
        </table>

        <h2>🔬 Nftables Counter Comparison</h2>

        <table>
            <tr>
                <th>Counter Type</th>
                <th>Nftables Value</th>
                <th>NFT Tracer Detected</th>
                <th>Match Rate</th>
            </tr>
            <tr>
                <td>ACCEPT Counter</td>
                <td>{result.get('nftables_counter_accept', 0)}</td>
                <td>{result.get('accepts_detected', 0)}</td>
                <td>{(result.get('accepts_detected', 0) / result.get('nftables_counter_accept', 1) * 100) if result.get('nftables_counter_accept', 0) > 0 else 0:.1f}%</td>
            </tr>
            <tr>
                <td>DROP Counter</td>
                <td>{result.get('nftables_counter_drop', 0)}</td>
                <td>{result.get('drops_detected', 0)}</td>
                <td>{(result.get('drops_detected', 0) / result.get('nftables_counter_drop', 1) * 100) if result.get('nftables_counter_drop', 0) > 0 else 0:.1f}%</td>
            </tr>
        </table>

        <h2>📋 Verdict Breakdown</h2>

        <table>
            <tr>
                <th>Verdict</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""

        # Add verdict breakdown rows
        total_verdicts = sum(verdict_breakdown.values()) if verdict_breakdown else 1
        for verdict, count in verdict_breakdown.items():
            percentage = (count / total_verdicts * 100) if total_verdicts > 0 else 0
            html_content += f"""            <tr>
                <td><strong>{verdict}</strong></td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""

        html_content += f"""        </table>

        <h2>💡 Key Findings & Recommendations</h2>

        <div class="alert alert-success">
            <strong>✓ Strengths:</strong><br>
"""

        # Add strengths
        if drop_accuracy >= 90:
            html_content += "            • Excellent DROP detection accuracy (>90%)<br>\n"
        if not result.get('spike_false_positive', False):
            html_content += "            • No false positives - correctly identified legitimate traffic spike<br>\n"
        if result.get('drop_record_completeness', 0) >= 90:
            html_content += "            • High-quality DROP records with complete information<br>\n"
        if result.get('detection_latency_ms', 999999) < 100:
            html_content += "            • Very fast detection latency (<100ms)<br>\n"

        html_content += """        </div>

"""

        # Add warnings if needed
        warnings = []
        if drop_accuracy < 70:
            warnings.append("DROP detection accuracy is below 70% - investigate missed detections")
        if result.get('spike_false_positive', False):
            warnings.append("False positive detected - system flagged legitimate spike as anomaly")
        if result.get('drop_record_completeness', 0) < 90:
            warnings.append("DROP record completeness below 90% - some events missing required fields")
        if result.get('cpu_usage_avg', 0) > 80:
            warnings.append("High CPU usage (>80%) - consider optimization")

        if warnings:
            html_content += """        <div class="alert alert-warning">
            <strong>⚠️ Areas for Improvement:</strong><br>
"""
            for warning in warnings:
                html_content += f"            • {warning}<br>\n"
            html_content += """        </div>

"""

        # Extract values for JavaScript (to avoid f-string nested braces issues)
        overall_acc = result.get('detection_accuracy', 0)
        cpu_avg = result.get('cpu_usage_avg', 0)
        cpu_max = result.get('cpu_usage_max', 0)

        html_content += f"""        <div class="alert alert-info">
            <strong>📊 Recommendations:</strong><br>
            • Use this data to establish baseline performance metrics<br>
            • Monitor detection latency trends over time<br>
            • Review DROP events with incomplete records to improve data collection<br>
            • Set up alerts for false positive rate above threshold<br>
            • Compare results across different test scenarios
        </div>

        <div class="footer">
            <p>Generated by NFT Tracer Test Suite | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Data source: {analysis.get('source', 'unknown')}</p>
        </div>
    </div>

    <script>
"""

        # Add JavaScript separately to avoid f-string brace issues
        html_content += """        // Verdict Pie Chart
        var verdictData = [{
            values: """ + json.dumps(list(verdict_breakdown.values())) + """,
            labels: """ + json.dumps(list(verdict_breakdown.keys())) + """,
            type: 'pie',
            marker: {
                colors: ['#e74c3c', '#27ae60', '#3498db', '#f39c12', '#9b59b6']
            },
            textinfo: 'label+percent',
            textposition: 'outside',
            automargin: true
        }];

        var verdictLayout = {
            height: 400,
            showlegend: true,
            legend: {
                orientation: 'h',
                y: -0.2
            }
        };

        Plotly.newPlot('verdictPieChart', verdictData, verdictLayout, {responsive: true});

        // Accuracy Bar Chart
        var accuracyData = [{
            x: ['Drop Detection', 'Accept Detection', 'Overall'],
            y: [""" + f"{drop_accuracy:.2f}, {accept_accuracy:.2f}, {overall_acc:.2f}" + """],
            type: 'bar',
            marker: {
                color: ['#e74c3c', '#27ae60', '#3498db']
            },
            text: ['""" + f"{drop_accuracy:.1f}%', '{accept_accuracy:.1f}%', '{overall_acc:.1f}%" + """'],
            textposition: 'outside'
        }];

        var accuracyLayout = {
            yaxis: {
                title: 'Accuracy (%)',
                range: [0, 105]
            },
            height: 400
        };

        Plotly.newPlot('accuracyBarChart', accuracyData, accuracyLayout, {responsive: true});

        // Performance Chart
        var performanceData = [{
            x: ['CPU Avg', 'CPU Max'],
            y: [""" + f"{cpu_avg:.2f}, {cpu_max:.2f}" + """],
            type: 'bar',
            marker: {
                color: ['#667eea', '#764ba2']
            },
            text: ['""" + f"{cpu_avg:.1f}%', '{cpu_max:.1f}%" + """'],
            textposition: 'outside'
        }];

        var performanceLayout = {
            yaxis: {
                title: 'CPU Usage (%)',
                range: [0, 105]
            },
            height: 400
        };

        Plotly.newPlot('performanceChart', performanceData, performanceLayout, {responsive: true});
    </script>
</body>
</html>
"""

        # Write HTML file
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"  ✓ HTML report generated: {html_path}")
        return html_path

    def generate_markdown_summary(
        self,
        results: List[Any],
        config: Dict,
        scenario_name: str,
        filename: str
    ):
        """Generate Markdown summary for documentation

        Args:
            results: List of TestResult objects
            config: Test configuration
            scenario_name: Name of the scenario
            filename: Output filename
        """
        md_path = os.path.join(self.results_dir, filename)

        # Convert to dicts
        result_dicts = [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in results]
        result = result_dicts[0] if result_dicts else {}

        # Calculate metrics
        drop_accuracy = 0.0
        accept_accuracy = 0.0

        if result.get('drops_expected', 0) > 0:
            drop_accuracy = (result.get('drops_detected', 0) / result['drops_expected']) * 100.0

        if result.get('accepts_expected', 0) > 0:
            accept_accuracy = (result.get('accepts_detected', 0) / result['accepts_expected']) * 100.0

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(f"# {scenario_name}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Test Duration:** {result.get('execution_time_sec', 0):.2f}s\n\n")

            f.write("## Executive Summary\n\n")
            f.write(f"- **Detection Accuracy:** {result.get('detection_accuracy', 0):.2f}%\n")
            f.write(f"- **Detection Latency:** {result.get('detection_latency_ms', 0):.2f}ms\n")
            f.write(f"- **False Positives:** {'YES ❌' if result.get('spike_false_positive', False) else 'NO ✓'}\n")
            f.write(f"- **DROP Record Completeness:** {result.get('drop_record_completeness', 0):.2f}%\n\n")

            f.write("## Test Configuration\n\n")
            f.write(f"| Parameter | Value |\n")
            f.write(f"|-----------|-------|\n")
            for key, value in config.items():
                f.write(f"| {key} | `{value}` |\n")
            f.write("\n")

            f.write("## Traffic Summary\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Total Packets Sent | {result.get('packets_sent', 0)} |\n")
            f.write(f"| Packets Detected | {result.get('packets_detected', 0)} |\n")
            f.write(f"| Drops Expected | {result.get('drops_expected', 0)} |\n")
            f.write(f"| Drops Detected | {result.get('drops_detected', 0)} |\n")
            f.write(f"| Drop Accuracy | {drop_accuracy:.2f}% |\n")
            f.write(f"| Accepts Expected | {result.get('accepts_expected', 0)} |\n")
            f.write(f"| Accepts Detected | {result.get('accepts_detected', 0)} |\n")
            f.write(f"| Accept Accuracy | {accept_accuracy:.2f}% |\n")
            f.write(f"| Unique Source IPs | {result.get('unique_source_ips', 0)} |\n\n")

            f.write("## Scenario 4.3.1 - Đánh Giá Chi Tiết\n\n")
            f.write("### 1. Khả Năng Phát Hiện Lưu Lượng\n\n")
            f.write(f"**Detection Latency:** {result.get('detection_latency_ms', 0):.2f}ms  \n")
            latency = result.get('detection_latency_ms', 0)
            if latency < 100:
                f.write("✓ **Đánh giá:** Excellent (<100ms)\n\n")
            elif latency < 500:
                f.write("✓ **Đánh giá:** Good (<500ms)\n\n")
            else:
                f.write("⚠ **Đánh giá:** Needs Improvement\n\n")

            f.write(f"**False Positive Detection:** {'YES ❌' if result.get('spike_false_positive', False) else 'NO ✓'}  \n")
            if result.get('spike_false_positive', False):
                f.write("❌ **Đánh giá:** FAILED - System flagged legitimate traffic as anomaly\n\n")
            else:
                f.write("✓ **Đánh giá:** PASSED - No false positives\n\n")

            f.write("### 2. Khả Năng Ghi Nhận và Truy Vết Packet Drop\n\n")
            f.write(f"**DROP Record Completeness:** {result.get('drop_record_completeness', 0):.2f}%  \n")
            completeness = result.get('drop_record_completeness', 0)
            if completeness == 100:
                f.write("✓ **Đánh giá:** Excellent (100%)\n\n")
            elif completeness >= 90:
                f.write("✓ **Đánh giá:** Good (>90%)\n\n")
            else:
                f.write("⚠ **Đánh giá:** Needs Improvement (<90%)\n\n")

            f.write("## Performance Metrics\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| CPU Usage (Avg) | {result.get('cpu_usage_avg', 0):.2f}% |\n")
            f.write(f"| CPU Usage (Max) | {result.get('cpu_usage_max', 0):.2f}% |\n")
            f.write(f"| Execution Time | {result.get('execution_time_sec', 0):.2f}s |\n\n")

            f.write("## Verdict Breakdown\n\n")
            verdict_breakdown = result.get('verdict_breakdown', {})
            if verdict_breakdown:
                f.write(f"| Verdict | Count |\n")
                f.write(f"|---------|-------|\n")
                for verdict, count in verdict_breakdown.items():
                    f.write(f"| {verdict} | {count} |\n")
            f.write("\n")

            f.write("## Key Findings\n\n")
            if drop_accuracy >= 90:
                f.write("- ✓ Excellent DROP detection accuracy\n")
            if not result.get('spike_false_positive', False):
                f.write("- ✓ No false positives detected\n")
            if result.get('drop_record_completeness', 0) >= 90:
                f.write("- ✓ High-quality DROP records\n")
            if result.get('detection_latency_ms', 999999) < 100:
                f.write("- ✓ Very fast detection latency\n")

            f.write("\n")

        print(f"  ✓ Markdown summary generated: {md_path}")
        return md_path

    def generate_statistics_table_csv(self, results: List[Any], filename: str):
        """Generate detailed statistics table in CSV format

        Args:
            results: List of TestResult objects
            filename: Output filename
        """
        csv_path = os.path.join(self.results_dir, filename)

        result_dicts = [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in results]

        if not result_dicts:
            return None

        result = result_dicts[0]

        # Calculate additional statistics
        statistics = []

        # Add detection metrics
        statistics.append({
            'Category': 'Detection',
            'Metric': 'Detection Accuracy',
            'Value': f"{result.get('detection_accuracy', 0):.2f}%",
            'Description': 'Overall detection accuracy'
        })

        statistics.append({
            'Category': 'Detection',
            'Metric': 'Detection Latency',
            'Value': f"{result.get('detection_latency_ms', 0):.2f}ms",
            'Description': 'Time from attack start to first DROP detection'
        })

        statistics.append({
            'Category': 'Detection',
            'Metric': 'False Positive',
            'Value': 'YES' if result.get('spike_false_positive', False) else 'NO',
            'Description': 'Legitimate traffic flagged as anomaly'
        })

        # Add DROP quality metrics
        statistics.append({
            'Category': 'Data Quality',
            'Metric': 'DROP Record Completeness',
            'Value': f"{result.get('drop_record_completeness', 0):.2f}%",
            'Description': 'Records with complete information'
        })

        # Add traffic metrics
        statistics.append({
            'Category': 'Traffic',
            'Metric': 'Total Packets Sent',
            'Value': result.get('packets_sent', 0),
            'Description': 'Total packets transmitted'
        })

        statistics.append({
            'Category': 'Traffic',
            'Metric': 'Packets Detected',
            'Value': result.get('packets_detected', 0),
            'Description': 'Packets successfully detected'
        })

        statistics.append({
            'Category': 'Traffic',
            'Metric': 'Unique Source IPs',
            'Value': result.get('unique_source_ips', 0),
            'Description': 'Number of distinct source IPs'
        })

        # Add DROP/ACCEPT metrics
        drop_accuracy = 0.0
        if result.get('drops_expected', 0) > 0:
            drop_accuracy = (result.get('drops_detected', 0) / result['drops_expected']) * 100.0

        statistics.append({
            'Category': 'Firewall',
            'Metric': 'DROP Detection Rate',
            'Value': f"{drop_accuracy:.2f}%",
            'Description': f"{result.get('drops_detected', 0)} / {result.get('drops_expected', 0)} expected"
        })

        accept_accuracy = 0.0
        if result.get('accepts_expected', 0) > 0:
            accept_accuracy = (result.get('accepts_detected', 0) / result['accepts_expected']) * 100.0

        statistics.append({
            'Category': 'Firewall',
            'Metric': 'ACCEPT Detection Rate',
            'Value': f"{accept_accuracy:.2f}%",
            'Description': f"{result.get('accepts_detected', 0)} / {result.get('accepts_expected', 0)} expected"
        })

        # Add nftables comparison
        statistics.append({
            'Category': 'Validation',
            'Metric': 'Nftables DROP Counter',
            'Value': result.get('nftables_counter_drop', 0),
            'Description': 'Nftables-reported DROP count'
        })

        statistics.append({
            'Category': 'Validation',
            'Metric': 'Nftables ACCEPT Counter',
            'Value': result.get('nftables_counter_accept', 0),
            'Description': 'Nftables-reported ACCEPT count'
        })

        # Add performance metrics
        statistics.append({
            'Category': 'Performance',
            'Metric': 'CPU Usage (Avg)',
            'Value': f"{result.get('cpu_usage_avg', 0):.2f}%",
            'Description': 'Average CPU utilization'
        })

        statistics.append({
            'Category': 'Performance',
            'Metric': 'CPU Usage (Max)',
            'Value': f"{result.get('cpu_usage_max', 0):.2f}%",
            'Description': 'Peak CPU utilization'
        })

        statistics.append({
            'Category': 'Performance',
            'Metric': 'Execution Time',
            'Value': f"{result.get('execution_time_sec', 0):.2f}s",
            'Description': 'Total test duration'
        })

        # Write CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['Category', 'Metric', 'Value', 'Description']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(statistics)

        print(f"  ✓ Statistics table CSV generated: {csv_path}")
        return csv_path
