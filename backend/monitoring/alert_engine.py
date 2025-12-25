"""
Alert Engine for NFT Tracer Monitoring
Detects anomalies and threshold violations in network metrics
"""

import time
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from collections import deque
import logging

logger = logging.getLogger(__name__)


@dataclass
class AlertRule:
    """Alert rule definition"""
    name: str
    description: str
    metric: str  # Metric to monitor
    condition: str  # 'gt', 'lt', 'gte', 'lte', 'eq'
    threshold: float
    duration: int = 0  # Seconds the condition must be true (0 = instant)
    enabled: bool = True
    severity: str = 'warning'  # 'info', 'warning', 'error', 'critical'


@dataclass
class Alert:
    """Active alert instance"""
    id: str
    rule_name: str
    severity: str
    message: str
    value: float
    threshold: float
    timestamp: int
    resolved: bool = False
    resolved_at: Optional[int] = None

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class AlertEngine:
    """
    Alert engine for monitoring and detecting anomalies

    Features:
    - Threshold-based alerts
    - Configurable alert rules
    - Alert history
    - Callbacks for notifications
    """

    def __init__(self, max_history: int = 100):
        """
        Initialize alert engine

        Args:
            max_history: Maximum number of alerts to keep in history
        """
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=max_history)

        # State tracking for duration-based alerts
        self.violation_start_times: Dict[str, int] = {}

        # Callbacks
        self.alert_callbacks: List[Callable[[Alert], None]] = []

        # Lock for thread safety
        self.lock = threading.RLock()

        # Define default rules
        self._setup_default_rules()

        logger.info("AlertEngine initialized")

    def _setup_default_rules(self):
        """Setup default alert rules"""
        default_rules = [
            AlertRule(
                name='high_drop_rate',
                description='Packet drop rate exceeded threshold',
                metric='drop_rate',
                condition='gt',
                threshold=5.0,  # > 5%
                duration=10,  # For 10 seconds
                severity='warning'
            ),
            AlertRule(
                name='critical_drop_rate',
                description='Critical packet drop rate',
                metric='drop_rate',
                condition='gt',
                threshold=20.0,  # > 20%
                duration=5,
                severity='error'
            ),
            AlertRule(
                name='high_latency',
                description='High packet processing latency detected',
                metric='latency_p99',
                condition='gt',
                threshold=1000.0,  # > 1000 μs = 1ms
                duration=30,
                severity='warning'
            ),
            AlertRule(
                name='critical_latency',
                description='Critical latency spike',
                metric='latency_p99',
                condition='gt',
                threshold=5000.0,  # > 5ms
                duration=10,
                severity='error'
            ),
            AlertRule(
                name='low_packet_rate',
                description='Packet rate dropped unexpectedly',
                metric='packets_per_second',
                condition='lt',
                threshold=1.0,  # < 1 pps
                duration=60,
                severity='info'
            ),
            AlertRule(
                name='high_error_count',
                description='High error count detected',
                metric='error_count',
                condition='gt',
                threshold=10,
                duration=30,
                severity='warning'
            ),
        ]

        for rule in default_rules:
            self.add_rule(rule)

    def add_rule(self, rule: AlertRule):
        """Add or update an alert rule"""
        with self.lock:
            self.rules[rule.name] = rule
            logger.info(f"Alert rule added: {rule.name}")

    def remove_rule(self, rule_name: str):
        """Remove an alert rule"""
        with self.lock:
            if rule_name in self.rules:
                del self.rules[rule_name]
                logger.info(f"Alert rule removed: {rule_name}")

    def enable_rule(self, rule_name: str):
        """Enable an alert rule"""
        with self.lock:
            if rule_name in self.rules:
                self.rules[rule_name].enabled = True

    def disable_rule(self, rule_name: str):
        """Disable an alert rule"""
        with self.lock:
            if rule_name in self.rules:
                self.rules[rule_name].enabled = False

    def register_callback(self, callback: Callable[[Alert], None]):
        """Register a callback for alert notifications"""
        self.alert_callbacks.append(callback)

    def check_metrics(self, metrics: Dict):
        """
        Check metrics against all alert rules

        Args:
            metrics: Dictionary containing current metrics
        """
        with self.lock:
            current_time = int(time.time())

            # Extract relevant metrics
            metric_values = self._extract_metrics(metrics)

            # Check each rule
            for rule_name, rule in self.rules.items():
                if not rule.enabled:
                    continue

                # Get metric value
                value = metric_values.get(rule.metric)
                if value is None:
                    continue

                # Check condition
                is_violated = self._check_condition(value, rule.condition, rule.threshold)

                if is_violated:
                    self._handle_violation(rule, value, current_time)
                else:
                    self._handle_resolution(rule_name, current_time)

    def _extract_metrics(self, metrics: Dict) -> Dict[str, float]:
        """Extract metric values from stats dictionary"""
        result = {}

        # Total packets
        result['total_packets'] = metrics.get('total_packets', 0)

        # Packets per second
        result['packets_per_second'] = metrics.get('packets_per_second', 0)

        # Calculate drop rate
        total_verdicts = metrics.get('total_verdicts', {})
        total_drops = total_verdicts.get('DROP', 0)
        total_packets = result['total_packets']
        result['drop_rate'] = (total_drops / total_packets * 100) if total_packets > 0 else 0
        result['total_drops'] = total_drops

        # Latency metrics
        top_latency = metrics.get('top_latency', [])
        if top_latency:
            latencies = [node.get('avg_latency_us', 0) for node in top_latency]
            result['latency_avg'] = sum(latencies) / len(latencies) if latencies else 0
            result['latency_p99'] = max(latencies) if latencies else 0
        else:
            result['latency_avg'] = 0
            result['latency_p99'] = 0

        # Error count
        nodes = metrics.get('nodes', {})
        total_errors = sum(node.get('error_count', 0) for node in nodes.values())
        result['error_count'] = total_errors

        # Active flows (estimate)
        result['active_flows'] = len(metrics.get('active_skbs', set()))

        return result

    def _check_condition(self, value: float, condition: str, threshold: float) -> bool:
        """Check if a condition is met"""
        if condition == 'gt':
            return value > threshold
        elif condition == 'gte':
            return value >= threshold
        elif condition == 'lt':
            return value < threshold
        elif condition == 'lte':
            return value <= threshold
        elif condition == 'eq':
            return value == threshold
        return False

    def _handle_violation(self, rule: AlertRule, value: float, current_time: int):
        """Handle a rule violation"""
        rule_name = rule.name

        # Check if duration requirement is met
        if rule.duration > 0:
            # Track when violation started
            if rule_name not in self.violation_start_times:
                self.violation_start_times[rule_name] = current_time
                return  # Not yet violated long enough

            # Check if violated for required duration
            violation_duration = current_time - self.violation_start_times[rule_name]
            if violation_duration < rule.duration:
                return  # Not yet violated long enough

        # Check if alert already exists
        if rule_name in self.active_alerts:
            # Update existing alert value
            self.active_alerts[rule_name].value = value
            return

        # Create new alert
        alert = Alert(
            id=f"{rule_name}_{current_time}",
            rule_name=rule_name,
            severity=rule.severity,
            message=f"{rule.description}: {value:.2f} (threshold: {rule.threshold:.2f})",
            value=value,
            threshold=rule.threshold,
            timestamp=current_time
        )

        # Store alert
        self.active_alerts[rule_name] = alert
        self.alert_history.append(alert)

        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}", exc_info=True)

        logger.warning(f"ALERT: {alert.message}")

    def _handle_resolution(self, rule_name: str, current_time: int):
        """Handle alert resolution"""
        # Clear violation start time
        if rule_name in self.violation_start_times:
            del self.violation_start_times[rule_name]

        # Resolve active alert if exists
        if rule_name in self.active_alerts:
            alert = self.active_alerts[rule_name]
            alert.resolved = True
            alert.resolved_at = current_time
            del self.active_alerts[rule_name]

            logger.info(f"RESOLVED: {alert.message}")

    def get_active_alerts(self) -> List[Dict]:
        """Get all active alerts"""
        with self.lock:
            return [alert.to_dict() for alert in self.active_alerts.values()]

    def get_alert_history(self, limit: int = 50) -> List[Dict]:
        """Get alert history"""
        with self.lock:
            history = list(self.alert_history)
            history.reverse()  # Most recent first
            return [alert.to_dict() for alert in history[:limit]]

    def get_rules(self) -> List[Dict]:
        """Get all alert rules"""
        with self.lock:
            return [asdict(rule) for rule in self.rules.values()]

    def clear_alerts(self):
        """Clear all active alerts"""
        with self.lock:
            self.active_alerts.clear()
            self.violation_start_times.clear()
            logger.info("All alerts cleared")

    def get_stats(self) -> Dict:
        """Get alert engine statistics"""
        with self.lock:
            return {
                'total_rules': len(self.rules),
                'active_alerts': len(self.active_alerts),
                'total_alerts_raised': len(self.alert_history),
                'rules_enabled': sum(1 for r in self.rules.values() if r.enabled)
            }
