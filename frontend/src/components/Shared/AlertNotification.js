import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import './AlertNotification.css';

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

const AlertNotification = ({ enabled }) => {
  const [alerts, setAlerts] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [socket, setSocket] = useState(null);

  // Connect to WebSocket for real-time alerts
  useEffect(() => {
    if (!enabled) {
      if (socket) {
        socket.disconnect();
        setSocket(null);
      }
      setAlerts([]);
      return;
    }

    const newSocket = io(SOCKET_URL);

    newSocket.on('connect', () => {
      console.log('[Alert] WebSocket connected');
    });

    newSocket.on('alert', (alert) => {
      console.log('[Alert] Received:', alert);
      addAlert(alert);
    });

    newSocket.on('disconnect', () => {
      console.log('[Alert] WebSocket disconnected');
    });

    setSocket(newSocket);

    // Fetch initial alerts
    fetchAlerts();
    fetchAlertHistory();

    return () => {
      newSocket.disconnect();
    };
  }, [enabled]);

  // Fetch active alerts
  const fetchAlerts = async () => {
    try {
      const response = await axios.get('/api/monitoring/alerts');
      if (Array.isArray(response.data)) {
        setAlerts(response.data);
      }
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  // Fetch alert history
  const fetchAlertHistory = async () => {
    try {
      const response = await axios.get('/api/monitoring/alerts/history');
      if (Array.isArray(response.data)) {
        setAlertHistory(response.data);
      }
    } catch (error) {
      console.error('Failed to fetch alert history:', error);
    }
  };

  // Add new alert
  const addAlert = (alert) => {
    setAlerts((prev) => {
      // Check if alert already exists
      const exists = prev.some((a) => a.id === alert.id);
      if (exists) {
        return prev;
      }
      return [...prev, alert];
    });

    // Add to history
    setAlertHistory((prev) => [alert, ...prev].slice(0, 50));

    // Auto-dismiss after 10 seconds for non-critical alerts
    if (alert.severity !== 'critical' && alert.severity !== 'error') {
      setTimeout(() => {
        dismissAlert(alert.id);
      }, 10000);
    }
  };

  // Dismiss alert
  const dismissAlert = (alertId) => {
    setAlerts((prev) => prev.filter((a) => a.id !== alertId));
  };

  // Clear all alerts
  const clearAllAlerts = async () => {
    try {
      await axios.post('/api/monitoring/alerts/clear');
      setAlerts([]);
    } catch (error) {
      console.error('Failed to clear alerts:', error);
    }
  };

  // Get severity icon and color
  const getSeverityStyle = (severity) => {
    const styles = {
      info: { icon: 'ℹ️', color: '#2196F3', bg: '#E3F2FD' },
      warning: { icon: '⚠️', color: '#FF9800', bg: '#FFF3E0' },
      error: { icon: '❌', color: '#f44336', bg: '#FFEBEE' },
      critical: { icon: '🚨', color: '#D32F2F', bg: '#FFCDD2' }
    };
    return styles[severity] || styles.info;
  };

  // Format timestamp
  const formatTime = (timestamp) => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString();
  };

  if (!enabled) {
    return null;
  }

  return (
    <div className="alert-notification-container">
      {/* Active Alerts */}
      <div className="alert-notifications">
        {alerts.map((alert) => {
          const style = getSeverityStyle(alert.severity);
          return (
            <div
              key={alert.id}
              className={`alert-notification ${alert.severity}`}
              style={{
                borderLeftColor: style.color,
                backgroundColor: style.bg
              }}
            >
              <div className="alert-icon">{style.icon}</div>
              <div className="alert-content">
                <div className="alert-message" style={{ color: style.color }}>
                  {alert.message}
                </div>
                <div className="alert-time">{formatTime(alert.timestamp)}</div>
              </div>
              <button
                className="alert-dismiss"
                onClick={() => dismissAlert(alert.id)}
              >
                ×
              </button>
            </div>
          );
        })}
      </div>

      {/* Alert Bell Icon (always visible when enabled) */}
      <div className="alert-bell-container">
        <button
          className={`alert-bell ${alerts.length > 0 ? 'has-alerts' : ''}`}
          onClick={() => setShowHistory(!showHistory)}
          title="Alert History"
        >
          🔔
          {alerts.length > 0 && (
            <span className="alert-badge">{alerts.length}</span>
          )}
        </button>

        {/* Alert History Panel */}
        {showHistory && (
          <div className="alert-history-panel">
            <div className="alert-history-header">
              <h4>Alert History</h4>
              <button
                className="clear-all-btn"
                onClick={clearAllAlerts}
                disabled={alerts.length === 0}
              >
                Clear All
              </button>
            </div>
            <div className="alert-history-list">
              {alertHistory.length === 0 ? (
                <div className="no-alerts">No alerts yet</div>
              ) : (
                alertHistory.map((alert) => {
                  const style = getSeverityStyle(alert.severity);
                  return (
                    <div
                      key={alert.id}
                      className={`alert-history-item ${alert.resolved ? 'resolved' : ''}`}
                    >
                      <div className="alert-history-icon">{style.icon}</div>
                      <div className="alert-history-content">
                        <div
                          className="alert-history-message"
                          style={{ color: style.color }}
                        >
                          {alert.message}
                        </div>
                        <div className="alert-history-time">
                          {formatTime(alert.timestamp)}
                          {alert.resolved && (
                            <span className="resolved-tag">✓ Resolved</span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertNotification;
