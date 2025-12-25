import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import './Realtime.css';
import PipelineNode from '../components/Pipeline/PipelineNode';
import AlertNotification from '../components/Shared/AlertNotification';
import PacketVolumeChart from '../components/Metrics/PacketVolumeChart';
import VerdictTimeSeriesChart from '../components/Metrics/VerdictTimeSeriesChart';
import { PIPELINE_DEFINITIONS } from '../constants/pipeline';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

// Global socket instance - persistent across component mount/unmount
let globalSocket = null;

function getDropRateColor(dropRate) {
  if (dropRate <= 1) {
    return { bg: 'rgba(40, 167, 69, 0.1)', border: '#28a745', text: '#28a745' };
  } else if (dropRate <= 3) {
    return { bg: 'rgba(255, 193, 7, 0.1)', border: '#ffc107', text: '#f0ad4e' };
  } else {
    return { bg: 'rgba(220, 53, 69, 0.1)', border: '#dc3545', text: '#dc3545' };
  }
}

function RealtimeView({ initialFilter = null, autoEnable = false }) {
  const [enabled, setEnabled] = useState(false);
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [traceFilter, setTraceFilter] = useState({
    src_ip: '',
    dst_ip: '',
    src_port: '',
    dst_port: '',
    protocol: '',
    comm: ''
  });

  const autoEnableProcessed = useRef(false);

  useEffect(() => {
    // Reuse existing global socket or create new one
    if (!globalSocket) {
      console.log('[Realtime] Creating new global WebSocket connection');
      globalSocket = io(SOCKET_URL, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
      });

      globalSocket.on('connect', () => {
        console.log('[Realtime] Connected to WebSocket');
        setConnected(true);
        loadStats();
      });

      globalSocket.on('disconnect', () => {
        console.log('[Realtime] Disconnected from WebSocket');
        setConnected(false);
      });

      globalSocket.on('stats_update', (stats) => {
        // console.log('[Realtime] Received stats_update:', stats);
        setStats(stats);
      });

      globalSocket.on('status', (status) => {
        setEnabled(status.enabled);
      });
    } else {
      console.log('[Realtime] Reusing existing global WebSocket connection');
      // Check current connection state
      if (globalSocket.connected) {
        setConnected(true);
        loadStats();
      }
    }

    // DON'T disconnect on unmount - keep socket alive for background tracing
    // Socket will only disconnect when browser closes or realtime is disabled
    return () => {
      console.log('[Realtime] Component unmounting but keeping WebSocket connected for background tracing');
    };
  }, []);

  useEffect(() => {
    if (enabled && connected) {
      const interval = setInterval(loadStats, 1000);
      return () => clearInterval(interval);
    }
  }, [enabled, connected]);

  // Handle initialFilter and autoEnable from session click
  useEffect(() => {
    if (initialFilter && !autoEnableProcessed.current) {
      console.log('[Realtime] Applying filter from session:', initialFilter);
      setTraceFilter(initialFilter);

      if (autoEnable && connected && !enabled) {
        autoEnableProcessed.current = true;
        // Auto-enable realtime with filter
        setLoading(true);
        axios.post(`${API_BASE}/realtime/enable`, {
          trace_filter: initialFilter
        })
        .then(() => {
          setEnabled(true);
          loadStats();
        })
        .catch((err) => {
          setError(err.response?.data?.error || 'Failed to enable realtime');
        })
        .finally(() => {
          setLoading(false);
        });
      }
    }
  }, [initialFilter, autoEnable, connected, enabled]);

  const loadStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/realtime/stats`);
      setStats(res.data);
      setEnabled(res.data.enabled);
    } catch (err) {
      console.error('[Realtime] Failed to load stats:', err);
    }
  };

  const toggleRealtime = async () => {
    setLoading(true);
    setError(null);

    try {
      if (enabled) {
        // Disable realtime tracing (backend stops emitting)
        await axios.post(`${API_BASE}/realtime/disable`);
        setEnabled(false);

        // Keep socket connected but idle - backend won't emit when disabled
        // This prevents race condition where socket disconnects while backend is mid-emission
        console.log('[Realtime] Disabled - socket stays connected but idle');
      } else {
        // Ensure socket is connected before enabling
        if (!globalSocket || !globalSocket.connected) {
          console.log('[Realtime] Reconnecting socket before enable');
          // Recreate socket if it was destroyed
          if (!globalSocket) {
            globalSocket = io(SOCKET_URL, {
              transports: ['websocket', 'polling'],
              reconnection: true,
              reconnectionDelay: 1000,
              reconnectionAttempts: 5
            });

            globalSocket.on('connect', () => {
              console.log('[Realtime] Connected to WebSocket');
              setConnected(true);
            });

            globalSocket.on('disconnect', () => {
              console.log('[Realtime] Disconnected from WebSocket');
              setConnected(false);
            });

            globalSocket.on('stats_update', (stats) => {
              setStats(stats);
            });

            globalSocket.on('status', (status) => {
              setEnabled(status.enabled);
            });
          } else {
            globalSocket.connect();
          }

          // Wait for connection
          await new Promise((resolve) => {
            if (globalSocket.connected) {
              resolve();
            } else {
              globalSocket.once('connect', resolve);
              setTimeout(resolve, 2000); // Timeout after 2s
            }
          });
        }

        // Send filter when enabling
        await axios.post(`${API_BASE}/realtime/enable`, {
          trace_filter: traceFilter
        });
        setEnabled(true);
      }
      await loadStats();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to toggle realtime');
    } finally {
      setLoading(false);
    }
  };

  const resetStats = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/realtime/reset`);
      await loadStats();
    } catch (err) {
      setError('Failed to reset stats');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="realtime-container">
      {/* Alert Notifications (top-right corner) */}
      <AlertNotification enabled={enabled} />
      {/* Header */}
      <div className="realtime-header">
        <div className="realtime-header-left">
          <h2>🔄 Realtime Packet Tracer</h2>
          <div className="connection-status">
            <div className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></div>
            <span>{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
        <div className="realtime-header-right">
          <button
            className={`realtime-btn ${enabled ? 'danger' : 'primary'}`}
            onClick={toggleRealtime}
            disabled={loading}
          >
            {loading ? '⏳' : enabled ? '⏸️ Disable' : '▶️ Enable'}
          </button>
          <button
            className="realtime-btn secondary"
            onClick={resetStats}
            disabled={loading || !enabled}
          >
            🔄 Reset
          </button>
        </div>
      </div>

      {error && (
        <div className="realtime-error">
          <span>{error}</span>
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Filter Form (only shown when disabled) */}
      {!enabled && (
        <div className="realtime-panel" style={{marginBottom: '1.5rem'}}>
          <h3 style={{marginBottom: '1rem', color: '#4CAF50'}}>🎯 Trace Filter (Optional)</h3>
          <p style={{fontSize: '0.9rem', color: '#666', marginBottom: '1rem'}}>
            Filter traffic before tracing. Leave empty to trace all packets.
          </p>
          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem'}}>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Source IP</label>
              <input
                type="text"
                placeholder="e.g., 192.168.1.100"
                value={traceFilter.src_ip}
                onChange={(e) => setTraceFilter({...traceFilter, src_ip: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              />
            </div>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Dest IP</label>
              <input
                type="text"
                placeholder="e.g., 10.0.0.1"
                value={traceFilter.dst_ip}
                onChange={(e) => setTraceFilter({...traceFilter, dst_ip: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              />
            </div>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Source Port</label>
              <input
                type="number"
                placeholder="e.g., 12345"
                value={traceFilter.src_port}
                onChange={(e) => setTraceFilter({...traceFilter, src_port: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              />
            </div>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Dest Port</label>
              <input
                type="number"
                placeholder="e.g., 80"
                value={traceFilter.dst_port}
                onChange={(e) => setTraceFilter({...traceFilter, dst_port: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              />
            </div>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Protocol</label>
              <select
                value={traceFilter.protocol}
                onChange={(e) => setTraceFilter({...traceFilter, protocol: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              >
                <option value="">All Protocols</option>
                <option value="1">ICMP</option>
                <option value="6">TCP</option>
                <option value="17">UDP</option>
                <option value="58">ICMPv6</option>
                <option value="132">SCTP</option>
              </select>
            </div>
            <div className="form-group">
              <label style={{display: 'block', marginBottom: '0.5rem', fontWeight: '500'}}>Process Name</label>
              <input
                type="text"
                placeholder="e.g., curl, nginx"
                value={traceFilter.comm}
                onChange={(e) => setTraceFilter({...traceFilter, comm: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  fontSize: '0.9rem'
                }}
              />
            </div>
          </div>
        </div>
      )}

      {!enabled ? (
        <div className="realtime-disabled-notice">
          <h3>⚙️ Realtime Tracing Disabled</h3>
          <p>Configure filter above (optional), then click "Enable" to start tracing</p>
          <p className="hint">🚀 Monitor packet flow through all netfilter hooks</p>
        </div>
      ) : (
        <>
          <div className="realtime-stats-grid">
            <div className="realtime-stat-card primary">
              <div className="stat-icon">📊</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.total_packets || 0}</div>
                <div className="stat-label">Total Packets</div>
              </div>
            </div>

            <div className="realtime-stat-card success">
              <div className="stat-icon">⚡</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.packets_per_second?.toFixed(1) || 0}</div>
                <div className="stat-label">Packets/Second</div>
              </div>
            </div>

            <div className="realtime-stat-card warning">
              <div className="stat-icon">⏱️</div>
              <div className="stat-content">
                <div className="stat-value">{stats?.uptime_seconds?.toFixed(0) || 0}s</div>
                <div className="stat-label">Uptime</div>
              </div>
            </div>

            <div className="realtime-stat-card info">
              <div className="stat-icon">🪝</div>
              <div className="stat-content">
                <div className="stat-value">{Object.keys(stats?.hooks || {}).length}</div>
                <div className="stat-label">Active Hooks</div>
              </div>
            </div>
          </div>

          {/* Filter Info Panel */}
          {stats?.filter_enabled && (
            <div className="realtime-panel" style={{
              background: 'linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%)',
              border: '2px solid #ffc107',
              marginBottom: '1.5rem'
            }}>
              <h3 style={{ color: '#856404', marginBottom: '1rem' }}>🎯 Trace Filter Active</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                {stats.trace_filter?.src_ip && (
                  <div className="filter-item">
                    <strong>Source IP:</strong>
                    <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', color: '#495057' }}>
                      {stats.trace_filter.src_ip}
                    </span>
                  </div>
                )}
                {stats.trace_filter?.dst_ip && (
                  <div className="filter-item">
                    <strong>Dest IP:</strong>
                    <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', color: '#495057' }}>
                      {stats.trace_filter.dst_ip}
                    </span>
                  </div>
                )}
                {stats.trace_filter?.src_port && (
                  <div className="filter-item">
                    <strong>Source Port:</strong>
                    <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', color: '#495057' }}>
                      {stats.trace_filter.src_port}
                    </span>
                  </div>
                )}
                {stats.trace_filter?.dst_port && (
                  <div className="filter-item">
                    <strong>Dest Port:</strong>
                    <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', color: '#495057' }}>
                      {stats.trace_filter.dst_port}
                    </span>
                  </div>
                )}
                {stats.trace_filter?.comm && (
                  <div className="filter-item">
                    <strong>Process:</strong>
                    <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', color: '#495057' }}>
                      {stats.trace_filter.comm}
                    </span>
                  </div>
                )}
              </div>
              {stats.filtered_events !== undefined && stats.filtered_events > 0 && (
                <div style={{
                  marginTop: '1rem',
                  paddingTop: '1rem',
                  borderTop: '1px solid #ffc107',
                  fontSize: '0.95rem',
                  color: '#666'
                }}>
                  <strong style={{ color: '#856404' }}>{stats.filtered_events.toLocaleString()}</strong> events filtered out
                  {stats.total_packets > 0 && (
                    <span style={{ marginLeft: '0.5rem' }}>
                      ({((stats.filtered_events / (stats.total_packets + stats.filtered_events)) * 100).toFixed(1)}% reduction)
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ENHANCED: Pipeline Statistics Panel */}
          {stats && stats.pipelines && Array.isArray(stats.pipelines) && (
            <div className="realtime-panel full-width">
              <h3>🚀 Pipeline Statistics</h3>
              <div className="pipeline-stats-grid">
                {stats.pipelines.map((pipelineData) => {
                  if (!pipelineData || pipelineData.started === 0) return null;

                  const completionRate = pipelineData.started > 0
                    ? ((pipelineData.completed / pipelineData.started) * 100).toFixed(1)
                    : 0;

                  return (
                    <div key={pipelineData.name} className="pipeline-stat-card">
                      <div className="pipeline-stat-header">{pipelineData.name}</div>
                      <div className="pipeline-stat-row">
                        <span className="pipeline-stat-label">Started:</span>
                        <span className="pipeline-stat-value success">{pipelineData.started.toLocaleString()}</span>
                      </div>
                      <div className="pipeline-stat-row">
                        <span className="pipeline-stat-label">In-Flight:</span>
                        <span className="pipeline-stat-value warning">{pipelineData.in_progress.toLocaleString()}</span>
                      </div>
                      <div className="pipeline-stat-row">
                        <span className="pipeline-stat-label">Completed:</span>
                        <span className="pipeline-stat-value primary">{pipelineData.completed.toLocaleString()}</span>
                      </div>
                      <div className="pipeline-stat-row">
                        <span className="pipeline-stat-label">Completion:</span>
                        <span className="pipeline-stat-value info">{completionRate}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ENHANCED: Netfilter Verdict Statistics Panel */}
          {stats && stats.total_verdicts && (
            <div className="realtime-panel full-width">
              <h3>⚖️ Netfilter Verdict Statistics</h3>
              <div className="verdict-stats-grid">
                {(() => {
                  // Define fixed verdict list with colors and icons (all 11 verdict types)
                  const verdictDefinitions = [
                    { name: 'ACCEPT', color: '#28a745', icon: '✓', bgColor: 'rgba(40, 167, 69, 0.1)' },
                    { name: 'DROP', color: '#dc3545', icon: '✗', bgColor: 'rgba(220, 53, 69, 0.1)' },
                    // { name: 'STOLEN', color: '#6c757d', icon: '⚡', bgColor: 'rgba(108, 117, 125, 0.1)' },
                    // { name: 'QUEUE', color: '#ffc107', icon: '⏸', bgColor: 'rgba(255, 193, 7, 0.1)' },
                    // { name: 'REPEAT', color: '#17a2b8', icon: '🔄', bgColor: 'rgba(23, 162, 184, 0.1)' },
                    // { name: 'STOP', color: '#fd7e14', icon: '⏹', bgColor: 'rgba(253, 126, 20, 0.1)' },
                    { name: 'CONTINUE', color: '#6610f2', icon: '⏩', bgColor: 'rgba(102, 16, 242, 0.1)' },
                    // { name: 'RETURN', color: '#e83e8c', icon: '↩', bgColor: 'rgba(232, 62, 140, 0.1)' },
                    { name: 'JUMP', color: '#20c997', icon: '↗', bgColor: 'rgba(32, 201, 151, 0.1)' },
                    { name: 'GOTO', color: '#fd7e14', icon: '➜', bgColor: 'rgba(253, 126, 20, 0.1)' },
                    { name: 'BREAK', color: '#6f42c1', icon: '⏸', bgColor: 'rgba(111, 66, 193, 0.1)' }
                  ];

                  const total = Object.values(stats.total_verdicts).reduce((sum, c) => sum + c, 0);

                  return verdictDefinitions.map(({ name, color, icon, bgColor }) => {
                    const count = stats.total_verdicts[name] || 0;
                    const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;

                    return (
                      <div key={name} className="verdict-stat-card" style={{ borderColor: color, backgroundColor: bgColor }}>
                        <div className="verdict-stat-icon" style={{ backgroundColor: color }}>
                          {icon}
                        </div>
                        <div className="verdict-stat-content">
                          <div className="verdict-stat-name" style={{ color }}>{name}</div>
                          <div className="verdict-stat-count">{count.toLocaleString()}</div>
                          <div className="verdict-stat-percentage">{percentage}%</div>
                        </div>
                      </div>
                    );
                  });
                })()}
              </div>
            </div>
          )}

          {/* Time-Series Metrics Charts */}
          <div style={{ marginTop: '24px' }}>
            <PacketVolumeChart />
          </div>

          <div style={{ marginTop: '24px' }}>
            <VerdictTimeSeriesChart />
          </div>

          {/* NEW: Top Latency Contributors Panel */}
          {stats && stats.top_latency && stats.top_latency.length > 0 && (
            <div className="realtime-panel full-width">
              <h3>🔥 Top Latency Contributors</h3>
              <p className="panel-subtitle">Nodes with highest average processing time - potential bottlenecks</p>
              <div className="latency-ranking-grid">
                {stats.top_latency.slice(0, 5).map((item, index) => {
                  // Color gradient from red (highest) to yellow (lowest)
                  const colors = [
                    { bg: 'rgba(220, 53, 69, 0.15)', border: '#dc3545', icon: '🔴' },  // Red
                    { bg: 'rgba(253, 126, 20, 0.15)', border: '#fd7e14', icon: '🟠' },  // Orange
                    { bg: 'rgba(255, 193, 7, 0.15)', border: '#ffc107', icon: '🟡' },   // Yellow
                    { bg: 'rgba(40, 167, 69, 0.15)', border: '#28a745', icon: '🟢' },   // Green
                    { bg: 'rgba(23, 162, 184, 0.15)', border: '#17a2b8', icon: '🔵' }   // Blue
                  ];
                  const colorScheme = colors[index] || colors[4];

                  return (
                    <div key={item.node} className="latency-rank-card" style={{
                      backgroundColor: colorScheme.bg,
                      borderColor: colorScheme.border
                    }}>
                      <div className="latency-rank-number">
                        {colorScheme.icon} #{index + 1}
                      </div>
                      <div className="latency-rank-content">
                        <div className="latency-rank-node">{item.node}</div>
                        <div className="latency-rank-stats">
                          <div className="latency-rank-stat">
                            <span className="latency-rank-label">Avg Latency:</span>
                            <span className="latency-rank-value" style={{ color: colorScheme.border }}>
                              {item.avg_latency_us.toFixed(1)} µs
                            </span>
                          </div>
                          <div className="latency-rank-stat">
                            <span className="latency-rank-label">Sample Count:</span>
                            <span className="latency-rank-value">{item.count.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ENHANCED: Pipeline Flow Visualization with Detailed Metrics */}
          {stats && stats.nodes && Object.keys(stats.nodes).length > 0 && (
            <div className="realtime-panel full-width">
              <h3>🔄 Enhanced Packet Pipeline Flow</h3>

              <div className="pipeline-flow-container">
                {(() => {
                  const inboundNodes = PIPELINE_DEFINITIONS.Inbound.mainFlow.concat(
                    ...Object.values(PIPELINE_DEFINITIONS.Inbound.branches)
                  );
                  const inboundCounts = inboundNodes.map(s => stats.nodes[s.name]?.count || 0);
                  const hasInbound = inboundCounts.some(c => c > 0);

                  if (!hasInbound) return null;

                  const maxCount = Math.max(...inboundCounts);

                  return (
                    <div className="pipeline-direction">
                      <div className="pipeline-direction-header">
                        <span className="pipeline-direction-icon">📥</span>
                        <h4>Inbound Traffic</h4>
                        <span className="pipeline-event-count">
                          {inboundCounts.reduce((sum, val) => sum + val, 0).toLocaleString()} events
                        </span>
                      </div>

                      <div className="pipeline-main-flow">
                        <div className="pipeline-stages">
                          {PIPELINE_DEFINITIONS.Inbound.mainFlow.map((stageDef, index, arr) => {
                            const nodeData = stats.nodes[stageDef.name];
                            const isActive = nodeData && nodeData.count > 0;

                            return (
                              <React.Fragment key={stageDef.name}>
                                <PipelineNode
                                  stageDef={stageDef}
                                  nodeData={nodeData}
                                  maxCount={maxCount}
                                  isActive={isActive}
                                />
                                {index < arr.length - 1 && (
                                  <div className="stage-arrow" style={{
                                    color: isActive ? stageDef.color : '#999'
                                  }}>→</div>
                                )}
                              </React.Fragment>
                            );
                          })}
                        </div>
                      </div>

                      <div className="pipeline-branches">
                        <div className="pipeline-branch local">
                          <div className="branch-header">
                            <span className="branch-arrow">⤷</span>
                            <span className="branch-label">Local Delivery</span>
                          </div>
                          <div className="pipeline-stages">
                            {PIPELINE_DEFINITIONS.Inbound.branches['Local Delivery'].map((stageDef, index, arr) => {
                              const nodeData = stats.nodes[stageDef.name];
                              const isActive = nodeData && nodeData.count > 0;

                              return (
                                <React.Fragment key={stageDef.name}>
                                  <PipelineNode
                                    stageDef={stageDef}
                                    nodeData={nodeData}
                                    maxCount={maxCount}
                                    isActive={isActive}
                                  />
                                  {index < arr.length - 1 && (
                                    <div className="stage-arrow" style={{
                                      color: isActive ? stageDef.color : '#999'
                                    }}>→</div>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        </div>

                        <div className="pipeline-branch forward">
                          <div className="branch-header">
                            <span className="branch-arrow">⤷</span>
                            <span className="branch-label">Forward</span>
                          </div>
                          <div className="pipeline-stages">
                            {PIPELINE_DEFINITIONS.Inbound.branches['Forward'].map((stageDef, index, arr) => {
                              const nodeData = stats.nodes[stageDef.name];
                              const isActive = nodeData && nodeData.count > 0;

                              return (
                                <React.Fragment key={stageDef.name}>
                                  <PipelineNode
                                    stageDef={stageDef}
                                    nodeData={nodeData}
                                    maxCount={maxCount}
                                    isActive={isActive}
                                  />
                                  {index < arr.length - 1 && (
                                    <div className="stage-arrow" style={{
                                      color: isActive ? stageDef.color : '#999'
                                    }}>→</div>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {(() => {
                  const outboundCounts = PIPELINE_DEFINITIONS.Outbound.map(s => stats.nodes[s.name]?.count || 0);
                  const hasOutbound = outboundCounts.some(c => c > 0);

                  if (!hasOutbound) return null;

                  const maxCount = Math.max(...outboundCounts);

                  return (
                    <div className="pipeline-direction">
                      <div className="pipeline-direction-header">
                        <span className="pipeline-direction-icon">📤</span>
                        <h4>Outbound Traffic</h4>
                        <span className="pipeline-event-count">
                          {outboundCounts.reduce((sum, val) => sum + val, 0).toLocaleString()} events
                        </span>
                      </div>

                      <div className="pipeline-stages">
                        {PIPELINE_DEFINITIONS.Outbound.map((stageDef, index, arr) => {
                          const nodeData = stats.nodes[stageDef.name];
                          const isActive = nodeData && nodeData.count > 0;

                          return (
                            <React.Fragment key={stageDef.name}>
                              <PipelineNode
                                stageDef={stageDef}
                                nodeData={nodeData}
                                maxCount={maxCount}
                                isActive={isActive}
                              />
                              {index < arr.length - 1 && (
                                <div className="stage-arrow" style={{
                                  color: isActive ? stageDef.color : '#999'
                                }}>→</div>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}

        </>
      )}
    </div>
  );
}

export default RealtimeView;