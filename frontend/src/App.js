import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import axios from 'axios';

import RealtimeView from './pages/RealtimeView';
import TraceViewer from './pages/TraceViewer';
import NFTablesManager from './pages/NFTablesManager';

import Login from './Login';
import ChangePassword from './ChangePassword';
import ProtectedRoute from './ProtectedRoute';
import { useAuth } from './AuthContext';
import './App.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';

function Dashboard() {
  const [sessions, setSessions] = useState([]);
  const [files, setFiles] = useState([]);
  const [modes, setModes] = useState([]);
  const [functions, setFunctions] = useState(null);
  const [newSession, setNewSession] = useState({
    id: '',
    mode: 'full',
    filter: '',
    trace_filter: {
      src_ip: '',
      dst_ip: '',
      src_port: '',
      dst_port: '',
      protocol: '',
      comm: ''
    }
  });
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionStats, setSessionStats] = useState(null);
  const [sessionDetailsTab, setSessionDetailsTab] = useState('overview');
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('sessions');
  const [selectedTraceFile, setSelectedTraceFile] = useState(null);
  const [realtimeFilter, setRealtimeFilter] = useState(null);
  const [autoEnableRealtime, setAutoEnableRealtime] = useState(false);

  useEffect(() => {
    checkHealth();
    loadModes();
    loadFunctions();
    loadSessions();
    loadFiles();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      if (sessions.length > 0) {
        loadSessions();
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [sessions]);

  const checkHealth = async () => {
    try {
      const res = await axios.get(`${API_BASE}/health`);
      setHealth(res.data);
    } catch (err) {
      setError('Backend không khả dụng. Vui lòng kiểm tra server!');
    }
  };

  const loadModes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/modes`);
      setModes(res.data.modes);
    } catch (err) {
      console.error('Error loading modes:', err);
    }
  };

  const loadFunctions = async () => {
    try {
      const res = await axios.get(`${API_BASE}/functions`);
      setFunctions(res.data);
    } catch (err) {
      console.log('Functions not discovered yet');
    }
  };

  const discoverFunctions = async () => {
    setDiscovering(true);
    setError(null);
    
    try {
      const res = await axios.post(`${API_BASE}/discover`, {
        max_priority: 2,
        categories: null
      });
      
      setFunctions(null);
      await loadFunctions();
      setError(null);
      alert(`✓ Đã phát hiện ${res.data.total_discovered} functions!`);
    } catch (err) {
      setError(err.response?.data?.error || 'Lỗi khi discover functions');
    } finally {
      setDiscovering(false);
    }
  };

  const loadSessions = async () => {
    try {
      const res = await axios.get(`${API_BASE}/sessions`);
      setSessions(res.data.sessions);
    } catch (err) {
      console.error('Error loading sessions:', err);
    }
  };

  const loadSessionStats = async (sessionId) => {
    try {
      const res = await axios.get(`${API_BASE}/sessions/${sessionId}/stats`);
      setSessionStats(res.data);
    } catch (err) {
      console.error('Error loading stats:', err);
    }
  };

  const loadFiles = async () => {
    try {
      const res = await axios.get(`${API_BASE}/files`);
      setFiles(res.data.files);
    } catch (err) {
      console.error('Error loading files:', err);
    }
  };

  const startSession = async () => {
    setLoading(true);
    setError(null);

    try {
      const sessionId = newSession.id || `trace_${Date.now()}`;
      await axios.post(`${API_BASE}/sessions`, {
        session_id: sessionId,
        mode: newSession.mode,
        pcap_filter: newSession.filter,
        trace_filter: newSession.trace_filter  // NEW: Send trace filter
      });

      setNewSession({
        id: '',
        mode: 'full',
        filter: '',
        trace_filter: {
          src_ip: '',
          dst_ip: '',
          src_port: '',
          dst_port: '',
          protocol: '',
          comm: ''
        }
      });
      loadSessions();
      setActiveTab('sessions');
    } catch (err) {
      setError(err.response?.data?.error || 'Không thể khởi động session');
    } finally {
      setLoading(false);
    }
  };

  const stopSession = async (sessionId) => {
    setLoading(true);
    setError(null);
    
    try {
      await axios.delete(`${API_BASE}/sessions/${sessionId}`);
      setSessions(sessions.filter(s => s.session_id !== sessionId));
      setSelectedSession(null);
      setSessionStats(null);
      loadFiles();
      alert('✓ Session đã dừng và export thành công!');
    } catch (err) {
      setError(err.response?.data?.error || 'Không thể dừng session');
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = (filename) => {
    window.open(`${API_BASE}/download/${filename}`, '_blank');
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDuration = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  };

  return (
    <div className="App">
      <header className="header">
        <h1>🔍 Kernel Packet Tracer</h1>
        <div className="header-info">
          {health && (
            <>
              <div className={`status ${health.bcc_available ? 'status-ok' : 'status-error'}`}>
                BCC: {health.bcc_available ? '✓ Available' : '✗ Not Available'}
              </div>
              {health.realtime_available && (
                <div className="status status-ok">
                  🎥 Realtime: Available
                </div>
              )}
              <div className="status status-ok">
                {health.kernel}
              </div>
            </>
          )}
        </div>
      </header>

      {error && (
        <div className="error-banner">
          <strong>⚠️ Lỗi:</strong> {error}
          <button onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {selectedTraceFile ? (
        <div className="trace-analyzer-view">
          <div className="trace-analyzer-header">
            <button
              className="btn btn-secondary"
              onClick={() => setSelectedTraceFile(null)}
            >
              ← Back to Files
            </button>
          </div>
          <TraceViewer filename={selectedTraceFile} />
        </div>
      ) : (
        <div className="container">
        <div className="tabs">
          <button 
            className={`tab ${activeTab === 'sessions' ? 'active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            📊 Sessions
          </button>
          <button
            className={`tab ${activeTab === 'realtime' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('realtime');
              // Reset auto-enable when clicking tab directly (not from session)
              setAutoEnableRealtime(false);
              setRealtimeFilter(null);
            }}
          >
            🎥 Realtime
          </button>
          <button
            className={`tab ${activeTab === 'discovery' ? 'active' : ''}`}
            onClick={() => setActiveTab('discovery')}
          >
            🔍 Discovery
          </button>
          <button
            className={`tab ${activeTab === 'files' ? 'active' : ''}`}
            onClick={() => setActiveTab('files')}
          >
            📁 Files ({files.length})
          </button>
          <button
            className={`tab ${activeTab === 'nftables' ? 'active' : ''}`}
            onClick={() => setActiveTab('nftables')}
          >
            🛡️ NFTables Manager
          </button>
        </div>

        {activeTab === 'sessions' && (
          <>
            <section className="card">
              <h2>🚀 Tạo Trace Session Mới</h2>
              <p className="card-description">
                Chọn mode tracing và cấu hình tham số. Full Mode (recommended) trace đầy đủ packet path + NFT verdicts.
              </p>
              
              <div className="form">
                <div className="form-group">
                  <label>Session ID (optional)</label>
                  <input
                    type="text"
                    placeholder="Tự động tạo nếu bỏ trống"
                    value={newSession.id}
                    onChange={(e) => setNewSession({...newSession, id: e.target.value})}
                  />
                </div>

                <div className="form-group">
                  <label>Mode</label>
                  <select
                    className="form-select"
                    value={newSession.mode}
                    onChange={(e) => setNewSession({...newSession, mode: e.target.value})}
                  >
                    {modes.map(mode => (
                      <option key={mode.id} value={mode.id}>
                        {mode.name} {mode.recommended ? '⭐' : ''} - {mode.description}
                      </option>
                    ))}
                  </select>
                </div>

                {/* NEW: Trace Filter Section */}
                <div className="form-section">
                  <h3 style={{marginTop: '20px', marginBottom: '10px', fontSize: '1rem', color: '#4CAF50'}}>
                    🎯 Trace Filter (Optional - Only trace matching traffic)
                  </h3>
                  <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px'}}>
                    <div className="form-group">
                      <label>Source IP</label>
                      <input
                        type="text"
                        placeholder="e.g., 192.168.1.100"
                        value={newSession.trace_filter.src_ip}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, src_ip: e.target.value}
                        })}
                      />
                    </div>
                    <div className="form-group">
                      <label>Dest IP</label>
                      <input
                        type="text"
                        placeholder="e.g., 10.0.0.1"
                        value={newSession.trace_filter.dst_ip}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, dst_ip: e.target.value}
                        })}
                      />
                    </div>
                    <div className="form-group">
                      <label>Source Port</label>
                      <input
                        type="number"
                        placeholder="e.g., 12345"
                        value={newSession.trace_filter.src_port}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, src_port: e.target.value}
                        })}
                      />
                    </div>
                    <div className="form-group">
                      <label>Dest Port</label>
                      <input
                        type="number"
                        placeholder="e.g., 80"
                        value={newSession.trace_filter.dst_port}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, dst_port: e.target.value}
                        })}
                      />
                    </div>
                    <div className="form-group">
                      <label>Protocol</label>
                      <select
                        className="form-select"
                        value={newSession.trace_filter.protocol}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, protocol: e.target.value}
                        })}
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
                      <label>Process Name</label>
                      <input
                        type="text"
                        placeholder="e.g., curl, nginx"
                        value={newSession.trace_filter.comm}
                        onChange={(e) => setNewSession({
                          ...newSession,
                          trace_filter: {...newSession.trace_filter, comm: e.target.value}
                        })}
                      />
                    </div>
                  </div>
                  <p style={{fontSize: '0.85rem', color: '#888', marginTop: '5px'}}>
                    💡 Leave empty to trace all traffic. Fill any field to filter.
                  </p>
                </div>

                <button
                  className="btn btn-primary"
                  onClick={startSession}
                  disabled={loading || !health?.bcc_available}
                >
                  {loading ? '⏳ Đang khởi động...' : '▶️ Bắt đầu Trace'}
                </button>
              </div>
            </section>

            <section className="card">
              <h2>🔄 Active Sessions ({sessions.length})</h2>
              {sessions.length === 0 ? (
                <p className="empty-state">Chưa có session nào đang chạy</p>
              ) : (
                <div className="sessions-grid">
                  {sessions.map((session) => (
                    <div
                      key={session.session_id}
                      className={`session-card ${selectedSession === session.session_id ? 'selected' : ''}`}
                      onClick={() => {
                        // When clicking session, switch to realtime tab and apply filter
                        const filter = session.trace_filter || {
                          src_ip: '',
                          dst_ip: '',
                          src_port: '',
                          dst_port: '',
                          protocol: '',
                          comm: ''
                        };
                        setRealtimeFilter(filter);
                        setAutoEnableRealtime(true);
                        setActiveTab('realtime');
                        setSelectedSession(session.session_id);
                      }}
                    >
                      <div className="session-header">
                        <h3>{session.session_id}</h3>
                        <div>
                          <span className={`badge ${session.running ? 'badge-running' : 'badge-stopped'}`}>
                            {session.running ? 'Running' : 'Stopped'}
                          </span>
                          <span className="badge badge-mode">{session.mode}</span>
                        </div>
                      </div>

                      <div className="session-stats">
                        <div className="stat">
                          <span className="stat-label">Events/sec</span>
                          <span className="stat-value">{session.events_per_second || 0}</span>
                        </div>
                        <div className="stat">
                          <span className="stat-label">Total Events</span>
                          <span className="stat-value">{session.total_events?.toLocaleString() || 0}</span>
                        </div>
                      </div>

                      {session.mode === 'full' && (
                        <div className="session-stats">
                          <div className="stat">
                            <span className="stat-label">Active Packets</span>
                            <span className="stat-value">{session.active_packets || 0}</span>
                          </div>
                          <div className="stat">
                            <span className="stat-label">Completed</span>
                            <span className="stat-value">{session.completed_packets || 0}</span>
                          </div>
                          <div className="stat">
                            <span className="stat-label">Functions</span>
                            <span className="stat-value">{session.functions_traced}</span>
                          </div>
                          <div className="stat">
                            <span className="stat-label">Functions Hit</span>
                            <span className="stat-value">{session.functions_hit}</span>
                          </div>
                        </div>
                      )}

                      <div className="stat">
                        <span className="stat-label">⏱️ Uptime</span>
                        <span className="stat-value">{formatDuration(session.uptime_seconds)}</span>
                      </div>

                      <button
                        className="btn btn-danger btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          stopSession(session.session_id);
                        }}
                        disabled={loading}
                      >
                        ⏹️ Dừng & Export
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        {activeTab === 'realtime' && <RealtimeView initialFilter={realtimeFilter} autoEnable={autoEnableRealtime} />}

        {activeTab === 'discovery' && (
          <>
            <section className="card">
              <h2>🔬 BTF Function Discovery</h2>
              <p className="card-description">
                Tự động phát hiện tất cả kernel functions xử lý sk_buff từ BTF (BPF Type Format).
                Cần thiết cho chế độ Full Tracer.
              </p>

              {!functions ? (
                <div className="discovery-section">
                  <div className="info-box">
                    <h3>⚠️ Chưa Discover Functions</h3>
                    <p>Bạn cần discover functions trước khi sử dụng Full Tracer.</p>
                    <p>Quá trình này sẽ quét kernel BTF và tìm tất cả functions xử lý packet.</p>
                  </div>
                  <button
                    className="btn btn-primary"
                    onClick={discoverFunctions}
                    disabled={discovering || !health?.bcc_available}
                  >
                    {discovering ? '🔄 Đang discover...' : '🔍 Bắt đầu Discovery'}
                  </button>
                </div>
              ) : (
                <div className="discovery-results">
                  <div className="stats-cards">
                    <div className="stat-card">
                      <div className="stat-card-value">{functions.total}</div>
                      <div className="stat-card-label">Tổng Functions</div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-card-value">{Object.keys(functions.by_category).length}</div>
                      <div className="stat-card-label">Categories</div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-card-value">{functions.by_priority?.[0]?.length || 0}</div>
                      <div className="stat-card-label">Critical Functions</div>
                    </div>
                  </div>

                  <div className="categories-grid">
                    {Object.entries(functions.by_category).map(([category, funcs]) => (
                      <div key={category} className="category-card">
                        <h4>{category}</h4>
                        <div className="category-count">{funcs.length} functions</div>
                        <div className="category-functions">
                          {funcs.slice(0, 5).map(func => (
                            <div key={func} className="function-tag">{func}</div>
                          ))}
                          {funcs.length > 5 && (
                            <div className="function-tag more">+{funcs.length - 5} more</div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  <button
                    className="btn btn-secondary"
                    onClick={discoverFunctions}
                    disabled={discovering}
                  >
                    🔄 Re-discover Functions
                  </button>
                </div>
              )}
            </section>
          </>
        )}

        {activeTab === 'files' && (
          <section className="card">
            <h2>📁 Kết quả Trace ({files.length})</h2>
            {files.length === 0 ? (
              <p className="empty-state">Chưa có file kết quả nào</p>
            ) : (
              <div className="files-list">
                {files.map((file) => (
                  <div key={file.filename} className="file-item">
                    <div className="file-info">
                      <div className="file-name">📄 {file.filename}</div>
                      <div className="file-meta">
                        <span>{formatBytes(file.size)}</span>
                        <span>•</span>
                        <span>{new Date(file.created).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="file-actions">
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => setSelectedTraceFile(file.filename)}
                      >
                        🔍 Analyze
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => downloadFile(file.filename)}
                      >
                        ⬇️ Download
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {activeTab === 'nftables' && (
          <NFTablesManager />
        )}
        </div>


      )}

    </div>
  );
}

function App() {
  const { user, logout } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/change-password" element={<ChangePassword />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <DashboardWithLogout />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

function DashboardWithLogout() {
  const { user, logout, refetchUser } = useAuth();
  const navigate = useNavigate();

  // Refetch user data when component mounts to ensure fresh state
  useEffect(() => {
    refetchUser();
  }, [refetchUser]);

  // Redirect to change password if first login
  useEffect(() => {
    if (user && user.first_login === true) {
      navigate('/change-password');
    }
  }, [user, navigate]);

  return (
    <div style={{ position: 'relative' }}>
      <div
        style={{
          position: 'fixed',
          bottom: '20px',
          right: '20px',
          zIndex: 1000,
        }}
      >
        <button
          onClick={logout}
          style={{
            padding: '8px 16px',
            backgroundColor: '#ff6b6b',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px',
          }}
        >
          Logout
        </button>
      </div>

      <Dashboard />
    </div>
  );
}


export default App;