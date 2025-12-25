import React, { useState, useEffect } from 'react';
import axios from 'axios';
import PacketList from '../components/Packet/PacketList';
import PacketDetail from '../components/Packet/PacketDetail';
import './TraceViewer.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';

const TraceViewer = ({ filename }) => {
  const [traceData, setTraceData] = useState(null);
  const [packets, setPackets] = useState([]);
  const [filteredPackets, setFilteredPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    src_ip: '',
    dst_ip: '',
    src_port: '',
    dst_port: '',
    protocol: '',
    skb: '',
    hook: '',
    verdict: '',
    any_verdict: '',
    had_verdict_change: false,
    function: '',
    keyword: ''
  });

  useEffect(() => {
    loadTraceFile();
  }, [filename]);

  const loadTraceFile = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE}/traces/${filename}`);
      setTraceData(response.data);
      setPackets(response.data.traces || []);
      setFilteredPackets(response.data.traces || []);
    } catch (err) {
      console.error('Error loading trace file:', err);
      setError(err.response?.data?.error || 'Failed to load trace file');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = async () => {
    setLoading(true);
    try {
      const queryParams = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) {
          queryParams.append(key, value);
        }
      });

      const response = await axios.get(
        `${API_BASE}/traces/${filename}/packets?${queryParams.toString()}`
      );
      setFilteredPackets(response.data.packets || []);
    } catch (err) {
      console.error('Error filtering packets:', err);
      setError(err.response?.data?.error || 'Failed to filter packets');
    } finally {
      setLoading(false);
    }
  };

  const clearFilters = () => {
    setFilters({
      src_ip: '',
      dst_ip: '',
      src_port: '',
      dst_port: '',
      protocol: '',
      skb: '',
      hook: '',
      verdict: '',
      any_verdict: '',
      had_verdict_change: false,
      function: '',
      keyword: ''
    });
    setFilteredPackets(packets);
  };

  const handlePacketSelect = async (packet) => {
    try {
      const originalIndex = packet.original_index;
      if (originalIndex === undefined) {
        console.warn('original_index not found, using packet data directly');
        setSelectedPacket({
          ...packet,
          packet_index: -1,
          analysis: {
            verdict_chain: [],
            jump_goto_chain: [],
            drop_reason: null,
            flow_summary: []
          }
        });
        return;
      }

      const response = await axios.get(
        `${API_BASE}/traces/${filename}/packets/${originalIndex}`
      );
      setSelectedPacket(response.data);
    } catch (err) {
      console.error('Error loading packet detail:', err);
      alert('Failed to load packet details');
    }
  };

  if (loading && !traceData) {
    return (
      <div className="trace-viewer-loading">
        <div className="spinner"></div>
        <p>Loading trace file...</p>
      </div>
    );
  }

  if (error && !traceData) {
    return (
      <div className="trace-viewer-error">
        <h3>Error</h3>
        <p>{error}</p>
        <button onClick={loadTraceFile}>Retry</button>
      </div>
    );
  }

  return (
    <div className="trace-viewer">
      <div className="trace-viewer-header">
        <h2>Packet Trace Analyzer</h2>
        <div className="trace-info">
          <span><strong>File:</strong> {filename}</span>
          <span><strong>Session:</strong> {traceData?.session?.id}</span>
          <span><strong>Mode:</strong> {traceData?.session?.mode?.toUpperCase()}</span>
          {/* <span><strong>Total Packets:</strong> {traceData?.statistics?.total_packets}</span> */}
          <span><strong>Total Events:</strong> {traceData?.statistics?.total_events}</span>
        </div>
      </div>

      {/* <div className="trace-statistics">
        <div className="stat-card">
          <div className="stat-label">Packets Analyzed</div>
          <div className="stat-value">{traceData?.statistics?.total_packets || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Packets Dropped</div>
          <div className="stat-value drop">{traceData?.statistics?.packets_dropped || 0}</div>
          <div className="stat-hint" style={{fontSize: '0.75rem', color: '#999', marginTop: '0.25rem'}}>
            (DROP + STOLEN verdicts)
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Packets Accepted</div>
          <div className="stat-value accept">{traceData?.statistics?.packets_accepted || 0}</div>
          <div className="stat-hint" style={{fontSize: '0.75rem', color: '#999', marginTop: '0.25rem'}}>
            (ACCEPT verdicts only)
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Functions Traced</div>
          <div className="stat-value">{traceData?.statistics?.functions_traced || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value">{traceData?.session?.duration_seconds?.toFixed(2) || 0}s</div>
        </div>
      </div> */}

      <div className="trace-viewer-content">
        <div className={`packet-list-panel ${selectedPacket ? 'split' : 'full'}`}>
          <PacketList
            packets={filteredPackets}
            filters={filters}
            onFilterChange={setFilters}
            onApplyFilters={applyFilters}
            onClearFilters={clearFilters}
            onPacketSelect={handlePacketSelect}
            selectedPacket={selectedPacket}
            loading={loading}
          />
        </div>

        {selectedPacket && (
          <div className="packet-detail-panel">
            <div className="packet-detail-header">
              <h3>Packet Detail</h3>
              <button
                className="close-button"
                onClick={() => setSelectedPacket(null)}
              >
                ✕
              </button>
            </div>
            <PacketDetail
              packet={selectedPacket}
              onClose={() => setSelectedPacket(null)}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default TraceViewer;
