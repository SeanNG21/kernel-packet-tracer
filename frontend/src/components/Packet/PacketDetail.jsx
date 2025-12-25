import React, { useState } from 'react';
import './PacketDetail.css';

const PacketDetail = ({ packet, onClose }) => {
  const [activeTab, setActiveTab] = useState('overview');

  if (!packet) {
    return (
      <div className="packet-detail">
        <div className="detail-placeholder">
          <div className="placeholder-icon">📦</div>
          <h3>No Packet Selected</h3>
          <p>Click on a packet in the list to view detailed information</p>
        </div>
      </div>
    );
  }

  const formatTimestamp = (ns) => {
    if (!ns && ns !== 0) return 'N/A';
    return (ns / 1000000).toFixed(3) + ' ms';
  };

  const formatDuration = (ns) => {
    if (!ns && ns !== 0) return 'N/A';
    if (ns < 1000) return ns + ' ns';
    if (ns < 1000000) return (ns / 1000).toFixed(2) + ' μs';
    return (ns / 1000000).toFixed(2) + ' ms';
  };

  const renderOverview = () => (
    <div className="detail-section">
      <h4>Packet Information</h4>

      {packet.original_index !== undefined && (
        <div className="packet-identifier">
          <span className="identifier-label">Packet Index:</span>
          <span className="identifier-value">#{packet.original_index}</span>
          {packet.skb_addr && (
            <>
              <span className="identifier-separator">•</span>
              <span className="identifier-skb" title={packet.skb_addr}>
                {packet.skb_addr.substring(0, 16)}...
              </span>
            </>
          )}
        </div>
      )}

      <div className="info-grid">
        <div className="info-item">
          <label>SKB Address</label>
          <span className="mono">{packet.skb_addr || 'N/A'}</span>
        </div>
        <div className="info-item">
          <label>Protocol</label>
          <span className="badge protocol">{packet.protocol_name || 'N/A'}</span>
        </div>
        <div className="info-item">
          <label>Source</label>
          <span>
            {packet.src_ip || 'N/A'}
            {packet.src_port ? `:${packet.src_port}` : ''}
          </span>
        </div>
        <div className="info-item">
          <label>Destination</label>
          <span>
            {packet.dst_ip || 'N/A'}
            {packet.dst_port ? `:${packet.dst_port}` : ''}
          </span>
        </div>
        <div className="info-item">
          <label>First Seen</label>
          <span>{formatTimestamp(packet.first_seen)}</span>
        </div>
        <div className="info-item">
          <label>Last Seen</label>
          <span>{formatTimestamp(packet.last_seen)}</span>
        </div>
        <div className="info-item">
          <label>Duration</label>
          <span>{formatDuration(packet.duration_ns)}</span>
        </div>
        {packet.branch ? (
          <div className="info-item">
            <label>Branch</label>
            <span className="badge branch">{packet.branch}</span>
          </div>
        ) : (
          <div className="info-item">
            <label>Hook</label>
            <span className="badge hook">{packet.hook_name || 'N/A'}</span>
          </div>
        )}
        <div className="info-item">
          <label>Final Verdict</label>
          <span className={`badge verdict verdict-${packet.final_verdict?.toLowerCase()}`}>
            {packet.final_verdict || 'N/A'}
          </span>
        </div>
        <div className="info-item">
          <label>Unique Functions</label>
          <span>{packet.unique_functions ?? 0}</span>
        </div>
        {packet.unique_layers !== undefined && (
          <div className="info-item">
            <label>Unique Layers</label>
            <span>{packet.unique_layers}</span>
          </div>
        )}
        <div className="info-item">
          <label>{packet.total_functions_called !== undefined ? 'Total Functions Called' : 'Total Events'}</label>
          <span>{packet.total_functions_called ?? packet.all_events_count ?? packet.total_events ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Rules Evaluated</label>
          <span>{packet.total_rules_evaluated ?? 0}</span>
        </div>
        <div className="info-item">
          <label>Verdict Changes</label>
          <span className={packet.verdict_changes > 0 ? 'highlight-changes' : ''}>
            {packet.verdict_changes ?? 0}
            {packet.verdict_changes > 0 && ' ⚠️'}
          </span>
        </div>
        <div className="info-item">
          <label>Function Events</label>
          <span>{packet.all_events_count || (packet.events ? packet.events.length : 0)}</span>
        </div>
        {packet.nft_events && packet.nft_events.length > 0 && (
          <div className="info-item">
            <label>NFT Events</label>
            <span className="highlight-nft">{packet.nft_events_count || packet.nft_events.length}</span>
          </div>
        )}
        {packet.layer_verdict_count !== undefined && packet.layer_verdict_count > 0 && (
          <div className="info-item">
            <label>Layer Verdicts</label>
            <span className="highlight-layer-verdict">{packet.layer_verdict_count}</span>
          </div>
        )}
      </div>

      {/* Layer Verdict Breakdown Section */}
      {packet.layer_verdicts_by_type && Object.keys(packet.layer_verdicts_by_type).length > 0 && (
        <div className="layer-verdicts-section">
          <h5>Layer Verdict Breakdown</h5>
          <div className="verdict-breakdown-grid">
            {Object.entries(packet.layer_verdicts_by_type).map(([verdict, count]) => (
              <div key={verdict} className="verdict-item">
                <span className={`verdict-badge verdict-${verdict.toLowerCase()}`}>{verdict}</span>
                <span className="verdict-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Layer Counts Section */}
      {packet.layer_counts && Object.keys(packet.layer_counts).length > 0 && (
        <div className="layer-counts-section">
          <h5>Layer Distribution</h5>
          <div className="layer-counts-grid">
            {Object.entries(packet.layer_counts).map(([layer, count]) => (
              <div key={layer} className="layer-count-item">
                <span className="layer-name">{layer}</span>
                <span className="layer-count badge">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderFunctionFlow = () => {
    // Merge function events and NFT events into a single timeline
    const functionEvents = (packet.events || []).map(event => ({
      ...event,
      event_type: 'function',
      timestamp: event.timestamp
    }));

    const nftEvents = (packet.nft_events || []).map(event => ({
      ...event,
      event_type: 'nft',
      timestamp: event.timestamp
    }));

    // Combine and sort by timestamp
    const timeline = [...functionEvents, ...nftEvents].sort((a, b) => a.timestamp - b.timestamp);

    const verdictMap = {
      0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
      3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
      '-1': 'JUMP', '-2': 'GOTO', '-3': 'RETURN'
    };

    const hookMap = {
      0: 'PREROUTING',
      1: 'INPUT',
      2: 'FORWARD',
      3: 'OUTPUT',
      4: 'POSTROUTING'
    };

    const getVerdictStr = (verdict) => {
      if (typeof verdict === 'string') return verdict;
      if (typeof verdict === 'number') return verdictMap[verdict] || `UNKNOWN(${verdict})`;
      return 'N/A';
    };

    const getHookStr = (hook) => {
      if (hook === undefined || hook === null) return 'N/A';
      return hookMap[hook] || `HOOK_${hook}`;
    };

    return (
      <div className="detail-section">
        <h4>Packet Journey Timeline</h4>
        <div className="timeline-info">
          <div className="timeline-stats">
            <span className="stat-item">
              <span className="stat-label">Total Events:</span>
              <span className="stat-value">{timeline.length}</span>
            </span>
            <span className="stat-item">
              <span className="stat-label">Function Calls:</span>
              <span className="stat-value">{functionEvents.length}</span>
            </span>
            <span className="stat-item">
              <span className="stat-label">NFT Events:</span>
              <span className="stat-value">{nftEvents.length}</span>
            </span>
          </div>
        </div>

        {timeline.length > 0 ? (
          <div className="unified-timeline">
            {timeline.map((event, idx) => {
              const isFunction = event.event_type === 'function';
              const isNFT = event.event_type === 'nft';

              return (
                <div key={idx} className={`timeline-event ${event.event_type}-event`}>
                  <div className="timeline-marker">
                    <div className={`timeline-dot ${event.event_type}`}>
                      {isFunction ? '🔧' : '🛡️'}
                    </div>
                    {idx < timeline.length - 1 && <div className="timeline-line"></div>}
                  </div>

                  <div className="timeline-content">
                    <div className="timeline-header">
                      <div className="timeline-type-badge">
                        <span className={`badge event-type-badge ${event.event_type}`}>
                          {isFunction ? 'FUNCTION' : 'NFT'}
                        </span>
                        {isFunction && event.layer && (
                          <span className="badge layer-badge">{event.layer}</span>
                        )}
                        {isNFT && event.trace_type && (
                          <span className="badge trace-type-badge">{event.trace_type}</span>
                        )}
                        {isNFT && event.verdict && (
                          <span className={`badge verdict verdict-${getVerdictStr(event.verdict).toLowerCase()}`}>
                            {getVerdictStr(event.verdict)}
                          </span>
                        )}
                      </div>
                      <span className="timeline-timestamp">{formatTimestamp(event.timestamp)}</span>
                    </div>

                    <div className="timeline-details">
                      {isFunction ? (
                        <>
                          <div className="timeline-main-info">
                            <span className="function-arrow">→</span>
                            <span className="function-name">{event.function}</span>
                            {event.layer_verdict && (
                              <>
                                <span className="arrow">→</span>
                                <span className={`layer-verdict-badge verdict-${event.layer_verdict.toLowerCase()}`}>
                                  {event.layer_verdict} (Layer)
                                </span>
                              </>
                            )}
                          </div>
                          <div className="timeline-meta">
                            {event.layer && (
                              <span className="meta-item">
                                <span className="meta-label">Layer:</span>
                                <span className="meta-value">{event.layer}</span>
                              </span>
                            )}
                            {event.layer_verdict && (
                              <span className="meta-item">
                                <span className="meta-label">Layer Verdict:</span>
                                <span className={`meta-value verdict-${event.layer_verdict.toLowerCase()}`}>
                                  {event.layer_verdict} (Code: {event.layer_verdict_code})
                                </span>
                              </span>
                            )}
                            <span className="meta-item">
                              <span className="meta-label">CPU:</span>
                              <span className="meta-value">{event.cpu_id}</span>
                            </span>
                            {event.comm && (
                              <span className="meta-item">
                                <span className="meta-label">Process:</span>
                                <span className="meta-value">{event.comm}</span>
                              </span>
                            )}
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="timeline-main-info">
                            <span className="nft-icon">🛡️</span>
                            <span className="nft-action">{event.trace_type || 'NFT Event'}</span>
                            {event.verdict && (
                              <>
                                <span className="arrow">→</span>
                                <span className={`verdict-text verdict-${getVerdictStr(event.verdict).toLowerCase()}`}>
                                  {getVerdictStr(event.verdict)}
                                </span>
                              </>
                            )}
                          </div>
                          <div className="timeline-meta">
                            {event.hook !== undefined && (
                              <span className="meta-item">
                                <span className="meta-label">Hook:</span>
                                <span className="meta-value">{getHookStr(event.hook)}</span>
                              </span>
                            )}
                            {event.rule_handle !== undefined && event.rule_handle !== 0 && (
                              <span className="meta-item">
                                <span className="meta-label">Rule:</span>
                                <span className="meta-value">#{event.rule_handle}</span>
                              </span>
                            )}
                            {event.chain_depth !== undefined && (
                              <span className="meta-item">
                                <span className="meta-label">Chain Depth:</span>
                                <span className="meta-value">{event.chain_depth}</span>
                              </span>
                            )}
                            <span className="meta-item">
                              <span className="meta-label">CPU:</span>
                              <span className="meta-value">{event.cpu_id}</span>
                            </span>
                            {event.comm && (
                              <span className="meta-item">
                                <span className="meta-label">Process:</span>
                                <span className="meta-value">{event.comm}</span>
                              </span>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="no-timeline-data">
            <div className="no-data-icon">📊</div>
            <h5>No Timeline Data</h5>
            <p>No function calls or NFT events were recorded for this packet</p>

            {/* Show function path if available */}
            {packet.functions_path && packet.functions_path.length > 0 && (
              <div className="function-path-fallback">
                <h6>Function Path (Summary)</h6>
                <div className="function-list">
                  {packet.functions_path.map((func, idx) => (
                    <div key={idx} className="function-item">
                      <span className="function-index">{idx + 1}</span>
                      <span className="function-arrow">→</span>
                      <span className="function-name">{func}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  const renderVerdictChain = () => {
    const nftEventsList = packet.nft_events || [];

    const verdictMap = {
      0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
      3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
      '-1': 'JUMP', '-2': 'GOTO', '-3': 'RETURN'
    };

    const hookMap = {
      0: 'PREROUTING',
      1: 'INPUT',
      2: 'FORWARD',
      3: 'OUTPUT',
      4: 'POSTROUTING'
    };

    const getVerdictStr = (verdict) => {
      if (typeof verdict === 'string') return verdict;
      if (typeof verdict === 'number') return verdictMap[verdict] || `UNKNOWN(${verdict})`;
      return 'N/A';
    };

    const getHookStr = (hook) => {
      if (hook === undefined || hook === null) return 'N/A';
      return hookMap[hook] || `HOOK_${hook}`;
    };

    return (
      <div className="detail-section">
        <h4>NFT Verdict Timeline</h4>

        {packet.analysis?.drop_reason && (
          <div className="drop-reason alert alert-danger">
            <strong>Drop Reason:</strong>
            <p>{packet.analysis.drop_reason.reason}</p>
            <div className="drop-details">
              <span><strong>Hook:</strong> {packet.analysis.drop_reason.hook}</span>
              <span><strong>Chain:</strong> {packet.analysis.drop_reason.chain}</span>
              <span><strong>Table:</strong> {packet.analysis.drop_reason.table}</span>
            </div>
          </div>
        )}

        {/* NFT Events Timeline */}
        {nftEventsList.length > 0 ? (
          <div className="nft-verdict-timeline">
            <div className="timeline-stats">
              <span className="stat-item">
                <span className="stat-label">Total NFT Events:</span>
                <span className="stat-value">{nftEventsList.length}</span>
              </span>
            </div>

            <div className="verdict-timeline">
              {nftEventsList.map((event, idx) => (
                <div key={idx} className="verdict-step">
                  <div className="verdict-marker">
                    <div className={`verdict-dot verdict-${getVerdictStr(event.verdict).toLowerCase()}`}>
                      🛡️
                    </div>
                    {idx < nftEventsList.length - 1 && (
                      <div className="verdict-line"></div>
                    )}
                  </div>
                  <div className="verdict-content">
                    <div className="verdict-header">
                      <div className="verdict-badges">
                        <span className="event-type badge trace-type-badge">
                          {event.trace_type || 'NFT Event'}
                        </span>
                        <span className={`verdict-badge verdict-${getVerdictStr(event.verdict).toLowerCase()}`}>
                          {getVerdictStr(event.verdict)}
                        </span>
                      </div>
                      <span className="verdict-time">{formatTimestamp(event.timestamp)}</span>
                    </div>
                    <div className="verdict-info">
                      {event.hook !== undefined && (
                        <span><strong>Hook:</strong> {getHookStr(event.hook)}</span>
                      )}
                      {event.verdict_code !== undefined && (
                        <span><strong>Verdict Code:</strong> {event.verdict_code}</span>
                      )}
                      {event.verdict_raw !== undefined && (
                        <span><strong>Verdict Raw:</strong> {event.verdict_raw}</span>
                      )}
                      {event.pf !== undefined && (
                        <span><strong>Protocol Family:</strong> {event.pf}</span>
                      )}
                      {event.chain_depth !== undefined && (
                        <span><strong>Chain Depth:</strong> {event.chain_depth}</span>
                      )}
                      {event.rule_seq !== undefined && event.rule_seq !== 0 && (
                        <span><strong>Rule Seq:</strong> {event.rule_seq}</span>
                      )}
                      {event.rule_handle !== undefined && event.rule_handle !== 0 && (
                        <span><strong>Rule Handle:</strong> #{event.rule_handle}</span>
                      )}
                      <span><strong>CPU:</strong> {event.cpu_id}</span>
                      {event.comm && (
                        <span><strong>Process:</strong> {event.comm}</span>
                      )}
                      {event.chain_addr && (
                        <span><strong>Chain Addr:</strong> <code className="mono-small">{event.chain_addr}</code></span>
                      )}
                      {event.expr_addr && (
                        <span><strong>Expr Addr:</strong> <code className="mono-small">{event.expr_addr}</code></span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p className="no-data">No NFT verdict events recorded</p>
        )}

        {packet.analysis?.jump_goto_chain && packet.analysis.jump_goto_chain.length > 0 && (
          <div className="jump-goto-section">
            <h5>Jump/Goto Chain</h5>
            <div className="jump-list">
              {packet.analysis.jump_goto_chain.map((jump, idx) => (
                <div key={idx} className="jump-item">
                  <span className="jump-source">{jump.source_chain}</span>
                  <span className="jump-arrow">
                    {jump.verdict_type === 'JUMP' ? '⇢' : '⇒'}
                  </span>
                  <span className="jump-target">{jump.target_chain}</span>
                  <span className="jump-type badge">{jump.verdict_type}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="packet-detail">
      <div className="detail-tabs">
        <button
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`tab ${activeTab === 'functions' ? 'active' : ''}`}
          onClick={() => setActiveTab('functions')}
        >
          Timeline
          {((packet.events && packet.events.length > 0) || (packet.nft_events && packet.nft_events.length > 0)) && (
            <span className="tab-badge">
              {(packet.events?.length || 0) + (packet.nft_events?.length || 0)}
            </span>
          )}
        </button>
        <button
          className={`tab ${activeTab === 'verdict' ? 'active' : ''}`}
          onClick={() => setActiveTab('verdict')}
        >
          NFT Verdict
          {packet.nft_events && packet.nft_events.length > 0 && (
            <span className="tab-badge">{packet.nft_events.length}</span>
          )}
        </button>
      </div>

      <div className="detail-content">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'functions' && renderFunctionFlow()}
        {activeTab === 'verdict' && renderVerdictChain()}
      </div>
    </div>
  );
};

export default PacketDetail;
