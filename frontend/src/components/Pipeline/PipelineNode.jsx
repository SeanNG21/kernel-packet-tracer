import React from 'react';
import { getNodeDescription } from '../../PipelineNodeDescriptions';

/**
 * PipelineNode Component
 * Displays individual pipeline stage with metrics, statistics, and verdicts
 */
function PipelineNode({ stageDef, nodeData, maxCount, isActive }) {
  const count = nodeData?.count || 0;
  const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;

  // Get educational description
  const nodeDesc = getNodeDescription(stageDef.name);

  // Check for drops/errors for highlighting
  const hasDrops = (nodeData?.drops || 0) > 0;
  const hasErrors = (nodeData?.errors || 0) > 0;
  const hasIssues = hasDrops || hasErrors;

  // Create gradient background based on stage color
  let gradientBg = isActive
    ? `linear-gradient(135deg, ${stageDef.color} 0%, ${stageDef.color}dd 100%)`
    : 'linear-gradient(135deg, #e0e0e0 0%, #c0c0c0 100%)';

  // Red tint if has drops/errors
  if (isActive && hasIssues) {
    gradientBg = `linear-gradient(135deg, #dc3545 0%, ${stageDef.color} 50%, ${stageDef.color}dd 100%)`;
  }

  // Verdict pie chart data for Netfilter nodes
  const verdictData = nodeData?.verdict || null;
  const isNetfilterNode = stageDef.name.includes('Netfilter');

  // Packet rate
  const packetRate = nodeData?.packet_rate || 0;

  return (
    <div className="pipeline-node-wrapper">
      <div
        className={`pipeline-node ${isActive ? 'active' : 'inactive'} ${hasIssues ? 'has-issues' : ''}`}
        style={{
          background: gradientBg,
          boxShadow: isActive
            ? hasIssues
              ? `0 4px 12px rgba(220, 53, 69, 0.6), 0 2px 4px ${stageDef.color}40`
              : `0 4px 12px ${stageDef.color}60, 0 2px 4px ${stageDef.color}40`
            : '0 2px 6px rgba(0,0,0,0.1)',
          border: `2px solid ${isActive ? (hasIssues ? '#dc3545' : stageDef.color) : '#bbb'}`,
        }}
      >
        <div className="node-icon">{stageDef.icon}</div>

        <div className="node-name">{stageDef.name}</div>

        {/* Count, In-Flight, and Packet Rate */}
        {isActive && (
          <div className="node-count">
            <div>{count.toLocaleString()}</div>
            {nodeData?.in_flight > 0 && (
              <div className="node-in-flight">⏳ {nodeData.in_flight}</div>
            )}
            {packetRate > 0 && (
              <div className="node-packet-rate">{packetRate.toLocaleString()} pkt/s</div>
            )}
          </div>
        )}

        {/* Drop/Error Badges */}
        {isActive && hasIssues && (
          <div className="node-issues">
            {hasDrops && (
              <div className="issue-badge drop-badge">❌ {nodeData.drops} drops</div>
            )}
            {hasErrors && (
              <div className="issue-badge error-badge">⚠️ {nodeData.errors} errors</div>
            )}
          </div>
        )}

        {/* Top Functions */}
        {isActive && nodeData?.top_functions && nodeData.top_functions.length > 0 && (
          <div className="node-functions">
            {nodeData.top_functions.slice(0, 2).map((func, idx) => (
              <div key={idx} className="func-line">
                <span className="func-name">{func.name}</span>
                <span className="func-pct">{func.pct}%</span>
              </div>
            ))}
          </div>
        )}

        {isActive && nodeData?.latency && nodeData.latency.p50 > 0 && (
          <div className="node-latency">
            ⏱️ p50: {nodeData.latency.p50.toFixed(1)}µs
          </div>
        )}

        {isActive && isNetfilterNode && verdictData && (
          <div className="node-verdict">
            {(() => {
              // Fixed verdict order (excluding ACCEPT)
              const verdictOrder = ['DROP', 'STOLEN', 'QUEUE', 'REPEAT', 'STOP', 'CONTINUE', 'RETURN', 'JUMP', 'GOTO', 'BREAK'];

              return verdictOrder
                .filter(verdict => verdictData[verdict] && verdictData[verdict] > 0) // Only show if exists and > 0
                .map(verdict => {
                  const vCount = verdictData[verdict];
                  const pct = count > 0 ? ((vCount / count) * 100).toFixed(0) : 0;

                  return (
                    <div key={verdict} className={`verdict-badge verdict-${verdict.toLowerCase()}`}>
                      <span className="verdict-name">{verdict}</span>
                      <span className="verdict-count">{vCount.toLocaleString()}</span>
                      <span className="verdict-pct">({pct}%)</span>
                    </div>
                  );
                });
            })()}
          </div>
        )}

        {isActive && (
          <div className="node-tooltip">
            <div className="tooltip-header">{stageDef.name}</div>

            {/* Educational Section */}
            <div className="tooltip-section educational">
              <div className="tooltip-description">{nodeDesc.description}</div>
              <div className="tooltip-details">{nodeDesc.details}</div>
            </div>

            {/* Statistics Section */}
            <div className="tooltip-section">
              <div className="tooltip-label">📊 Statistics:</div>
              <div className="tooltip-stat">Events: {count.toLocaleString()}</div>
              {nodeData?.unique_packets && (
                <div className="tooltip-stat">Unique: {nodeData.unique_packets}</div>
              )}
              {nodeData?.in_flight > 0 && (
                <div className="tooltip-stat" style={{ color: '#ffeb3b' }}>In-flight: {nodeData.in_flight}</div>
              )}
              {packetRate > 0 && (
                <div className="tooltip-stat" style={{ color: '#4fc3f7' }}>Rate: {packetRate} pkt/s</div>
              )}
            </div>
            {nodeData?.latency && nodeData.latency.p50 > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Latency (µs):</div>
                <div className="tooltip-stat">p50: {nodeData.latency.p50.toFixed(1)}</div>
                <div className="tooltip-stat">p90: {nodeData.latency.p90.toFixed(1)}</div>
                <div className="tooltip-stat">p99: {nodeData.latency.p99.toFixed(1)}</div>
              </div>
            )}
            {nodeData?.top_functions && nodeData.top_functions.length > 0 && (
              <div className="tooltip-section">
                <div className="tooltip-label">Top Functions:</div>
                {nodeData.top_functions.map((func, idx) => (
                  <div key={idx} className="tooltip-stat">
                    {idx + 1}. {func.name} – {func.pct}%
                  </div>
                ))}
              </div>
            )}
            {verdictData && (
              <div className="tooltip-section">
                <div className="tooltip-label">Verdicts:</div>
                {Object.entries(verdictData).map(([verdict, vCount]) => (
                  <div key={verdict} className="tooltip-stat">
                    {verdict}: {vCount} ({((vCount / count) * 100).toFixed(1)}%)
                  </div>
                ))}
              </div>
            )}
            {nodeData?.drops > 0 && (
              <div className="tooltip-stat error">Drops: {nodeData.drops}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default PipelineNode;
