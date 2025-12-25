import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';

/**
 * VerdictTimeSeriesChart - Time-series chart showing verdict counts per 10-minute bucket
 *
 * Features:
 * - Multiple lines for different verdict types (ACCEPT, DROP, CONTINUE, etc.)
 * - Ability to toggle visibility of each verdict type
 * - Time range selector (1h, 2h, 24h, 7d)
 * - Beautiful card design matching dashboard style
 * - Interactive tooltip with detailed breakdown
 */
const VerdictTimeSeriesChart = () => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('2h');
  const [summary, setSummary] = useState(null);
  const [visibleLines, setVisibleLines] = useState({
    accept: true,
    drop: true,
    continue: true,
    queue: false,
    other: false
  });

  // Verdict type configuration with colors
  const verdictConfig = {
    accept: {
      label: 'ACCEPT',
      color: '#48bb78', // Green
      icon: '✅'
    },
    drop: {
      label: 'DROP',
      color: '#f56565', // Red
      icon: '❌'
    },
    // continue: {
    //   label: 'CONTINUE',
    //   color: '#ed8936', // Orange
    //   icon: '➡️'
    // },
    // queue: {
    //   label: 'QUEUE',
    //   color: '#9f7aea', // Purple
    //   icon: '📋'
    // },
    // other: {
    //   label: 'OTHER',
    //   color: '#a0aec0', // Gray
    //   icon: '⚙️'
    // }
  };

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await axios.get(`${API_BASE}/metrics/verdicts`, {
        params: { range: timeRange }
      });

      const formattedData = response.data.buckets.map(bucket => ({
        time: new Date(bucket.start).toLocaleTimeString('vi-VN', {
          hour: '2-digit',
          minute: '2-digit',
          hour12: false,
          timeZone: 'Asia/Ho_Chi_Minh'  // GMT+7 Vietnam time
        }),
        fullTime: bucket.start,
        accept: bucket.accept,
        drop: bucket.drop,
        continue: bucket.continue,
        queue: bucket.queue,
        other: (bucket.break || 0) + (bucket.return || 0) + (bucket.jump || 0) +
               (bucket.goto || 0) + (bucket.stolen || 0) + (bucket.repeat || 0) +
               (bucket.stop || 0),
        endTime: bucket.end
      }));

      setData(formattedData);
      setSummary(response.data.totals);
      setLoading(false);
    } catch (err) {
      console.error('Error fetching verdict metrics:', err);
      setError(err.response?.data?.error || 'Không thể tải dữ liệu');
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Auto-refresh every 10 minutes
    const interval = setInterval(fetchData, 10 * 60 * 1000);

    return () => clearInterval(interval);
  }, [timeRange]);

  const toggleLine = (verdictType) => {
    setVisibleLines(prev => ({
      ...prev,
      [verdictType]: !prev[verdictType]
    }));
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          padding: '12px 16px',
          borderRadius: '8px',
          border: '2px solid #fff',
          boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
          color: '#fff'
        }}>
          <p style={{ margin: '0 0 8px 0', fontWeight: '600', fontSize: '14px' }}>
            ⚖️ Verdicts - {data.time}
          </p>
          {Object.keys(verdictConfig).map(key => (
            visibleLines[key] && (
              <p key={key} style={{ margin: '4px 0', fontSize: '13px' }}>
                <span style={{ marginRight: '6px' }}>{verdictConfig[key].icon}</span>
                <strong>{verdictConfig[key].label}:</strong> {data[key].toLocaleString()}
              </p>
            )
          ))}
          <p style={{ margin: '8px 0 0 0', fontSize: '11px', opacity: 0.9, borderTop: '1px solid rgba(255,255,255,0.3)', paddingTop: '6px' }}>
            {data.time} - {new Date(data.endTime).toLocaleTimeString('vi-VN', {
              hour: '2-digit',
              minute: '2-digit',
              hour12: false,
              timeZone: 'Asia/Ho_Chi_Minh'  // GMT+7 Vietnam time
            })}
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{
      background: 'linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%)',
      borderRadius: '16px',
      padding: '24px',
      boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
      border: '1px solid rgba(255, 255, 255, 0.8)',
      marginBottom: '24px'
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <h2 style={{
            margin: '0 0 8px 0',
            color: '#2d3748',
            fontSize: '22px',
            fontWeight: '700'
          }}>
            ⚖️ Verdict Statistics Over Time
          </h2>
          <p style={{
            margin: 0,
            color: '#5a4f3b',
            fontSize: '14px'
          }}>
            Số lượng các verdict (ACCEPT, DROP, CONTINUE...) theo từng khoảng 10 phút
          </p>
        </div>

        {/* Time Range Selector */}
        <div style={{ display: 'flex', gap: '8px' }}>
          {['1h', '2h', '24h', '7d'].map(range => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                border: 'none',
                background: timeRange === range
                  ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
                  : '#fff',
                color: timeRange === range ? '#fff' : '#4a5568',
                cursor: 'pointer',
                fontWeight: timeRange === range ? '600' : '500',
                fontSize: '14px',
                boxShadow: timeRange === range
                  ? '0 4px 12px rgba(102, 126, 234, 0.4)'
                  : '0 2px 4px rgba(0,0,0,0.1)',
                transition: 'all 0.3s ease'
              }}
            >
              {range.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Summary Stats */}
      {summary && !loading && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '12px',
          marginBottom: '20px'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(72, 187, 120, 0.3)'
          }}>
            <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '4px' }}>✅ ACCEPT</div>
            <div style={{ fontSize: '24px', fontWeight: '700' }}>
              {(summary.accept || 0).toLocaleString()}
            </div>
          </div>
          <div style={{
            background: 'linear-gradient(135deg, #f56565 0%, #e53e3e 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(245, 101, 101, 0.3)'
          }}>
            <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '4px' }}>❌ DROP</div>
            <div style={{ fontSize: '24px', fontWeight: '700' }}>
              {(summary.drop || 0).toLocaleString()}
            </div>
          </div>
          {/* <div style={{
            background: 'linear-gradient(135deg, #ed8936 0%, #dd6b20 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(237, 137, 54, 0.3)'
          }}>
            <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '4px' }}>➡️ CONTINUE</div>
            <div style={{ fontSize: '24px', fontWeight: '700' }}>
              {(summary.continue || 0).toLocaleString()}
            </div>
          </div> */}
          {/* <div style={{
            background: 'linear-gradient(135deg, #9f7aea 0%, #805ad5 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(159, 122, 234, 0.3)'
          }}>
            <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '4px' }}>📋 QUEUE</div>
            <div style={{ fontSize: '24px', fontWeight: '700' }}>
              {(summary.queue || 0).toLocaleString()}
            </div>
          </div> */}
        </div>
      )}

      {/* Line Toggle Buttons */}
      <div style={{
        display: 'flex',
        gap: '8px',
        marginBottom: '16px',
        flexWrap: 'wrap'
      }}>
        {Object.entries(verdictConfig).map(([key, config]) => (
          <button
            key={key}
            onClick={() => toggleLine(key)}
            style={{
              padding: '6px 12px',
              borderRadius: '6px',
              border: `2px solid ${config.color}`,
              background: visibleLines[key] ? config.color : '#fff',
              color: visibleLines[key] ? '#fff' : config.color,
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: '600',
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span>{config.icon}</span>
            <span>{config.label}</span>
          </button>
        ))}
      </div>

      {/* Chart */}
      <div style={{
        background: '#fff',
        borderRadius: '12px',
        padding: '20px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
      }}>
        {loading && (
          <div style={{
            textAlign: 'center',
            padding: '60px 20px',
            color: '#718096'
          }}>
            <div style={{ fontSize: '32px', marginBottom: '16px' }}>⏳</div>
            <div>Đang tải dữ liệu...</div>
          </div>
        )}

        {error && (
          <div style={{
            textAlign: 'center',
            padding: '60px 20px',
            color: '#e53e3e'
          }}>
            <div style={{ fontSize: '32px', marginBottom: '16px' }}>⚠️</div>
            <div>{error}</div>
            <button
              onClick={fetchData}
              style={{
                marginTop: '16px',
                padding: '8px 20px',
                borderRadius: '8px',
                border: 'none',
                background: '#667eea',
                color: '#fff',
                cursor: 'pointer',
                fontWeight: '600'
              }}
            >
              Thử lại
            </button>
          </div>
        )}

        {!loading && !error && data.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: '60px 20px',
            color: '#718096'
          }}>
            <div style={{ fontSize: '32px', marginBottom: '16px' }}>📭</div>
            <div>Chưa có dữ liệu metrics</div>
            <p style={{ fontSize: '14px', marginTop: '8px' }}>
              Hãy chạy aggregation job để tổng hợp dữ liệu
            </p>
          </div>
        )}

        {!loading && !error && data.length > 0 && (
          <ResponsiveContainer width="100%" height={400}>
            <LineChart
              data={data}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis
                dataKey="time"
                stroke="#718096"
                style={{ fontSize: '12px' }}
              />
              <YAxis
                stroke="#718096"
                style={{ fontSize: '12px' }}
                tickFormatter={(value) => value.toLocaleString()}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                wrapperStyle={{ paddingTop: '20px' }}
                iconType="line"
              />

              {/* Render lines based on visibility */}
              {visibleLines.accept && (
                <Line
                  type="monotone"
                  dataKey="accept"
                  name="ACCEPT ✅"
                  stroke={verdictConfig.accept.color}
                  strokeWidth={3}
                  dot={{ fill: verdictConfig.accept.color, strokeWidth: 2, r: 4 }}
                  activeDot={{ r: 6 }}
                />
              )}
              {visibleLines.drop && (
                <Line
                  type="monotone"
                  dataKey="drop"
                  name="DROP ❌"
                  stroke={verdictConfig.drop.color}
                  strokeWidth={3}
                  dot={{ fill: verdictConfig.drop.color, strokeWidth: 2, r: 4 }}
                  activeDot={{ r: 6 }}
                />
              )}
              {/* {visibleLines.continue && (
                <Line
                  type="monotone"
                  dataKey="continue"
                  name="CONTINUE ➡️"
                  stroke={verdictConfig.continue.color}
                  strokeWidth={3}
                  dot={{ fill: verdictConfig.continue.color, strokeWidth: 2, r: 4 }}
                  activeDot={{ r: 6 }}
                />
              )}
              {visibleLines.queue && (
                <Line
                  type="monotone"
                  dataKey="queue"
                  name="QUEUE 📋"
                  stroke={verdictConfig.queue.color}
                  strokeWidth={2}
                  dot={{ fill: verdictConfig.queue.color, strokeWidth: 2, r: 3 }}
                  activeDot={{ r: 5 }}
                  strokeDasharray="5 5"
                />
              )}
              {visibleLines.other && (
                <Line
                  type="monotone"
                  dataKey="other"
                  name="OTHER ⚙️"
                  stroke={verdictConfig.other.color}
                  strokeWidth={2}
                  dot={{ fill: verdictConfig.other.color, strokeWidth: 2, r: 3 }}
                  activeDot={{ r: 5 }}
                  strokeDasharray="3 3"
                />
              )} */}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default VerdictTimeSeriesChart;
