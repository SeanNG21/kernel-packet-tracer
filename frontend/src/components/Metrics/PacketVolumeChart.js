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
 * PacketVolumeChart - Time-series chart showing packet volume per 10-minute bucket
 *
 * Features:
 * - Displays total packets for each 10-minute interval
 * - Time range selector (1h, 2h, 24h, 7d)
 * - Beautiful card design matching dashboard style
 * - Interactive tooltip with detailed information
 */
const PacketVolumeChart = () => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('2h');
  const [summary, setSummary] = useState(null);
  const [dataSource, setDataSource] = useState(null); // 'realtime' or 'aggregation'

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      // PRIORITY 1: Try realtime tracer data first
      let response;
      let source = 'aggregation';

      try {
        const token = localStorage.getItem('token');
        response = await axios.get(`${API_BASE}/metrics/realtime/packets`, {
          params: { range: timeRange },
          headers: token ? {
            'Authorization': `Bearer ${token}`
          } : {}
        });

        // Check if we have realtime data
        if (response.data.source === 'realtime_tracer' && response.data.buckets && response.data.buckets.length > 0) {
          source = 'realtime';
          console.log('[PacketVolumeChart] Using realtime tracer data');
        } else {
          throw new Error('No realtime data available');
        }
      } catch (realtimeErr) {
        // FALLBACK: Use aggregation-based data
        console.log('[PacketVolumeChart] Falling back to aggregation data');
        const token = localStorage.getItem('token');
        response = await axios.get(`${API_BASE}/metrics/packets`, {
          params: { range: timeRange },
          headers: token ? {
            'Authorization': `Bearer ${token}`
          } : {}
        });
      }

      const formattedData = response.data.buckets.map(bucket => ({
        time: new Date(bucket.start).toLocaleTimeString('vi-VN', {
          hour: '2-digit',
          minute: '2-digit',
          hour12: false,
          timeZone: 'Asia/Ho_Chi_Minh'  // GMT+7 Vietnam time
        }),
        fullTime: bucket.start,
        packets: bucket.total_packets,
        endTime: bucket.end
      }));

      setData(formattedData);
      setDataSource(source);
      setSummary({
        totalPackets: response.data.total_packets,
        totalBuckets: response.data.total_buckets,
        avgPacketsPerBucket: response.data.total_buckets > 0
          ? Math.round(response.data.total_packets / response.data.total_buckets)
          : 0
      });
      setLoading(false);
    } catch (err) {
      console.error('Error fetching packet metrics:', err);
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
            📊 {data.time}
          </p>
          <p style={{ margin: '4px 0', fontSize: '13px' }}>
            <strong>Total Packets:</strong> {data.packets.toLocaleString()}
          </p>
          <p style={{ margin: '4px 0 0 0', fontSize: '11px', opacity: 0.9 }}>
            Khoảng 10 phút: {data.time} - {new Date(data.endTime).toLocaleTimeString('vi-VN', {
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
      background: 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <h2 style={{
              margin: 0,
              color: '#2d3748',
              fontSize: '22px',
              fontWeight: '700'
            }}>
              📈 Packet Volume Over Time
            </h2>
            {dataSource && (
              <span style={{
                padding: '4px 10px',
                borderRadius: '12px',
                fontSize: '11px',
                fontWeight: '600',
                background: dataSource === 'realtime'
                  ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
                  : 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
                color: '#fff',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
              }}>
                {dataSource === 'realtime' ? '🔴 REALTIME TRACER' : '📦 DEMO/AGGREGATED'}
              </span>
            )}
          </div>
          <p style={{
            margin: 0,
            color: '#718096',
            fontSize: '14px'
          }}>
            Số lượng packet đi vào kernel theo từng khoảng 10 phút
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
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '12px',
          marginBottom: '20px'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(102, 126, 234, 0.3)'
          }}>
            <div style={{ fontSize: '24px', fontWeight: '700', marginBottom: '4px' }}>
              {summary.totalPackets.toLocaleString()}
            </div>
            <div style={{ fontSize: '12px', opacity: 0.9 }}>Total Packets</div>
          </div>
          <div style={{
            background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(245, 87, 108, 0.3)'
          }}>
            <div style={{ fontSize: '24px', fontWeight: '700', marginBottom: '4px' }}>
              {summary.avgPacketsPerBucket.toLocaleString()}
            </div>
            <div style={{ fontSize: '12px', opacity: 0.9 }}>Avg per 10min</div>
          </div>
          <div style={{
            background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
            padding: '16px',
            borderRadius: '12px',
            color: '#fff',
            boxShadow: '0 4px 12px rgba(79, 172, 254, 0.3)'
          }}>
            <div style={{ fontSize: '24px', fontWeight: '700', marginBottom: '4px' }}>
              {summary.totalBuckets}
            </div>
            <div style={{ fontSize: '12px', opacity: 0.9 }}>Time Buckets</div>
          </div>
        </div>
      )}

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
              <Line
                type="monotone"
                dataKey="packets"
                name="Total Packets"
                stroke="url(#colorPackets)"
                strokeWidth={3}
                dot={{ fill: '#667eea', strokeWidth: 2, r: 4 }}
                activeDot={{ r: 6, fill: '#764ba2' }}
              />
              <defs>
                <linearGradient id="colorPackets" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#667eea" />
                  <stop offset="100%" stopColor="#764ba2" />
                </linearGradient>
              </defs>
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default PacketVolumeChart;
