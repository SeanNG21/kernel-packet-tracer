import React from 'react';
import PacketVolumeChart from '../components/Metrics/PacketVolumeChart';
import VerdictTimeSeriesChart from '../components/Metrics/VerdictTimeSeriesChart';

/**
 * MetricsView - Page displaying time-series metrics charts
 *
 * This page shows:
 * 1. Packet Volume Chart - Total packets per 10-minute bucket
 * 2. Verdict Statistics Chart - Verdict counts (ACCEPT, DROP, CONTINUE, etc.) per 10-minute bucket
 */
const MetricsView = () => {
  return (
    <div style={{
      padding: '24px',
      maxWidth: '1400px',
      margin: '0 auto'
    }}>
      {/* Page Header */}
      <div style={{
        marginBottom: '32px',
        textAlign: 'center'
      }}>
        <h1 style={{
          fontSize: '32px',
          fontWeight: '800',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '12px'
        }}>
          📊 Time-Series Metrics Dashboard
        </h1>
        <p style={{
          color: '#718096',
          fontSize: '16px',
          maxWidth: '600px',
          margin: '0 auto'
        }}>
          Phân tích packet volume và verdict statistics theo thời gian (10-minute buckets)
        </p>
      </div>

      {/* Info Box */}
      <div style={{
        background: 'linear-gradient(135deg, #e0f7fa 0%, #b2ebf2 100%)',
        borderRadius: '12px',
        padding: '16px 20px',
        marginBottom: '24px',
        border: '2px solid #00acc1',
        display: 'flex',
        alignItems: 'center',
        gap: '12px'
      }}>
        <div style={{ fontSize: '24px' }}>ℹ️</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: '600', color: '#006064', marginBottom: '4px' }}>
            Lưu ý về dữ liệu
          </div>
          <div style={{ fontSize: '14px', color: '#00838f' }}>
            Dữ liệu metrics được tổng hợp mỗi 10 phút bởi aggregation job.
            Nếu chưa có dữ liệu, hãy chạy: <code style={{
              background: '#fff',
              padding: '2px 6px',
              borderRadius: '4px',
              fontFamily: 'monospace'
            }}>python3 backend/metrics_aggregator.py</code>
          </div>
        </div>
      </div>

      {/* Charts */}
      <PacketVolumeChart />
      <VerdictTimeSeriesChart />

      {/* Footer Info */}
      <div style={{
        marginTop: '32px',
        padding: '20px',
        background: 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)',
        borderRadius: '12px',
        textAlign: 'center'
      }}>
        <p style={{
          margin: '0 0 8px 0',
          color: '#4a5568',
          fontSize: '14px',
          fontWeight: '600'
        }}>
          💡 Tips
        </p>
        <ul style={{
          margin: 0,
          padding: 0,
          listStyle: 'none',
          color: '#718096',
          fontSize: '13px'
        }}>
          <li style={{ marginBottom: '6px' }}>
            📅 Chọn time range (1h, 2h, 24h, 7d) để xem dữ liệu trong khoảng thời gian khác nhau
          </li>
          <li style={{ marginBottom: '6px' }}>
            👁️ Click vào các nút verdict type để ẩn/hiện từng đường trên đồ thị
          </li>
          <li>
            🔄 Dữ liệu tự động refresh mỗi 10 phút
          </li>
        </ul>
      </div>
    </div>
  );
};

export default MetricsView;
