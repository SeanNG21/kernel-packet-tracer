/**
 * Pipeline Utility Functions
 * Shared helper functions for pipeline visualization and data processing
 */

/**
 * Get drop rate color based on drop percentage
 * @param {number} dropRate - Drop percentage (0-100)
 * @returns {string} - Color hex code
 */
export const getDropRateColor = (dropRate) => {
  if (dropRate === 0) return '#4caf50'; // Green - no drops
  if (dropRate < 5) return '#8bc34a'; // Light green - low drops
  if (dropRate < 10) return '#ffeb3b'; // Yellow - moderate drops
  if (dropRate < 20) return '#ff9800'; // Orange - significant drops
  return '#f44336'; // Red - critical drops
};

/**
 * Format latency value to human-readable string
 * @param {number} latency - Latency in microseconds
 * @returns {string} - Formatted latency string
 */
export const formatLatency = (latency) => {
  if (!latency) return 'N/A';
  if (latency < 1000) return `${latency.toFixed(1)}µs`;
  if (latency < 1000000) return `${(latency / 1000).toFixed(1)}ms`;
  return `${(latency / 1000000).toFixed(1)}s`;
};

/**
 * Format packet count to human-readable string
 * @param {number} count - Packet count
 * @returns {string} - Formatted count string
 */
export const formatCount = (count) => {
  if (!count) return '0';
  if (count < 1000) return count.toString();
  if (count < 1000000) return `${(count / 1000).toFixed(1)}K`;
  return `${(count / 1000000).toFixed(1)}M`;
};

/**
 * Calculate percentage value with boundary checks
 * @param {number} value - Current value
 * @param {number} max - Maximum value
 * @returns {number} - Percentage (0-100)
 */
export const calculatePercentage = (value, max) => {
  if (max <= 0) return 0;
  return Math.min((value / max) * 100, 100);
};

/**
 * Get verdict color for packet verdicts
 * @param {string} verdict - Verdict type (ACCEPT, DROP, REJECT, etc)
 * @returns {string} - Color hex code
 */
export const getVerdictColor = (verdict) => {
  const verdictColors = {
    'ACCEPT': '#4caf50',
    'DROP': '#f44336',
    'REJECT': '#ff5722',
    'QUEUE': '#ff9800',
    'REPEAT': '#2196f3',
    'NF_STOLEN': '#9c27b0'
  };
  return verdictColors[verdict] || '#999999';
};

/**
 * Sort hook orders based on predefined order
 * @param {array} hooks - Array of hook objects
 * @param {array} order - Predefined order array
 * @returns {array} - Sorted hooks
 */
export const sortHooksByOrder = (hooks, order) => {
  return hooks.sort((a, b) => {
    const indexA = order.indexOf(a);
    const indexB = order.indexOf(b);
    if (indexA === -1) return 1;
    if (indexB === -1) return -1;
    return indexA - indexB;
  });
};
