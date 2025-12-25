// Shared Pipeline Constants
export const HOOK_ORDER = ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD', 'LOCAL_OUT', 'POST_ROUTING'];
export const LAYER_ORDER = ['Ingress', 'L2', 'IP', 'Firewall', 'Socket', 'Egress'];

export const HOOK_ICONS = {
  'PRE_ROUTING': '⚙️',
  'LOCAL_IN': '📥',
  'FORWARD': '↔️',
  'LOCAL_OUT': '📤',
  'POST_ROUTING': '⚙️'
};

export const PIPELINE_DEFINITIONS = {
  Inbound: {
    mainFlow: [
      { name: 'GRO', icon: '🔄', color: '#0d47a1' },
      { name: 'TC Ingress', icon: '🚦', color: '#01579b' },
      { name: 'Netfilter PREROUTING', icon: '🔧', color: '#006064' },
      { name: 'Conntrack', icon: '🔗', color: '#00838f' },
      { name: 'Routing Decision', icon: '🗺️', color: '#00acc1' },
    ],
    branches: {
      'Local Delivery': [
        { name: 'Netfilter INPUT', icon: '🛡️', color: '#4dd0e1' },
        { name: 'TCP/UDP', icon: '📦', color: '#80deea' },
        { name: 'Socket', icon: '🔌', color: '#b2ebf2' },
      ],
      'Forward': [
        { name: 'Netfilter FORWARD', icon: '🔀', color: '#fb8c00' },
        { name: 'Netfilter POSTROUTING', icon: '⚙️', color: '#f57c00' },
      ]
    }
  },
  Outbound: [
    { name: 'Application', icon: '💻', color: '#4caf50' },
    { name: 'TCP/UDP Output', icon: '📤', color: '#43a047' },
    { name: 'Netfilter OUTPUT', icon: '🛡️', color: '#388e3c' },
    { name: 'Routing Lookup', icon: '🗺️', color: '#2e7d32' },
    { name: 'TC Egress', icon: '🚦', color: '#689f38' },
    { name: 'Driver TX', icon: '🚗', color: '#7cb342' },
  ]
};
