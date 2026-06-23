/** Shared Recharts tooltip styling for dark theme readability */
export const CHART_TOOLTIP_PROPS = {
  contentStyle: {
    background: '#18181b',
    border: '1px solid #27272a',
    borderRadius: 8,
    color: '#e4e4e7',
  },
  labelStyle: {
    color: '#e4e4e7',
    fontWeight: 600,
    marginBottom: 4,
  },
  itemStyle: {
    color: '#e4e4e7',
  },
  wrapperStyle: {
    outline: 'none',
  },
} as const;
