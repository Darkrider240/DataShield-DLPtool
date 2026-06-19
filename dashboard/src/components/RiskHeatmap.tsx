import { Treemap, ResponsiveContainer, Tooltip } from 'recharts';
import type { Employee } from '../types';

const RISK_COLORS: Record<string, string> = {
  HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#3b82f6', CLEAN: '#22c55e',
};

interface Props { employees: Employee[]; }

// Recharts CustomizedContent must be a proper React component (not an inline fn)
// to satisfy the ReactElement return type constraint.
function CustomCell(props: Record<string, unknown>) {
  const { x, y, width, height, name } = props as {
    x: number; y: number; width: number; height: number;
    name: string; risk_level?: string;
  };
  const color = RISK_COLORS[(props.risk_level as string) ?? 'CLEAN'] ?? '#22c55e';
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} fill={color} fillOpacity={0.85} rx={4} stroke="#0f172a" strokeWidth={1} />
      {width > 60 && height > 24 && (
        <text x={x + width / 2} y={y + height / 2} textAnchor="middle" fill="#fff" fontSize={11} dominantBaseline="central">
          {String(name).slice(0, 16)}
        </text>
      )}
    </g>
  );
}

export default function RiskHeatmap({ employees }: Props) {
  const data = employees
    .filter((e) => e.risk_score > 0)
    .map((e) => ({
      name: e.full_name || e.email,
      size: Math.max(e.risk_score, 1),
      risk_level: e.risk_level,
    }));

  if (data.length === 0) {
    return (
      <div className="chart-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 220 }}>
        <span style={{ color: '#64748b' }}>No risk data yet</span>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <h3 className="chart-title">Employee Risk Heatmap</h3>
      <ResponsiveContainer width="100%" height={220}>
        <Treemap
          data={data}
          dataKey="size"
          nameKey="name"
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          content={<CustomCell /> as any}
        >
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
            formatter={(value: number) => [`Risk score: ${value.toFixed(1)}`, '']}
          />
        </Treemap>
      </ResponsiveContainer>
    </div>
  );
}
