import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { DLPEvent } from '../types';

interface Props { events: DLPEvent[]; }

function buildChartData(events: DLPEvent[]) {
  const days: Record<string, { date: string; HIGH: number; MEDIUM: number; LOW: number }> = {};
  const now = Date.now();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    days[key] = { date: key.slice(5), HIGH: 0, MEDIUM: 0, LOW: 0 };
  }
  events.forEach((ev) => {
    const key = ev.occurred_at.slice(0, 10);
    if (days[key] && ev.risk_level !== 'CLEAN') {
      days[key][ev.risk_level as 'HIGH' | 'MEDIUM' | 'LOW'] += 1;
    }
  });
  return Object.values(days);
}

export default function ViolationChart({ events }: Props) {
  const data = buildChartData(events);
  return (
    <div className="chart-card">
      <h3 className="chart-title">Violations — Last 7 Days</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
          <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
          <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} labelStyle={{ color: '#e2e8f0' }} />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Bar dataKey="HIGH"   fill="#ef4444" radius={[4, 4, 0, 0]} />
          <Bar dataKey="MEDIUM" fill="#f59e0b" radius={[4, 4, 0, 0]} />
          <Bar dataKey="LOW"    fill="#3b82f6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
