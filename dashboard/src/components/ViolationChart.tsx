import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, Cell } from 'recharts';
import type { DLPEvent } from '../types';

interface Props { events: DLPEvent[]; }

function buildChartData(events: DLPEvent[]) {
  const days: Record<string, { date: string; HIGH: number; MEDIUM: number; LOW: number }> = {};

  // Build last-7-days buckets in UTC
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86_400_000);
    const key = d.toISOString().slice(0, 10); // YYYY-MM-DD in UTC
    days[key] = { date: key.slice(5), HIGH: 0, MEDIUM: 0, LOW: 0 }; // display as MM-DD
  }

  events.forEach((ev) => {
    if (!ev.occurred_at) return;
    // Handle both "2026-06-19T18:04:00Z" and "2026-06-19T18:04:00+00:00"
    const raw = typeof ev.occurred_at === 'string'
      ? ev.occurred_at
      : new Date(ev.occurred_at as unknown as string).toISOString();
    const key = raw.slice(0, 10);

    if (days[key] && ev.risk_level && ev.risk_level !== 'CLEAN') {
      const lvl = ev.risk_level.toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW';
      if (lvl in days[key]) {
        days[key][lvl] += 1;
      }
    }
  });

  return Object.values(days);
}

const TOOLTIP_STYLE = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8 },
  labelStyle: { color: '#e2e8f0' },
  itemStyle: { color: '#94a3b8' },
};

export default function ViolationChart({ events }: Props) {
  const data = buildChartData(events);
  const hasData = data.some(d => d.HIGH > 0 || d.MEDIUM > 0 || d.LOW > 0);

  return (
    <div className="chart-card">
      <h3 className="chart-title">
        Violations — Last 7 Days
        {!hasData && events.length === 0 && (
          <span style={{ marginLeft: 10, fontSize: 11, color: '#475569', fontWeight: 400, textTransform: 'none' }}>
            (no events yet — run a scan to populate)
          </span>
        )}
      </h3>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
          <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
          <Tooltip {...TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Bar dataKey="HIGH"   fill="#ef4444" radius={[4, 4, 0, 0]} minPointSize={2} />
          <Bar dataKey="MEDIUM" fill="#f59e0b" radius={[4, 4, 0, 0]} minPointSize={2} />
          <Bar dataKey="LOW"    fill="#3b82f6" radius={[4, 4, 0, 0]} minPointSize={2} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
