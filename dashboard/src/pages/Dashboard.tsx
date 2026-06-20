import { useQuery } from '@tanstack/react-query';
import { getEmployees } from '../api/employees';
import { getEvents } from '../api/events';
import { getAlerts } from '../api/alerts';
import { apiClient } from '../api/client';
import type { ComplianceMetrics } from '../types';
import ViolationChart from '../components/ViolationChart';
import RiskHeatmap from '../components/RiskHeatmap';
import { Activity, ShieldAlert, Users, AlertTriangle, Flag } from 'lucide-react';

export default function Dashboard() {
  const { data: metrics } = useQuery<ComplianceMetrics>({
    queryKey: ['metrics'],
    queryFn: () => apiClient.get<ComplianceMetrics>('/api/reports/metrics').then(r => r.data),
    refetchInterval: 10_000,
  });
  const { data: events = [] } = useQuery({
    queryKey: ['events-dash'],
    queryFn: () => getEvents({ per_page: 500 }).then(r => {
      console.debug('[Dashboard] events loaded:', r.data?.length);
      return r.data;
    }),
    refetchInterval: 10_000,
  });
  const { data: employees = [] } = useQuery({ queryKey: ['employees-dash'], queryFn: () => getEmployees(1, '').then(r => r.data), refetchInterval: 30_000 });
  const { data: alerts = [] }    = useQuery({ queryKey: ['alerts-dash'],    queryFn: () => getAlerts({ status: 'OPEN', per_page: 8 }).then(r => r.data), refetchInterval: 10_000 });

  const METRIC_CARDS = [
    { label: 'Events Today',       value: metrics?.total_events        ?? 0, icon: Activity,      color: '#6366f1' },
    { label: 'HIGH Violations',    value: metrics?.high_events         ?? 0, icon: ShieldAlert,   color: '#ef4444' },
    { label: 'Active Alerts',      value: metrics?.open_alerts         ?? 0, icon: AlertTriangle, color: '#f59e0b' },
    { label: 'Flagged Employees',  value: metrics?.flagged_employees   ?? 0, icon: Flag,          color: '#ec4899' },
    { label: 'Total Employees',    value: employees.length             ?? 0, icon: Users,         color: '#0ea5e9' },
  ];

  const sevColor: Record<string, string> = {
    CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#eab308', LOW: '#22c55e',
  };

  return (
    <div className="page">
      <h1 className="page-title">Dashboard</h1>

      {/* Metric cards */}
      <div className="metrics-grid">
        {METRIC_CARDS.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="metric-card">
            <div className="metric-icon" style={{ background: color + '22', color }}>
              <Icon size={22} />
            </div>
            <div>
              <p className="metric-value">{value}</p>
              <p className="metric-label">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="dashboard-grid">
        <div className="dashboard-col-wide">
          <ViolationChart events={events} />
          <RiskHeatmap employees={employees} />
        </div>

        {/* Recent alerts panel — replaces live feed */}
        <div className="dashboard-col-narrow">
          <div className="card" style={{ padding: '18px' }}>
            <h3 className="section-title" style={{ marginBottom: '12px' }}>
              Open Alerts
            </h3>
            {alerts.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No open alerts — all clear ✓</p>
            ) : (
              alerts.map(a => (
                <div key={a.id} style={{
                  display: 'flex', alignItems: 'flex-start', gap: '10px',
                  padding: '10px 0', borderBottom: '1px solid var(--border)'
                }}>
                  <span style={{
                    width: 8, height: 8, borderRadius: '50%', flexShrink: 0, marginTop: 5,
                    background: sevColor[a.severity] ?? '#64748b'
                  }} />
                  <div>
                    <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.4 }}>{a.title}</p>
                    <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 2 }}>
                      {a.severity} · {a.employee_email ?? ''}
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
