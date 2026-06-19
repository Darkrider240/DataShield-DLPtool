import { useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getEmployees } from '../api/employees';
import { getEvents } from '../api/events';
import { getAlerts } from '../api/alerts';
import { getMe } from '../api/auth';
import { apiClient } from '../api/client';
import type { ComplianceMetrics, WsMessage } from '../types';
import LiveFeed from '../components/LiveFeed';
import ViolationChart from '../components/ViolationChart';
import RiskHeatmap from '../components/RiskHeatmap';
import { useWebSocket } from '../hooks/useWebSocket';
import { Activity, ShieldAlert, Users, AlertTriangle } from 'lucide-react';

export default function Dashboard() {
  const [liveFeed, setLiveFeed] = useState<WsMessage[]>([]);

  const onWsEvent = useCallback((msg: WsMessage) => {
    setLiveFeed(prev => [msg, ...prev].slice(0, 100));
  }, []);
  useWebSocket(onWsEvent);

  const { data: metrics } = useQuery<ComplianceMetrics>({
    queryKey: ['metrics'],
    queryFn: () => apiClient.get<ComplianceMetrics>('/api/reports/metrics').then(r => r.data),
    refetchInterval: 30000,
  });
  const { data: events = [] } = useQuery({ queryKey: ['events-dash'], queryFn: () => getEvents({ per_page: 200 }).then(r => r.data), refetchInterval: 30000 });
  const { data: employees = [] } = useQuery({ queryKey: ['employees-dash'], queryFn: () => getEmployees(1, '').then(r => r.data) });
  const { data: alerts = [] } = useQuery({ queryKey: ['alerts-dash'], queryFn: () => getAlerts({ status: 'OPEN', per_page: 5 }).then(r => r.data), refetchInterval: 20000 });

  const METRIC_CARDS = [
    { label: 'Events Today',    value: metrics?.total_events   ?? 0, icon: Activity,     color: '#6366f1' },
    { label: 'HIGH Violations', value: metrics?.high_events    ?? 0, icon: ShieldAlert,  color: '#ef4444' },
    { label: 'Active Alerts',   value: metrics?.open_alerts    ?? 0, icon: AlertTriangle, color: '#f59e0b' },
    { label: 'Flagged Employees', value: metrics?.flagged_employees ?? 0, icon: Users,  color: '#ec4899' },
  ];

  return (
    <div className="page">
      <h1 className="page-title">Dashboard</h1>

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

      <div className="dashboard-grid">
        <div className="dashboard-col-wide">
          <ViolationChart events={events} />
          <RiskHeatmap employees={employees} />
        </div>
        <div className="dashboard-col-narrow">
          <LiveFeed events={liveFeed} />
          {alerts.length > 0 && (
            <div className="alert-preview">
              <h3 className="section-title">Recent Open Alerts</h3>
              {alerts.slice(0, 5).map(a => (
                <div key={a.id} className="alert-preview-row">
                  <span className={`sev-dot sev-${a.severity.toLowerCase()}`} />
                  <span className="alert-preview-title">{a.title}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
