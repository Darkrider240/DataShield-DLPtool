import type { Alert } from '../types';
import { AlertTriangle, CheckCircle2, Clock } from 'lucide-react';

interface Props { alert: Alert; onAck: (id: string) => void; onResolve: (id: string) => void; }

const SEV_COLOR: Record<string, string> = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#3b82f6' };

export default function AlertRow({ alert, onAck, onResolve }: Props) {
  const color = SEV_COLOR[alert.severity] ?? '#64748b';
  return (
    <div className="alert-row" style={{ borderLeftColor: color }}>
      <div className="alert-row-left">
        <AlertTriangle size={16} style={{ color }} />
        <div>
          <p className="alert-title">{alert.title}</p>
          <p className="alert-meta">
            {alert.severity} · {alert.top_pattern} · {new Date(alert.created_at).toLocaleString()}
            {alert.escalation_count > 1 && <span className="escalation-badge"> ×{alert.escalation_count}</span>}
          </p>
          <p className="alert-desc">{alert.description}</p>
        </div>
      </div>
      <div className="alert-row-actions">
        {alert.status === 'OPEN' && (
          <>
            <button className="btn-sm btn-warn" onClick={() => onAck(alert.id)}><Clock size={14} /> Ack</button>
            <button className="btn-sm btn-ok"   onClick={() => onResolve(alert.id)}><CheckCircle2 size={14} /> Resolve</button>
          </>
        )}
        {alert.status !== 'OPEN' && <span className="status-chip">{alert.status}</span>}
      </div>
    </div>
  );
}
