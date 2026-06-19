import type { Employee } from '../types';
import RiskBadge from './RiskBadge';
import { Flag, X } from 'lucide-react';

interface Props { employee: Employee; onFlag: () => void; onUnflag: () => void; onClose: () => void; }

export default function EmployeeCard({ employee, onFlag, onUnflag, onClose }: Props) {
  return (
    <div className="employee-card-overlay" onClick={onClose}>
      <div className="employee-card" onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <div>
            <h2 className="card-name">{employee.full_name || employee.email}</h2>
            <p className="card-sub">{employee.job_title} · {employee.department}</p>
          </div>
          <div className="card-header-right">
            <RiskBadge level={employee.risk_level} />
            <button className="btn-icon" onClick={onClose}><X size={18} /></button>
          </div>
        </div>

        <div className="card-stats">
          <div className="stat"><span className="stat-value">{employee.risk_score.toFixed(1)}</span><span className="stat-label">Risk Score</span></div>
          <div className="stat"><span className="stat-value" style={{ color: '#ef4444' }}>{employee.high_violations_7d}</span><span className="stat-label">HIGH 7d</span></div>
          <div className="stat"><span className="stat-value" style={{ color: '#f59e0b' }}>{employee.medium_violations_7d}</span><span className="stat-label">MED 7d</span></div>
          <div className="stat"><span className="stat-value">{employee.total_events_30d}</span><span className="stat-label">Events 30d</span></div>
        </div>

        {employee.is_flagged && (
          <div className="flag-banner">
            <Flag size={14} /> Flagged: {employee.flag_reason}
            {employee.flagged_at && <> · {new Date(employee.flagged_at).toLocaleDateString()}</>}
          </div>
        )}

        <div className="card-footer">
          {employee.is_flagged
            ? <button className="btn btn-outline" onClick={onUnflag}>Remove Flag</button>
            : <button className="btn btn-danger"  onClick={onFlag}><Flag size={14} /> Flag Employee</button>
          }
        </div>
      </div>
    </div>
  );
}
