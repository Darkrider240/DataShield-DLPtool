import React, { useState, useEffect } from 'react';
import type { Employee } from '../types';
import RiskBadge from './RiskBadge';
import { Flag, X } from 'lucide-react';

interface MonitoringState {
  monitor_clipboard: boolean;
  monitor_usb: boolean;
  monitor_webmail: boolean;
  monitor_file_scan: boolean;
}

interface Props { employee: Employee; onFlag: () => void; onUnflag: () => void; onClose: () => void; }

export default function EmployeeCard({ employee, onFlag, onUnflag, onClose }: Props) {
  const [monitoring, setMonitoring] = useState<MonitoringState>({
    monitor_clipboard: true,
    monitor_usb: true,
    monitor_webmail: true,
    monitor_file_scan: true,
  });
  const [monitorSaving, setMonitorSaving] = useState(false);
  const [monitorMsg, setMonitorMsg] = useState('');

  useEffect(() => {
    if (!employee?.id) return;
    fetch(`/api/employees/${employee.id}/monitoring`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
    })
      .then(r => r.json())
      .then(d => setMonitoring(d))
      .catch(() => {});
  }, [employee?.id]);

  const handleMonitorToggle = (key: string) => {
    const updated: MonitoringState = { ...monitoring, [key]: !monitoring[key as keyof MonitoringState] };
    setMonitoring(updated);
    setMonitorSaving(true);
    fetch(`/api/employees/${employee.id}/monitoring`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('access_token')}`,
      },
      body: JSON.stringify(updated),
    })
      .then(r => r.json())
      .then(() => { setMonitorMsg('Saved'); setTimeout(() => setMonitorMsg(''), 2000); })
      .catch(() => setMonitorMsg('Error saving'))
      .finally(() => setMonitorSaving(false));
  };

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
          <button
            className="btn btn-outline btn-sm"
            onClick={() => {
              const pin = prompt(`Set PIN for ${employee.full_name || employee.email}:\n(minimum 4 characters)`);
              if (!pin || pin.length < 4) { alert('PIN must be at least 4 characters'); return; }
              fetch(`/api/employees/${employee.id}/set-pin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('access_token')}` },
                body: JSON.stringify({ pin })
              }).then(r => r.json()).then(d => alert(d.message || 'PIN set')).catch(() => alert('Failed to set PIN'));
            }}
          >
            🔑 Set PIN
          </button>
        </div>

        {/* Monitoring Controls */}
        <div style={{ marginTop: 24, borderTop: '1px solid #1e293b', paddingTop: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h4 style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', margin: 0 }}>
              Monitoring Controls
            </h4>
            {monitorMsg && (
              <span style={{ color: monitorMsg === 'Saved' ? '#22c55e' : '#ef4444', fontSize: 11 }}>
                {monitorMsg}
              </span>
            )}
          </div>
          {([
            ['monitor_clipboard',  '📋 Clipboard Monitoring',        'Intercept sensitive clipboard copy/paste'],
            ['monitor_usb',        '🔌 USB Monitoring',              'Detect USB drive insertions and file transfers'],
            ['monitor_webmail',    '✉️ Webmail / Email Monitoring',  'Scan outgoing Gmail, Outlook webmail content'],
            ['monitor_file_scan',  '📁 File Scanning',               'Scan files when employee triggers manual scan'],
          ] as [string, string, string][]).map(([key, label, desc]) => (
            <div key={key} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 0', borderBottom: '1px solid #0f172a'
            }}>
              <div>
                <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{label}</div>
                <div style={{ color: '#475569', fontSize: 11, marginTop: 2 }}>{desc}</div>
              </div>
              <div
                onClick={() => !monitorSaving && handleMonitorToggle(key)}
                style={{
                  width: 44, height: 24, borderRadius: 12, flexShrink: 0,
                  background: monitoring[key as keyof MonitoringState] ? '#6366f1' : '#334155',
                  position: 'relative',
                  cursor: monitorSaving ? 'not-allowed' : 'pointer',
                  transition: 'background 0.2s',
                  marginLeft: 16,
                  opacity: monitorSaving ? 0.6 : 1,
                }}
              >
                <div style={{
                  position: 'absolute', top: 3,
                  left: monitoring[key as keyof MonitoringState] ? 23 : 3,
                  width: 18, height: 18, borderRadius: '50%',
                  background: 'white', transition: 'left 0.2s',
                }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
