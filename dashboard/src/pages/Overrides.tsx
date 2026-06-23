import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { listOverrides, reviewOverride } from '../api/overrides';
import type { OverrideRequest } from '../types';
import { CheckCircle, XCircle, Clock, X } from 'lucide-react';

const STATUS_TABS = ['PENDING', 'APPROVED', 'DENIED'] as const;

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { bg: string; color: string; icon: React.ReactNode }> = {
    PENDING:  { bg: 'rgba(245,158,11,0.15)',  color: '#f59e0b', icon: <Clock size={11} /> },
    APPROVED: { bg: 'rgba(34,197,94,0.12)',   color: '#22c55e', icon: <CheckCircle size={11} /> },
    DENIED:   { bg: 'rgba(239,68,68,0.12)',   color: '#ef4444', icon: <XCircle size={11} /> },
  };
  const s = map[status] ?? map['PENDING'];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: s.bg, color: s.color, border: `1px solid ${s.color}40`,
      borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 700,
    }}>
      {s.icon} {status}
    </span>
  );
}

function ReviewModal({ request, onClose }: { request: OverrideRequest; onClose: () => void }) {
  const [note, setNote] = useState('');
  const qc = useQueryClient();
  const mut = useMutation({
    mutationFn: ({ status }: { status: string }) =>
      reviewOverride(request.id, status, note || undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['overrides'] });
      qc.invalidateQueries({ queryKey: ['overrides-pending-count'] });
      onClose();
    },
  });

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: '#0f172a', border: '1px solid #1e293b', borderRadius: 16,
          padding: 28, width: '100%', maxWidth: 520, boxShadow: '0 25px 60px rgba(0,0,0,0.6)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <h2 style={{ color: '#e2e8f0', fontSize: 17, fontWeight: 700, margin: 0 }}>
              Review Override Request
            </h2>
            <p style={{ color: '#64748b', fontSize: 13, margin: '4px 0 0' }}>
              {request.employee_name ?? request.employee_id}
              {request.employee_email && <> · <span style={{ color: '#94a3b8' }}>{request.employee_email}</span></>}
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        {/* Event info */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <span style={{ background: '#1e293b', color: '#94a3b8', borderRadius: 6, padding: '3px 10px', fontSize: 12, fontWeight: 600 }}>
            {request.event_channel}
          </span>
          {request.pattern && (
            <span style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', borderRadius: 6, padding: '3px 10px', fontSize: 12, fontWeight: 600 }}>
              {request.pattern}
            </span>
          )}
        </div>

        {/* Justification */}
        <div style={{ background: '#1e293b', borderRadius: 10, padding: '12px 16px', marginBottom: 16 }}>
          <p style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 6px' }}>
            Employee Justification
          </p>
          <p style={{ color: '#e2e8f0', fontSize: 14, margin: 0, lineHeight: 1.5 }}>{request.justification}</p>
        </div>

        {/* Event detail */}
        {request.event_detail && (
          <div style={{ background: '#0b0f1a', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontFamily: 'monospace', fontSize: 12, color: '#94a3b8' }}>
            {request.event_detail}
          </div>
        )}

        {/* Admin note */}
        <textarea
          rows={3}
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="Admin note (optional)…"
          style={{
            width: '100%', background: '#1e293b', border: '1px solid #334155',
            borderRadius: 10, padding: '10px 14px', color: '#e2e8f0', fontSize: 13,
            resize: 'none', outline: 'none', boxSizing: 'border-box', marginBottom: 20,
          }}
        />

        {/* Actions */}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            style={{ padding: '8px 18px', borderRadius: 8, background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', cursor: 'pointer', fontSize: 13 }}
          >
            Cancel
          </button>
          <button
            onClick={() => mut.mutate({ status: 'DENIED' })}
            disabled={mut.isPending}
            style={{ padding: '8px 18px', borderRadius: 8, background: 'rgba(239,68,68,0.2)', border: '1px solid rgba(239,68,68,0.4)', color: '#ef4444', fontWeight: 700, cursor: 'pointer', fontSize: 13 }}
          >
            Deny
          </button>
          <button
            onClick={() => mut.mutate({ status: 'APPROVED' })}
            disabled={mut.isPending}
            style={{ padding: '8px 18px', borderRadius: 8, background: 'rgba(34,197,94,0.2)', border: '1px solid rgba(34,197,94,0.4)', color: '#22c55e', fontWeight: 700, cursor: 'pointer', fontSize: 13 }}
          >
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Overrides() {
  const [tab, setTab] = useState<'PENDING' | 'APPROVED' | 'DENIED'>('PENDING');
  const [reviewing, setReviewing] = useState<OverrideRequest | null>(null);

  const { data: requests = [], isLoading } = useQuery({
    queryKey: ['overrides', tab],
    queryFn: () => listOverrides(tab).then((r: { data: OverrideRequest[] }) => r.data),
    refetchInterval: 30_000,
  });

  return (
    <div className="page">
      {reviewing && <ReviewModal request={reviewing} onClose={() => setReviewing(null)} />}

      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>Override Requests</h1>
          <p style={{ color: '#64748b', fontSize: 13, margin: '4px 0 0' }}>
            Employees requesting approval for blocked data transfers
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {STATUS_TABS.map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 700,
                cursor: 'pointer', border: 'none',
                background: tab === t ? '#6366f1' : '#1e293b',
                color: tab === t ? 'white' : '#64748b',
                transition: 'all 0.15s',
              }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <div className="table-card">
        {isLoading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#475569' }}>Loading…</div>
        ) : requests.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center' }}>
            <p style={{ color: '#64748b', fontSize: 15, margin: 0 }}>No {tab.toLowerCase()} override requests</p>
          </div>
        ) : (
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Time</th>
                <th>Employee</th>
                <th>Channel</th>
                <th>Pattern</th>
                <th>Justification</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {requests.map((req: OverrideRequest) => (
                <tr key={req.id} className="table-row">
                  <td style={{ fontSize: 12, color: '#64748b', whiteSpace: 'nowrap' }}>
                    {new Date(req.created_at).toLocaleString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>
                        {req.employee_name ?? req.employee_id}
                      </span>
                      {req.employee_email && (
                        <span style={{ color: '#475569', fontSize: 11 }}>{req.employee_email}</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <span style={{ background: '#1e293b', color: '#94a3b8', borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
                      {req.event_channel}
                    </span>
                  </td>
                  <td>
                    <span style={{ color: '#a5b4fc', fontSize: 12, fontFamily: 'monospace' }}>
                      {req.pattern || '—'}
                    </span>
                  </td>
                  <td style={{ maxWidth: 220 }}>
                    <span style={{ color: '#cbd5e1', fontSize: 13 }}>
                      {req.justification.length > 60 ? req.justification.slice(0, 60) + '…' : req.justification}
                    </span>
                  </td>
                  <td><StatusBadge status={req.status} /></td>
                  <td>
                    {req.status === 'PENDING' && (
                      <button
                        onClick={() => setReviewing(req)}
                        style={{
                          padding: '5px 14px', borderRadius: 8, fontSize: 12, fontWeight: 700,
                          background: '#1e293b', border: '1px solid #334155', color: '#e2e8f0',
                          cursor: 'pointer', transition: 'background 0.15s',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = '#312e81')}
                        onMouseLeave={e => (e.currentTarget.style.background = '#1e293b')}
                      >
                        Review
                      </button>
                    )}
                    {req.admin_note && req.status !== 'PENDING' && (
                      <span style={{ fontSize: 11, color: '#64748b', fontStyle: 'italic' }}>
                        {req.admin_note.slice(0, 40)}{req.admin_note.length > 40 ? '…' : ''}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
