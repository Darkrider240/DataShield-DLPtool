import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getEmployees, flagEmployee, unflagEmployee, createEmployee, getEmployeeReport, importEmployeesCSV } from '../api/employees';
import type { Employee, EmployeeStats } from '../types';
import RiskBadge from '../components/RiskBadge';
import EmployeeCard from '../components/EmployeeCard';
import { Search, Flag, UserPlus, X, Upload, AlertTriangle, Printer } from 'lucide-react';

/* ── Add Employee Modal ──────────────────────────────────────────── */
function AddEmployeeModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({ full_name: '', email: '', department: '', job_title: '' });
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.full_name.trim() || !form.email.trim()) {
      setError('Name and email are required.');
      return;
    }
    setSaving(true);
    try {
      await createEmployee(form);
      onSaved();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to create employee.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Add Employee</h2>
          <button className="icon-btn" onClick={onClose}><X size={18} /></button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body">
          {error && <div className="error-banner">{error}</div>}
          <div className="form-group">
            <label className="form-label">Full Name *</label>
            <input className="form-input" placeholder="Jane Smith"
              value={form.full_name} onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label">Work Email *</label>
            <input className="form-input" placeholder="jane@company.com" type="email"
              value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label">Department</label>
            <input className="form-input" placeholder="Engineering"
              value={form.department} onChange={e => setForm(f => ({ ...f, department: e.target.value }))} />
          </div>
          <div className="form-group">
            <label className="form-label">Job Title</label>
            <input className="form-input" placeholder="Software Engineer"
              value={form.job_title} onChange={e => setForm(f => ({ ...f, job_title: e.target.value }))} />
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Add Employee'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Feature 6: Report Card Drawer ───────────────────────────────── */
function ReportDrawer({ employeeId, onClose }: { employeeId: string; onClose: () => void }) {
  const { data: stats, isLoading } = useQuery<EmployeeStats>({
    queryKey: ['employee-report', employeeId],
    queryFn: () => getEmployeeReport(employeeId).then(r => r.data),
  });

  const scoreColor = (s: number) => s >= 10 ? '#ef4444' : s >= 5 ? '#f59e0b' : '#22c55e';

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 50, display: 'flex', justifyContent: 'flex-end' }}
      onClick={onClose}
    >
      <div
        style={{ width: '100%', maxWidth: 480, background: '#0f172a', borderLeft: '1px solid #1e293b', height: '100%', overflowY: 'auto', padding: 24 }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h2 style={{ color: '#e2e8f0', fontSize: 17, fontWeight: 700, margin: 0 }}>Employee Report Card</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {isLoading && <div style={{ color: '#64748b', textAlign: 'center', padding: 40 }}>Loading report…</div>}

        {stats && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Identity */}
            <div style={{ background: '#1e293b', borderRadius: 12, padding: 16 }}>
              <p style={{ color: '#e2e8f0', fontSize: 17, fontWeight: 700, margin: '0 0 2px' }}>{stats.employee_name}</p>
              <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>{stats.employee_email}</p>
              {stats.is_flagged && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#ef4444', fontSize: 13, marginTop: 8 }}>
                  <AlertTriangle size={14} />
                  <span>Flagged: {stats.flag_reason || 'Risk threshold exceeded'}</span>
                </div>
              )}
            </div>

            {/* Risk score */}
            <div style={{ background: '#1e293b', borderRadius: 12, padding: 16 }}>
              <p style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 10px' }}>Risk Score (30 days)</p>
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16 }}>
                <span style={{ fontSize: 40, fontWeight: 800, color: scoreColor(stats.risk_score), lineHeight: 1 }}>
                  {stats.risk_score.toFixed(1)}
                </span>
                <span style={{ color: '#475569', fontSize: 13, paddingBottom: 4 }}>
                  Org avg: {stats.org_avg_risk_score.toFixed(1)}
                </span>
              </div>
            </div>

            {/* Violation counts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
              {([['HIGH', stats.high_events_30d, '#ef4444'], ['MEDIUM', stats.medium_events_30d, '#f59e0b'], ['LOW', stats.low_events_30d, '#0ea5e9']] as [string, number, string][]).map(([label, count, color]) => (
                <div key={label} style={{ background: '#1e293b', borderRadius: 10, padding: '12px 0', textAlign: 'center' }}>
                  <p style={{ fontSize: 26, fontWeight: 800, color, margin: '0 0 2px' }}>{count}</p>
                  <p style={{ fontSize: 11, color: '#64748b', margin: 0 }}>{label}</p>
                </div>
              ))}
            </div>

            {/* Top patterns */}
            {stats.top_patterns.length > 0 && (
              <div style={{ background: '#1e293b', borderRadius: 12, padding: 16 }}>
                <p style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 10px' }}>Top Patterns Triggered</p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {stats.top_patterns.map(p => (
                    <span key={p} style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 6, padding: '3px 10px', fontSize: 12, fontWeight: 600 }}>
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Channel breakdown */}
            {Object.keys(stats.channel_breakdown).length > 0 && (
              <div style={{ background: '#1e293b', borderRadius: 12, padding: 16 }}>
                <p style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 12px' }}>Channel Breakdown</p>
                {Object.entries(stats.channel_breakdown).map(([ch, count]) => (
                  <div key={ch} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span style={{ color: '#94a3b8', fontSize: 13, width: 80 }}>{ch}</span>
                    <div style={{ flex: 1, background: '#0b0f1a', borderRadius: 4, height: 6 }}>
                      <div style={{
                        background: '#6366f1', height: 6, borderRadius: 4,
                        width: `${Math.min(100, (count / stats.total_events_30d) * 100)}%`
                      }} />
                    </div>
                    <span style={{ color: '#64748b', fontSize: 12, width: 20, textAlign: 'right' }}>{count}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Print button */}
            <button
              onClick={() => window.print()}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, width: '100%', padding: '11px 0', borderRadius: 10, background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}
            >
              <Printer size={15} /> Print Report Card
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────────── */
export default function Employees() {
  const [search, setSearch]       = useState('');
  const [page, setPage]           = useState(1);
  const [selected, setSelected]   = useState<Employee | null>(null);
  const [showAdd, setShowAdd]     = useState(false);
  const [reportId, setReportId]   = useState<string | null>(null);
  const [importMsg, setImportMsg] = useState('');
  const csvRef                    = useRef<HTMLInputElement>(null);
  const qc = useQueryClient();

  const { data: employees = [], isLoading } = useQuery({
    queryKey: ['employees', page, search],
    queryFn: () => getEmployees(page, search).then(r => r.data),
  });

  const flagMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => flagEmployee(id, reason),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['employees'] }); setSelected(null); }
  });
  const unflagMut = useMutation({
    mutationFn: (id: string) => unflagEmployee(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['employees'] }); setSelected(null); }
  });

  // Feature 11 — CSV import
  const handleCSVImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    setImportMsg('Importing…');
    try {
      const res = await importEmployeesCSV(file);
      const { created, skipped } = res.data;
      setImportMsg(`✓ Imported ${created} employee(s). Skipped: ${skipped}.`);
      qc.invalidateQueries({ queryKey: ['employees'] });
    } catch (err: any) {
      setImportMsg(`✗ Import failed: ${err?.response?.data?.detail || 'Unknown error'}`);
    }
    setTimeout(() => setImportMsg(''), 5000);
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Employees</h1>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <div className="search-bar">
            <Search size={16} />
            <input placeholder="Search by name or email…" value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }} />
          </div>

          {/* Feature 11: CSV Import */}
          <label
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 8, background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', fontSize: 13, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}
            title="Import employees from CSV (columns: name, email, department)"
          >
            <Upload size={14} /> Import CSV
            <input ref={csvRef} type="file" accept=".csv" style={{ display: 'none' }} onChange={handleCSVImport} />
          </label>

          <button className="btn btn-primary" onClick={() => setShowAdd(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}>
            <UserPlus size={16} /> Add Employee
          </button>
        </div>
      </div>

      {/* Import status message */}
      {importMsg && (
        <div style={{
          padding: '8px 16px', borderRadius: 8, marginBottom: 12, fontSize: 13,
          background: importMsg.startsWith('✓') ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
          color: importMsg.startsWith('✓') ? '#22c55e' : '#ef4444',
          border: `1px solid ${importMsg.startsWith('✓') ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
        }}>
          {importMsg}
        </div>
      )}

      {/* CSV template hint */}
      <p style={{ color: '#475569', fontSize: 11, marginBottom: 12 }}>
        CSV template columns: <code style={{ color: '#94a3b8' }}>name, email, department</code>
      </p>

      {isLoading ? <div className="loading">Loading…</div> : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Employee</th><th>Department</th><th>Risk</th>
                <th>Score</th><th>HIGH 7d</th><th>MED 7d</th><th>Flagged</th><th>Report</th>
              </tr>
            </thead>
            <tbody>
              {employees.map(emp => (
                <tr key={emp.id} className="table-row clickable" onClick={() => setSelected(emp)}>
                  <td>
                    <div className="emp-cell">
                      <div className="emp-avatar">{(emp.full_name || emp.email)[0].toUpperCase()}</div>
                      <div>
                        <p className="emp-name">{emp.full_name || '—'}</p>
                        <p className="emp-email">{emp.email}</p>
                      </div>
                    </div>
                  </td>
                  <td><span className="text-muted">{emp.department || '—'}</span></td>
                  <td><RiskBadge level={emp.risk_level} /></td>
                  <td><span className="score-num">{emp.risk_score.toFixed(1)}</span></td>
                  <td><span style={{ color: '#ef4444' }}>{emp.high_violations_7d}</span></td>
                  <td><span style={{ color: '#f59e0b' }}>{emp.medium_violations_7d}</span></td>
                  <td>{emp.is_flagged && <Flag size={14} style={{ color: '#ef4444' }} />}</td>
                  <td>
                    {/* Feature 6: Report card button */}
                    <button
                      onClick={e => { e.stopPropagation(); setReportId(emp.id); }}
                      style={{ padding: '4px 10px', borderRadius: 6, background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}
                      title="View 30-day report card"
                    >
                      Report
                    </button>
                  </td>
                </tr>
              ))}
              {employees.length === 0 && (
                <tr>
                  <td colSpan={8} className="table-empty">
                    No employees found. Click <strong>Add Employee</strong> or <strong>Import CSV</strong> to register employees.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="pagination">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</button>
        <span>Page {page}</span>
        <button className="btn btn-sm" disabled={employees.length < 20} onClick={() => setPage(p => p + 1)}>Next</button>
      </div>

      {/* Feature 6: Report card side drawer */}
      {reportId && <ReportDrawer employeeId={reportId} onClose={() => setReportId(null)} />}

      {selected && (
        <EmployeeCard
          employee={selected}
          onClose={() => setSelected(null)}
          onFlag={() => flagMut.mutate({ id: selected.id, reason: 'Manually flagged by admin' })}
          onUnflag={() => unflagMut.mutate(selected.id)}
        />
      )}

      {showAdd && (
        <AddEmployeeModal
          onClose={() => setShowAdd(false)}
          onSaved={() => qc.invalidateQueries({ queryKey: ['employees'] })}
        />
      )}
    </div>
  );
}
