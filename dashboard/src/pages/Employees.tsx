import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getEmployees, flagEmployee, unflagEmployee, createEmployee } from '../api/employees';
import type { Employee } from '../types';
import RiskBadge from '../components/RiskBadge';
import EmployeeCard from '../components/EmployeeCard';
import { Search, Flag, UserPlus, X } from 'lucide-react';

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

/* ── Main Page ───────────────────────────────────────────────────── */
export default function Employees() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Employee | null>(null);
  const [showAdd, setShowAdd] = useState(false);
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

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Employees</h1>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div className="search-bar">
            <Search size={16} />
            <input placeholder="Search by name or email…" value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }} />
          </div>
          <button className="btn btn-primary" onClick={() => setShowAdd(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}>
            <UserPlus size={16} /> Add Employee
          </button>
        </div>
      </div>

      {isLoading ? <div className="loading">Loading…</div> : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Employee</th><th>Department</th><th>Risk</th>
                <th>Score</th><th>HIGH 7d</th><th>MED 7d</th><th>Flagged</th>
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
                </tr>
              ))}
              {employees.length === 0 && (
                <tr>
                  <td colSpan={7} className="table-empty">
                    No employees found. Click <strong>Add Employee</strong> to register one,
                    or run the endpoint agent (<code>python main.py</code>) to auto-register.
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
