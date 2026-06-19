import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getEmployees, flagEmployee, unflagEmployee } from '../api/employees';
import type { Employee } from '../types';
import RiskBadge from '../components/RiskBadge';
import EmployeeCard from '../components/EmployeeCard';
import { Search, Flag } from 'lucide-react';

export default function Employees() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Employee | null>(null);
  const qc = useQueryClient();

  const { data: employees = [], isLoading } = useQuery({
    queryKey: ['employees', page, search],
    queryFn: () => getEmployees(page, search).then(r => r.data),
  });

  const flagMut = useMutation({ mutationFn: ({ id, reason }: { id: string; reason: string }) => flagEmployee(id, reason), onSuccess: () => { qc.invalidateQueries({ queryKey: ['employees'] }); setSelected(null); } });
  const unflagMut = useMutation({ mutationFn: (id: string) => unflagEmployee(id), onSuccess: () => { qc.invalidateQueries({ queryKey: ['employees'] }); setSelected(null); } });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Employees</h1>
        <div className="search-bar">
          <Search size={16} />
          <input placeholder="Search by name or email…" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} />
        </div>
      </div>

      {isLoading ? <div className="loading">Loading…</div> : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr><th>Employee</th><th>Department</th><th>Risk</th><th>Score</th><th>HIGH 7d</th><th>MED 7d</th><th>Flagged</th></tr>
            </thead>
            <tbody>
              {employees.map(emp => (
                <tr key={emp.id} className="table-row clickable" onClick={() => setSelected(emp)}>
                  <td><div className="emp-cell"><div className="emp-avatar">{(emp.full_name || emp.email)[0]}</div><div><p className="emp-name">{emp.full_name || '—'}</p><p className="emp-email">{emp.email}</p></div></div></td>
                  <td><span className="text-muted">{emp.department || '—'}</span></td>
                  <td><RiskBadge level={emp.risk_level} /></td>
                  <td><span className="score-num">{emp.risk_score.toFixed(1)}</span></td>
                  <td><span style={{ color: '#ef4444' }}>{emp.high_violations_7d}</span></td>
                  <td><span style={{ color: '#f59e0b' }}>{emp.medium_violations_7d}</span></td>
                  <td>{emp.is_flagged && <Flag size={14} style={{ color: '#ef4444' }} />}</td>
                </tr>
              ))}
              {employees.length === 0 && <tr><td colSpan={7} className="table-empty">No employees found.</td></tr>}
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
    </div>
  );
}
