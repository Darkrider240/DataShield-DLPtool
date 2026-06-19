import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getEvents } from '../api/events';
import RiskBadge from '../components/RiskBadge';
import { Filter } from 'lucide-react';

const CHANNELS = ['', 'FILE', 'EMAIL', 'WEBMAIL', 'USB', 'CLIPBOARD'];
const RISK_LEVELS = ['', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];

export default function Events() {
  const [page, setPage] = useState(1);
  const [channel, setChannel] = useState('');
  const [riskLevel, setRiskLevel] = useState('');

  const { data: events = [], isLoading } = useQuery({
    queryKey: ['events', page, channel, riskLevel],
    queryFn: () => getEvents({ page, per_page: 30, ...(channel && { channel }), ...(riskLevel && { risk_level: riskLevel }) }).then(r => r.data),
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Events</h1>
        <div className="filter-bar">
          <Filter size={15} />
          <select value={channel} onChange={e => { setChannel(e.target.value); setPage(1); }}>
            {CHANNELS.map(c => <option key={c} value={c}>{c || 'All Channels'}</option>)}
          </select>
          <select value={riskLevel} onChange={e => { setRiskLevel(e.target.value); setPage(1); }}>
            {RISK_LEVELS.map(r => <option key={r} value={r}>{r || 'All Risks'}</option>)}
          </select>
        </div>
      </div>

      {isLoading ? <div className="loading">Loading…</div> : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Channel</th><th>Action</th><th>Risk</th><th>Score</th><th>Pattern</th><th>File Path</th></tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev.id} className="table-row">
                  <td><span className="text-muted text-sm">{new Date(ev.occurred_at).toLocaleString()}</span></td>
                  <td><span className="channel-tag">{ev.channel}</span></td>
                  <td><span className={`action-tag action-${ev.action_taken.toLowerCase()}`}>{ev.action_taken}</span></td>
                  <td><RiskBadge level={ev.risk_level} /></td>
                  <td>{ev.risk_score.toFixed(1)}</td>
                  <td><span className="pattern-list">{ev.pattern_names.join(', ') || '—'}</span></td>
                  <td><span className="file-path">{ev.file_path ?? '••••••'}</span></td>
                </tr>
              ))}
              {events.length === 0 && <tr><td colSpan={7} className="table-empty">No events found.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      <div className="pagination">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</button>
        <span>Page {page}</span>
        <button className="btn btn-sm" disabled={events.length < 30} onClick={() => setPage(p => p + 1)}>Next</button>
      </div>
    </div>
  );
}
