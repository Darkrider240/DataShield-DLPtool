import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getEvents } from '../api/events';
import RiskBadge from '../components/RiskBadge';
import { Filter, ChevronDown, ChevronRight, User, Mail, FileText } from 'lucide-react';
import type { DLPEvent } from '../types';

const CHANNELS   = ['', 'FILE', 'EMAIL', 'WEBMAIL', 'USB', 'CLIPBOARD'];
const RISK_LEVELS = ['', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];

// ── Action badge ───────────────────────────────────────────────────────────────
function ActionBadge({ action }: { action: string }) {
  const styles: Record<string, string> = {
    BLOCK: 'bg-red-900/60 text-red-300 border border-red-700',
    WARN:  'bg-amber-900/60 text-amber-300 border border-amber-700',
    ALLOW: 'bg-green-900/40 text-green-400 border border-green-800',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold tracking-wide ${styles[action] ?? 'bg-slate-700 text-slate-300'}`}>
      {action}
    </span>
  );
}

// ── Channel badge ──────────────────────────────────────────────────────────────
function ChannelBadge({ channel }: { channel: string }) {
  const icons: Record<string, string> = {
    FILE: '📂', EMAIL: '📧', WEBMAIL: '🌐', USB: '💾', CLIPBOARD: '📋',
  };
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-700/60 text-slate-300 text-xs font-medium border border-slate-600">
      {icons[channel] ?? '⚡'} {channel}
    </span>
  );
}

// ── Expanded row — shows all attribution + email details ──────────────────────
function ExpandedRow({ ev }: { ev: DLPEvent }) {
  const isEmail = ev.channel === 'WEBMAIL' || ev.channel === 'EMAIL';

  return (
    <tr>
      <td colSpan={7} className="px-0 py-0">
        <div className="bg-slate-800/70 border-t border-slate-700 px-6 py-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">

          {/* Left: Who triggered it */}
          <div className="space-y-2">
            <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-1">
              <User size={12} /> Employee
            </p>
            <div className="space-y-1">
              <div className="flex gap-2">
                <span className="text-slate-500 w-20 shrink-0">Name</span>
                <span className="text-slate-200 font-medium">
                  {ev.employee_name ?? <span className="text-slate-500 italic">Unknown</span>}
                </span>
              </div>
              <div className="flex gap-2">
                <span className="text-slate-500 w-20 shrink-0">Email</span>
                <span className="text-slate-300">
                  {ev.employee_email ?? <span className="text-slate-500 italic">—</span>}
                </span>
              </div>
              {ev.employee_dept && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-20 shrink-0">Dept</span>
                  <span className="text-slate-300">{ev.employee_dept}</span>
                </div>
              )}
            </div>
          </div>

          {/* Right: email details or file path */}
          <div className="space-y-2">
            {isEmail ? (
              <>
                <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-1">
                  <Mail size={12} /> Email Details
                </p>
                {ev.email_subject && (
                  <div className="flex gap-2">
                    <span className="text-slate-500 w-20 shrink-0">Subject</span>
                    <span className="text-slate-200 font-medium truncate">{ev.email_subject}</span>
                  </div>
                )}
                <div className="flex gap-2">
                  <span className="text-slate-500 w-20 shrink-0">From</span>
                  <span className="text-slate-300">
                    {ev.sender_email || ev.employee_email || <span className="italic text-slate-500">unknown</span>}
                  </span>
                </div>
                <div className="flex gap-2">
                  <span className="text-slate-500 w-20 shrink-0">To</span>
                  <span className="text-slate-300 break-all">
                    {ev.recipient_emails || <span className="italic text-slate-500">unknown</span>}
                  </span>
                </div>
              </>
            ) : (
              <>
                <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-1">
                  <FileText size={12} /> File Details
                </p>
                <div className="flex gap-2">
                  <span className="text-slate-500 w-20 shrink-0">Path</span>
                  <span className="text-slate-300 font-mono text-xs break-all">
                    {ev.file_path ?? <span className="italic text-slate-500">encrypted / not authorised</span>}
                  </span>
                </div>
              </>
            )}

            {/* Patterns + Regulations always shown */}
            {ev.pattern_names?.length > 0 && (
              <div className="flex gap-2 mt-1">
                <span className="text-slate-500 w-20 shrink-0">Patterns</span>
                <div className="flex flex-wrap gap-1">
                  {ev.pattern_names.map(p => (
                    <span key={p} className="px-1.5 py-0.5 rounded bg-indigo-900/50 text-indigo-300 text-xs border border-indigo-700">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {ev.regulation_tags?.length > 0 && (
              <div className="flex gap-2">
                <span className="text-slate-500 w-20 shrink-0">Regs</span>
                <span className="text-slate-400 text-xs">{ev.regulation_tags.join(' · ')}</span>
              </div>
            )}
            {ev.ai_explanation && (
              <div className="flex gap-2 mt-1">
                <span className="text-slate-500 w-20 shrink-0">AI Note</span>
                <span className="text-slate-300 text-xs italic">{ev.ai_explanation}</span>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}

// ── Main table row ─────────────────────────────────────────────────────────────
function EventRow({ ev }: { ev: DLPEvent }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <tr
        className="table-row cursor-pointer hover:bg-slate-700/40 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        {/* Expand toggle */}
        <td className="w-6 pl-3 pr-0">
          {open
            ? <ChevronDown size={14} className="text-slate-400" />
            : <ChevronRight size={14} className="text-slate-500" />}
        </td>
        <td>
          <span className="text-slate-400 text-xs">{new Date(ev.occurred_at).toLocaleString()}</span>
        </td>
        {/* WHO */}
        <td>
          <div className="flex flex-col gap-0.5">
            <span className="text-slate-200 text-sm font-medium leading-tight">
              {ev.employee_name ?? <span className="text-slate-500 italic text-xs">Unknown</span>}
            </span>
            {ev.employee_email && (
              <span className="text-slate-500 text-xs">{ev.employee_email}</span>
            )}
          </div>
        </td>
        <td><ChannelBadge channel={ev.channel} /></td>
        <td><ActionBadge action={ev.action_taken} /></td>
        <td><RiskBadge level={ev.risk_level} /></td>
        <td>
          <span className="text-slate-400 text-xs font-mono">
            {ev.pattern_names?.[0] ?? '—'}
            {ev.pattern_names?.length > 1 && (
              <span className="text-slate-600"> +{ev.pattern_names.length - 1}</span>
            )}
          </span>
        </td>
      </tr>
      {open && <ExpandedRow ev={ev} />}
    </>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function Events() {
  const [page, setPage]           = useState(1);
  const [channel, setChannel]     = useState('');
  const [riskLevel, setRiskLevel] = useState('');

  const { data: events = [], isLoading } = useQuery({
    queryKey: ['events', page, channel, riskLevel],
    queryFn: () =>
      getEvents({
        page,
        per_page: 30,
        ...(channel    && { channel }),
        ...(riskLevel  && { risk_level: riskLevel }),
      }).then(r => r.data),
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
          <table className="data-table w-full">
            <thead>
              <tr>
                <th className="w-6" />
                <th>Time</th>
                <th>Employee</th>
                <th>Channel</th>
                <th>Action</th>
                <th>Risk</th>
                <th>Pattern</th>
              </tr>
            </thead>
            <tbody>
              {events.map(ev => <EventRow key={ev.id} ev={ev} />)}
              {events.length === 0 && (
                <tr>
                  <td colSpan={7} className="table-empty">No events found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="pagination">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
          Prev
        </button>
        <span>Page {page}</span>
        <button className="btn btn-sm" disabled={events.length < 30} onClick={() => setPage(p => p + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
