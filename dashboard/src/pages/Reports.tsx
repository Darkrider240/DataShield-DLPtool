import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import type { ComplianceMetrics } from '../types';
import { Sparkles, Loader2, Download, RefreshCw, Clock } from 'lucide-react';

interface ExecSummary { summary: string; generated_at: string; }

const CACHE_TTL_MS = 10 * 60 * 1000; // mirrors server-side 10-minute cache

export default function Reports() {
  const [summary, setSummary]     = useState<ExecSummary | null>(null);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);

  const { data: metrics, isLoading: metricsLoading } = useQuery<ComplianceMetrics>({
    queryKey: ['metrics-reports'],
    queryFn:  () => apiClient.get<ComplianceMetrics>('/api/reports/metrics').then(r => r.data),
  });

  const summaryMut = useMutation({
    mutationFn: () => apiClient.get<ExecSummary>('/api/reports/executive-summary').then(r => r.data),
    onSuccess: (data) => {
      setSummary(data);
      setFetchedAt(new Date());
    },
  });

  /** Whether the local copy of the summary is still within the 10-min cache window. */
  const isCached = fetchedAt && (Date.now() - fetchedAt.getTime() < CACHE_TTL_MS);

  const downloadJSON = () => {
    if (!metrics) return;
    const blob = new Blob([JSON.stringify(metrics, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'datashield_metrics.json'; a.click();
    URL.revokeObjectURL(url);
  };

  const isError = summary?.summary?.startsWith('Gemini error') ||
                  summary?.summary?.startsWith('All Gemini models') ||
                  summary?.summary?.startsWith('Gemini API key');

  return (
    <div className="page">
      <h1 className="page-title">Reports &amp; Compliance</h1>

      {/* ── Compliance Metrics ─────────────────────────────────────────────── */}
      <div className="reports-section">
        <div className="section-header">
          <h2 className="section-title">Compliance Metrics</h2>
          <button className="btn btn-outline btn-sm" onClick={downloadJSON} disabled={!metrics}>
            <Download size={14} /> Export JSON
          </button>
        </div>

        {metricsLoading ? <div className="loading">Loading…</div> : metrics && (
          <>
            <div className="metrics-grid" style={{ marginBottom: '24px' }}>
              {[
                { label: 'Total Events (Today)', value: metrics.total_events },
                { label: 'HIGH Violations',      value: metrics.high_events },
                { label: 'MEDIUM Violations',    value: metrics.medium_events },
                { label: 'Blocked Sends',        value: metrics.blocked_events },
                { label: 'Flagged Employees',    value: metrics.flagged_employees },
                { label: 'Open Alerts',          value: metrics.open_alerts },
                { label: 'Critical Alerts',      value: metrics.critical_alerts },
              ].map(({ label, value }) => (
                <div key={label} className="metric-card compact">
                  <p className="metric-value">{value}</p>
                  <p className="metric-label">{label}</p>
                </div>
              ))}
            </div>

            {Object.keys(metrics.regulation_hit_counts).length > 0 && (
              <div className="reg-table">
                <h3 className="section-title" style={{ marginBottom: '12px' }}>Regulation Hit Counts (All-time)</h3>
                <table className="data-table">
                  <thead><tr><th>Regulation</th><th>Hits</th></tr></thead>
                  <tbody>
                    {Object.entries(metrics.regulation_hit_counts).sort((a, b) => b[1] - a[1]).map(([reg, count]) => (
                      <tr key={reg}><td><span className="tag">{reg}</span></td><td>{count}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>

      {/* ── AI Executive Summary ───────────────────────────────────────────── */}
      <div className="reports-section">
        <div className="section-header">
          <h2 className="section-title">AI Executive Summary</h2>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* Cache hint — shown after first generate */}
            {isCached && (
              <span style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Clock size={12} /> Cached · next refresh available in ~10 min
              </span>
            )}

            <button
              className="btn btn-primary btn-sm"
              onClick={() => summaryMut.mutate()}
              disabled={summaryMut.isPending}
              title={isCached ? 'Result is cached on the server for 10 minutes to preserve Gemini quota' : 'Generate AI summary'}
            >
              {summaryMut.isPending
                ? <><Loader2 size={14} className="spin" /> Generating…</>
                : summary
                  ? <><RefreshCw size={14} /> Regenerate</>
                  : <><Sparkles size={14} /> Generate with Gemini</>
              }
            </button>
          </div>
        </div>

        {/* Quota / error notice */}
        {isError && summary && (
          <div style={{
            background: '#1e293b', border: '1px solid #f59e0b', borderRadius: '8px',
            padding: '12px 16px', marginBottom: '12px', color: '#fbbf24', fontSize: '13px',
          }}>
            ⚠ {summary.summary}
            <br />
            <span style={{ color: '#94a3b8', fontSize: '12px' }}>
              The free Gemini API tier has per-minute and per-day token limits.
              Wait a minute and try again, or add a paid API key in <code>server/.env</code>.
            </span>
          </div>
        )}

        {summary && !isError ? (
          <div className="summary-box">
            <p className="summary-meta">
              Generated {new Date(summary.generated_at).toLocaleString()} · Powered by Gemini
              {isCached && ' · (serving cached result)'}
            </p>
            <pre className="summary-text">{summary.summary}</pre>
          </div>
        ) : !isError && (
          <div className="summary-placeholder">
            <Sparkles size={32} style={{ color: '#6366f1', marginBottom: '8px' }} />
            <p>Click "Generate with Gemini" to produce an AI-powered DLP posture summary and remediation recommendations.</p>
            <p style={{ fontSize: '12px', color: '#475569', marginTop: '6px' }}>
              Results are cached for 10 minutes server-side to preserve your Gemini API quota.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
