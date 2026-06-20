import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import type { ComplianceMetrics } from '../types';
import { FileText, Sparkles, Loader2, Download } from 'lucide-react';

interface ExecSummary { summary: string; generated_at: string; }

export default function Reports() {
  const [summary, setSummary] = useState<ExecSummary | null>(null);

  const { data: metrics, isLoading: metricsLoading } = useQuery<ComplianceMetrics>({
    queryKey: ['metrics-reports'],
    queryFn: () => apiClient.get<ComplianceMetrics>('/api/reports/metrics').then(r => r.data),
  });

  const summaryMut = useMutation({
    mutationFn: () => apiClient.get<ExecSummary>('/api/reports/executive-summary').then(r => r.data),
    onSuccess: setSummary,
  });

  const downloadJSON = () => {
    if (!metrics) return;
    const blob = new Blob([JSON.stringify(metrics, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'datashield_metrics.json'; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <h1 className="page-title">Reports &amp; Compliance</h1>

      <div className="reports-section">
        <div className="section-header">
          <h2 className="section-title">Compliance Metrics</h2>
          <button className="btn btn-outline btn-sm" onClick={downloadJSON} disabled={!metrics}><Download size={14} /> Export JSON</button>
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

      <div className="reports-section">
        <div className="section-header">
          <h2 className="section-title">AI Executive Summary</h2>
          <button className="btn btn-primary btn-sm" onClick={() => summaryMut.mutate()} disabled={summaryMut.isPending}>
            {summaryMut.isPending ? <><Loader2 size={14} className="spin" /> Generating…</> : <><Sparkles size={14} /> Generate with Gemini</>}
          </button>
        </div>

        {summary ? (
          <div className="summary-box">
            <p className="summary-meta">Generated {new Date(summary.generated_at).toLocaleString()} · Powered by Gemini</p>
            <pre className="summary-text">{summary.summary}</pre>
          </div>
        ) : (
          <div className="summary-placeholder">
            <Sparkles size={32} style={{ color: '#6366f1', marginBottom: '8px' }} />
            <p>Click "Generate with Gemini" to produce an AI-powered DLP posture summary and remediation recommendations.</p>
          </div>
        )}
      </div>
    </div>
  );
}
