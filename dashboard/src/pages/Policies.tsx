import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getPolicies, importPolicies, pushPolicies } from '../api/policies';
import { Upload, Send, CheckCircle2 } from 'lucide-react';

const DEFAULT_YAML = `rules:
  - name: Credit Card Number
    category: FINANCIAL
    pattern: "\\\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\\\\b"
    base_weight: 3.0
    regulation_tags: [PCI-DSS]
    description: Detects Visa/MC credit card numbers
`;

export default function Policies() {
  const [yaml, setYaml] = useState(DEFAULT_YAML);
  const [msg, setMsg] = useState('');
  const qc = useQueryClient();

  const { data: policies = [] } = useQuery({ queryKey: ['policies'], queryFn: () => getPolicies().then(r => r.data) });

  const importMut = useMutation({
    mutationFn: () => importPolicies(yaml),
    onSuccess: () => { setMsg('Imported and pushed to all agents.'); qc.invalidateQueries({ queryKey: ['policies'] }); },
    onError: () => setMsg('Import failed — check YAML syntax.'),
  });

  const pushMut = useMutation({
    mutationFn: pushPolicies,
    onSuccess: () => setMsg('All agents flagged for policy update.'),
  });

  return (
    <div className="page">
      <h1 className="page-title">Policies</h1>

      <div className="policies-grid">
        <div className="policy-list-col">
          <h2 className="section-title">Active Rules ({policies.length})</h2>
          <div className="table-card">
            {policies.map(p => (
              <div key={p.id} className="policy-row">
                <div><p className="policy-name">{p.name}</p><p className="text-muted text-sm">{p.category} · weight {p.base_weight}</p></div>
                <div className="policy-tags">{p.regulation_tags.map(t => <span key={t} className="tag">{t}</span>)}</div>
              </div>
            ))}
            {policies.length === 0 && <p className="table-empty">No policies loaded.</p>}
          </div>
        </div>

        <div className="policy-editor-col">
          <h2 className="section-title">YAML Editor</h2>
          <textarea className="yaml-editor" value={yaml} onChange={e => setYaml(e.target.value)} rows={18} spellCheck={false} />
          {msg && <div className="import-msg"><CheckCircle2 size={14} />{msg}</div>}
          <div className="policy-actions">
            <button className="btn btn-primary" onClick={() => importMut.mutate()} disabled={importMut.isPending}><Upload size={15} /> Import & Push</button>
            <button className="btn btn-outline" onClick={() => pushMut.mutate()} disabled={pushMut.isPending}><Send size={15} /> Push Existing</button>
          </div>
        </div>
      </div>
    </div>
  );
}
