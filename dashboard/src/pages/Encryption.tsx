import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { KeyRound, RotateCcw, ShieldCheck, AlertTriangle, Loader2 } from 'lucide-react';

// Extend the types locally
interface KeyStatus { master_key_age_days: number; total_employees: number; dek_rotation_needed: boolean; }
interface RotationStatus { employees_rotated: number; status: string; }

export default function Encryption() {
  const [confirm, setConfirm] = useState(false);
  const [rotationResult, setRotationResult] = useState<RotationStatus | null>(null);

  const { data: status, isLoading, refetch } = useQuery<KeyStatus>({
    queryKey: ['key-status'],
    queryFn: () => apiClient.get<KeyStatus>('/api/encryption/status').then(r => r.data),
  });

  const rotateMut = useMutation({
    mutationFn: () => apiClient.post<RotationStatus>('/api/encryption/rotate').then(r => r.data),
    onSuccess: (data) => { setRotationResult(data); setConfirm(false); refetch(); },
  });

  return (
    <div className="page">
      <h1 className="page-title">Encryption &amp; Key Management</h1>

      {isLoading ? <div className="loading">Loading…</div> : status && (
        <>
          <div className="encryption-cards">
            <div className="enc-card">
              <KeyRound size={24} style={{ color: '#6366f1' }} />
              <div>
                <p className="enc-label">Master Key Age</p>
                <p className="enc-value">{status.master_key_age_days} days</p>
              </div>
            </div>
            <div className="enc-card">
              <ShieldCheck size={24} style={{ color: '#22c55e' }} />
              <div>
                <p className="enc-label">Employees with DEK</p>
                <p className="enc-value">{status.total_employees}</p>
              </div>
            </div>
            <div className={`enc-card ${status.dek_rotation_needed ? 'enc-warn' : ''}`}>
              {status.dek_rotation_needed ? <AlertTriangle size={24} style={{ color: '#f59e0b' }} /> : <ShieldCheck size={24} style={{ color: '#22c55e' }} />}
              <div>
                <p className="enc-label">Rotation Status</p>
                <p className="enc-value">{status.dek_rotation_needed ? 'Rotation recommended' : 'Up to date'}</p>
              </div>
            </div>
          </div>

          <div className="enc-info-box">
            <h2 className="section-title">About Envelope Encryption</h2>
            <p className="text-muted">Each employee's sensitive data (file paths, AI explanations) is encrypted with a unique AES-256-GCM Data Encryption Key (DEK). The DEK itself is encrypted by the master key derived from your passphrase using PBKDF2-HMAC-SHA256. Rotating keys re-encrypts all DEKs and event data with fresh keys — the master passphrase never changes.</p>
          </div>

          {rotationResult && (
            <div className="rotation-result">
              <ShieldCheck size={16} style={{ color: '#22c55e' }} />
              Key rotation complete — {rotationResult.employees_rotated} employee(s) rotated.
            </div>
          )}

          {!confirm ? (
            <button className="btn btn-danger" onClick={() => setConfirm(true)}>
              <RotateCcw size={16} /> Rotate All Employee Keys
            </button>
          ) : (
            <div className="confirm-box">
              <p>⚠️ This will re-encrypt all employee DEKs and event data. This operation is irreversible. Proceed?</p>
              <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                <button className="btn btn-danger" onClick={() => rotateMut.mutate()} disabled={rotateMut.isPending}>
                  {rotateMut.isPending ? <><Loader2 size={14} className="spin" /> Rotating…</> : 'Confirm Rotation'}
                </button>
                <button className="btn btn-outline" onClick={() => setConfirm(false)}>Cancel</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
