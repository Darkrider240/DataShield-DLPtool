import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAlerts, acknowledgeAlert, resolveAlert } from '../api/alerts';
import AlertRow from '../components/AlertRow';
import { useState } from 'react';

export default function Alerts() {
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const qc = useQueryClient();

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts', statusFilter],
    queryFn: () => getAlerts({ status: statusFilter, per_page: 50 }).then(r => r.data),
    refetchInterval: 15000,
  });

  const ackMut   = useMutation({ mutationFn: (id: string) => acknowledgeAlert(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) });
  const resMut   = useMutation({ mutationFn: (id: string) => resolveAlert(id),     onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Alerts</h1>
        <div className="filter-bar">
          {['OPEN', 'ACKNOWLEDGED', 'RESOLVED'].map(s => (
            <button key={s} className={`btn btn-sm ${statusFilter === s ? 'btn-primary' : 'btn-outline'}`} onClick={() => setStatusFilter(s)}>{s}</button>
          ))}
        </div>
      </div>

      {isLoading ? <div className="loading">Loading…</div> : (
        <div className="alerts-list">
          {alerts.map(a => (
            <AlertRow
              key={a.id}
              alert={a}
              onAck={ackMut.mutate}
              onResolve={resMut.mutate}
            />
          ))}
          {alerts.length === 0 && <div className="table-empty">No {statusFilter.toLowerCase()} alerts.</div>}
        </div>
      )}
    </div>
  );
}
