import type { WsMessage } from '../types';
import { Activity } from 'lucide-react';

interface Props { events: WsMessage[]; }

const CHANNEL_COLOR: Record<string, string> = {
  EMAIL: '#f97316', WEBMAIL: '#f97316', FILE: '#6366f1',
  USB: '#ef4444', CLIPBOARD: '#8b5cf6',
};

export default function LiveFeed({ events }: Props) {
  return (
    <div className="live-feed">
      <div className="live-feed-header">
        <Activity size={16} className="pulse-icon" />
        <span>Live Feed</span>
        <span className="live-badge">LIVE</span>
      </div>
      <div className="live-feed-list">
        {events.length === 0 && (
          <div className="feed-empty">Waiting for events…</div>
        )}
        {events.slice(0, 50).map((ev, i) => (
          <div key={i} className="feed-item">
            <span className="feed-dot" style={{ background: CHANNEL_COLOR[(ev.channel as string) ?? ''] ?? '#64748b' }} />
            <span className="feed-type">{ev.type}</span>
            <span className="feed-channel">{ev.channel as string}</span>
            <span className={`feed-risk feed-risk-${(ev.risk_level as string ?? '').toLowerCase()}`}>
              {ev.risk_level as string}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
