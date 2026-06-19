import { useEffect, useRef, useCallback } from 'react';
import type { WsMessage } from '../types';

const WS_BASE = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000';

export function useWebSocket(onEvent: (msg: WsMessage) => void) {
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryCount = useRef(0);

  const connect = useCallback(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    const ws = new WebSocket(`${WS_BASE}/ws/events?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => { retryCount.current = 0; };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as WsMessage;
        onEvent(msg);
      } catch { /* ignore parse errors */ }
    };

    ws.onclose = () => {
      const delay = Math.min(1000 * 2 ** retryCount.current, 30000);
      retryCount.current += 1;
      retryRef.current = setTimeout(connect, delay);
    };

    ws.onerror = () => ws.close();
  }, [onEvent]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
      if (retryRef.current) clearTimeout(retryRef.current);
    };
  }, [connect]);
}
