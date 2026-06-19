import { apiClient } from './client';
import type { Alert } from '../types';

export const getAlerts = (params?: Record<string, string | number>) =>
  apiClient.get<Alert[]>('/api/alerts', { params });

export const acknowledgeAlert = (id: string, note = '') =>
  apiClient.post(`/api/alerts/${id}/acknowledge`, { note });

export const resolveAlert = (id: string) =>
  apiClient.post(`/api/alerts/${id}/resolve`);
