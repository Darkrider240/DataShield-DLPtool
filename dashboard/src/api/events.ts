import { apiClient } from './client';
import type { DLPEvent } from '../types';

export const getEvents = (params?: Record<string, string | number>) =>
  apiClient.get<DLPEvent[]>('/api/events', { params });

export const getEvent = (id: string) =>
  apiClient.get<DLPEvent>(`/api/events/${id}`);
