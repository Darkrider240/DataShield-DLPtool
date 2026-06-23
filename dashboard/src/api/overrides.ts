import { apiClient } from './client';
import type { OverrideRequest } from '../types';

export const listOverrides = (status = '') =>
  apiClient.get<OverrideRequest[]>(`/api/overrides${status ? `?status=${status}` : ''}`);

export const getPendingCount = () =>
  apiClient.get<{ pending: number }>('/api/overrides/pending-count');

export const reviewOverride = (id: string, status: string, admin_note?: string) =>
  apiClient.patch(`/api/overrides/${id}`, { status, admin_note });
