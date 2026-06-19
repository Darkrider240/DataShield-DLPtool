import { apiClient } from './client';

export const getKeyStatus = () =>
  apiClient.get<{ master_key_age_days: number; total_employees: number; dek_rotation_needed: boolean }>('/api/encryption/status');

export const rotateKeys = () =>
  apiClient.post<{ employees_rotated: number; status: string }>('/api/encryption/rotate');
