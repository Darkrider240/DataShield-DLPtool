import { apiClient } from './client';
import type { Policy } from '../types';

export const getPolicies = () => apiClient.get<Policy[]>('/api/policies');

export const importPolicies = (yaml_content: string) =>
  apiClient.post('/api/policies/import', { yaml_content });

export const pushPolicies = () => apiClient.post('/api/policies/push');
