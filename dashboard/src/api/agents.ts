import { apiClient } from './client';
import { Agent } from '../types';

export const getAgents = async (): Promise<Agent[]> => {
  const response = await apiClient.get('/api/agents');
  return response.data;
};

export const getAgent = async (id: string): Promise<Agent> => {
  const response = await apiClient.get(`/api/agents/${id}`);
  return response.data;
};

export const syncAgentPolicy = async (id: string): Promise<{ status: string; message: string }> => {
  const response = await apiClient.post(`/api/agents/${id}/sync`);
  return response.data;
};
