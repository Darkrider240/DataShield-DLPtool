import { apiClient } from './client';
import type { Employee } from '../types';

export const getEmployees = (page = 1, search = '') =>
  apiClient.get<Employee[]>('/api/employees', { params: { page, search } });

export const getEmployee = (id: string) =>
  apiClient.get<Employee>(`/api/employees/${id}`);

export const flagEmployee = (id: string, reason: string) =>
  apiClient.post(`/api/employees/${id}/flag`, { reason });

export const unflagEmployee = (id: string) =>
  apiClient.post(`/api/employees/${id}/unflag`);
