import { apiClient } from './client';
import type { Employee } from '../types';

export const getEmployees = (page = 1, search = '') =>
  apiClient.get<Employee[]>('/api/employees', { params: { page, search } });

export const getEmployee = (id: string) =>
  apiClient.get<Employee>(`/api/employees/${id}`);

export const createEmployee = (data: { email: string; full_name: string; department?: string; job_title?: string }) =>
  apiClient.post<Employee>('/api/employees', data);

export const flagEmployee = (id: string, reason: string) =>
  apiClient.post(`/api/employees/${id}/flag`, { reason });

export const unflagEmployee = (id: string) =>
  apiClient.post(`/api/employees/${id}/unflag`);
