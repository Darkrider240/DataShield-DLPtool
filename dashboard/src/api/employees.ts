import { apiClient } from './client';
import type { Employee, EmployeeStats } from '../types';

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

// Feature 6 — Report card
export const getEmployeeReport = (id: string) =>
  apiClient.get<EmployeeStats>(`/api/employees/${id}/report`);

// Feature 11 — CSV bulk import
export const importEmployeesCSV = (file: File) => {
  const form = new FormData();
  form.append('file', file);
  return apiClient.post<{ status: string; created: number; skipped: number; errors: string[] }>(
    '/api/employees/import',
    form,
    { headers: { 'Content-Type': 'multipart/form-data' } }
  );
};
