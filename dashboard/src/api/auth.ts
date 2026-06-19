import { apiClient } from './client';
import type { User } from '../types';

export const login = (email: string, password: string) =>
  apiClient.post<{ access_token: string; refresh_token: string }>('/api/auth/login', { email, password });

export const getMe = () => apiClient.get<User>('/api/auth/me');
