import { apiClient } from './client';

export interface ComplianceReport {
  standard: string;
  timestamp: string;
  overall_compliance_score: number;
  checks_passed: number;
  checks_failed: number;
  integrity_hash: string;
  violations_by_regulation: Record<string, number>;
  audited_files_count: number;
  failures: Array<{
    rule_name: string;
    description: string;
    affected_files: string[];
    remediation_steps: string;
  }>;
}

export interface AiRecommendations {
  summary: string;
  remedy_plan: string[];
  systemic_risk_evaluation: string;
  generated_at: string;
}

export const generateComplianceReport = async (standard: string): Promise<ComplianceReport> => {
  const response = await apiClient.post('/api/reports/compliance', { standard });
  return response.data;
};

export const getAiRecommendations = async (): Promise<AiRecommendations> => {
  const response = await apiClient.get('/api/reports/ai-recommendations');
  return response.data;
};
