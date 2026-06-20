export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'superadmin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface Employee {
  id: string;
  email: string;
  full_name: string;
  department: string;
  job_title: string;
  risk_score: number;
  risk_level: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH';
  high_violations_7d: number;
  medium_violations_7d: number;
  total_events_30d: number;
  is_flagged: boolean;
  flag_reason: string;
  flagged_at: string | null;
  created_at: string;
}

export interface Agent {
  id: string;
  hostname: string;
  employee_id: string;
  employee_email: string;
  platform: string;
  agent_version: string;
  policy_version: string;
  policy_update_available: boolean;
  last_heartbeat: string | null;
  is_active: boolean;
}

export interface DLPEvent {
  id: string;
  employee_id: string;
  agent_id: string;
  channel: 'FILE' | 'EMAIL' | 'WEBMAIL' | 'CLIPBOARD' | 'USB';
  action_taken: 'ALLOW' | 'BLOCK' | 'WARN';
  justification: string;
  risk_level: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH';
  risk_score: number;
  matched_value_redacted: string;
  pattern_names: string[];
  regulation_tags: string[];
  occurred_at: string;
  ingested_at: string;
  file_path?: string;
  ai_explanation?: string;
}

export interface Alert {
  id: string;
  employee_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
  top_pattern: string;
  escalation_count: number;
  created_at: string;
  acknowledged_by: string;
  acknowledged_at: string | null;
}

export interface Policy {
  id: string;
  name: string;
  category: string;
  pattern: string;
  base_weight: number;
  regulation_tags: string[];
  description: string;
  is_active: boolean;
  version: string;
  updated_at: string;
}

export interface ComplianceMetrics {
  total_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  blocked_events: number;
  flagged_employees: number;
  open_alerts: number;
  critical_alerts: number;
  regulation_hit_counts: Record<string, number>;
}

export interface WsMessage {
  type: 'EVENT' | 'ALERT';
  [key: string]: unknown;
}
