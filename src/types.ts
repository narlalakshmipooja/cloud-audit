export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  role: UserRole;
  createdAt?: unknown;
  lastLoginAt?: unknown;
}

export type LogSeverity = 'DEFAULT' | 'INFO' | 'NOTICE' | 'WARNING' | 'ERROR' | 'CRITICAL' | 'ALERT' | 'EMERGENCY';
export type LogStatus = 'SUCCESS' | 'FAILURE';
export type LogCategory = 'ADMIN_ACTIVITY' | 'DATA_ACCESS' | 'SYSTEM_EVENT' | 'POLICY_DENIED';
export type DataSource = 'GCP_LIVE' | 'DEMO';

export interface AuditLogRecord {
  id: string;
  insertId: string;
  timestamp: string;
  principalEmail: string;
  serviceName: string;
  methodName: string;
  resourceName: string;
  severity: LogSeverity;
  callerIp: string;
  status: LogStatus;
  statusCode: number;
  statusMessage: string;
  category: LogCategory;
  source: DataSource;
  projectId: string;
  rawPayload: Record<string, unknown>;
  createdAt?: unknown;
}

export type PolicyCategory = 'ALL' | LogCategory;
export type PolicyStatus = 'ENABLED' | 'DISABLED';

export interface RetentionPolicyRecord {
  id: string;
  name: string;
  description: string;
  logCategory: PolicyCategory;
  retentionDays: number;
  status: PolicyStatus;
  lastExecutionAt: string;
  lastDeletedCount: number;
  createdBy: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertRuleId =
  | 'REPEATED_FAILURES'
  | 'UNUSUAL_IAM_CHANGE'
  | 'SENSITIVE_ADMIN_OP'
  | 'ACTIVITY_SPIKE'
  | 'UNUSUAL_IP';
export type AlertStatus = 'OPEN' | 'REVIEWED' | 'CONFIRMED_INCIDENT' | 'DISMISSED';

export interface SecurityAlertRecord {
  id: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  eventTime: string;
  associatedLogId: string;
  principalEmail: string;
  callerIp: string;
  ruleId: AlertRuleId;
  detectionReason: string;
  status: AlertStatus;
  source: DataSource;
  reviewedBy: string;
  reviewedAt: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface RetentionExecutionRecord {
  id: string;
  policyId: string;
  policyName: string;
  logCategory: string;
  retentionDays: number;
  cutoffTimestamp: string;
  deletedCount: number;
  executedBy: string;
  status: 'COMPLETED' | 'DRY_RUN' | 'FAILED';
  details: string;
  executedAt?: unknown;
}

export type ConnectionStatus = 'CONNECTED' | 'DISCONNECTED' | 'MISSING_CREDENTIALS' | 'ERROR';

export interface IntegrationSettingRecord {
  id: string;
  gcpProjectId: string;
  logFilter: string;
  connectionStatus: ConnectionStatus;
  lastSyncAt: string;
  lastSyncCount: number;
  lastError: string;
  demoMode: boolean;
  updatedBy: string;
  updatedAt?: unknown;
}

export interface LogFilterParams {
  search?: string;
  startDate?: string;
  endDate?: string;
  principalEmail?: string;
  serviceName?: string;
  severity?: string;
  category?: string;
  status?: string;
  source?: string;
  sortBy?: 'timestamp' | 'severity' | 'serviceName' | 'principalEmail';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
}

export interface DashboardStats {
  totalEvents: number;
  adminActivities: number;
  failedOperations: number;
  highRiskEvents: number;
  logsStoredBytesEstimate: number;
  openAlertsCount: number;
  confirmedIncidentsCount: number;
  activePoliciesCount: number;
  eventsOverTime: { date: string; total: number; failed: number; highRisk: number }[];
  severityDistribution: { severity: string; count: number }[];
  operationCategories: { category: string; count: number }[];
  activityByPrincipal: { principal: string; count: number; failed: number }[];
  recentLogs: AuditLogRecord[];
  recentAlerts: SecurityAlertRecord[];
}
