import { auth, db, OperationType, handleFirestoreError } from './firebase';
import {
  doc,
  setDoc,
  deleteDoc,
  serverTimestamp,
  collection,
  query,
  where,
  getDocs,
} from 'firebase/firestore';
import {
  AuditLogRecord,
  RetentionPolicyRecord,
  SecurityAlertRecord,
  RetentionExecutionRecord,
  IntegrationSettingRecord,
  DashboardStats,
  LogFilterParams,
} from './types';
import { buildRealisticDemoDataset } from './demoData';
import { detectSecurityAlertsFromLogs, sanitizeId } from './securityEngine';

async function getAuthHeaders(): Promise<Record<string, string>> {
  const user = auth.currentUser;
  if (!user) throw new Error('User is not signed in.');
  const token = await user.getIdToken();
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

export async function apiFetchStats(source: string = 'ALL'): Promise<DashboardStats> {
  const headers = await getAuthHeaders();
  const res = await fetch(`/api/stats?source=${encodeURIComponent(source)}`, { headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Failed to fetch dashboard stats');
  }
  return res.json();
}

export async function apiFetchLogs(params: LogFilterParams): Promise<{
  items: AuditLogRecord[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}> {
  const headers = await getAuthHeaders();
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') qs.set(k, String(v));
  });
  const res = await fetch(`/api/logs?${qs.toString()}`, { headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Failed to fetch audit logs');
  }
  return res.json();
}

export async function apiFetchLogById(id: string): Promise<AuditLogRecord> {
  const headers = await getAuthHeaders();
  const res = await fetch(`/api/logs/${encodeURIComponent(id)}`, { headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Failed to fetch log detail');
  }
  return res.json();
}

export async function apiSyncGcpLogs(payload: {
  gcpProjectId: string;
  logFilter?: string;
  daysBack?: number;
  maxEntries?: number;
}): Promise<{
  synced: boolean;
  status: string;
  gcpProjectId?: string;
  fetchedCount?: number;
  importedCount?: number;
  duplicateSkippedCount?: number;
  newAlertsCount?: number;
  lastSyncAt?: string;
  error?: string;
}> {
  const headers = await getAuthHeaders();
  const res = await fetch('/api/logs/sync', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok && !data.status) {
    throw new Error(data.error || 'Failed to sync GCP logs');
  }
  return data;
}

export async function apiTestGcpIntegration(payload: {
  gcpProjectId: string;
  logFilter?: string;
}): Promise<{
  connected: boolean;
  status: string;
  gcpProjectId: string;
  sampleEntriesCount?: number;
  message: string;
}> {
  const headers = await getAuthHeaders();
  const res = await fetch('/api/integration/test', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok && !data.status) {
    throw new Error(data.error || 'Failed to test GCP connectivity');
  }
  return data;
}

export async function apiFetchRetention(): Promise<{
  policies: RetentionPolicyRecord[];
  executions: RetentionExecutionRecord[];
}> {
  const headers = await getAuthHeaders();
  const res = await fetch('/api/retention', { headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Failed to fetch retention policies');
  }
  return res.json();
}

export async function apiCreateRetentionPolicy(payload: {
  name: string;
  description: string;
  logCategory: RetentionPolicyRecord['logCategory'];
  retentionDays: number;
  status: RetentionPolicyRecord['status'];
}): Promise<RetentionPolicyRecord> {
  const headers = await getAuthHeaders();
  const res = await fetch('/api/retention', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to create retention policy');
  return data;
}

export async function apiUpdateRetentionPolicy(
  id: string,
  payload: Partial<
    Pick<
      RetentionPolicyRecord,
      'name' | 'description' | 'logCategory' | 'retentionDays' | 'status'
    >
  >
): Promise<RetentionPolicyRecord> {
  const headers = await getAuthHeaders();
  const res = await fetch(`/api/retention/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update retention policy');
  return data;
}

export async function apiDeleteRetentionPolicy(id: string): Promise<void> {
  const headers = await getAuthHeaders();
  const res = await fetch(`/api/retention/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(data.error || 'Failed to delete retention policy');
  }
}

export async function apiRunRetentionCleanup(payload: {
  policyId?: string;
  dryRun?: boolean;
}): Promise<{
  dryRun: boolean;
  totalDeleted: number;
  executions: RetentionExecutionRecord[];
}> {
  const headers = await getAuthHeaders();
  const res = await fetch('/api/retention/run', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to run retention cleanup');
  return data;
}

export async function apiFetchAlerts(params: {
  severity?: string;
  status?: string;
  ruleId?: string;
  source?: string;
  startDate?: string;
  endDate?: string;
  search?: string;
}): Promise<{ alerts: SecurityAlertRecord[]; total: number }> {
  const headers = await getAuthHeaders();
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') qs.set(k, String(v));
  });
  const res = await fetch(`/api/alerts?${qs.toString()}`, { headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to fetch security alerts');
  return data;
}

export async function apiUpdateAlertStatus(
  id: string,
  status: SecurityAlertRecord['status']
): Promise<SecurityAlertRecord> {
  const headers = await getAuthHeaders();
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify({ status }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update alert status');
  return data;
}

export async function apiDownloadCsvReport(params: {
  type: 'full_report' | 'logs_only';
  startDate?: string;
  endDate?: string;
  source?: string;
  severity?: string;
  category?: string;
  status?: string;
}): Promise<void> {
  const headers = await getAuthHeaders();
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') qs.set(k, String(v));
  });
  const res = await fetch(`/api/reports/export?${qs.toString()}`, { headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Failed to export CSV report');
  }
  const csvBlob = await res.blob();
  const url = URL.createObjectURL(csvBlob);
  const a = document.createElement('a');
  a.href = url;
  a.download =
    params.type === 'logs_only'
      ? `cloud-audit-logs-${new Date().toISOString().slice(0, 10)}.csv`
      : `cloud-security-analytics-report-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Seed or Reset Demo Data in Firestore with strict schema validation and error handling
export async function seedOrResetDemoDataInFirestore(
  adminUid: string,
  adminEmail: string,
  forceReset: boolean = false
): Promise<{ seededLogs: number; seededPolicies: number; seededAlerts: number }> {
  try {
    const existingLogsQuery = query(
      collection(db, 'audit_logs'),
      where('source', 'in', ['GCP_LIVE', 'DEMO'])
    );
    const existingLogsSnap = await getDocs(existingLogsQuery);

    if (!forceReset && !existingLogsSnap.empty) {
      return { seededLogs: 0, seededPolicies: 0, seededAlerts: 0 };
    }

    if (forceReset) {
      // Delete only DEMO logs and DEMO alerts
      for (const docSnap of existingLogsSnap.docs) {
        if (docSnap.data().source === 'DEMO') {
          await deleteDoc(doc(db, 'audit_logs', docSnap.id));
        }
      }
      const existingAlertsSnap = await getDocs(
        query(collection(db, 'security_alerts'), where('source', 'in', ['GCP_LIVE', 'DEMO']))
      );
      for (const docSnap of existingAlertsSnap.docs) {
        if (docSnap.data().source === 'DEMO') {
          await deleteDoc(doc(db, 'security_alerts', docSnap.id));
        }
      }
    }

    const dataset = buildRealisticDemoDataset(adminUid);

    for (const logItem of dataset.logs) {
      await setDoc(doc(db, 'audit_logs', logItem.id), {
        ...logItem,
        createdAt: serverTimestamp(),
      });
    }

    const existingPoliciesSnap = await getDocs(
      query(collection(db, 'retention_policies'), where('status', 'in', ['ENABLED', 'DISABLED']))
    );
    if (forceReset || existingPoliciesSnap.empty) {
      for (const pol of dataset.policies) {
        await setDoc(doc(db, 'retention_policies', pol.id), {
          ...pol,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
    }

    for (const alertItem of dataset.alerts) {
      await setDoc(doc(db, 'security_alerts', alertItem.id), {
        ...alertItem,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }

    const defaultSettings: Omit<IntegrationSettingRecord, 'updatedAt'> = {
      id: 'default',
      gcpProjectId: 'btech-secops-demo-prod',
      logFilter: 'logName:"cloudaudit.googleapis.com"',
      connectionStatus: 'DISCONNECTED',
      lastSyncAt: '',
      lastSyncCount: 0,
      lastError: '',
      demoMode: true,
      updatedBy: adminEmail || adminUid,
    };

    await setDoc(doc(db, 'integration_settings', 'default'), {
      ...defaultSettings,
      updatedAt: serverTimestamp(),
    });

    return {
      seededLogs: dataset.logs.length,
      seededPolicies: dataset.policies.length,
      seededAlerts: dataset.alerts.length,
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, 'audit_logs');
  }
}

// Trigger a specific test detection scenario and write the synthetic audit log(s) + resulting alert to Firestore
export async function triggerTestDetectionScenario(
  scenarioType: 'IAM_PRIVILEGE_ESCALATION' | 'BRUTE_FORCE_SECRET_ACCESS' | 'CRITICAL_SINK_DELETION'
): Promise<{ createdLogs: number; createdAlerts: number; alertTitle: string }> {
  const now = Date.now();
  const projectId = 'btech-secops-demo-prod';
  const suffix = Math.random().toString(36).slice(2, 7);

  try {
    const newLogs: Omit<AuditLogRecord, 'createdAt'>[] = [];

    if (scenarioType === 'IAM_PRIVILEGE_ESCALATION') {
      const id = sanitizeId(`sim_iam_${now}_${suffix}`);
      newLogs.push({
        id,
        insertId: `ins_${id}`,
        timestamp: new Date(now).toISOString(),
        principalEmail: 'rogue-insider@btech-cloudsec.edu',
        serviceName: 'iam.googleapis.com',
        methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
        resourceName: `projects/${projectId}/serviceAccounts/prod-admin@${projectId}.iam.gserviceaccount.com`,
        severity: 'CRITICAL',
        callerIp: '198.51.100.77',
        status: 'SUCCESS',
        statusCode: 0,
        statusMessage: 'Created external JSON private key for privileged service account',
        category: 'ADMIN_ACTIVITY',
        source: 'DEMO',
        projectId,
        rawPayload: {
          simulatedScenario: scenarioType,
          methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
          callerIp: '198.51.100.77',
        },
      });
    } else if (scenarioType === 'BRUTE_FORCE_SECRET_ACCESS') {
      for (let i = 1; i <= 3; i++) {
        const id = sanitizeId(`sim_fail_${now}_${i}_${suffix}`);
        newLogs.push({
          id,
          insertId: `ins_${id}`,
          timestamp: new Date(now - (3 - i) * 30000).toISOString(),
          principalEmail: 'compromised-Runner@vendor-ops.org',
          serviceName: 'secretmanager.googleapis.com',
          methodName: 'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion',
          resourceName: `projects/${projectId}/secrets/jwt-signing-private-key/versions/${i}`,
          severity: 'ERROR',
          callerIp: '45.155.205.99',
          status: 'FAILURE',
          statusCode: 7,
          statusMessage: 'PERMISSION_DENIED: Unauthorized attempt to dump secret version',
          category: 'POLICY_DENIED',
          source: 'DEMO',
          projectId,
          rawPayload: {
            simulatedScenario: scenarioType,
            attemptNumber: i,
            callerIp: '45.155.205.99',
          },
        });
      }
    } else {
      const id = sanitizeId(`sim_sink_${now}_${suffix}`);
      newLogs.push({
        id,
        insertId: `ins_${id}`,
        timestamp: new Date(now).toISOString(),
        principalEmail: 'unknown-admin@btech-cloudsec.edu',
        serviceName: 'logging.googleapis.com',
        methodName: 'google.logging.v2.ConfigServiceV2.DeleteSink',
        resourceName: `projects/${projectId}/sinks/compliance-audit-export-sink`,
        severity: 'EMERGENCY',
        callerIp: '203.0.113.199',
        status: 'SUCCESS',
        statusCode: 0,
        statusMessage: 'Deleted primary compliance log export sink',
        category: 'ADMIN_ACTIVITY',
        source: 'DEMO',
        projectId,
        rawPayload: {
          simulatedScenario: scenarioType,
          methodName: 'DeleteSink',
          callerIp: '203.0.113.199',
        },
      });
    }

    for (const logItem of newLogs) {
      await setDoc(doc(db, 'audit_logs', logItem.id), {
        ...logItem,
        createdAt: serverTimestamp(),
      });
    }

    const detected = detectSecurityAlertsFromLogs(newLogs as AuditLogRecord[]);
    for (const alertItem of detected) {
      await setDoc(doc(db, 'security_alerts', alertItem.id), {
        ...alertItem,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }

    return {
      createdLogs: newLogs.length,
      createdAlerts: detected.length,
      alertTitle: detected[0]?.title || 'Security Alert Generated',
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, 'security_alerts');
  }
}
