import { describe, it, expect } from 'vitest';
import {
  normalizeGcpAuditEntry,
  filterAndSortLogs,
  evaluateRetentionEligibility,
  detectSecurityAlertsFromLogs,
  computeDashboardStats,
  generateLogsCsv,
} from './securityEngine';
import { buildRealisticDemoDataset } from './demoData';
import { AuditLogRecord } from './types';

describe('Security Engine - Normalization, Filtering, Retention & Rule-Based Detection', () => {
  const nowMs = new Date('2026-10-10T12:00:00Z').getTime();
  const demo = buildRealisticDemoDataset('admin_uid_01', nowMs);
  const demoLogs = demo.logs as AuditLogRecord[];

  it('1. Normalizes raw Google Cloud Audit Log entries into consistent schema', () => {
    const rawEntry = {
      insertId: 'abc-12345',
      timestamp: '2026-10-10T10:00:00Z',
      severity: 'WARNING',
      logName: 'projects/my-gcp-proj/logs/cloudaudit.googleapis.com%2Factivity',
      protoPayload: {
        serviceName: 'iam.googleapis.com',
        methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
        resourceName: 'projects/my-gcp-proj/serviceAccounts/test@my-gcp-proj.iam.gserviceaccount.com',
        authenticationInfo: { principalEmail: 'alice@example.com' },
        requestMetadata: { callerIp: '203.0.113.50' },
        status: { code: 0, message: 'OK' },
      },
    };

    const normalized = normalizeGcpAuditEntry(rawEntry, 'my-gcp-proj');
    expect(normalized.id).toBe('gcp_my-gcp-proj_abc-12345');
    expect(normalized.source).toBe('GCP_LIVE');
    expect(normalized.category).toBe('ADMIN_ACTIVITY');
    expect(normalized.principalEmail).toBe('alice@example.com');
    expect(normalized.status).toBe('SUCCESS');
    expect(normalized.callerIp).toBe('203.0.113.50');
  });

  it('2. Filters and paginates audit logs accurately by status, category, and search query', () => {
    const failedResult = filterAndSortLogs(demoLogs, {
      status: 'FAILURE',
      page: 1,
      pageSize: 10,
    });
    expect(failedResult.total).toBeGreaterThanOrEqual(4);
    expect(failedResult.items.every((l) => l.status === 'FAILURE')).toBe(true);

    const searchResult = filterAndSortLogs(demoLogs, {
      search: 'DestroyCryptoKeyVersion',
      page: 1,
      pageSize: 10,
    });
    expect(searchResult.total).toBe(1);
    expect(searchResult.items[0].serviceName).toBe('cloudkms.googleapis.com');
  });

  it('3. Evaluates retention policy eligibility strictly by log category and cutoff timestamp', () => {
    // 30-day DATA_ACCESS policy should only flag DATA_ACCESS logs older than 30 days
    const { eligibleLogs } = evaluateRetentionEligibility(
      demoLogs,
      {
        logCategory: 'DATA_ACCESS',
        retentionDays: 30,
        status: 'ENABLED',
      },
      nowMs
    );

    expect(eligibleLogs.length).toBe(2); // demo_log_018 (42d) and demo_log_019 (65d)
    expect(eligibleLogs.every((l) => l.category === 'DATA_ACCESS')).toBe(true);

    // Disabled policy should return 0 eligible records
    const disabledEval = evaluateRetentionEligibility(
      demoLogs,
      {
        logCategory: 'ALL',
        retentionDays: 1,
        status: 'DISABLED',
      },
      nowMs
    );
    expect(disabledEval.eligibleLogs.length).toBe(0);
  });

  it('4. Detects all 5 rule-based security alert categories from audit log patterns', () => {
    const alerts = detectSecurityAlertsFromLogs(demoLogs);
    const ruleIds = new Set(alerts.map((a) => a.ruleId));

    expect(ruleIds.has('REPEATED_FAILURES')).toBe(true);
    expect(ruleIds.has('UNUSUAL_IAM_CHANGE')).toBe(true);
    expect(ruleIds.has('SENSITIVE_ADMIN_OP')).toBe(true);
    expect(ruleIds.has('ACTIVITY_SPIKE')).toBe(true);
    expect(ruleIds.has('UNUSUAL_IP')).toBe(true);
  });

  it('5. Computes dashboard statistics and exports valid CSV records', () => {
    const stats = computeDashboardStats(demoLogs, demo.alerts as any, demo.policies as any);
    expect(stats.totalEvents).toBe(demoLogs.length);
    expect(stats.failedOperations).toBeGreaterThan(0);
    expect(stats.highRiskEvents).toBeGreaterThan(0);

    const csv = generateLogsCsv(demoLogs.slice(0, 2));
    const lines = csv.split('\n');
    expect(lines.length).toBe(3); // header + 2 rows
    expect(lines[0]).toContain('"Principal Email"');
  });
});
