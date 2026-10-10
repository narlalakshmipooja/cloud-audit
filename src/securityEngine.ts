import {
  AuditLogRecord,
  RetentionPolicyRecord,
  SecurityAlertRecord,
  LogFilterParams,
  DashboardStats,
  LogSeverity,
  LogCategory,
} from './types';

export const HIGH_RISK_SEVERITIES: LogSeverity[] = ['ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'];

const SENSITIVE_ADMIN_METHODS = [
  'SetIamPolicy',
  'CreateServiceAccountKey',
  'DeleteBucket',
  'DeleteCryptoKeyVersion',
  'DestroyCryptoKeyVersion',
  'DeleteInstance',
  'DeleteCluster',
  'UpdateSink',
  'DeleteSink',
  'DisableService',
  'SetOrgPolicy',
];

const IAM_METHODS = [
  'SetIamPolicy',
  'CreateRole',
  'UpdateRole',
  'CreateServiceAccount',
  'CreateServiceAccountKey',
  'GrantRole',
];

export function sanitizeId(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120);
  return cleaned.length > 0 ? cleaned : `id_${Date.now()}`;
}

export function normalizeGcpAuditEntry(
  rawEntry: Record<string, unknown>,
  projectId: string
): Omit<AuditLogRecord, 'createdAt'> {
  const metadata = (rawEntry.metadata as Record<string, unknown>) || rawEntry;
  const protoPayload =
    (rawEntry.protoPayload as Record<string, unknown>) ||
    (rawEntry.jsonPayload as Record<string, unknown>) ||
    (rawEntry.data as Record<string, unknown>) ||
    {};

  const insertIdRaw = String(metadata.insertId || rawEntry.insertId || `gcp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  const id = sanitizeId(`gcp_${projectId}_${insertIdRaw}`);

  const timestampRaw = metadata.timestamp || rawEntry.timestamp || new Date().toISOString();
  const timestamp = typeof timestampRaw === 'string' ? timestampRaw : new Date().toISOString();

  const authInfo = (protoPayload.authenticationInfo as Record<string, unknown>) || {};
  const requestMetadata = (protoPayload.requestMetadata as Record<string, unknown>) || {};
  const statusObj = (protoPayload.status as Record<string, unknown>) || {};

  const principalEmail = String(
    authInfo.principalEmail ||
      authInfo.serviceAccountKeyName ||
      protoPayload.principalEmail ||
      'system@google-cloud-platform.internal'
  ).slice(0, 256);

  const serviceName = String(
    protoPayload.serviceName ||
      ((metadata.resource as Record<string, unknown>)?.type as string) ||
      'cloudaudit.googleapis.com'
  ).slice(0, 128);

  const methodName = String(protoPayload.methodName || 'UnknownOperation').slice(0, 256);
  const resourceName = String(
    protoPayload.resourceName ||
      ((metadata.resource as Record<string, unknown>)?.labels
        ? JSON.stringify((metadata.resource as Record<string, unknown>).labels)
        : `projects/${projectId}`)
  ).slice(0, 512);

  const rawSev = String(metadata.severity || rawEntry.severity || 'INFO').toUpperCase();
  const validSeverities: LogSeverity[] = [
    'DEFAULT',
    'INFO',
    'NOTICE',
    'WARNING',
    'ERROR',
    'CRITICAL',
    'ALERT',
    'EMERGENCY',
  ];
  const severity: LogSeverity = validSeverities.includes(rawSev as LogSeverity)
    ? (rawSev as LogSeverity)
    : 'INFO';

  const callerIp = String(requestMetadata.callerIp || 'internal').slice(0, 64);

  const statusCode = typeof statusObj.code === 'number' ? statusObj.code : severity === 'ERROR' || severity === 'CRITICAL' ? 7 : 0;
  const status: 'SUCCESS' | 'FAILURE' = statusCode === 0 ? 'SUCCESS' : 'FAILURE';
  const statusMessage = String(
    statusObj.message || (status === 'SUCCESS' ? 'OK' : 'Operation failed or permission denied')
  ).slice(0, 512);

  const logName = String(metadata.logName || rawEntry.logName || '');
  let category: LogCategory = 'ADMIN_ACTIVITY';
  if (logName.includes('data_access')) category = 'DATA_ACCESS';
  else if (logName.includes('system_event')) category = 'SYSTEM_EVENT';
  else if (logName.includes('policy')) category = 'POLICY_DENIED';

  return {
    id,
    insertId: insertIdRaw.slice(0, 128),
    timestamp,
    principalEmail,
    serviceName,
    methodName,
    resourceName,
    severity,
    callerIp,
    status,
    statusCode,
    statusMessage,
    category,
    source: 'GCP_LIVE',
    projectId: projectId.slice(0, 128),
    rawPayload: {
      logName: logName.slice(0, 256),
      serviceName,
      methodName,
      resourceName,
      principalEmail,
      callerIp,
      callerSuppliedUserAgent: String(requestMetadata.callerSuppliedUserAgent || 'gcloud-sdk').slice(0, 256),
      status: { code: statusCode, message: statusMessage },
    },
  };
}

export function filterAndSortLogs(
  logs: AuditLogRecord[],
  params: LogFilterParams
): { items: AuditLogRecord[]; total: number; page: number; pageSize: number; totalPages: number } {
  let filtered = [...logs];

  if (params.source && params.source !== 'ALL') {
    filtered = filtered.filter((l) => l.source === params.source);
  }
  if (params.severity && params.severity !== 'ALL') {
    filtered = filtered.filter((l) => l.severity === params.severity);
  }
  if (params.category && params.category !== 'ALL') {
    filtered = filtered.filter((l) => l.category === params.category);
  }
  if (params.status && params.status !== 'ALL') {
    filtered = filtered.filter((l) => l.status === params.status);
  }
  if (params.serviceName && params.serviceName !== 'ALL') {
    filtered = filtered.filter((l) =>
      l.serviceName.toLowerCase().includes(params.serviceName!.toLowerCase())
    );
  }
  if (params.principalEmail && params.principalEmail.trim() !== '') {
    const q = params.principalEmail.trim().toLowerCase();
    filtered = filtered.filter((l) => l.principalEmail.toLowerCase().includes(q));
  }
  if (params.startDate) {
    const startMs = new Date(params.startDate).getTime();
    if (!isNaN(startMs)) {
      filtered = filtered.filter((l) => new Date(l.timestamp).getTime() >= startMs);
    }
  }
  if (params.endDate) {
    const endDateObj = new Date(params.endDate);
    if (params.endDate.length <= 10) {
      endDateObj.setHours(23, 59, 59, 999);
    }
    const endMs = endDateObj.getTime();
    if (!isNaN(endMs)) {
      filtered = filtered.filter((l) => new Date(l.timestamp).getTime() <= endMs);
    }
  }
  if (params.search && params.search.trim() !== '') {
    const q = params.search.trim().toLowerCase();
    filtered = filtered.filter(
      (l) =>
        l.principalEmail.toLowerCase().includes(q) ||
        l.serviceName.toLowerCase().includes(q) ||
        l.methodName.toLowerCase().includes(q) ||
        l.resourceName.toLowerCase().includes(q) ||
        l.callerIp.toLowerCase().includes(q) ||
        l.statusMessage.toLowerCase().includes(q) ||
        l.id.toLowerCase().includes(q)
    );
  }

  const sortBy = params.sortBy || 'timestamp';
  const sortOrder = params.sortOrder || 'desc';
  const dir = sortOrder === 'asc' ? 1 : -1;

  filtered.sort((a, b) => {
    if (sortBy === 'timestamp') {
      return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * dir;
    }
    const valA = String(a[sortBy] || '').toLowerCase();
    const valB = String(b[sortBy] || '').toLowerCase();
    return valA.localeCompare(valB) * dir;
  });

  const total = filtered.length;
  const pageSize = Math.max(1, Math.min(200, Number(params.pageSize) || 15));
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.max(1, Math.min(totalPages, Number(params.page) || 1));
  const startIdx = (page - 1) * pageSize;
  const items = filtered.slice(startIdx, startIdx + pageSize);

  return { items, total, page, pageSize, totalPages };
}

export function evaluateRetentionEligibility(
  logs: AuditLogRecord[],
  policy: Pick<RetentionPolicyRecord, 'logCategory' | 'retentionDays' | 'status'>,
  referenceNowMs: number = Date.now()
): { eligibleLogs: AuditLogRecord[]; cutoffIso: string } {
  const cutoffMs = referenceNowMs - policy.retentionDays * 24 * 60 * 60 * 1000;
  const cutoffIso = new Date(cutoffMs).toISOString();

  if (policy.status !== 'ENABLED') {
    return { eligibleLogs: [], cutoffIso };
  }

  const eligibleLogs = logs.filter((log) => {
    const categoryMatches = policy.logCategory === 'ALL' || log.category === policy.logCategory;
    if (!categoryMatches) return false;
    const logTimeMs = new Date(log.timestamp).getTime();
    if (isNaN(logTimeMs)) return false;
    return logTimeMs < cutoffMs;
  });

  return { eligibleLogs, cutoffIso };
}

export function detectSecurityAlertsFromLogs(
  logs: AuditLogRecord[]
): Omit<SecurityAlertRecord, 'createdAt' | 'updatedAt'>[] {
  const alertsMap = new Map<string, Omit<SecurityAlertRecord, 'createdAt' | 'updatedAt'>>();
  const sortedLogs = [...logs].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  // Track historical IPs per principal
  const principalIpCounts = new Map<string, Map<string, number>>();
  for (const log of sortedLogs) {
    if (!log.callerIp || log.callerIp === 'internal') continue;
    if (!principalIpCounts.has(log.principalEmail)) {
      principalIpCounts.set(log.principalEmail, new Map());
    }
    const ipMap = principalIpCounts.get(log.principalEmail)!;
    ipMap.set(log.callerIp, (ipMap.get(log.callerIp) || 0) + 1);
  }

  // Rule 1: Repeated Failed Operations (>= 3 failures by same principal within 60 minutes)
  const failedByPrincipal = new Map<string, AuditLogRecord[]>();
  for (const log of sortedLogs) {
    if (log.status === 'FAILURE') {
      const list = failedByPrincipal.get(log.principalEmail) || [];
      list.push(log);
      failedByPrincipal.set(log.principalEmail, list);
    }
  }

  for (const [principal, failLogs] of failedByPrincipal.entries()) {
    for (let i = 0; i < failLogs.length; i++) {
      const windowStart = new Date(failLogs[i].timestamp).getTime();
      const inWindow = failLogs.filter((l) => {
        const t = new Date(l.timestamp).getTime();
        return t >= windowStart && t <= windowStart + 60 * 60 * 1000;
      });
      if (inWindow.length >= 3) {
        const triggerLog = inWindow[inWindow.length - 1];
        const alertId = sanitizeId(`alert_rep_fail_${triggerLog.id}`);
        alertsMap.set(alertId, {
          id: alertId,
          severity: inWindow.length >= 5 ? 'CRITICAL' : 'HIGH',
          title: `Repeated Failed Operations (${inWindow.length} attempts)`,
          description: `Principal ${principal} experienced ${inWindow.length} failed cloud operations within a 60-minute window on ${triggerLog.serviceName}.`,
          eventTime: triggerLog.timestamp,
          associatedLogId: triggerLog.id,
          principalEmail: principal,
          callerIp: triggerLog.callerIp,
          ruleId: 'REPEATED_FAILURES',
          detectionReason: `Rule [REPEATED_FAILURES]: Threshold >= 3 failed operations in 60m exceeded (${inWindow.length} failures). Last status: ${triggerLog.statusMessage}`,
          status: 'OPEN',
          source: triggerLog.source,
          reviewedBy: '',
          reviewedAt: '',
        });
        break;
      }
    }
  }

  // Rule 2 & Rule 3: Unusual IAM / Permission Changes & Sensitive Administrative Operations
  for (const log of sortedLogs) {
    const isIamOp = IAM_METHODS.some((m) => log.methodName.includes(m));
    const isSensitiveAdmin = SENSITIVE_ADMIN_METHODS.some((m) => log.methodName.includes(m));

    if (isIamOp && (log.serviceName.includes('iam') || log.serviceName.includes('cloudresourcemanager'))) {
      const alertId = sanitizeId(`alert_iam_${log.id}`);
      alertsMap.set(alertId, {
        id: alertId,
        severity: log.methodName.includes('CreateServiceAccountKey') || log.methodName.includes('SetIamPolicy') ? 'HIGH' : 'MEDIUM',
        title: `IAM Policy or Credential Modification: ${log.methodName.split('.').pop()}`,
        description: `Principal ${log.principalEmail} invoked ${log.methodName} on resource ${log.resourceName} from IP ${log.callerIp}.`,
        eventTime: log.timestamp,
        associatedLogId: log.id,
        principalEmail: log.principalEmail,
        callerIp: log.callerIp,
        ruleId: 'UNUSUAL_IAM_CHANGE',
        detectionReason: `Rule [UNUSUAL_IAM_CHANGE]: Privileged IAM mutation or key creation method (${log.methodName}) executed.`,
        status: 'OPEN',
        source: log.source,
        reviewedBy: '',
        reviewedAt: '',
      });
    } else if (isSensitiveAdmin || log.severity === 'CRITICAL' || log.severity === 'ALERT' || log.severity === 'EMERGENCY') {
      const alertId = sanitizeId(`alert_sens_${log.id}`);
      alertsMap.set(alertId, {
        id: alertId,
        severity: log.severity === 'CRITICAL' || log.severity === 'EMERGENCY' ? 'CRITICAL' : 'HIGH',
        title: `Sensitive Administrative Operation: ${log.methodName.split('.').pop()}`,
        description: `Sensitive infrastructure or audit configuration action (${log.methodName}) performed by ${log.principalEmail} on ${log.resourceName}.`,
        eventTime: log.timestamp,
        associatedLogId: log.id,
        principalEmail: log.principalEmail,
        callerIp: log.callerIp,
        ruleId: 'SENSITIVE_ADMIN_OP',
        detectionReason: `Rule [SENSITIVE_ADMIN_OP]: Destructive or high-impact administrative method (${log.methodName}) with severity ${log.severity}.`,
        status: 'OPEN',
        source: log.source,
        reviewedBy: '',
        reviewedAt: '',
      });
    }
  }

  // Rule 4: Sudden Spikes in Activity (>= 6 events within 15 minutes from a single principal)
  const logsByPrincipal = new Map<string, AuditLogRecord[]>();
  for (const log of sortedLogs) {
    const list = logsByPrincipal.get(log.principalEmail) || [];
    list.push(log);
    logsByPrincipal.set(log.principalEmail, list);
  }

  for (const [principal, pLogs] of logsByPrincipal.entries()) {
    for (let i = 0; i < pLogs.length; i++) {
      const startMs = new Date(pLogs[i].timestamp).getTime();
      const burst = pLogs.filter((l) => {
        const t = new Date(l.timestamp).getTime();
        return t >= startMs && t <= startMs + 15 * 60 * 1000;
      });
      if (burst.length >= 6) {
        const triggerLog = burst[burst.length - 1];
        const alertId = sanitizeId(`alert_spike_${principal}_${triggerLog.id}`);
        alertsMap.set(alertId, {
          id: alertId,
          severity: 'MEDIUM',
          title: `Sudden Activity Spike (${burst.length} ops / 15m)`,
          description: `Principal ${principal} executed ${burst.length} operations within a 15-minute window, exceeding baseline velocity.`,
          eventTime: triggerLog.timestamp,
          associatedLogId: triggerLog.id,
          principalEmail: principal,
          callerIp: triggerLog.callerIp,
          ruleId: 'ACTIVITY_SPIKE',
          detectionReason: `Rule [ACTIVITY_SPIKE]: Burst rate of ${burst.length} events in 15m exceeds threshold (>= 6 events/15m).`,
          status: 'OPEN',
          source: triggerLog.source,
          reviewedBy: '',
          reviewedAt: '',
        });
        break;
      }
    }
  }

  // Rule 5: Activity from Unusual IP Address when sufficient historical data exists (>= 4 events for principal, and an IP appears only once with external/non-standard prefix)
  for (const [principal, pLogs] of logsByPrincipal.entries()) {
    if (pLogs.length < 4) continue;
    const ipMap = principalIpCounts.get(principal);
    if (!ipMap || ipMap.size < 2) continue;

    // Find primary IP with >= 3 occurrences
    let baselineIp = '';
    let maxCount = 0;
    for (const [ip, count] of ipMap.entries()) {
      if (count > maxCount) {
        maxCount = count;
        baselineIp = ip;
      }
    }

    if (maxCount >= 3) {
      for (const log of pLogs) {
        if (log.callerIp && log.callerIp !== 'internal' && log.callerIp !== baselineIp && ipMap.get(log.callerIp) === 1) {
          const alertId = sanitizeId(`alert_ip_${log.id}`);
          alertsMap.set(alertId, {
            id: alertId,
            severity: 'HIGH',
            title: `Activity from Unusual Source IP (${log.callerIp})`,
            description: `Principal ${principal} (baseline IP ${baselineIp} across ${maxCount} events) performed ${log.methodName} from anomalous IP ${log.callerIp}.`,
            eventTime: log.timestamp,
            associatedLogId: log.id,
            principalEmail: principal,
            callerIp: log.callerIp,
            ruleId: 'UNUSUAL_IP',
            detectionReason: `Rule [UNUSUAL_IP]: Historical baseline established (${maxCount} events from ${baselineIp}); single outlier request detected from ${log.callerIp}.`,
            status: 'OPEN',
            source: log.source,
            reviewedBy: '',
            reviewedAt: '',
          });
        }
      }
    }
  }

  return Array.from(alertsMap.values()).sort(
    (a, b) => new Date(b.eventTime).getTime() - new Date(a.eventTime).getTime()
  );
}

export function computeDashboardStats(
  logs: AuditLogRecord[],
  alerts: SecurityAlertRecord[],
  policies: RetentionPolicyRecord[]
): DashboardStats {
  const totalEvents = logs.length;
  const adminActivities = logs.filter((l) => l.category === 'ADMIN_ACTIVITY').length;
  const failedOperations = logs.filter((l) => l.status === 'FAILURE').length;
  const highRiskEvents = logs.filter((l) => HIGH_RISK_SEVERITIES.includes(l.severity)).length;
  const logsStoredBytesEstimate = logs.reduce(
    (acc, log) => acc + JSON.stringify(log).length,
    0
  );

  const openAlertsCount = alerts.filter((a) => a.status === 'OPEN').length;
  const confirmedIncidentsCount = alerts.filter((a) => a.status === 'CONFIRMED_INCIDENT').length;
  const activePoliciesCount = policies.filter((p) => p.status === 'ENABLED').length;

  // Events over time grouped by date (YYYY-MM-DD)
  const dateMap = new Map<string, { date: string; total: number; failed: number; highRisk: number }>();
  for (const log of logs) {
    const day = log.timestamp.slice(0, 10);
    const entry = dateMap.get(day) || { date: day, total: 0, failed: 0, highRisk: 0 };
    entry.total += 1;
    if (log.status === 'FAILURE') entry.failed += 1;
    if (HIGH_RISK_SEVERITIES.includes(log.severity)) entry.highRisk += 1;
    dateMap.set(day, entry);
  }
  const eventsOverTime = Array.from(dateMap.values()).sort((a, b) => a.date.localeCompare(b.date));

  // Severity distribution
  const sevOrder: LogSeverity[] = ['INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY', 'DEFAULT'];
  const sevCounts = new Map<string, number>();
  for (const log of logs) {
    sevCounts.set(log.severity, (sevCounts.get(log.severity) || 0) + 1);
  }
  const severityDistribution = sevOrder
    .filter((s) => (sevCounts.get(s) || 0) > 0)
    .map((severity) => ({ severity, count: sevCounts.get(severity) || 0 }));

  // Operation categories
  const catCounts = new Map<string, number>();
  for (const log of logs) {
    catCounts.set(log.category, (catCounts.get(log.category) || 0) + 1);
  }
  const operationCategories = Array.from(catCounts.entries()).map(([category, count]) => ({
    category,
    count,
  }));

  // Activity by principal
  const prinMap = new Map<string, { principal: string; count: number; failed: number }>();
  for (const log of logs) {
    const entry = prinMap.get(log.principalEmail) || {
      principal: log.principalEmail,
      count: 0,
      failed: 0,
    };
    entry.count += 1;
    if (log.status === 'FAILURE') entry.failed += 1;
    prinMap.set(log.principalEmail, entry);
  }
  const activityByPrincipal = Array.from(prinMap.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  const sortedLogs = [...logs].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
  const sortedAlerts = [...alerts].sort(
    (a, b) => new Date(b.eventTime).getTime() - new Date(a.eventTime).getTime()
  );

  return {
    totalEvents,
    adminActivities,
    failedOperations,
    highRiskEvents,
    logsStoredBytesEstimate,
    openAlertsCount,
    confirmedIncidentsCount,
    activePoliciesCount,
    eventsOverTime,
    severityDistribution,
    operationCategories,
    activityByPrincipal,
    recentLogs: sortedLogs.slice(0, 6),
    recentAlerts: sortedAlerts.slice(0, 5),
  };
}

export function generateLogsCsv(logs: AuditLogRecord[]): string {
  const headers = [
    'Log ID',
    'Timestamp (UTC)',
    'Source',
    'Project ID',
    'Category',
    'Severity',
    'Status',
    'Status Code',
    'Principal Email',
    'Caller IP',
    'Service Name',
    'Method Name',
    'Resource Name',
    'Status Message',
  ];

  const escapeCsv = (val: unknown) => {
    const str = String(val ?? '').replace(/"/g, '""');
    return `"${str}"`;
  };

  const rows = logs.map((l) =>
    [
      l.id,
      l.timestamp,
      l.source,
      l.projectId,
      l.category,
      l.severity,
      l.status,
      l.statusCode,
      l.principalEmail,
      l.callerIp,
      l.serviceName,
      l.methodName,
      l.resourceName,
      l.statusMessage,
    ]
      .map(escapeCsv)
      .join(',')
  );

  return [headers.map(escapeCsv).join(','), ...rows].join('\n');
}

export function generateSecurityReportCsv(
  logs: AuditLogRecord[],
  alerts: SecurityAlertRecord[],
  dateRangeLabel: string
): string {
  const escapeCsv = (val: unknown) => `"${String(val ?? '').replace(/"/g, '""')}"`;

  const totalLogs = logs.length;
  const failedLogs = logs.filter((l) => l.status === 'FAILURE').length;
  const highRiskLogs = logs.filter((l) => HIGH_RISK_SEVERITIES.includes(l.severity)).length;
  const openAlerts = alerts.filter((a) => a.status === 'OPEN').length;
  const confirmedIncidents = alerts.filter((a) => a.status === 'CONFIRMED_INCIDENT').length;
  const reviewedAlerts = alerts.filter((a) => a.status === 'REVIEWED').length;

  const lines: string[] = [
    '"CLOUD AUDIT LOGS RETENTION & SECURITY ANALYSIS REPORT"',
    `"Generated At","${new Date().toISOString()}"`,
    `"Selected Date Filter","${dateRangeLabel}"`,
    `"Total Audit Events Analyzed","${totalLogs}"`,
    `"Failed Operations","${failedLogs}"`,
    `"High-Risk Events (ERROR+)","${highRiskLogs}"`,
    `"Detected Security Alerts (Open)","${openAlerts}"`,
    `"Reviewed Alerts","${reviewedAlerts}"`,
    `"Confirmed Security Incidents","${confirmedIncidents}"`,
    '',
    '"--- SECTION 1: SECURITY ALERTS & CONFIRMED INCIDENTS ---"',
    [
      'Alert ID',
      'Classification',
      'Status',
      'Severity',
      'Rule ID',
      'Event Time',
      'Principal Email',
      'Caller IP',
      'Title',
      'Detection Reason',
      'Associated Log ID',
      'Reviewed By',
    ]
      .map(escapeCsv)
      .join(','),
  ];

  for (const a of alerts) {
    const classification =
      a.status === 'CONFIRMED_INCIDENT' ? 'CONFIRMED_SECURITY_INCIDENT' : 'DETECTED_EVENT';
    lines.push(
      [
        a.id,
        classification,
        a.status,
        a.severity,
        a.ruleId,
        a.eventTime,
        a.principalEmail,
        a.callerIp,
        a.title,
        a.detectionReason,
        a.associatedLogId,
        a.reviewedBy || 'Unassigned',
      ]
        .map(escapeCsv)
        .join(',')
    );
  }

  lines.push('');
  lines.push('"--- SECTION 2: AUDIT LOG RECORDS ---"');
  lines.push(generateLogsCsv(logs));

  return lines.join('\n');
}
