import { AuditLogRecord, RetentionPolicyRecord, SecurityAlertRecord } from './types';
import { detectSecurityAlertsFromLogs } from './securityEngine';

export function buildRealisticDemoDataset(
  adminUid: string,
  nowMs: number = Date.now()
): {
  logs: Omit<AuditLogRecord, 'createdAt'>[];
  policies: Omit<RetentionPolicyRecord, 'createdAt' | 'updatedAt'>[];
  alerts: Omit<SecurityAlertRecord, 'createdAt' | 'updatedAt'>[];
} {
  const isoAgo = (days: number, hours: number = 0, minutes: number = 0) =>
    new Date(nowMs - ((days * 24 + hours) * 60 + minutes) * 60 * 1000).toISOString();

  const projectId = 'btech-secops-demo-prod';

  const rawEvents: Array<{
    id: string;
    timestamp: string;
    principalEmail: string;
    serviceName: string;
    methodName: string;
    resourceName: string;
    severity: AuditLogRecord['severity'];
    callerIp: string;
    status: AuditLogRecord['status'];
    statusCode: number;
    statusMessage: string;
    category: AuditLogRecord['category'];
  }> = [
    // Today / Recent events: Repeated failures by contractor account (triggers REPEATED_FAILURES)
    {
      id: 'demo_log_001',
      timestamp: isoAgo(0, 1, 45),
      principalEmail: 'ext-contractor@vendor-ops.org',
      serviceName: 'secretmanager.googleapis.com',
      methodName: 'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion',
      resourceName: `projects/${projectId}/secrets/prod-db-master-key/versions/latest`,
      severity: 'ERROR',
      callerIp: '185.220.101.44',
      status: 'FAILURE',
      statusCode: 7,
      statusMessage: 'PERMISSION_DENIED: Principal lacks secretmanager.versions.access permission',
      category: 'POLICY_DENIED',
    },
    {
      id: 'demo_log_002',
      timestamp: isoAgo(0, 1, 30),
      principalEmail: 'ext-contractor@vendor-ops.org',
      serviceName: 'secretmanager.googleapis.com',
      methodName: 'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion',
      resourceName: `projects/${projectId}/secrets/stripe-live-webhook-secret/versions/1`,
      severity: 'ERROR',
      callerIp: '185.220.101.44',
      status: 'FAILURE',
      statusCode: 7,
      statusMessage: 'PERMISSION_DENIED: Principal lacks secretmanager.versions.access permission',
      category: 'POLICY_DENIED',
    },
    {
      id: 'demo_log_003',
      timestamp: isoAgo(0, 1, 18),
      principalEmail: 'ext-contractor@vendor-ops.org',
      serviceName: 'iam.googleapis.com',
      methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
      resourceName: `projects/${projectId}/serviceAccounts/prod-compute@${projectId}.iam.gserviceaccount.com`,
      severity: 'CRITICAL',
      callerIp: '185.220.101.44',
      status: 'FAILURE',
      statusCode: 7,
      statusMessage: 'PERMISSION_DENIED: Organization policy constraints/iam.disableServiceAccountKeyCreation enforced',
      category: 'POLICY_DENIED',
    },
    {
      id: 'demo_log_004',
      timestamp: isoAgo(0, 1, 10),
      principalEmail: 'ext-contractor@vendor-ops.org',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.objects.get',
      resourceName: `projects/_/buckets/${projectId}-customer-backups/objects/dump-2026.sql.gz`,
      severity: 'ERROR',
      callerIp: '185.220.101.44',
      status: 'FAILURE',
      statusCode: 7,
      statusMessage: 'PERMISSION_DENIED: Caller does not have storage.objects.get access to bucket',
      category: 'DATA_ACCESS',
    },

    // Unusual IAM Policy Mutation (triggers UNUSUAL_IAM_CHANGE)
    {
      id: 'demo_log_005',
      timestamp: isoAgo(0, 3, 20),
      principalEmail: 'devops-lead@btech-cloudsec.edu',
      serviceName: 'cloudresourcemanager.googleapis.com',
      methodName: 'SetIamPolicy',
      resourceName: `projects/${projectId}`,
      severity: 'NOTICE',
      callerIp: '103.21.244.12',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Granted roles/owner to temporary-debug-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      category: 'ADMIN_ACTIVITY',
    },

    // Sensitive Admin Operation: Audit Sink Modification (triggers SENSITIVE_ADMIN_OP)
    {
      id: 'demo_log_006',
      timestamp: isoAgo(0, 5, 10),
      principalEmail: 'devops-lead@btech-cloudsec.edu',
      serviceName: 'logging.googleapis.com',
      methodName: 'google.logging.v2.ConfigServiceV2.UpdateSink',
      resourceName: `projects/${projectId}/sinks/central-siem-archive-sink`,
      severity: 'CRITICAL',
      callerIp: '103.21.244.12',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Modified exclusion filter on central-siem-archive-sink',
      category: 'ADMIN_ACTIVITY',
    },

    // Baseline events for devops-lead from 103.21.244.12 + 1 outlier from 91.132.14.88 (triggers UNUSUAL_IP)
    {
      id: 'demo_log_007',
      timestamp: isoAgo(1, 2, 15),
      principalEmail: 'devops-lead@btech-cloudsec.edu',
      serviceName: 'compute.googleapis.com',
      methodName: 'v1.compute.firewalls.patch',
      resourceName: `projects/${projectId}/global/firewalls/allow-ssh-ingress`,
      severity: 'WARNING',
      callerIp: '103.21.244.12',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Updated sourceRanges to 0.0.0.0/0 on port 22',
      category: 'ADMIN_ACTIVITY',
    },
    {
      id: 'demo_log_008',
      timestamp: isoAgo(1, 4, 30),
      principalEmail: 'devops-lead@btech-cloudsec.edu',
      serviceName: 'container.googleapis.com',
      methodName: 'google.container.v1.ClusterManager.UpdateCluster',
      resourceName: `projects/${projectId}/locations/asia-south1/clusters/secops-gke-prod`,
      severity: 'INFO',
      callerIp: '103.21.244.12',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Cluster master authorized networks updated',
      category: 'ADMIN_ACTIVITY',
    },
    {
      id: 'demo_log_009',
      timestamp: isoAgo(1, 6, 0),
      principalEmail: 'devops-lead@btech-cloudsec.edu',
      serviceName: 'cloudkms.googleapis.com',
      methodName: 'DestroyCryptoKeyVersion',
      resourceName: `projects/${projectId}/locations/global/keyRings/pii-ring/cryptoKeys/user-key/cryptoKeyVersions/2`,
      severity: 'ALERT',
      callerIp: '91.132.14.88',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Scheduled destruction of KMS CryptoKeyVersion from unrecognized geographic IP',
      category: 'ADMIN_ACTIVITY',
    },

    // Activity Spike burst (6 rapid operations in 10 minutes by ci-deployer service account -> triggers ACTIVITY_SPIKE)
    {
      id: 'demo_log_010',
      timestamp: isoAgo(2, 3, 12),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'bigquery.googleapis.com',
      methodName: 'jobservice.insert',
      resourceName: `projects/${projectId}/datasets/financial_ledger/tables/transactions_2026`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Executed table export query job_01',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_011',
      timestamp: isoAgo(2, 3, 10),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'bigquery.googleapis.com',
      methodName: 'jobservice.insert',
      resourceName: `projects/${projectId}/datasets/financial_ledger/tables/payroll_records`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Executed table export query job_02',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_012',
      timestamp: isoAgo(2, 3, 8),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.objects.list',
      resourceName: `projects/_/buckets/${projectId}-Export-Staging`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Listed 1,420 objects in bucket',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_013',
      timestamp: isoAgo(2, 3, 6),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.objects.create',
      resourceName: `projects/_/buckets/${projectId}-Export-Staging/objects/batch_export_1.parquet`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Created object batch_export_1.parquet',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_014',
      timestamp: isoAgo(2, 3, 4),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.objects.create',
      resourceName: `projects/_/buckets/${projectId}-Export-Staging/objects/batch_export_2.parquet`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Created object batch_export_2.parquet',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_015',
      timestamp: isoAgo(2, 3, 2),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'iam.googleapis.com',
      methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
      resourceName: `projects/${projectId}/serviceAccounts/ci-pipeline-sa@${projectId}.iam.gserviceaccount.com`,
      severity: 'WARNING',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Created new persistent user-managed service account key during burst activity',
      category: 'ADMIN_ACTIVITY',
    },

    // Historical logs across 5 days to 120 days ago (so Retention Policy cleanup has eligible records to test!)
    {
      id: 'demo_log_016',
      timestamp: isoAgo(4, 5, 0),
      principalEmail: 'system@google-cloud-platform.internal',
      serviceName: 'compute.googleapis.com',
      methodName: 'compute.instances.migrateOnHostMaintenance',
      resourceName: `projects/${projectId}/zones/asia-south1-a/instances/web-tier-node-01`,
      severity: 'DEFAULT',
      callerIp: 'internal',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Transparent host maintenance live migration completed',
      category: 'SYSTEM_EVENT',
    },
    {
      id: 'demo_log_017',
      timestamp: isoAgo(12, 8, 20),
      principalEmail: 'sec-auditor@btech-cloudsec.edu',
      serviceName: 'bigquery.googleapis.com',
      methodName: 'tableservice.get',
      resourceName: `projects/${projectId}/datasets/security_telemetry/tables/iam_bindings`,
      severity: 'INFO',
      callerIp: '14.139.220.10',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Read table metadata for compliance review',
      category: 'DATA_ACCESS',
    },
    // Older logs (45 days, 75 days, 110 days ago) specifically designed so running a 30-day or 60-day or 90-day retention cleanup removes eligible records!
    {
      id: 'demo_log_018',
      timestamp: isoAgo(42, 2, 10),
      principalEmail: 'ci-pipeline-sa@btech-secops-demo-prod.iam.gserviceaccount.com',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.objects.get',
      resourceName: `projects/_/buckets/${projectId}-build-artifacts/objects/release-v1.0.2.tar.gz`,
      severity: 'INFO',
      callerIp: '34.93.110.25',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Archived artifact read (42 days old - eligible for 30-day DATA_ACCESS retention cleanup)',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_019',
      timestamp: isoAgo(65, 6, 40),
      principalEmail: 'sec-auditor@btech-cloudsec.edu',
      serviceName: 'storage.googleapis.com',
      methodName: 'storage.buckets.getIamPolicy',
      resourceName: `projects/_/buckets/${projectId}-customer-backups`,
      severity: 'INFO',
      callerIp: '14.139.220.10',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Periodic IAM audit check (65 days old - eligible for 30-day DATA_ACCESS retention cleanup)',
      category: 'DATA_ACCESS',
    },
    {
      id: 'demo_log_020',
      timestamp: isoAgo(95, 11, 0),
      principalEmail: 'system@google-cloud-platform.internal',
      serviceName: 'compute.googleapis.com',
      methodName: 'compute.instances.automaticRestart',
      resourceName: `projects/${projectId}/zones/asia-south1-b/instances/worker-node-04`,
      severity: 'NOTICE',
      callerIp: 'internal',
      status: 'SUCCESS',
      statusCode: 0,
      statusMessage: 'Instance automatically restarted (95 days old - eligible for 90-day SYSTEM_EVENT cleanup)',
      category: 'SYSTEM_EVENT',
    },
    {
      id: 'demo_log_021',
      timestamp: isoAgo(125, 4, 15),
      principalEmail: 'ext-contractor@vendor-ops.org',
      serviceName: 'compute.googleapis.com',
      methodName: 'v1.compute.instances.delete',
      resourceName: `projects/${projectId}/zones/asia-south1-a/instances/staging-bastion`,
      severity: 'ERROR',
      callerIp: '185.220.101.44',
      status: 'FAILURE',
      statusCode: 7,
      statusMessage: 'PERMISSION_DENIED: Legacy contractor attempt (125 days old)',
      category: 'POLICY_DENIED',
    },
  ];

  const logs: Omit<AuditLogRecord, 'createdAt'>[] = rawEvents.map((e) => ({
    ...e,
    insertId: `ins_${e.id}`,
    source: 'DEMO',
    projectId,
    rawPayload: {
      logName: `projects/${projectId}/logs/cloudaudit.googleapis.com%2F${e.category.toLowerCase()}`,
      insertId: `ins_${e.id}`,
      timestamp: e.timestamp,
      severity: e.severity,
      resource: {
        type: e.serviceName.split('.')[0],
        labels: { project_id: projectId, resource_name: e.resourceName },
      },
      protoPayload: {
        '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
        serviceName: e.serviceName,
        methodName: e.methodName,
        resourceName: e.resourceName,
        authenticationInfo: { principalEmail: e.principalEmail },
        requestMetadata: {
          callerIp: e.callerIp,
          callerSuppliedUserAgent: 'google-cloud-sdk gcloud/492.0.0',
        },
        status: { code: e.statusCode, message: e.statusMessage },
      },
    },
  }));

  const policies: Omit<RetentionPolicyRecord, 'createdAt' | 'updatedAt'>[] = [
    {
      id: 'policy_data_access_30d',
      name: 'High-Volume Data Access Log Pruning (30 Days)',
      description:
        'Application-level Firestore retention policy that prunes DATA_ACCESS audit records older than 30 days to control storage footprint.',
      logCategory: 'DATA_ACCESS',
      retentionDays: 30,
      status: 'ENABLED',
      lastExecutionAt: '',
      lastDeletedCount: 0,
      createdBy: adminUid,
    },
    {
      id: 'policy_system_events_90d',
      name: 'System Maintenance Event Retention (90 Days)',
      description:
        'Retains Google Cloud SYSTEM_EVENT records in the application database for 90 days for quarterly infrastructure reliability audits.',
      logCategory: 'SYSTEM_EVENT',
      retentionDays: 90,
      status: 'ENABLED',
      lastExecutionAt: '',
      lastDeletedCount: 0,
      createdBy: adminUid,
    },
    {
      id: 'policy_admin_activity_365d',
      name: 'Admin & IAM Compliance Archive (365 Days)',
      description:
        'Preserves ADMIN_ACTIVITY records for a full 365-day compliance window. Disabled by default during short-term testing.',
      logCategory: 'ADMIN_ACTIVITY',
      retentionDays: 365,
      status: 'DISABLED',
      lastExecutionAt: '',
      lastDeletedCount: 0,
      createdBy: adminUid,
    },
  ];

  const detectedAlerts = detectSecurityAlertsFromLogs(logs as AuditLogRecord[]);
  // Mark one alert as CONFIRMED_INCIDENT and one as REVIEWED so the demo showcases distinct incident triage states
  const alerts = detectedAlerts.map((a, idx) => {
    if (idx === 0) {
      return {
        ...a,
        status: 'CONFIRMED_INCIDENT' as const,
        reviewedBy: '2400560511bba@gmail.com',
        reviewedAt: isoAgo(0, 0, 25),
      };
    }
    if (idx === 2) {
      return {
        ...a,
        status: 'REVIEWED' as const,
        reviewedBy: '2400560511bba@gmail.com',
        reviewedAt: isoAgo(0, 2, 10),
      };
    }
    return a;
  });

  return { logs, policies, alerts };
}
