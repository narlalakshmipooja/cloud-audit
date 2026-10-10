import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { Logging } from '@google-cloud/logging';
import {
  normalizeGcpAuditEntry,
  filterAndSortLogs,
  evaluateRetentionEligibility,
  detectSecurityAlertsFromLogs,
  computeDashboardStats,
  generateLogsCsv,
  generateSecurityReportCsv,
  sanitizeId,
} from './src/securityEngine';
import {
  AuditLogRecord,
  RetentionPolicyRecord,
  SecurityAlertRecord,
  RetentionExecutionRecord,
} from './src/types';

const firebaseConfigPath = path.resolve(process.cwd(), 'firebase-applet-config.json');
const firebaseConfig = JSON.parse(fs.readFileSync(firebaseConfigPath, 'utf-8'));

const PROJECT_ID = firebaseConfig.projectId;
const DATABASE_ID = firebaseConfig.firestoreDatabaseId || '(default)';
const FIRESTORE_BASE_URL = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/${DATABASE_ID}/documents`;
const BOOTSTRAPPED_ADMIN_EMAIL = '2400560511bba@gmail.com';

// Helper to convert JS values to Firestore REST Value format
function toFirestoreValue(val: unknown): Record<string, unknown> {
  if (val === null || val === undefined) {
    return { nullValue: null };
  }
  if (val === '__SERVER_TIMESTAMP__') {
    return { timestampValue: new Date().toISOString() };
  }
  if (typeof val === 'boolean') {
    return { booleanValue: val };
  }
  if (typeof val === 'number') {
    if (Number.isInteger(val)) {
      return { integerValue: String(val) };
    }
    return { doubleValue: val };
  }
  if (typeof val === 'string') {
    return { stringValue: val };
  }
  if (Array.isArray(val)) {
    return {
      arrayValue: {
        values: val.map((item) => toFirestoreValue(item)),
      },
    };
  }
  if (typeof val === 'object') {
    const fields: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (v !== undefined) {
        fields[k] = toFirestoreValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function fromFirestoreValue(valObj: Record<string, unknown> | undefined): unknown {
  if (!valObj) return undefined;
  if ('stringValue' in valObj) return valObj.stringValue;
  if ('integerValue' in valObj) return Number(valObj.integerValue);
  if ('doubleValue' in valObj) return Number(valObj.doubleValue);
  if ('booleanValue' in valObj) return Boolean(valObj.booleanValue);
  if ('timestampValue' in valObj) return valObj.timestampValue;
  if ('nullValue' in valObj) return null;
  if ('arrayValue' in valObj) {
    const arr = (valObj.arrayValue as { values?: Record<string, unknown>[] })?.values || [];
    return arr.map((v) => fromFirestoreValue(v));
  }
  if ('mapValue' in valObj) {
    const fields =
      (valObj.mapValue as { fields?: Record<string, Record<string, unknown>> })?.fields || {};
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(fields)) {
      out[k] = fromFirestoreValue(v);
    }
    return out;
  }
  return undefined;
}

function parseFirestoreDoc<T>(docObj: {
  name?: string;
  fields?: Record<string, Record<string, unknown>>;
}): T {
  const fields = docObj.fields || {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = fromFirestoreValue(v);
  }
  if (!out.id && docObj.name) {
    const parts = docObj.name.split('/');
    out.id = parts[parts.length - 1];
  }
  return out as T;
}

// Decode JWT payload safely to inspect uid and email (Firestore REST enforces cryptographic signature verification on every request)
function decodeJwtPayload(token: string): { user_id?: string; sub?: string; email?: string; email_verified?: boolean } {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return {};
    const json = Buffer.from(parts[1], 'base64url').toString('utf-8');
    return JSON.parse(json);
  } catch {
    return {};
  }
}

interface AuthenticatedRequest extends Request {
  idToken?: string;
  userUid?: string;
  userEmail?: string;
  userRole?: 'admin' | 'analyst' | 'viewer';
}

async function firestoreListCollection<T>(collectionName: string, idToken: string): Promise<T[]> {
  // Use runQuery with a WHERE filter that satisfies the hardened Firestore list rules
  let fieldFilter: Record<string, unknown> | undefined;
  if (collectionName === 'audit_logs' || collectionName === 'security_alerts') {
    fieldFilter = {
      fieldFilter: {
        field: { fieldPath: 'source' },
        op: 'IN',
        value: {
          arrayValue: {
            values: [{ stringValue: 'GCP_LIVE' }, { stringValue: 'DEMO' }],
          },
        },
      },
    };
  } else if (collectionName === 'retention_policies') {
    fieldFilter = {
      fieldFilter: {
        field: { fieldPath: 'status' },
        op: 'IN',
        value: {
          arrayValue: {
            values: [{ stringValue: 'ENABLED' }, { stringValue: 'DISABLED' }],
          },
        },
      },
    };
  } else if (collectionName === 'retention_executions') {
    fieldFilter = {
      fieldFilter: {
        field: { fieldPath: 'status' },
        op: 'IN',
        value: {
          arrayValue: {
            values: [
              { stringValue: 'COMPLETED' },
              { stringValue: 'DRY_RUN' },
              { stringValue: 'FAILED' },
            ],
          },
        },
      },
    };
  } else if (collectionName === 'integration_settings') {
    fieldFilter = {
      fieldFilter: {
        field: { fieldPath: 'connectionStatus' },
        op: 'IN',
        value: {
          arrayValue: {
            values: [
              { stringValue: 'CONNECTED' },
              { stringValue: 'DISCONNECTED' },
              { stringValue: 'MISSING_CREDENTIALS' },
              { stringValue: 'ERROR' },
            ],
          },
        },
      },
    };
  }

  const structuredQuery: Record<string, unknown> = {
    from: [{ collectionId: collectionName }],
    limit: 500,
  };
  if (fieldFilter) {
    structuredQuery.where = fieldFilter;
  }

  const resp = await fetch(`${FIRESTORE_BASE_URL}:runQuery`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${idToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ structuredQuery }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Firestore query error (${collectionName}): ${resp.status} ${errText}`);
  }

  const rows = (await resp.json()) as Array<{ document?: { name?: string; fields?: Record<string, Record<string, unknown>> } }>;
  return rows.filter((r) => r.document).map((r) => parseFirestoreDoc<T>(r.document!));
}

async function firestoreGetDoc<T>(
  collectionName: string,
  docId: string,
  idToken: string
): Promise<T | null> {
  const resp = await fetch(`${FIRESTORE_BASE_URL}/${collectionName}/${encodeURIComponent(docId)}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${idToken}`,
    },
  });
  if (resp.status === 404) return null;
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Firestore get error (${collectionName}/${docId}): ${resp.status} ${errText}`);
  }
  const docObj = await resp.json();
  return parseFirestoreDoc<T>(docObj);
}

async function firestoreUpsertDoc(
  collectionName: string,
  docId: string,
  data: Record<string, unknown>,
  idToken: string,
  serverTimestampFields: string[] = ['createdAt', 'updatedAt']
): Promise<void> {
  const docName = `projects/${PROJECT_ID}/databases/${DATABASE_ID}/documents/${collectionName}/${docId}`;
  const fields: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (serverTimestampFields.includes(k)) continue;
    fields[k] = toFirestoreValue(v);
  }

  const writes: unknown[] = [
    {
      update: {
        name: docName,
        fields,
      },
      updateTransforms: serverTimestampFields.map((fieldPath) => ({
        fieldPath,
        setToServerValue: 'REQUEST_TIME',
      })),
    },
  ];

  const resp = await fetch(`${FIRESTORE_BASE_URL}:commit`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${idToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ writes }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Firestore write error (${collectionName}/${docId}): ${resp.status} ${errText}`);
  }
}

async function firestorePatchDoc(
  collectionName: string,
  docId: string,
  existingData: Record<string, unknown>,
  updatedFields: Record<string, unknown>,
  idToken: string,
  serverTimestampFields: string[] = ['updatedAt']
): Promise<void> {
  const merged = { ...existingData, ...updatedFields };
  const docName = `projects/${PROJECT_ID}/databases/${DATABASE_ID}/documents/${collectionName}/${docId}`;
  const fields: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(merged)) {
    if (serverTimestampFields.includes(k)) continue;
    if (k === 'createdAt' && typeof v === 'string') {
      fields[k] = { timestampValue: v };
    } else if (k === 'executedAt' && typeof v === 'string') {
      fields[k] = { timestampValue: v };
    } else if (k === 'lastLoginAt' && typeof v === 'string') {
      fields[k] = { timestampValue: v };
    } else {
      fields[k] = toFirestoreValue(v);
    }
  }

  const updateMaskFieldPaths = [
    ...Object.keys(updatedFields).filter((k) => !serverTimestampFields.includes(k)),
  ];

  const writes: unknown[] = [
    {
      update: {
        name: docName,
        fields,
      },
      updateMask: { fieldPaths: updateMaskFieldPaths },
      updateTransforms: serverTimestampFields.map((fieldPath) => ({
        fieldPath,
        setToServerValue: 'REQUEST_TIME',
      })),
    },
  ];

  const resp = await fetch(`${FIRESTORE_BASE_URL}:commit`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${idToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ writes }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Firestore patch error (${collectionName}/${docId}): ${resp.status} ${errText}`);
  }
}

async function firestoreDeleteBatch(
  collectionName: string,
  docIds: string[],
  idToken: string
): Promise<number> {
  if (docIds.length === 0) return 0;
  let deletedTotal = 0;
  const BATCH_SIZE = 100;
  for (let i = 0; i < docIds.length; i += BATCH_SIZE) {
    const chunk = docIds.slice(i, i + BATCH_SIZE);
    const writes = chunk.map((id) => ({
      delete: `projects/${PROJECT_ID}/databases/${DATABASE_ID}/documents/${collectionName}/${id}`,
    }));
    const resp = await fetch(`${FIRESTORE_BASE_URL}:commit`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${idToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ writes }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Firestore batch delete error: ${resp.status} ${errText}`);
    }
    deletedTotal += chunk.length;
  }
  return deletedTotal;
}

// Authentication & Role Resolution Middleware
async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization Bearer token.' });
    return;
  }
  const token = authHeader.slice(7).trim();
  const payload = decodeJwtPayload(token);
  const uid = payload.user_id || payload.sub;
  if (!uid) {
    res.status(401).json({ error: 'Invalid Firebase ID token payload.' });
    return;
  }

  req.idToken = token;
  req.userUid = uid;
  req.userEmail = payload.email || '';

  // Determine user role from Firestore /users/{uid} or bootstrapped admin email
  try {
    const userDoc = await firestoreGetDoc<{ role?: 'admin' | 'analyst' | 'viewer' }>(
      'users',
      uid,
      token
    );
    if (req.userEmail === BOOTSTRAPPED_ADMIN_EMAIL) {
      req.userRole = 'admin';
    } else if (userDoc?.role) {
      req.userRole = userDoc.role;
    } else {
      req.userRole = 'viewer';
    }
    next();
  } catch (err) {
    res.status(401).json({
      error: 'Authentication failed against Firestore security boundary.',
      details: err instanceof Error ? err.message : String(err),
    });
  }
}

function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (req.userRole !== 'admin') {
    res.status(403).json({
      error: 'Forbidden: Administrator role is required to perform this action.',
    });
    return;
  }
  next();
}

function requireAnalystOrAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (req.userRole !== 'admin' && req.userRole !== 'analyst') {
    res.status(403).json({
      error: 'Forbidden: Security Analyst or Administrator role is required.',
    });
    return;
  }
  next();
}

// Helper to initialize Google Cloud Logging client from server-side environment secrets
function createGcpLoggingClient(overrideProjectId?: string): {
  logging: Logging | null;
  resolvedProjectId: string;
  hasCredentials: boolean;
  credentialError?: string;
} {
  const saJsonRaw = process.env.GCP_SERVICE_ACCOUNT_JSON?.trim();
  const envProjectId = process.env.GCP_PROJECT_ID?.trim();
  const resolvedProjectId = overrideProjectId?.trim() || envProjectId || '';

  if (!saJsonRaw) {
    return {
      logging: null,
      resolvedProjectId,
      hasCredentials: false,
      credentialError:
        'Missing GCP_SERVICE_ACCOUNT_JSON secret on server. Configure a Service Account key with roles/logging.viewer in the AI Studio Secrets panel.',
    };
  }

  try {
    const credentials = JSON.parse(saJsonRaw);
    const projectId = resolvedProjectId || credentials.project_id || '';
    if (!projectId) {
      return {
        logging: null,
        resolvedProjectId: '',
        hasCredentials: false,
        credentialError: 'No GCP Project ID provided in request or Service Account JSON.',
      };
    }
    const logging = new Logging({
      projectId,
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key,
      },
    });
    return { logging, resolvedProjectId: projectId, hasCredentials: true };
  } catch (err) {
    return {
      logging: null,
      resolvedProjectId,
      hasCredentials: false,
      credentialError: `Invalid GCP_SERVICE_ACCOUNT_JSON format: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '2mb' }));

  // 1. GET /api/health
  app.get('/api/health', (_req: Request, res: Response) => {
    const hasGcpCreds = Boolean(process.env.GCP_SERVICE_ACCOUNT_JSON?.trim());
    res.json({
      status: 'ok',
      service: 'Cloud Audit Logs Retention & Analysis Backend',
      timestamp: new Date().toISOString(),
      firestoreProjectId: PROJECT_ID,
      firestoreDatabaseId: DATABASE_ID,
      gcpCredentialsConfigured: hasGcpCreds,
    });
  });

  // 2. GET /api/stats
  app.get('/api/stats', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const sourceFilter = typeof req.query.source === 'string' ? req.query.source : 'ALL';
      const [allLogs, allAlerts, policies] = await Promise.all([
        firestoreListCollection<AuditLogRecord>('audit_logs', req.idToken!),
        firestoreListCollection<SecurityAlertRecord>('security_alerts', req.idToken!),
        firestoreListCollection<RetentionPolicyRecord>('retention_policies', req.idToken!),
      ]);

      const logs =
        sourceFilter && sourceFilter !== 'ALL'
          ? allLogs.filter((l) => l.source === sourceFilter)
          : allLogs;
      const alerts =
        sourceFilter && sourceFilter !== 'ALL'
          ? allAlerts.filter((a) => a.source === sourceFilter)
          : allAlerts;

      const stats = computeDashboardStats(logs, alerts, policies);
      res.json(stats);
    } catch (err) {
      res.status(500).json({
        error: 'Failed to compute dashboard statistics.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // 3. GET /api/logs
  app.get('/api/logs', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const allLogs = await firestoreListCollection<AuditLogRecord>('audit_logs', req.idToken!);
      const result = filterAndSortLogs(allLogs, {
        search: typeof req.query.search === 'string' ? req.query.search : undefined,
        startDate: typeof req.query.startDate === 'string' ? req.query.startDate : undefined,
        endDate: typeof req.query.endDate === 'string' ? req.query.endDate : undefined,
        principalEmail:
          typeof req.query.principalEmail === 'string' ? req.query.principalEmail : undefined,
        serviceName: typeof req.query.serviceName === 'string' ? req.query.serviceName : undefined,
        severity: typeof req.query.severity === 'string' ? req.query.severity : undefined,
        category: typeof req.query.category === 'string' ? req.query.category : undefined,
        status: typeof req.query.status === 'string' ? req.query.status : undefined,
        source: typeof req.query.source === 'string' ? req.query.source : undefined,
        sortBy:
          typeof req.query.sortBy === 'string'
            ? (req.query.sortBy as 'timestamp' | 'severity' | 'serviceName' | 'principalEmail')
            : 'timestamp',
        sortOrder:
          typeof req.query.sortOrder === 'string'
            ? (req.query.sortOrder as 'asc' | 'desc')
            : 'desc',
        page: req.query.page ? Number(req.query.page) : 1,
        pageSize: req.query.pageSize ? Number(req.query.pageSize) : 15,
      });
      res.json(result);
    } catch (err) {
      res.status(500).json({
        error: 'Failed to fetch and filter audit logs.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // 4. GET /api/logs/:id
  app.get('/api/logs/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const log = await firestoreGetDoc<AuditLogRecord>('audit_logs', req.params.id, req.idToken!);
      if (!log) {
        res.status(404).json({ error: `Audit log ${req.params.id} not found.` });
        return;
      }
      res.json(log);
    } catch (err) {
      res.status(500).json({
        error: 'Failed to retrieve audit log details.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // 5. POST /api/integration/test
  app.post(
    '/api/integration/test',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      const requestedProjectId =
        typeof req.body?.gcpProjectId === 'string' ? req.body.gcpProjectId.trim() : '';
      const logFilter =
        typeof req.body?.logFilter === 'string' && req.body.logFilter.trim()
          ? req.body.logFilter.trim()
          : 'logName:"cloudaudit.googleapis.com"';

      const clientInfo = createGcpLoggingClient(requestedProjectId);

      if (!clientInfo.hasCredentials || !clientInfo.logging) {
        // Persist MISSING_CREDENTIALS status to integration_settings/default
        try {
          await firestoreUpsertDoc(
            'integration_settings',
            'default',
            {
              id: 'default',
              gcpProjectId: clientInfo.resolvedProjectId || requestedProjectId || '',
              logFilter: logFilter.slice(0, 500),
              connectionStatus: 'MISSING_CREDENTIALS',
              lastSyncAt: '',
              lastSyncCount: 0,
              lastError: (clientInfo.credentialError || 'Missing credentials').slice(0, 500),
              demoMode: true,
              updatedBy: req.userEmail || req.userUid || 'admin',
            },
            req.idToken!,
            ['updatedAt']
          );
        } catch {
          // ignore secondary persistence error
        }

        res.status(200).json({
          connected: false,
          status: 'MISSING_CREDENTIALS',
          gcpProjectId: clientInfo.resolvedProjectId || requestedProjectId,
          message:
            clientInfo.credentialError ||
            'GCP Service Account credentials are not configured on the server.',
        });
        return;
      }

      try {
        // Perform a lightweight live read (pageSize: 1) against Google Cloud Logging API
        const [entries] = await clientInfo.logging.getEntries({
          filter: logFilter,
          pageSize: 1,
          autoPaginate: false,
        });

        await firestoreUpsertDoc(
          'integration_settings',
          'default',
          {
            id: 'default',
            gcpProjectId: clientInfo.resolvedProjectId,
            logFilter: logFilter.slice(0, 500),
            connectionStatus: 'CONNECTED',
            lastSyncAt: new Date().toISOString(),
            lastSyncCount: entries.length,
            lastError: '',
            demoMode: false,
            updatedBy: req.userEmail || req.userUid || 'admin',
          },
          req.idToken!,
          ['updatedAt']
        );

        res.json({
          connected: true,
          status: 'CONNECTED',
          gcpProjectId: clientInfo.resolvedProjectId,
          sampleEntriesCount: entries.length,
          message: `Successfully authenticated and queried Google Cloud Logging for project "${clientInfo.resolvedProjectId}".`,
        });
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        try {
          await firestoreUpsertDoc(
            'integration_settings',
            'default',
            {
              id: 'default',
              gcpProjectId: clientInfo.resolvedProjectId,
              logFilter: logFilter.slice(0, 500),
              connectionStatus: 'ERROR',
              lastSyncAt: '',
              lastSyncCount: 0,
              lastError: errMsg.slice(0, 500),
              demoMode: true,
              updatedBy: req.userEmail || req.userUid || 'admin',
            },
            req.idToken!,
            ['updatedAt']
          );
        } catch {
          // ignore
        }

        res.status(200).json({
          connected: false,
          status: 'ERROR',
          gcpProjectId: clientInfo.resolvedProjectId,
          message: `Google Cloud Logging API call failed: ${errMsg}`,
        });
      }
    }
  );

  // 6. POST /api/logs/sync
  app.post(
    '/api/logs/sync',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      const requestedProjectId =
        typeof req.body?.gcpProjectId === 'string' ? req.body.gcpProjectId.trim() : '';
      const maxEntries = Math.max(1, Math.min(100, Number(req.body?.maxEntries) || 50));
      const daysBack = Math.max(1, Math.min(90, Number(req.body?.daysBack) || 7));

      const clientInfo = createGcpLoggingClient(requestedProjectId);
      if (!clientInfo.hasCredentials || !clientInfo.logging) {
        res.status(400).json({
          synced: false,
          status: 'MISSING_CREDENTIALS',
          error:
            clientInfo.credentialError ||
            'Cannot sync live logs: GCP_SERVICE_ACCOUNT_JSON is not configured on the server.',
        });
        return;
      }

      const startIso = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000).toISOString();
      const customFilter =
        typeof req.body?.logFilter === 'string' && req.body.logFilter.trim()
          ? req.body.logFilter.trim()
          : 'logName:"cloudaudit.googleapis.com"';
      const combinedFilter = `${customFilter} AND timestamp >= "${startIso}"`;

      try {
        const [entries] = await clientInfo.logging.getEntries({
          filter: combinedFilter,
          pageSize: maxEntries,
          autoPaginate: false,
        });

        const existingLogs = await firestoreListCollection<AuditLogRecord>(
          'audit_logs',
          req.idToken!
        );
        const existingIds = new Set(existingLogs.map((l) => l.id));

        let importedCount = 0;
        let duplicateSkippedCount = 0;
        const newlyImported: AuditLogRecord[] = [];

        for (const entry of entries) {
          const entryAny = entry as unknown as { toJSON?: () => Record<string, unknown> };
          const rawJson =
            typeof entryAny.toJSON === 'function'
              ? entryAny.toJSON()
              : (entry as unknown as Record<string, unknown>);
          const normalized = normalizeGcpAuditEntry(rawJson, clientInfo.resolvedProjectId);
          if (existingIds.has(normalized.id)) {
            duplicateSkippedCount += 1;
            continue;
          }
          await firestoreUpsertDoc(
            'audit_logs',
            normalized.id,
            normalized as unknown as Record<string, unknown>,
            req.idToken!,
            ['createdAt']
          );
          existingIds.add(normalized.id);
          importedCount += 1;
          newlyImported.push(normalized as AuditLogRecord);
        }

        // Run rule-based security detection over updated live logs
        const allUpdatedLogs = [...existingLogs, ...newlyImported].filter(
          (l) => l.source === 'GCP_LIVE'
        );
        const generatedAlerts = detectSecurityAlertsFromLogs(allUpdatedLogs);
        const existingAlerts = await firestoreListCollection<SecurityAlertRecord>(
          'security_alerts',
          req.idToken!
        );
        const existingAlertIds = new Set(existingAlerts.map((a) => a.id));

        let newAlertsCount = 0;
        for (const alert of generatedAlerts) {
          if (!existingAlertIds.has(alert.id)) {
            await firestoreUpsertDoc(
              'security_alerts',
              alert.id,
              alert as unknown as Record<string, unknown>,
              req.idToken!,
              ['createdAt', 'updatedAt']
            );
            newAlertsCount += 1;
          }
        }

        const nowIso = new Date().toISOString();
        await firestoreUpsertDoc(
          'integration_settings',
          'default',
          {
            id: 'default',
            gcpProjectId: clientInfo.resolvedProjectId,
            logFilter: customFilter.slice(0, 500),
            connectionStatus: 'CONNECTED',
            lastSyncAt: nowIso,
            lastSyncCount: importedCount,
            lastError: '',
            demoMode: false,
            updatedBy: req.userEmail || req.userUid || 'admin',
          },
          req.idToken!,
          ['updatedAt']
        );

        res.json({
          synced: true,
          status: 'CONNECTED',
          gcpProjectId: clientInfo.resolvedProjectId,
          fetchedCount: entries.length,
          importedCount,
          duplicateSkippedCount,
          newAlertsCount,
          lastSyncAt: nowIso,
        });
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        res.status(502).json({
          synced: false,
          status: 'ERROR',
          error: `Failed to sync logs from Google Cloud Logging: ${errMsg}`,
        });
      }
    }
  );

  // 7. GET /api/retention
  app.get('/api/retention', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const [policies, executions] = await Promise.all([
        firestoreListCollection<RetentionPolicyRecord>('retention_policies', req.idToken!),
        firestoreListCollection<RetentionExecutionRecord>('retention_executions', req.idToken!),
      ]);
      res.json({
        policies,
        executions: executions.sort((a, b) =>
          String(b.executedAt || b.cutoffTimestamp).localeCompare(
            String(a.executedAt || a.cutoffTimestamp)
          )
        ),
      });
    } catch (err) {
      res.status(500).json({
        error: 'Failed to fetch retention policies.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // 8. POST /api/retention
  app.post(
    '/api/retention',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const name = String(req.body?.name || '').trim();
        const description = String(req.body?.description || '').trim();
        const logCategory = String(req.body?.logCategory || 'ALL');
        const retentionDays = Number(req.body?.retentionDays);
        const status = req.body?.status === 'DISABLED' ? 'DISABLED' : 'ENABLED';

        if (!name || name.length > 120) {
          res.status(400).json({ error: 'Policy name is required (1-120 characters).' });
          return;
        }
        if (
          !['ALL', 'ADMIN_ACTIVITY', 'DATA_ACCESS', 'SYSTEM_EVENT', 'POLICY_DENIED'].includes(
            logCategory
          )
        ) {
          res.status(400).json({ error: 'Invalid log category.' });
          return;
        }
        if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
          res
            .status(400)
            .json({ error: 'Retention days must be an integer between 1 and 3650 days.' });
          return;
        }

        const id = sanitizeId(req.body?.id || `pol_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
        const newPolicy: Omit<RetentionPolicyRecord, 'createdAt' | 'updatedAt'> = {
          id,
          name,
          description: description.slice(0, 500),
          logCategory: logCategory as RetentionPolicyRecord['logCategory'],
          retentionDays,
          status,
          lastExecutionAt: '',
          lastDeletedCount: 0,
          createdBy: req.userUid!,
        };

        await firestoreUpsertDoc(
          'retention_policies',
          id,
          newPolicy as unknown as Record<string, unknown>,
          req.idToken!,
          ['createdAt', 'updatedAt']
        );

        res.status(201).json(newPolicy);
      } catch (err) {
        res.status(500).json({
          error: 'Failed to create retention policy.',
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  );

  // 9. PATCH /api/retention/:id
  app.patch(
    '/api/retention/:id',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const policyId = req.params.id;
        const existing = await firestoreGetDoc<RetentionPolicyRecord>(
          'retention_policies',
          policyId,
          req.idToken!
        );
        if (!existing) {
          res.status(404).json({ error: `Retention policy ${policyId} not found.` });
          return;
        }

        const updates: Record<string, unknown> = {};
        if (typeof req.body?.name === 'string') {
          const name = req.body.name.trim();
          if (!name || name.length > 120) {
            res.status(400).json({ error: 'Policy name must be between 1 and 120 characters.' });
            return;
          }
          updates.name = name;
        }
        if (typeof req.body?.description === 'string') {
          updates.description = req.body.description.trim().slice(0, 500);
        }
        if (typeof req.body?.logCategory === 'string') {
          updates.logCategory = req.body.logCategory;
        }
        if (req.body?.retentionDays !== undefined) {
          const days = Number(req.body.retentionDays);
          if (!Number.isInteger(days) || days < 1 || days > 3650) {
            res.status(400).json({ error: 'Retention days must be between 1 and 3650.' });
            return;
          }
          updates.retentionDays = days;
        }
        if (req.body?.status === 'ENABLED' || req.body?.status === 'DISABLED') {
          updates.status = req.body.status;
        }

        await firestorePatchDoc(
          'retention_policies',
          policyId,
          existing as unknown as Record<string, unknown>,
          updates,
          req.idToken!,
          ['updatedAt']
        );

        res.json({ ...existing, ...updates });
      } catch (err) {
        res.status(500).json({
          error: 'Failed to update retention policy.',
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  );

  // 10. DELETE /api/retention/:id
  app.delete(
    '/api/retention/:id',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const policyId = req.params.id;
        await firestoreDeleteBatch('retention_policies', [policyId], req.idToken!);
        res.json({ deleted: true, id: policyId });
      } catch (err) {
        res.status(500).json({
          error: 'Failed to delete retention policy.',
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  );

  // 11. POST /api/retention/run
  app.post(
    '/api/retention/run',
    requireAuth,
    requireAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const targetPolicyId =
          typeof req.body?.policyId === 'string' ? req.body.policyId.trim() : '';
        const dryRun = Boolean(req.body?.dryRun);

        const [allPolicies, allLogs] = await Promise.all([
          firestoreListCollection<RetentionPolicyRecord>('retention_policies', req.idToken!),
          firestoreListCollection<AuditLogRecord>('audit_logs', req.idToken!),
        ]);

        const policiesToRun = targetPolicyId
          ? allPolicies.filter((p) => p.id === targetPolicyId)
          : allPolicies.filter((p) => p.status === 'ENABLED');

        if (policiesToRun.length === 0) {
          res.status(400).json({
            error: targetPolicyId
              ? 'Specified retention policy not found.'
              : 'No enabled retention policies found to execute.',
          });
          return;
        }

        const executionsCreated: Omit<RetentionExecutionRecord, 'executedAt'>[] = [];
        let totalDeleted = 0;
        const alreadyDeletedLogIds = new Set<string>();

        for (const policy of policiesToRun) {
          // If a specific policy was requested even while disabled, evaluate using ENABLED override only if dryRun, else require ENABLED
          if (policy.status !== 'ENABLED' && !dryRun) {
            continue;
          }

          const remainingLogs = allLogs.filter((l) => !alreadyDeletedLogIds.has(l.id));
          const { eligibleLogs, cutoffIso } = evaluateRetentionEligibility(remainingLogs, {
            logCategory: policy.logCategory,
            retentionDays: policy.retentionDays,
            status: 'ENABLED',
          });

          const eligibleIds = eligibleLogs.map((l) => l.id);
          let deletedCount = 0;

          if (!dryRun && eligibleIds.length > 0) {
            deletedCount = await firestoreDeleteBatch('audit_logs', eligibleIds, req.idToken!);
            eligibleIds.forEach((id) => alreadyDeletedLogIds.add(id));
          } else {
            deletedCount = eligibleIds.length;
          }

          totalDeleted += deletedCount;
          const nowIso = new Date().toISOString();

          if (!dryRun) {
            await firestorePatchDoc(
              'retention_policies',
              policy.id,
              policy as unknown as Record<string, unknown>,
              {
                lastExecutionAt: nowIso,
                lastDeletedCount: deletedCount,
              },
              req.idToken!,
              ['updatedAt']
            );
          }

          const execId = sanitizeId(
            `exec_${policy.id}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
          );
          const execRecord: Omit<RetentionExecutionRecord, 'executedAt'> = {
            id: execId,
            policyId: policy.id,
            policyName: policy.name,
            logCategory: policy.logCategory,
            retentionDays: policy.retentionDays,
            cutoffTimestamp: cutoffIso,
            deletedCount,
            executedBy: req.userEmail || req.userUid || 'admin',
            status: dryRun ? 'DRY_RUN' : 'COMPLETED',
            details: dryRun
              ? `Dry run identified ${deletedCount} application Firestore records older than ${policy.retentionDays} days (cutoff ${cutoffIso.slice(0, 10)}).`
              : `Deleted ${deletedCount} application Firestore records in category ${policy.logCategory} older than ${policy.retentionDays} days (cutoff ${cutoffIso.slice(0, 10)}). Native GCP _Default/_Required buckets were not modified.`,
          };

          await firestoreUpsertDoc(
            'retention_executions',
            execId,
            execRecord as unknown as Record<string, unknown>,
            req.idToken!,
            ['executedAt']
          );
          executionsCreated.push(execRecord);
        }

        res.json({
          dryRun,
          totalDeleted,
          executions: executionsCreated,
        });
      } catch (err) {
        res.status(500).json({
          error: 'Failed to execute retention cleanup.',
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  );

  // 12. GET /api/alerts
  app.get('/api/alerts', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      let alerts = await firestoreListCollection<SecurityAlertRecord>(
        'security_alerts',
        req.idToken!
      );

      const { severity, status, ruleId, source, startDate, endDate, search } = req.query;
      if (typeof source === 'string' && source !== 'ALL') {
        alerts = alerts.filter((a) => a.source === source);
      }
      if (typeof severity === 'string' && severity !== 'ALL') {
        alerts = alerts.filter((a) => a.severity === severity);
      }
      if (typeof status === 'string' && status !== 'ALL') {
        alerts = alerts.filter((a) => a.status === status);
      }
      if (typeof ruleId === 'string' && ruleId !== 'ALL') {
        alerts = alerts.filter((a) => a.ruleId === ruleId);
      }
      if (typeof startDate === 'string' && startDate) {
        const ms = new Date(startDate).getTime();
        if (!isNaN(ms)) alerts = alerts.filter((a) => new Date(a.eventTime).getTime() >= ms);
      }
      if (typeof endDate === 'string' && endDate) {
        const d = new Date(endDate);
        if (endDate.length <= 10) d.setHours(23, 59, 59, 999);
        const ms = d.getTime();
        if (!isNaN(ms)) alerts = alerts.filter((a) => new Date(a.eventTime).getTime() <= ms);
      }
      if (typeof search === 'string' && search.trim()) {
        const q = search.trim().toLowerCase();
        alerts = alerts.filter(
          (a) =>
            a.title.toLowerCase().includes(q) ||
            a.description.toLowerCase().includes(q) ||
            a.principalEmail.toLowerCase().includes(q) ||
            a.callerIp.toLowerCase().includes(q) ||
            a.detectionReason.toLowerCase().includes(q)
        );
      }

      alerts.sort((a, b) => new Date(b.eventTime).getTime() - new Date(a.eventTime).getTime());
      res.json({ alerts, total: alerts.length });
    } catch (err) {
      res.status(500).json({
        error: 'Failed to retrieve security alerts.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // 13. PATCH /api/alerts/:id
  app.patch(
    '/api/alerts/:id',
    requireAuth,
    requireAnalystOrAdmin,
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const alertId = req.params.id;
        const existing = await firestoreGetDoc<SecurityAlertRecord>(
          'security_alerts',
          alertId,
          req.idToken!
        );
        if (!existing) {
          res.status(404).json({ error: `Security alert ${alertId} not found.` });
          return;
        }

        const newStatus = req.body?.status;
        if (!['OPEN', 'REVIEWED', 'CONFIRMED_INCIDENT', 'DISMISSED'].includes(newStatus)) {
          res.status(400).json({ error: 'Invalid alert status.' });
          return;
        }

        const updates = {
          status: newStatus,
          reviewedBy: req.userEmail || req.userUid || 'analyst',
          reviewedAt: new Date().toISOString(),
        };

        await firestorePatchDoc(
          'security_alerts',
          alertId,
          existing as unknown as Record<string, unknown>,
          updates,
          req.idToken!,
          ['updatedAt']
        );

        res.json({ ...existing, ...updates });
      } catch (err) {
        res.status(500).json({
          error: 'Failed to update security alert status.',
          details: err instanceof Error ? err.message : String(err),
        });
      }
    }
  );

  // 14. GET /api/reports/export
  app.get('/api/reports/export', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const reportType = typeof req.query.type === 'string' ? req.query.type : 'full_report';
      const startDate = typeof req.query.startDate === 'string' ? req.query.startDate : '';
      const endDate = typeof req.query.endDate === 'string' ? req.query.endDate : '';
      const source = typeof req.query.source === 'string' ? req.query.source : 'ALL';
      const severity = typeof req.query.severity === 'string' ? req.query.severity : 'ALL';
      const category = typeof req.query.category === 'string' ? req.query.category : 'ALL';
      const status = typeof req.query.status === 'string' ? req.query.status : 'ALL';

      const [allLogs, allAlerts] = await Promise.all([
        firestoreListCollection<AuditLogRecord>('audit_logs', req.idToken!),
        firestoreListCollection<SecurityAlertRecord>('security_alerts', req.idToken!),
      ]);

      const { items: filteredLogs } = filterAndSortLogs(allLogs, {
        startDate: startDate || undefined,
        endDate: endDate || undefined,
        source,
        severity,
        category,
        status,
        page: 1,
        pageSize: 1000,
      });

      let filteredAlerts = [...allAlerts];
      if (source && source !== 'ALL') {
        filteredAlerts = filteredAlerts.filter((a) => a.source === source);
      }
      if (startDate) {
        const ms = new Date(startDate).getTime();
        if (!isNaN(ms))
          filteredAlerts = filteredAlerts.filter((a) => new Date(a.eventTime).getTime() >= ms);
      }
      if (endDate) {
        const d = new Date(endDate);
        if (endDate.length <= 10) d.setHours(23, 59, 59, 999);
        const ms = d.getTime();
        if (!isNaN(ms))
          filteredAlerts = filteredAlerts.filter((a) => new Date(a.eventTime).getTime() <= ms);
      }

      const dateRangeLabel =
        startDate || endDate ? `${startDate || 'Beginning'} to ${endDate || 'Present'}` : 'All Time';

      const csvContent =
        reportType === 'logs_only'
          ? generateLogsCsv(filteredLogs)
          : generateSecurityReportCsv(filteredLogs, filteredAlerts, dateRangeLabel);

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="cloud-audit-security-report-${new Date().toISOString().slice(0, 10)}.csv"`
      );
      res.send(csvContent);
    } catch (err) {
      res.status(500).json({
        error: 'Failed to generate CSV report.',
        details: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Vite middleware in development or static serving in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Cloud Audit Logs Retention & Analysis Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
