# Cloud Audit Logs Retention & Analysis Design

An academic B.Tech Cloud Security project built with **React 19**, **TypeScript**, **Tailwind CSS**, **Node.js (Express)**, **Firebase Cloud Firestore & Authentication**, and the official **Google Cloud Logging SDK (`@google-cloud/logging`)**.

---

## 1. Architecture Overview

1. **Frontend Security Console (`src/`)**:
   - **Authentication & RBAC**: Uses Firebase Authentication with Google Sign-In (`signInWithPopup`). Users are assigned roles (`admin`, `analyst`, `viewer`) stored in `/users/{uid}` and enforced by both Firestore Security Rules and backend middleware.
   - **7 Core Views**:
     1. **Login Page**: Google Sign-In with RBAC tier documentation.
     2. **Overview Dashboard**: Live KPIs (Total Audit Events, Admin Activities, Failed Operations, High-Risk Events, Stored Volume), Recharts time-series & distribution charts, Activity by Principal table, and recent logs/alerts.
     3. **Audit Logs Explorer**: Server-filtered, sortable, paginated data grid with keyword search, principal, service, category, severity, status, and date range filters, slide-over JSON payload inspection drawer, and CSV export.
     4. **Retention Policies**: Create, view, edit, enable/disable, and delete application-level Firestore retention policies. Supports dry-run simulation and batch deletion cleanup with an immutable execution audit trail. Explicitly distinguishes application-level Firestore record retention from native Google Cloud Logging bucket retention (`_Required` / `_Default`).
     5. **Security Alerts**: Rule-based detection across 5 deterministic rules, triage workflow (`OPEN` -> `REVIEWED` / `CONFIRMED_INCIDENT` / `DISMISSED`), and interactive test-rule injection buttons.
     6. **Analytics & Reports**: Distinguishes unreviewed detections from confirmed security incidents and exports multi-section CSV compliance reports.
     7. **Cloud Integration & Settings**: Server-side connectivity tester, manual GCP log sync with deduplication, Demo Mode dataset reset, and RBAC user directory.

2. **Server Backend (`server.ts`)**:
   - Express API server running on port 3000 with Vite middleware in development and static asset serving in production.
   - Keeps privileged Google Cloud Service Account credentials (`GCP_SERVICE_ACCOUNT_JSON`) strictly server-side.
   - Exposes all required REST endpoints (`/api/health`, `/api/stats`, `/api/logs`, `/api/logs/:id`, `/api/logs/sync`, `/api/retention`, `/api/retention/:id`, `/api/retention/run`, `/api/alerts`, `/api/alerts/:id`, `/api/reports/export`, `/api/integration/test`).

---

## 2. Firestore Database Schema & Collections

Defined in `firebase-blueprint.json` and protected by `firestore.rules`:

- **`users/{userId}`**: `uid`, `email`, `displayName`, `role` (`admin` | `analyst` | `viewer`), `createdAt`, `lastLoginAt`.
- **`audit_logs/{logId}`**: `id` (deterministic stable ID), `insertId`, `timestamp`, `principalEmail`, `serviceName`, `methodName`, `resourceName`, `severity`, `callerIp`, `status` (`SUCCESS` | `FAILURE`), `statusCode`, `statusMessage`, `category` (`ADMIN_ACTIVITY` | `DATA_ACCESS` | `SYSTEM_EVENT` | `POLICY_DENIED`), `source` (`GCP_LIVE` | `DEMO`), `projectId`, `rawPayload`, `createdAt`.
- **`retention_policies/{policyId}`**: `id`, `name`, `description`, `logCategory`, `retentionDays`, `status` (`ENABLED` | `DISABLED`), `lastExecutionAt`, `lastDeletedCount`, `createdBy`, `createdAt`, `updatedAt`.
- **`security_alerts/{alertId}`**: `id`, `severity`, `title`, `description`, `eventTime`, `associatedLogId`, `principalEmail`, `callerIp`, `ruleId`, `detectionReason`, `status` (`OPEN` | `REVIEWED` | `CONFIRMED_INCIDENT` | `DISMISSED`), `source`, `reviewedBy`, `reviewedAt`, `createdAt`, `updatedAt`.
- **`retention_executions/{executionId}`**: `id`, `policyId`, `policyName`, `logCategory`, `retentionDays`, `cutoffTimestamp`, `deletedCount`, `executedBy`, `status` (`COMPLETED` | `DRY_RUN` | `FAILED`), `details`, `executedAt`.
- **`integration_settings/{settingId}`**: `id`, `gcpProjectId`, `logFilter`, `connectionStatus`, `lastSyncAt`, `lastSyncCount`, `lastError`, `demoMode`, `updatedBy`, `updatedAt`.

---

## 3. Google Cloud Logging Permissions & Secrets Setup

To connect live Google Cloud Audit Logs:
1. Create a Service Account in your target GCP project.
2. Grant the minimum required read-only IAM roles:
   - `roles/logging.viewer` (Logs Viewer — required for Admin Activity & System Event audit logs)
   - `roles/logging.privateLogViewer` (Private Logs Viewer — optional, required if reading Data Access audit logs)
3. Export a JSON key for that Service Account and add it to the environment secrets:
   - `GCP_SERVICE_ACCOUNT_JSON`: Full JSON string of the service account key.
   - `GCP_PROJECT_ID`: Default GCP Project ID.

---

## 4. Running, Testing & Building

```bash
# Run unit & security rule verification tests
npm test

# Lint TypeScript & Firestore security rules
npm run lint
npx eslint firestore.rules

# Start full-stack dev server on port 3000
npm run dev

# Build production bundle
npm run build
```
