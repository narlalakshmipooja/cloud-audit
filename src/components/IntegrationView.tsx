import React, { useState, useEffect } from 'react';
import {
  Cloud,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  RotateCcw,
  Terminal,
  Shield,
  Users,
} from 'lucide-react';
import {
  doc,
  onSnapshot,
  collection,
  query,
  getDocs,
  updateDoc,
  serverTimestamp,
} from 'firebase/firestore';
import { db, OperationType, handleFirestoreError } from '../firebase';
import { IntegrationSettingRecord, UserProfile, UserRole } from '../types';
import {
  apiTestGcpIntegration,
  apiSyncGcpLogs,
  seedOrResetDemoDataInFirestore,
} from '../apiClient';

interface IntegrationViewProps {
  currentUser: UserProfile;
  onNotify: (msg: string, type?: 'success' | 'error' | 'info') => void;
  onDataChanged: () => void;
}

export const IntegrationView: React.FC<IntegrationViewProps> = ({
  currentUser,
  onNotify,
  onDataChanged,
}) => {
  const [settings, setSettings] = useState<IntegrationSettingRecord | null>(null);
  const [gcpProjectId, setGcpProjectId] = useState('btech-secops-demo-prod');
  const [logFilter, setLogFilter] = useState('logName:"cloudaudit.googleapis.com"');
  const [daysBack, setDaysBack] = useState(7);
  const [maxEntries, setMaxEntries] = useState(50);

  const [testingConn, setTestingConn] = useState(false);
  const [testResultMsg, setTestResultMsg] = useState<{
    status: string;
    message: string;
  } | null>(null);

  const [syncing, setSyncing] = useState(false);
  const [syncSummary, setSyncSummary] = useState<{
    fetchedCount: number;
    importedCount: number;
    duplicateSkippedCount: number;
    newAlertsCount: number;
  } | null>(null);

  const [confirmResetDemo, setConfirmResetDemo] = useState(false);
  const [resettingDemo, setResettingDemo] = useState(false);

  // User Role Management list (for Admins)
  const [usersList, setUsersList] = useState<UserProfile[]>([]);

  const isAdmin = currentUser.role === 'admin';

  useEffect(() => {
    const unsub = onSnapshot(
      doc(db, 'integration_settings', 'default'),
      (snap) => {
        if (snap.exists()) {
          const data = snap.data() as IntegrationSettingRecord;
          setSettings(data);
          if (data.gcpProjectId) setGcpProjectId(data.gcpProjectId);
          if (data.logFilter) setLogFilter(data.logFilter);
        }
      },
      (err) => {
        handleFirestoreError(err, OperationType.GET, 'integration_settings/default');
      }
    );
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    getDocs(query(collection(db, 'users')))
      .then((snap) => {
        const list = snap.docs.map((d) => d.data() as UserProfile);
        setUsersList(list);
      })
      .catch(() => {
        // ignore if non-admin
      });
  }, [isAdmin]);

  const handleTestConnectivity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdmin) {
      onNotify('Administrator role is required to test GCP connectivity.', 'error');
      return;
    }
    setTestingConn(true);
    setTestResultMsg(null);
    try {
      const res = await apiTestGcpIntegration({
        gcpProjectId: gcpProjectId.trim(),
        logFilter: logFilter.trim(),
      });
      setTestResultMsg({
        status: res.status,
        message: res.message,
      });
      if (res.connected) {
        onNotify('Successfully connected to Google Cloud Logging API.', 'success');
      } else {
        onNotify(`GCP Connectivity status: ${res.status}`, 'info');
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Connectivity test failed', 'error');
    } finally {
      setTestingConn(false);
    }
  };

  const handleSyncLiveLogs = async () => {
    if (!isAdmin) {
      onNotify('Administrator role is required to synchronize logs.', 'error');
      return;
    }
    setSyncing(true);
    setSyncSummary(null);
    try {
      const res = await apiSyncGcpLogs({
        gcpProjectId: gcpProjectId.trim(),
        logFilter: logFilter.trim(),
        daysBack,
        maxEntries,
      });
      if (res.synced) {
        setSyncSummary({
          fetchedCount: res.fetchedCount || 0,
          importedCount: res.importedCount || 0,
          duplicateSkippedCount: res.duplicateSkippedCount || 0,
          newAlertsCount: res.newAlertsCount || 0,
        });
        onNotify(
          `Synced ${res.importedCount} new GCP audit logs (${res.duplicateSkippedCount} duplicates skipped).`,
          'success'
        );
        onDataChanged();
      } else {
        setTestResultMsg({
          status: res.status || 'ERROR',
          message: res.error || 'Sync failed because live credentials are not configured.',
        });
        onNotify(res.error || 'Live sync requires GCP_SERVICE_ACCOUNT_JSON secret.', 'error');
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to sync logs', 'error');
    } finally {
      setSyncing(false);
    }
  };

  const handleResetDemoDataset = async () => {
    if (!isAdmin) return;
    setResettingDemo(true);
    try {
      const res = await seedOrResetDemoDataInFirestore(
        currentUser.uid,
        currentUser.email,
        true
      );
      onNotify(
        `Demo dataset reset: Restored ${res.seededLogs} synthetic logs, ${res.seededPolicies} policies, and ${res.seededAlerts} security alerts.`,
        'success'
      );
      setConfirmResetDemo(false);
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to reset demo dataset', 'error');
    } finally {
      setResettingDemo(false);
    }
  };

  const handleChangeUserRole = async (targetUid: string, newRole: UserRole) => {
    if (!isAdmin) return;
    try {
      await updateDoc(doc(db, 'users', targetUid), {
        role: newRole,
        lastLoginAt: serverTimestamp(),
      });
      setUsersList((prev) =>
        prev.map((u) => (u.uid === targetUid ? { ...u, role: newRole } : u))
      );
      onNotify(`Updated user role to ${newRole}.`, 'success');
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${targetUid}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-200">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Google Cloud Logging Integration & Settings
        </h1>
        <p className="text-sm text-slate-600 mt-0.5">
          Configure server-side Google Cloud Logging API connectivity, manual log synchronization, Demo Mode dataset management, and RBAC roles.
        </p>
      </div>

      {/* Live GCP Connection Configuration Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Cloud className="w-5 h-5 text-sky-600" />
              <h2 className="text-base font-bold text-slate-900">
                Google Cloud Logging API Configuration
              </h2>
            </div>

            <div className="text-xs font-mono font-semibold">
              Status:{' '}
              <span
                className={
                  settings?.connectionStatus === 'CONNECTED'
                    ? 'text-emerald-700'
                    : settings?.connectionStatus === 'MISSING_CREDENTIALS'
                    ? 'text-amber-700'
                    : 'text-slate-600'
                }
              >
                {settings?.connectionStatus || 'DISCONNECTED'}
              </span>
            </div>
          </div>

          <form onSubmit={handleTestConnectivity} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Target GCP Project ID
                </label>
                <input
                  type="text"
                  required
                  disabled={!isAdmin}
                  value={gcpProjectId}
                  onChange={(e) => setGcpProjectId(e.target.value)}
                  placeholder="e.g., my-production-gcp-project"
                  className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:bg-white focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Cloud Audit Log Filter
                </label>
                <input
                  type="text"
                  required
                  disabled={!isAdmin}
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:bg-white focus:border-sky-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Sync Lookback Window (Days)
                </label>
                <input
                  type="number"
                  min={1}
                  max={90}
                  disabled={!isAdmin}
                  value={daysBack}
                  onChange={(e) => setDaysBack(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Max Entries per Sync Batch
                </label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  disabled={!isAdmin}
                  value={maxEntries}
                  onChange={(e) => setMaxEntries(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-3 flex-wrap pt-2">
              <button
                type="submit"
                disabled={testingConn || !isAdmin}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${testingConn ? 'animate-spin' : ''}`} />
                <span>{testingConn ? 'Testing GCP Connection...' : 'Test GCP Connectivity'}</span>
              </button>

              <button
                type="button"
                disabled={syncing || !isAdmin}
                onClick={handleSyncLiveLogs}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-700 rounded-lg transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                <span>{syncing ? 'Syncing Audit Logs...' : 'Sync Logs from GCP'}</span>
              </button>
            </div>
          </form>

          {/* Actual Connectivity Outcome Banner */}
          {testResultMsg && (
            <div
              className={`p-4 rounded-xl border text-xs ${
                testResultMsg.status === 'CONNECTED'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  : 'bg-amber-50 border-amber-200 text-amber-900'
              }`}
            >
              <div className="flex items-start gap-2.5">
                {testResultMsg.status === 'CONNECTED' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-bold">
                    Connectivity Test Result: {testResultMsg.status}
                  </div>
                  <div className="mt-1 leading-relaxed">{testResultMsg.message}</div>
                </div>
              </div>
            </div>
          )}

          {/* Sync Result Summary */}
          {syncSummary && (
            <div className="p-4 rounded-xl border bg-sky-50 border-sky-200 text-sky-950 text-xs">
              <div className="font-bold mb-1">Live Sync Completed Successfully</div>
              <div className="font-mono flex items-center gap-3 flex-wrap">
                <span>Fetched: {syncSummary.fetchedCount}</span>
                <span>·</span>
                <span>Newly Imported: {syncSummary.importedCount}</span>
                <span>·</span>
                <span>Duplicates Skipped: {syncSummary.duplicateSkippedCount}</span>
                <span>·</span>
                <span>New Alerts Generated: {syncSummary.newAlertsCount}</span>
              </div>
            </div>
          )}

          {/* Stored Telemetry Metadata */}
          {settings && (
            <div className="pt-3 border-t border-slate-200 text-xs text-slate-500 flex items-center gap-3 flex-wrap">
              <span>
                Last Successful Sync:{' '}
                <strong className="font-mono text-slate-800">
                  {settings.lastSyncAt ? settings.lastSyncAt.replace('T', ' ').slice(0, 19) : 'Never'}
                </strong>
              </span>
              <span>·</span>
              <span>
                Last Imported Count:{' '}
                <strong className="font-mono text-slate-800">{settings.lastSyncCount}</strong>
              </span>
              {settings.lastError && (
                <>
                  <span>·</span>
                  <span className="text-amber-700">Last Notice: {settings.lastError}</span>
                </>
              )}
            </div>
          )}
        </div>

        {/* Demo Mode Management Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <h2 className="text-base font-bold text-slate-900">
              Demo Mode & Synthetic Dataset
            </h2>
            <p className="text-xs text-slate-600 leading-relaxed">
              So this B.Tech project can be demonstrated immediately before external GCP Service Account credentials are configured, the application includes a realistic synthetic dataset stored in Firestore.
            </p>
            <p className="text-xs text-slate-600 leading-relaxed">
              Every demo record is explicitly tagged with{' '}
              <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">source: &quot;DEMO&quot;</code>{' '}
              and never mixed silently with <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">GCP_LIVE</code> logs.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-200">
            <button
              type="button"
              disabled={!isAdmin || resettingDemo}
              onClick={() => setConfirmResetDemo(true)}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors disabled:opacity-50"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset Demo Dataset in Firestore</span>
            </button>
          </div>
        </div>
      </div>

      {/* Least-Privilege GCP Setup Instructions */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-slate-800" />
          <h2 className="text-base font-bold text-slate-900">
            Server-Side Service Account Setup Instructions (Least-Privilege IAM)
          </h2>
        </div>

        <p className="text-xs text-slate-600 leading-relaxed">
          For security compliance, service account keys are never accepted via browser forms or stored in Firestore. To connect live Google Cloud Audit Logs:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="font-bold text-slate-900 mb-1">
              01. Create Read-Only Service Account
            </div>
            <p className="text-slate-600 leading-relaxed">
              In Google Cloud Console &rarr; IAM &amp; Admin &rarr; Service Accounts, create a dedicated service account and grant only{' '}
              <code className="font-mono text-slate-900">roles/logging.viewer</code> (and{' '}
              <code className="font-mono text-slate-900">roles/logging.privateLogViewer</code> if inspecting Data Access logs).
            </p>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="font-bold text-slate-900 mb-1">
              02. Add Server Secret in AI Studio
            </div>
            <p className="text-slate-600 leading-relaxed">
              Open the AI Studio Secrets panel and set{' '}
              <code className="font-mono text-slate-900">GCP_SERVICE_ACCOUNT_JSON</code> to the JSON key contents, and optionally{' '}
              <code className="font-mono text-slate-900">GCP_PROJECT_ID</code>.
            </p>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="font-bold text-slate-900 mb-1">
              03. Verify & Sync via Backend Proxy
            </div>
            <p className="text-slate-600 leading-relaxed">
              Click <strong>Test GCP Connectivity</strong> above. The Express backend (<code className="font-mono">POST /api/integration/test</code>) authenticates using <code className="font-mono">@google-cloud/logging</code> and verifies read access.
            </p>
          </div>
        </div>
      </div>

      {/* Role-Based Access Control (RBAC) Directory */}
      {isAdmin && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-sky-600" />
              <h2 className="text-sm font-bold text-slate-900">
                Role-Based Access Control (RBAC) User Directory
              </h2>
            </div>
            <span className="text-xs text-slate-500">
              Enforced by both Firestore Security Rules and Express Backend Middleware
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                  <th className="py-3 px-4">User Display Name</th>
                  <th className="py-3 px-4">Email Address</th>
                  <th className="py-3 px-4">UID</th>
                  <th className="py-3 px-4">Assigned Role</th>
                  <th className="py-3 px-4 text-right">Modify Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {usersList.map((u) => (
                  <tr key={u.uid} className="hover:bg-slate-50">
                    <td className="py-3 px-4 font-medium text-slate-900">{u.displayName}</td>
                    <td className="py-3 px-4 font-mono text-slate-700">{u.email}</td>
                    <td className="py-3 px-4 font-mono text-slate-500">{u.uid}</td>
                    <td className="py-3 px-4 font-mono font-semibold text-slate-900 uppercase">
                      {u.role}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <select
                        value={u.role}
                        onChange={(e) =>
                          handleChangeUserRole(u.uid, e.target.value as UserRole)
                        }
                        className="px-2.5 py-1 bg-white border border-slate-200 rounded text-xs font-medium"
                      >
                        <option value="admin">admin (Full Access)</option>
                        <option value="analyst">analyst (Triage Alerts & View)</option>
                        <option value="viewer">viewer (Read-Only)</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Demo Reset */}
      {confirmResetDemo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="bg-white border border-slate-200 rounded-xl shadow-xl max-w-md w-full p-6">
            <div className="flex items-center gap-2 text-slate-900 font-bold text-base">
              <Shield className="w-5 h-5 text-sky-600" />
              <span>Confirm Demo Dataset Reset</span>
            </div>
            <p className="text-xs text-slate-600 mt-2 leading-relaxed">
              This will restore the 21 baseline synthetic <code className="font-mono">DEMO</code> audit logs, 3 default retention policies, and rule-based security alerts in Firestore. Any imported <code className="font-mono">GCP_LIVE</code> logs will remain untouched.
            </p>
            <div className="flex items-center justify-end gap-2 mt-5">
              <button
                type="button"
                disabled={resettingDemo}
                onClick={() => setConfirmResetDemo(false)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={resettingDemo}
                onClick={handleResetDemoDataset}
                className="px-4 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 disabled:opacity-50"
              >
                {resettingDemo ? 'Restoring Demo Data...' : 'Confirm & Reset Demo Data'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
