import React, { useState, useEffect, useCallback } from 'react';
import {
  Plus,
  Play,
  Trash2,
  Edit3,
  Info,
  Clock,
  CheckCircle2,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { RetentionPolicyRecord, RetentionExecutionRecord, UserRole } from '../types';
import {
  apiFetchRetention,
  apiCreateRetentionPolicy,
  apiUpdateRetentionPolicy,
  apiDeleteRetentionPolicy,
  apiRunRetentionCleanup,
} from '../apiClient';

interface RetentionViewProps {
  userRole: UserRole;
  onNotify: (msg: string, type?: 'success' | 'error' | 'info') => void;
  onDataChanged: () => void;
}

export const RetentionView: React.FC<RetentionViewProps> = ({
  userRole,
  onNotify,
  onDataChanged,
}) => {
  const [policies, setPolicies] = useState<RetentionPolicyRecord[]>([]);
  const [executions, setExecutions] = useState<RetentionExecutionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningCleanup, setRunningCleanup] = useState(false);

  // Modal state for Create / Edit
  const [modalOpen, setModalOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<RetentionPolicyRecord | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [logCategory, setLogCategory] = useState<RetentionPolicyRecord['logCategory']>('DATA_ACCESS');
  const [retentionDays, setRetentionDays] = useState<number>(30);
  const [status, setStatus] = useState<RetentionPolicyRecord['status']>('ENABLED');
  const [saving, setSaving] = useState(false);

  // Confirmation modal state for Delete or Run Cleanup
  const [confirmDeletePolicy, setConfirmDeletePolicy] = useState<RetentionPolicyRecord | null>(null);
  const [confirmCleanupTarget, setConfirmCleanupTarget] = useState<{
    policyId?: string;
    policyName: string;
    dryRun: boolean;
  } | null>(null);

  const isAdmin = userRole === 'admin';

  const loadRetentionData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetchRetention();
      setPolicies(res.policies);
      setExecutions(res.executions);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to load retention policies', 'error');
    } finally {
      setLoading(false);
    }
  }, [onNotify]);

  useEffect(() => {
    loadRetentionData();
  }, [loadRetentionData]);

  const openCreateModal = () => {
    setEditingPolicy(null);
    setName('');
    setDescription('');
    setLogCategory('DATA_ACCESS');
    setRetentionDays(30);
    setStatus('ENABLED');
    setModalOpen(true);
  };

  const openEditModal = (pol: RetentionPolicyRecord) => {
    setEditingPolicy(pol);
    setName(pol.name);
    setDescription(pol.description);
    setLogCategory(pol.logCategory);
    setRetentionDays(pol.retentionDays);
    setStatus(pol.status);
    setModalOpen(true);
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      onNotify('Policy name is required.', 'error');
      return;
    }
    if (!Number.isInteger(Number(retentionDays)) || retentionDays < 1 || retentionDays > 3650) {
      onNotify('Retention days must be an integer between 1 and 3650.', 'error');
      return;
    }

    setSaving(true);
    try {
      if (editingPolicy) {
        await apiUpdateRetentionPolicy(editingPolicy.id, {
          name: name.trim(),
          description: description.trim(),
          logCategory,
          retentionDays: Number(retentionDays),
          status,
        });
        onNotify(`Updated retention policy "${name.trim()}".`, 'success');
      } else {
        await apiCreateRetentionPolicy({
          name: name.trim(),
          description: description.trim(),
          logCategory,
          retentionDays: Number(retentionDays),
          status,
        });
        onNotify(`Created retention policy "${name.trim()}".`, 'success');
      }
      setModalOpen(false);
      await loadRetentionData();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to save policy', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleToggleStatus = async (pol: RetentionPolicyRecord) => {
    if (!isAdmin) {
      onNotify('Only administrators can enable or disable retention policies.', 'error');
      return;
    }
    const nextStatus = pol.status === 'ENABLED' ? 'DISABLED' : 'ENABLED';
    try {
      await apiUpdateRetentionPolicy(pol.id, { status: nextStatus });
      onNotify(`Policy "${pol.name}" is now ${nextStatus}.`, 'info');
      await loadRetentionData();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to update status', 'error');
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDeletePolicy) return;
    try {
      await apiDeleteRetentionPolicy(confirmDeletePolicy.id);
      onNotify(`Deleted retention policy "${confirmDeletePolicy.name}".`, 'success');
      setConfirmDeletePolicy(null);
      await loadRetentionData();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to delete policy', 'error');
    }
  };

  const handleExecuteCleanup = async () => {
    if (!confirmCleanupTarget) return;
    setRunningCleanup(true);
    try {
      const res = await apiRunRetentionCleanup({
        policyId: confirmCleanupTarget.policyId,
        dryRun: confirmCleanupTarget.dryRun,
      });
      if (res.dryRun) {
        onNotify(
          `Dry Run complete: ${res.totalDeleted} application records matched the retention cutoff criteria (0 records deleted).`,
          'info'
        );
      } else {
        onNotify(
          `Retention cleanup executed: Deleted ${res.totalDeleted} eligible application records from Firestore.`,
          'success'
        );
      }
      setConfirmCleanupTarget(null);
      await loadRetentionData();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Retention cleanup failed', 'error');
    } finally {
      setRunningCleanup(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Retention Policy Management
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Configure lifecycle rules and execute batched cleanup for application audit records stored in Firestore.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={loadRetentionData}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-600' : ''}`} />
            <span>Refresh</span>
          </button>

          {isAdmin && (
            <>
              <button
                type="button"
                onClick={() =>
                  setConfirmCleanupTarget({
                    policyName: 'All Enabled Policies',
                    dryRun: true,
                  })
                }
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
              >
                <Clock className="w-3.5 h-3.5 text-sky-600" />
                <span>Simulate Dry Run</span>
              </button>

              <button
                type="button"
                onClick={() =>
                  setConfirmCleanupTarget({
                    policyName: 'All Enabled Policies',
                    dryRun: false,
                  })
                }
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Run Retention Cleanup</span>
              </button>

              <button
                type="button"
                onClick={openCreateModal}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Policy</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Architectural Distinction Callout (No thick left border per design rules) */}
      <div className="bg-slate-100/80 border border-slate-200 rounded-xl p-4 flex items-start gap-3">
        <Info className="w-5 h-5 text-sky-700 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-700 leading-relaxed">
          <span className="font-semibold text-slate-900">
            Architectural Scope — Application Firestore vs. Native GCP Log Buckets:
          </span>{' '}
          Policies configured on this page govern the retention of normalized audit log records stored in this application&apos;s{' '}
          <code className="font-mono bg-white px-1 py-0.5 rounded border border-slate-200">
            audit_logs
          </code>{' '}
          Firestore collection. Running cleanup deletes eligible Firestore documents in safe batches and records an immutable execution log. It does{' '}
          <span className="font-semibold underline">not</span> alter native Google Cloud Logging bucket retention settings (such as{' '}
          <code className="font-mono">_Required</code> at 400 days or <code className="font-mono">_Default</code> at 30 days) in your GCP project.
        </div>
      </div>

      {/* Policies Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900">
            Configured Application Retention Policies ({policies.length})
          </h2>
          {!isAdmin && (
            <span className="text-xs text-slate-500">
              Read-only view (Administrator role required to modify policies)
            </span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                <th className="py-3 px-4">Policy Name & Description</th>
                <th className="py-3 px-4">Target Category</th>
                <th className="py-3 px-4 text-right">Retention Window</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Execution</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Loading retention policies...
                  </td>
                </tr>
              ) : policies.length > 0 ? (
                policies.map((pol) => (
                  <tr key={pol.id} className="hover:bg-slate-50">
                    <td className="py-3.5 px-4 max-w-md">
                      <div className="font-semibold text-slate-900">{pol.name}</div>
                      <div className="text-slate-500 mt-0.5">{pol.description}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-800 whitespace-nowrap">
                      {pol.logCategory}
                    </td>
                    <td className="py-3.5 px-4 text-right font-mono tabular-nums font-semibold text-slate-900 whitespace-nowrap">
                      {pol.retentionDays} days
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <button
                        type="button"
                        disabled={!isAdmin}
                        onClick={() => handleToggleStatus(pol)}
                        className={`text-xs font-semibold underline-offset-2 ${
                          pol.status === 'ENABLED'
                            ? 'text-emerald-700 hover:underline'
                            : 'text-slate-500 hover:underline'
                        }`}
                      >
                        {pol.status}
                      </button>
                    </td>
                    <td className="py-3.5 px-4 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                      {pol.lastExecutionAt ? (
                        <div>
                          <div>{pol.lastExecutionAt.replace('T', ' ').slice(0, 19)}</div>
                          <div className="text-[11px] text-slate-400">
                            Pruned {pol.lastDeletedCount} records
                          </div>
                        </div>
                      ) : (
                        <span className="text-slate-400">Never executed</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      {isAdmin ? (
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              setConfirmCleanupTarget({
                                policyId: pol.id,
                                policyName: pol.name,
                                dryRun: false,
                              })
                            }
                            disabled={pol.status !== 'ENABLED'}
                            title={
                              pol.status !== 'ENABLED'
                                ? 'Enable policy first to run cleanup'
                                : 'Run cleanup for this policy'
                            }
                            className="px-2.5 py-1 text-xs font-medium text-sky-700 hover:bg-sky-50 rounded-md disabled:opacity-40"
                          >
                            Run Now
                          </button>
                          <button
                            type="button"
                            onClick={() => openEditModal(pol)}
                            className="p-1.5 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-md"
                            title="Edit Policy"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => setConfirmDeletePolicy(pol)}
                            className="p-1.5 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-md"
                            title="Delete Policy"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500">
                    No retention policies configured yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Retention Cleanup Execution History */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200">
          <h2 className="text-sm font-semibold text-slate-900">
            Retention Cleanup Execution Audit Trail ({executions.length})
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Every dry run and destructive batch cleanup is permanently logged in the{' '}
            <code className="font-mono">retention_executions</code> collection.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                <th className="py-3 px-4">Execution Mode</th>
                <th className="py-3 px-4">Policy & Category</th>
                <th className="py-3 px-4">Cutoff Date</th>
                <th className="py-3 px-4 text-right">Records Affected</th>
                <th className="py-3 px-4">Executed By</th>
                <th className="py-3 px-4">Execution Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {executions.length > 0 ? (
                executions.map((ex) => (
                  <tr key={ex.id} className="hover:bg-slate-50">
                    <td className="py-3 px-4 whitespace-nowrap font-mono font-semibold">
                      <span
                        className={
                          ex.status === 'COMPLETED'
                            ? 'text-emerald-700'
                            : ex.status === 'DRY_RUN'
                            ? 'text-sky-700'
                            : 'text-red-700'
                        }
                      >
                        {ex.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="font-medium text-slate-900">{ex.policyName}</div>
                      <div className="text-[11px] font-mono text-slate-500">
                        {ex.logCategory} · {ex.retentionDays}d
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                      {ex.cutoffTimestamp.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums font-bold text-slate-900 whitespace-nowrap">
                      {ex.deletedCount}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-700 whitespace-nowrap">
                      {ex.executedBy}
                    </td>
                    <td className="py-3 px-4 text-slate-600 max-w-md">{ex.details}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No retention cleanup executions recorded yet. Click &ldquo;Simulate Dry Run&rdquo; or &ldquo;Run Retention Cleanup&rdquo; above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="bg-white border border-slate-200 rounded-xl shadow-xl max-w-lg w-full p-6">
            <h2 className="text-lg font-bold text-slate-900">
              {editingPolicy ? 'Edit Retention Policy' : 'Create Application Retention Policy'}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              Define how many days matching audit logs should be retained in Firestore before cleanup eligibility.
            </p>

            <form onSubmit={handleSavePolicy} className="space-y-4 mt-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Policy Name (1–120 chars)
                </label>
                <input
                  type="text"
                  required
                  maxLength={120}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Data Access 30-Day Lifecycle Policy"
                  className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  maxLength={500}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Describe the compliance or storage optimization rationale..."
                  className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Log Category
                  </label>
                  <select
                    value={logCategory}
                    onChange={(e) =>
                      setLogCategory(e.target.value as RetentionPolicyRecord['logCategory'])
                    }
                    className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                  >
                    <option value="DATA_ACCESS">DATA_ACCESS</option>
                    <option value="SYSTEM_EVENT">SYSTEM_EVENT</option>
                    <option value="POLICY_DENIED">POLICY_DENIED</option>
                    <option value="ADMIN_ACTIVITY">ADMIN_ACTIVITY</option>
                    <option value="ALL">ALL CATEGORIES</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Retention (Days)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={3650}
                    required
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(Number(e.target.value))}
                    className="w-full px-3 py-2 text-xs font-mono border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Status</label>
                  <select
                    value={status}
                    onChange={(e) =>
                      setStatus(e.target.value as RetentionPolicyRecord['status'])
                    }
                    className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                  >
                    <option value="ENABLED">ENABLED</option>
                    <option value="DISABLED">DISABLED</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-200">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 disabled:opacity-50"
                >
                  {saving ? 'Saving...' : 'Save Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Dialog for Deleting a Policy */}
      {confirmDeletePolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="bg-white border border-slate-200 rounded-xl shadow-xl max-w-md w-full p-6">
            <div className="flex items-center gap-2 text-red-600 font-bold text-base">
              <ShieldAlert className="w-5 h-5" />
              <span>Confirm Policy Deletion</span>
            </div>
            <p className="text-xs text-slate-600 mt-2 leading-relaxed">
              Are you sure you want to permanently delete the retention policy{' '}
              <span className="font-semibold text-slate-900">
                &ldquo;{confirmDeletePolicy.name}&rdquo;
              </span>
              ? Existing audit logs will remain untouched.
            </p>
            <div className="flex items-center justify-end gap-2 mt-5">
              <button
                type="button"
                onClick={() => setConfirmDeletePolicy(null)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                className="px-4 py-2 text-xs font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
              >
                Delete Policy
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Dialog for Running Cleanup */}
      {confirmCleanupTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
          <div className="bg-white border border-slate-200 rounded-xl shadow-xl max-w-md w-full p-6">
            <div className="flex items-center gap-2 text-slate-900 font-bold text-base">
              <CheckCircle2 className="w-5 h-5 text-sky-600" />
              <span>
                {confirmCleanupTarget.dryRun
                  ? 'Confirm Retention Dry Run'
                  : 'Confirm Application Log Cleanup'}
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-2 leading-relaxed">
              {confirmCleanupTarget.dryRun ? (
                <>
                  This will evaluate{' '}
                  <span className="font-semibold text-slate-900">
                    {confirmCleanupTarget.policyName}
                  </span>{' '}
                  against stored Firestore audit logs and record how many records are older than the retention cutoff without deleting any records.
                </>
              ) : (
                <>
                  This will execute{' '}
                  <span className="font-semibold text-slate-900">
                    {confirmCleanupTarget.policyName}
                  </span>{' '}
                  and permanently delete eligible application audit records from Firestore that exceed the configured retention days. Native Google Cloud Logging buckets will not be modified.
                </>
              )}
            </p>
            <div className="flex items-center justify-end gap-2 mt-5">
              <button
                type="button"
                disabled={runningCleanup}
                onClick={() => setConfirmCleanupTarget(null)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={runningCleanup}
                onClick={handleExecuteCleanup}
                className="px-4 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 disabled:opacity-50"
              >
                {runningCleanup
                  ? 'Executing...'
                  : confirmCleanupTarget.dryRun
                  ? 'Run Dry Run'
                  : 'Confirm & Delete Eligible Logs'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
