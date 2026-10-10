import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Zap,
  ExternalLink,
  Search,
  RotateCcw,
} from 'lucide-react';
import { SecurityAlertRecord, UserRole } from '../types';
import {
  apiFetchAlerts,
  apiUpdateAlertStatus,
  triggerTestDetectionScenario,
  apiFetchLogById,
} from '../apiClient';
import { AuditLogRecord } from '../types';

interface AlertsViewProps {
  userRole: UserRole;
  onNotify: (msg: string, type?: 'success' | 'error' | 'info') => void;
  onInspectLog: (log: AuditLogRecord) => void;
  onDataChanged: () => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  userRole,
  onNotify,
  onInspectLog,
  onDataChanged,
}) => {
  const [alerts, setAlerts] = useState<SecurityAlertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);

  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [ruleFilter, setRuleFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const canReview = userRole === 'admin' || userRole === 'analyst';

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetchAlerts({
        severity: severityFilter,
        status: statusFilter,
        ruleId: ruleFilter,
        source: sourceFilter,
        search: searchQuery,
      });
      setAlerts(res.alerts);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to load security alerts', 'error');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, statusFilter, ruleFilter, sourceFilter, searchQuery, onNotify]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const handleStatusChange = async (
    alert: SecurityAlertRecord,
    newStatus: SecurityAlertRecord['status']
  ) => {
    if (!canReview) {
      onNotify('Analyst or Administrator role required to update alert status.', 'error');
      return;
    }
    try {
      await apiUpdateAlertStatus(alert.id, newStatus);
      onNotify(`Alert marked as ${newStatus}.`, 'success');
      await loadAlerts();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to update alert', 'error');
    }
  };

  const handleSimulateRule = async (
    scenario:
      | 'IAM_PRIVILEGE_ESCALATION'
      | 'BRUTE_FORCE_SECRET_ACCESS'
      | 'CRITICAL_SINK_DELETION'
  ) => {
    if (userRole !== 'admin') {
      onNotify('Administrator role required to inject test detection events.', 'error');
      return;
    }
    setSimulating(true);
    try {
      const res = await triggerTestDetectionScenario(scenario);
      onNotify(
        `Injected ${res.createdLogs} audit record(s) and triggered rule alert: "${res.alertTitle}"`,
        'success'
      );
      await loadAlerts();
      onDataChanged();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Simulation failed', 'error');
    } finally {
      setSimulating(false);
    }
  };

  const handleOpenAssociatedLog = async (logId: string) => {
    try {
      const log = await apiFetchLogById(logId);
      onInspectLog(log);
    } catch (err) {
      onNotify(
        err instanceof Error
          ? err.message
          : 'Associated audit log record may have been pruned by retention cleanup.',
        'error'
      );
    }
  };

  const openCount = alerts.filter((a) => a.status === 'OPEN').length;
  const reviewedCount = alerts.filter((a) => a.status === 'REVIEWED').length;
  const confirmedCount = alerts.filter((a) => a.status === 'CONFIRMED_INCIDENT').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Security Alerts & Rule-Based Detections
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Deterministic rule-based threat detection for repeated failures, IAM changes, sensitive operations, activity spikes, and anomalous IPs.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={() => {
              setSeverityFilter('ALL');
              setStatusFilter('ALL');
              setRuleFilter('ALL');
              setSourceFilter('ALL');
              setSearchQuery('');
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Filters</span>
          </button>

          <button
            type="button"
            onClick={loadAlerts}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-600' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Summary & Test Detection Trigger Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-500">Detected Events vs Confirmed Incidents</div>
            <div className="text-sm font-semibold text-slate-900 mt-1 flex items-center gap-3 font-mono tabular-nums">
              <span className="text-amber-700">{openCount} Open</span>
              <span>·</span>
              <span className="text-sky-700">{reviewedCount} Reviewed</span>
              <span>·</span>
              <span className="text-red-700">{confirmedCount} Confirmed Incidents</span>
            </div>
          </div>
          <ShieldAlert className="w-6 h-6 text-slate-400" />
        </div>

        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold text-slate-900">
              Trigger Test Detection Rule (Acceptance Verification)
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Inject a synthetic suspicious audit log sequence into Firestore and run the deterministic rule engine.
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <button
              type="button"
              disabled={simulating || userRole !== 'admin'}
              onClick={() => handleSimulateRule('IAM_PRIVILEGE_ESCALATION')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors disabled:opacity-40 whitespace-nowrap"
            >
              <Zap className="w-3.5 h-3.5 text-amber-600" />
              <span>Test IAM Key Rule</span>
            </button>

            <button
              type="button"
              disabled={simulating || userRole !== 'admin'}
              onClick={() => handleSimulateRule('BRUTE_FORCE_SECRET_ACCESS')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors disabled:opacity-40 whitespace-nowrap"
            >
              <Zap className="w-3.5 h-3.5 text-red-600" />
              <span>Test Repeated Failures</span>
            </button>

            <button
              type="button"
              disabled={simulating || userRole !== 'admin'}
              onClick={() => handleSimulateRule('CRITICAL_SINK_DELETION')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors disabled:opacity-40 whitespace-nowrap"
            >
              <Zap className="w-3.5 h-3.5 text-sky-600" />
              <span>Test Sink Deletion</span>
            </button>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Search Alerts</label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Principal, IP, or title..."
              className="w-full pl-8 pr-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Detection Rule</label>
          <select
            value={ruleFilter}
            onChange={(e) => setRuleFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All 5 Detection Rules</option>
            <option value="REPEATED_FAILURES">REPEATED_FAILURES</option>
            <option value="UNUSUAL_IAM_CHANGE">UNUSUAL_IAM_CHANGE</option>
            <option value="SENSITIVE_ADMIN_OP">SENSITIVE_ADMIN_OP</option>
            <option value="ACTIVITY_SPIKE">ACTIVITY_SPIKE</option>
            <option value="UNUSUAL_IP">UNUSUAL_IP</option>
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Alert Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Triage Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Triage States</option>
            <option value="OPEN">OPEN (Detected Event)</option>
            <option value="REVIEWED">REVIEWED</option>
            <option value="CONFIRMED_INCIDENT">CONFIRMED_INCIDENT</option>
            <option value="DISMISSED">DISMISSED</option>
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Data Source</label>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Sources</option>
            <option value="GCP_LIVE">GCP_LIVE</option>
            <option value="DEMO">DEMO</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200">
        {loading ? (
          <div className="p-10 text-center text-sm text-slate-500">Loading security alerts...</div>
        ) : alerts.length > 0 ? (
          alerts.map((alert) => (
            <div key={alert.id} className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-slate-50/60 transition-colors">
              <div className="space-y-1.5 max-w-3xl">
                <div className="flex items-center gap-2 flex-wrap">
                  <AlertTriangle
                    className={`w-4 h-4 shrink-0 ${
                      alert.severity === 'CRITICAL' || alert.severity === 'HIGH'
                        ? 'text-red-600'
                        : 'text-amber-600'
                    }`}
                  />
                  <span
                    className={`text-xs font-mono font-bold ${
                      alert.severity === 'CRITICAL' || alert.severity === 'HIGH'
                        ? 'text-red-700'
                        : 'text-amber-700'
                    }`}
                  >
                    [{alert.severity}]
                  </span>
                  <h3 className="text-sm font-bold text-slate-900">{alert.title}</h3>
                </div>

                <p className="text-xs text-slate-700 leading-relaxed">{alert.description}</p>

                <div className="text-xs text-slate-600 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 font-mono">
                  {alert.detectionReason}
                </div>

                <div className="flex items-center gap-2 text-xs text-slate-500 flex-wrap pt-1">
                  <span className="font-mono">Rule: {alert.ruleId}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">Principal: {alert.principalEmail}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">IP: {alert.callerIp}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    {alert.eventTime.replace('T', ' ').slice(0, 19)} UTC
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">Source: {alert.source}</span>
                  {alert.reviewedBy && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span>Reviewed by {alert.reviewedBy}</span>
                    </>
                  )}
                </div>
              </div>

              <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between gap-3 shrink-0">
                <div className="text-xs font-mono font-semibold">
                  {alert.status === 'CONFIRMED_INCIDENT' ? (
                    <span className="text-red-700">CONFIRMED SECURITY INCIDENT</span>
                  ) : alert.status === 'REVIEWED' ? (
                    <span className="text-emerald-700">REVIEWED</span>
                  ) : alert.status === 'DISMISSED' ? (
                    <span className="text-slate-400">DISMISSED</span>
                  ) : (
                    <span className="text-amber-700">OPEN DETECTION</span>
                  )}
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => handleOpenAssociatedLog(alert.associatedLogId)}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-100 whitespace-nowrap"
                  >
                    <span>Inspect Log</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>

                  {canReview && alert.status !== 'REVIEWED' && (
                    <button
                      type="button"
                      onClick={() => handleStatusChange(alert, 'REVIEWED')}
                      className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100 whitespace-nowrap"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Mark Reviewed</span>
                    </button>
                  )}

                  {canReview && alert.status !== 'CONFIRMED_INCIDENT' && (
                    <button
                      type="button"
                      onClick={() => handleStatusChange(alert, 'CONFIRMED_INCIDENT')}
                      className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 whitespace-nowrap"
                    >
                      <span>Confirm Incident</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="p-10 text-center text-sm text-slate-500">
            No security alerts match the current filter criteria.
          </div>
        )}
      </div>
    </div>
  );
};
