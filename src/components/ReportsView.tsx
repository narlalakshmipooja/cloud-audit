import React, { useState } from 'react';
import { Download, FileSpreadsheet, ShieldCheck, AlertTriangle } from 'lucide-react';
import { DashboardStats, SecurityAlertRecord } from '../types';
import { apiDownloadCsvReport } from '../apiClient';

interface ReportsViewProps {
  stats: DashboardStats | null;
  alerts: SecurityAlertRecord[];
  onNotify: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ stats, alerts, onNotify }) => {
  const [reportType, setReportType] = useState<'full_report' | 'logs_only'>('full_report');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [source, setSource] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');
  const [category, setCategory] = useState('ALL');
  const [exporting, setExporting] = useState(false);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setExporting(true);
    try {
      await apiDownloadCsvReport({
        type: reportType,
        startDate: startDate || undefined,
        endDate: endDate || undefined,
        source,
        severity,
        category,
      });
      onNotify('Generated and downloaded CSV security report.', 'success');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Report generation failed', 'error');
    } finally {
      setExporting(false);
    }
  };

  const openDetections = alerts.filter((a) => a.status === 'OPEN').length;
  const reviewedDetections = alerts.filter((a) => a.status === 'REVIEWED').length;
  const confirmedIncidents = alerts.filter((a) => a.status === 'CONFIRMED_INCIDENT').length;

  const ruleBreakdown = [
    {
      ruleId: 'REPEATED_FAILURES',
      label: 'Repeated Failed Operations (>= 3 in 60m)',
      count: alerts.filter((a) => a.ruleId === 'REPEATED_FAILURES').length,
    },
    {
      ruleId: 'UNUSUAL_IAM_CHANGE',
      label: 'Unusual IAM or Permission Changes',
      count: alerts.filter((a) => a.ruleId === 'UNUSUAL_IAM_CHANGE').length,
    },
    {
      ruleId: 'SENSITIVE_ADMIN_OP',
      label: 'Sensitive Administrative Operations',
      count: alerts.filter((a) => a.ruleId === 'SENSITIVE_ADMIN_OP').length,
    },
    {
      ruleId: 'ACTIVITY_SPIKE',
      label: 'Sudden Spikes in Principal Activity (>= 6 in 15m)',
      count: alerts.filter((a) => a.ruleId === 'ACTIVITY_SPIKE').length,
    },
    {
      ruleId: 'UNUSUAL_IP',
      label: 'Activity from Unusual Source IP Address',
      count: alerts.filter((a) => a.ruleId === 'UNUSUAL_IP').length,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-200">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Security Analytics & Compliance Reports
        </h1>
        <p className="text-sm text-slate-600 mt-0.5">
          Generate downloadable CSV audit and incident reports directly from persistent Firestore records.
        </p>
      </div>

      {/* Classification Breakdown: Detected Events vs Confirmed Incidents */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">
              Unreviewed Detected Events
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-600" />
          </div>
          <div className="text-3xl font-bold text-amber-600 font-mono tabular-nums mt-2">
            {openDetections}
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Rule-matched anomalies awaiting analyst triage
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">
              Reviewed & Verified Benign / Mitigated
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-3xl font-bold text-emerald-700 font-mono tabular-nums mt-2">
            {reviewedDetections}
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Inspected by security analyst and marked reviewed
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">
              Confirmed Security Incidents
            </span>
            <AlertTriangle className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-3xl font-bold text-red-600 font-mono tabular-nums mt-2">
            {confirmedIncidents}
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Escalated incidents requiring formal remediation
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Report Generator Form */}
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <FileSpreadsheet className="w-5 h-5 text-sky-600" />
            <h2 className="text-base font-bold text-slate-900">
              Generate Custom CSV Compliance Report
            </h2>
          </div>

          <form onSubmit={handleGenerateReport} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Report Format & Scope
              </label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as 'full_report' | 'logs_only')}
                className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
              >
                <option value="full_report">
                  Executive Summary + Security Incidents + Filtered Audit Logs (CSV)
                </option>
                <option value="logs_only">Raw Filtered Audit Log Records Only (CSV)</option>
              </select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Start Date (Optional)
                </label>
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  End Date (Optional)
                </label>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Data Source</label>
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                >
                  <option value="ALL">All Sources</option>
                  <option value="GCP_LIVE">GCP_LIVE</option>
                  <option value="DEMO">DEMO</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Category</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                >
                  <option value="ALL">All Categories</option>
                  <option value="ADMIN_ACTIVITY">ADMIN_ACTIVITY</option>
                  <option value="DATA_ACCESS">DATA_ACCESS</option>
                  <option value="SYSTEM_EVENT">SYSTEM_EVENT</option>
                  <option value="POLICY_DENIED">POLICY_DENIED</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="INFO">INFO</option>
                  <option value="NOTICE">NOTICE</option>
                  <option value="WARNING">WARNING</option>
                  <option value="ERROR">ERROR</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="ALERT">ALERT</option>
                  <option value="EMERGENCY">EMERGENCY</option>
                </select>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={exporting}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-sky-600 rounded-lg hover:bg-sky-700 transition-colors disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                <span>{exporting ? 'Generating CSV Report...' : 'Download CSV Security Report'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Rule Engine Breakdown */}
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <h2 className="text-base font-bold text-slate-900 mb-1">
            Detection Rule Engine Coverage
          </h2>
          <p className="text-xs text-slate-500 mb-4">
            Summary of deterministic security rules evaluated across stored audit logs
          </p>

          <div className="divide-y divide-slate-100">
            {ruleBreakdown.map((r) => (
              <div key={r.ruleId} className="py-3 flex items-center justify-between gap-4 text-xs">
                <div>
                  <div className="font-semibold text-slate-900">{r.label}</div>
                  <div className="font-mono text-[11px] text-slate-500 mt-0.5">{r.ruleId}</div>
                </div>
                <div className="font-mono tabular-nums font-bold text-sm text-slate-900">
                  {r.count} alerts
                </div>
              </div>
            ))}
          </div>

          {stats && (
            <div className="mt-4 pt-4 border-t border-slate-200 flex items-center justify-between text-xs text-slate-600">
              <span>Total Stored Audit Records Evaluated:</span>
              <span className="font-mono font-bold text-slate-900">{stats.totalEvents}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
