import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts';
import {
  ShieldAlert,
  FileSearch,
  Clock,
  Download,
  RefreshCw,
  ArrowUpRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { DashboardStats, AuditLogRecord } from '../types';

interface OverviewViewProps {
  stats: DashboardStats | null;
  loading: boolean;
  sourceFilter: 'ALL' | 'GCP_LIVE' | 'DEMO';
  onSourceFilterChange: (source: 'ALL' | 'GCP_LIVE' | 'DEMO') => void;
  onRefresh: () => void;
  onNavigate: (tab: string) => void;
  onSelectLog: (log: AuditLogRecord) => void;
  onExportCsv: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  stats,
  loading,
  sourceFilter,
  onSourceFilterChange,
  onRefresh,
  onNavigate,
  onSelectLog,
  onExportCsv,
}) => {
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  return (
    <div className="space-y-6">
      {/* Workspace Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Security Operations Overview
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Real-time telemetry computed from persistent Firestore audit log records and rule-based threat detections.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Interactive Source Filter Tabs */}
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg border border-slate-200">
            {(['ALL', 'GCP_LIVE', 'DEMO'] as const).map((src) => (
              <button
                key={src}
                type="button"
                onClick={() => onSourceFilterChange(src)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  sourceFilter === src
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {src === 'ALL' ? 'All Records' : src === 'GCP_LIVE' ? 'GCP Live Only' : 'Demo Dataset'}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-600' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            type="button"
            onClick={onExportCsv}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download CSV</span>
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500">Total Audit Events</div>
          <div className="text-3xl font-bold text-slate-900 font-mono tabular-nums mt-2">
            {loading && !stats ? '—' : stats?.totalEvents.toLocaleString() ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            <span>Persistent Firestore records</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500">Admin Activities</div>
          <div className="text-3xl font-bold text-slate-900 font-mono tabular-nums mt-2">
            {loading && !stats ? '—' : stats?.adminActivities.toLocaleString() ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            <span>IAM & resource mutations</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500">Failed Operations</div>
          <div className="text-3xl font-bold text-amber-600 font-mono tabular-nums mt-2">
            {loading && !stats ? '—' : stats?.failedOperations.toLocaleString() ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            <span>Non-zero status / denied</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500">High-Risk Events</div>
          <div className="text-3xl font-bold text-red-600 font-mono tabular-nums mt-2">
            {loading && !stats ? '—' : stats?.highRiskEvents.toLocaleString() ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            <span>Severity ERROR to EMERGENCY</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="text-xs font-medium text-slate-500">Logs Stored Volume</div>
          <div className="text-3xl font-bold text-sky-700 font-mono tabular-nums mt-2">
            {loading && !stats ? '—' : formatBytes(stats?.logsStoredBytesEstimate ?? 0)}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            <span>{stats?.activePoliciesCount ?? 0} active retention policies</span>
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Audit Events & High-Risk Operations Over Time
              </h2>
              <p className="text-xs text-slate-500">
                Daily volume of ingested audit records vs failed and high-severity operations
              </p>
            </div>
          </div>
          <div className="h-64 w-full">
            {stats && stats.eventsOverTime.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.eventsOverTime} margin={{ top: 10, right: 16, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#64748b' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      color: '#f8fafc',
                      fontSize: '12px',
                      borderRadius: '8px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    name="Total Events"
                    stroke="#0284c7"
                    fill="#e0f2fe"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="failed"
                    name="Failed Operations"
                    stroke="#d97706"
                    fill="#fef3c7"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="highRisk"
                    name="High-Risk Events"
                    stroke="#dc2626"
                    fill="#fee2e2"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-slate-500">
                No audit events available for the selected source filter.
              </div>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-slate-900">Severity Distribution</h2>
            <p className="text-xs text-slate-500">Breakdown by Cloud Logging severity level</p>
          </div>
          <div className="h-64 w-full">
            {stats && stats.severityDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.severityDistribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="severity" tick={{ fontSize: 11, fill: '#64748b' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#64748b' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      color: '#f8fafc',
                      fontSize: '12px',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" name="Events" fill="#0284c7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-slate-500">
                No severity metrics available.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Charts Row 2: Operation Categories & Activity by Principal */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-slate-900">Operation Categories</h2>
            <p className="text-xs text-slate-500">
              Distribution across Admin Activity, Data Access, System Event, and Policy Denied
            </p>
          </div>
          <div className="h-56 w-full">
            {stats && stats.operationCategories.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.operationCategories}
                  layout="vertical"
                  margin={{ top: 5, right: 20, left: 30, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    tick={{ fontSize: 11, fill: '#334155' }}
                    width={110}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      color: '#f8fafc',
                      fontSize: '12px',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" name="Log Count" fill="#0ea5e9" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-slate-500">
                No category breakdown available.
              </div>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-slate-900">Activity by Principal</h2>
            <p className="text-xs text-slate-500">Top user and service accounts by total & failed operations</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                  <th className="py-2 pr-3">Principal Email</th>
                  <th className="py-2 px-3 text-right">Total Ops</th>
                  <th className="py-2 pl-3 text-right">Failed Ops</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {stats && stats.activityByPrincipal.length > 0 ? (
                  stats.activityByPrincipal.map((item) => (
                    <tr key={item.principal} className="hover:bg-slate-50">
                      <td className="py-2.5 pr-3 font-mono text-slate-800 truncate max-w-[260px]">
                        {item.principal}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums font-medium text-slate-900">
                        {item.count}
                      </td>
                      <td className="py-2.5 pl-3 text-right font-mono tabular-nums font-medium text-amber-700">
                        {item.failed}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={3} className="py-8 text-center text-slate-500">
                      No principal activity recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Recent Audit Events & Recent Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Recent Audit Events</h2>
              <p className="text-xs text-slate-500">Click any record to inspect full JSON payload</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('logs')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-600 hover:text-sky-700 whitespace-nowrap shrink-0"
            >
              <span>Open Explorer</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-100">
            {stats && stats.recentLogs.length > 0 ? (
              stats.recentLogs.map((log) => (
                <div
                  key={log.id}
                  onClick={() => onSelectLog(log)}
                  className="py-3 flex items-start justify-between gap-4 hover:bg-slate-50 px-2 -mx-2 rounded-lg cursor-pointer transition-colors"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-slate-900 truncate">
                      {log.methodName}
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5 flex items-center gap-1.5 flex-wrap">
                      <span className="font-mono">{log.principalEmail}</span>
                      <span aria-hidden="true">·</span>
                      <span>{log.serviceName}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{log.source}</span>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="flex items-center justify-end gap-1 text-xs font-medium">
                      {log.status === 'SUCCESS' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-red-600" />
                      )}
                      <span
                        className={
                          log.status === 'SUCCESS' ? 'text-emerald-700' : 'text-red-700'
                        }
                      >
                        {log.severity}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-0.5">
                      {log.timestamp.replace('T', ' ').slice(0, 19)}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-sm text-slate-500">
                No audit log events stored yet.
              </div>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Recent Security Alerts</h2>
              <p className="text-xs text-slate-500">
                {stats?.openAlertsCount ?? 0} open detections · {stats?.confirmedIncidentsCount ?? 0} confirmed incidents
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-600 hover:text-sky-700 whitespace-nowrap shrink-0"
            >
              <span>Triage Alerts</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-100">
            {stats && stats.recentAlerts.length > 0 ? (
              stats.recentAlerts.map((alert) => (
                <div key={alert.id} className="py-3 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                      <AlertTriangle
                        className={`w-3.5 h-3.5 shrink-0 ${
                          alert.severity === 'CRITICAL' || alert.severity === 'HIGH'
                            ? 'text-red-600'
                            : 'text-amber-600'
                        }`}
                      />
                      <span className="truncate">{alert.title}</span>
                    </div>
                    <div className="text-xs text-slate-600 mt-0.5 line-clamp-1">
                      {alert.detectionReason}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1.5">
                      <span className="font-mono">{alert.principalEmail}</span>
                      <span aria-hidden="true">·</span>
                      <span>Status: {alert.status}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{alert.source}</span>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div
                      className={`text-xs font-semibold font-mono ${
                        alert.severity === 'CRITICAL' || alert.severity === 'HIGH'
                          ? 'text-red-700'
                          : 'text-amber-700'
                      }`}
                    >
                      {alert.severity}
                    </div>
                    <div className="text-[11px] font-mono tabular-nums text-slate-400 mt-0.5">
                      {alert.eventTime.replace('T', ' ').slice(0, 19)}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-sm text-slate-500">
                No security alerts triggered.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
