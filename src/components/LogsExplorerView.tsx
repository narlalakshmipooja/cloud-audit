import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  RefreshCw,
  Download,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  X,
  CheckCircle2,
  XCircle,
  Eye,
  Copy,
  Check,
} from 'lucide-react';
import { AuditLogRecord, LogFilterParams } from '../types';
import { apiFetchLogs, apiDownloadCsvReport } from '../apiClient';

interface LogsExplorerViewProps {
  initialSelectedLog: AuditLogRecord | null;
  onClearInitialLog: () => void;
  onNotify: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const LogsExplorerView: React.FC<LogsExplorerViewProps> = ({
  initialSelectedLog,
  onClearInitialLog,
  onNotify,
}) => {
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState<AuditLogRecord | null>(initialSelectedLog);
  const [copiedJson, setCopiedJson] = useState(false);

  const [filters, setFilters] = useState<LogFilterParams>({
    search: '',
    startDate: '',
    endDate: '',
    principalEmail: '',
    serviceName: 'ALL',
    severity: 'ALL',
    category: 'ALL',
    status: 'ALL',
    source: 'ALL',
    sortBy: 'timestamp',
    sortOrder: 'desc',
    page: 1,
    pageSize: 12,
  });

  useEffect(() => {
    if (initialSelectedLog) {
      setSelectedLog(initialSelectedLog);
    }
  }, [initialSelectedLog]);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetchLogs(filters);
      setLogs(res.items);
      setTotal(res.total);
      setTotalPages(res.totalPages);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Failed to load logs', 'error');
    } finally {
      setLoading(false);
    }
  }, [filters, onNotify]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const handleResetFilters = () => {
    setFilters({
      search: '',
      startDate: '',
      endDate: '',
      principalEmail: '',
      serviceName: 'ALL',
      severity: 'ALL',
      category: 'ALL',
      status: 'ALL',
      source: 'ALL',
      sortBy: 'timestamp',
      sortOrder: 'desc',
      page: 1,
      pageSize: 12,
    });
  };

  const toggleSort = (field: 'timestamp' | 'severity' | 'serviceName' | 'principalEmail') => {
    setFilters((prev) => ({
      ...prev,
      sortBy: field,
      sortOrder: prev.sortBy === field && prev.sortOrder === 'desc' ? 'asc' : 'desc',
      page: 1,
    }));
  };

  const handleExportFilteredCsv = async () => {
    try {
      await apiDownloadCsvReport({
        type: 'logs_only',
        startDate: filters.startDate,
        endDate: filters.endDate,
        source: filters.source,
        severity: filters.severity,
        category: filters.category,
        status: filters.status,
      });
      onNotify('Exported filtered audit logs to CSV.', 'success');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'CSV export failed', 'error');
    }
  };

  const handleCopyPayload = () => {
    if (!selectedLog) return;
    navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Audit Logs Explorer</h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Search, filter, sort, and inspect normalized Google Cloud Audit Log entries stored in Firestore.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={handleResetFilters}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Filters</span>
          </button>

          <button
            type="button"
            onClick={loadLogs}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-600' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            type="button"
            onClick={handleExportFilteredCsv}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-sky-600 rounded-lg hover:bg-sky-700 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download CSV</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {/* Free text search */}
          <div className="lg:col-span-2">
            <label className="block text-xs font-medium text-slate-700 mb-1">
              Keyword / Method / Resource / IP Search
            </label>
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={filters.search || ''}
                onChange={(e) => setFilters((p) => ({ ...p, search: e.target.value, page: 1 }))}
                placeholder="Search methodName, resource, IP, or message..."
                className="w-full pl-9 pr-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:bg-white focus:border-sky-500"
              />
            </div>
          </div>

          {/* Principal Email filter */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Principal Email</label>
            <input
              type="text"
              value={filters.principalEmail || ''}
              onChange={(e) =>
                setFilters((p) => ({ ...p, principalEmail: e.target.value, page: 1 }))
              }
              placeholder="e.g. devops-lead@ or ext-contractor@"
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:bg-white focus:border-sky-500"
            />
          </div>

          {/* Service filter */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Cloud Service</label>
            <select
              value={filters.serviceName || 'ALL'}
              onChange={(e) => setFilters((p) => ({ ...p, serviceName: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:bg-white focus:border-sky-500"
            >
              <option value="ALL">All GCP Services</option>
              <option value="iam.googleapis.com">iam.googleapis.com</option>
              <option value="secretmanager.googleapis.com">secretmanager.googleapis.com</option>
              <option value="storage.googleapis.com">storage.googleapis.com</option>
              <option value="compute.googleapis.com">compute.googleapis.com</option>
              <option value="bigquery.googleapis.com">bigquery.googleapis.com</option>
              <option value="logging.googleapis.com">logging.googleapis.com</option>
              <option value="cloudkms.googleapis.com">cloudkms.googleapis.com</option>
              <option value="cloudresourcemanager.googleapis.com">
                cloudresourcemanager.googleapis.com
              </option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Log Category</label>
            <select
              value={filters.category || 'ALL'}
              onChange={(e) => setFilters((p) => ({ ...p, category: e.target.value, page: 1 }))}
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
              value={filters.severity || 'ALL'}
              onChange={(e) => setFilters((p) => ({ ...p, severity: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="DEFAULT">DEFAULT</option>
              <option value="INFO">INFO</option>
              <option value="NOTICE">NOTICE</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="ALERT">ALERT</option>
              <option value="EMERGENCY">EMERGENCY</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Operation Status</label>
            <select
              value={filters.status || 'ALL'}
              onChange={(e) => setFilters((p) => ({ ...p, status: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILURE">FAILURE</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Data Source</label>
            <select
              value={filters.source || 'ALL'}
              onChange={(e) => setFilters((p) => ({ ...p, source: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Sources</option>
              <option value="GCP_LIVE">GCP_LIVE</option>
              <option value="DEMO">DEMO</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Start Date</label>
            <input
              type="date"
              value={filters.startDate || ''}
              onChange={(e) => setFilters((p) => ({ ...p, startDate: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">End Date</label>
            <input
              type="date"
              value={filters.endDate || ''}
              onChange={(e) => setFilters((p) => ({ ...p, endDate: e.target.value, page: 1 }))}
              className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-sky-500"
            />
          </div>
        </div>
      </div>

      {/* High-Density Data Grid */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between text-xs text-slate-600">
          <div>
            Showing <span className="font-mono font-semibold text-slate-900">{logs.length}</span> of{' '}
            <span className="font-mono font-semibold text-slate-900">{total}</span> matching audit records
          </div>
          <div className="font-mono tabular-nums">
            Page {filters.page} of {totalPages}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                <th className="py-3 px-4">
                  <button
                    type="button"
                    onClick={() => toggleSort('timestamp')}
                    className="inline-flex items-center gap-1 hover:text-slate-900"
                  >
                    <span>Timestamp (UTC)</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">
                  <button
                    type="button"
                    onClick={() => toggleSort('severity')}
                    className="inline-flex items-center gap-1 hover:text-slate-900"
                  >
                    <span>Severity & Status</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">
                  <button
                    type="button"
                    onClick={() => toggleSort('principalEmail')}
                    className="inline-flex items-center gap-1 hover:text-slate-900"
                  >
                    <span>Principal</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">
                  <button
                    type="button"
                    onClick={() => toggleSort('serviceName')}
                    className="inline-flex items-center gap-1 hover:text-slate-900"
                  >
                    <span>Service & Method</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">Resource & Source IP</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {loading ? (
                Array.from({ length: 6 }).map((_, idx) => (
                  <tr key={idx} className="animate-pulse">
                    <td className="py-3.5 px-4">
                      <div className="h-3.5 w-32 bg-slate-200 rounded" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="h-3.5 w-24 bg-slate-200 rounded" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="h-3.5 w-40 bg-slate-200 rounded" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="h-3.5 w-48 bg-slate-200 rounded" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="h-3.5 w-36 bg-slate-200 rounded" />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="h-3.5 w-12 bg-slate-200 rounded ml-auto" />
                    </td>
                  </tr>
                ))
              ) : logs.length > 0 ? (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                      <div>{log.timestamp.replace('T', ' ').slice(0, 19)}</div>
                      <div className="text-[11px] text-slate-400">
                        {log.source} · {log.category}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 font-medium">
                        {log.status === 'SUCCESS' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-red-600 shrink-0" />
                        )}
                        <span
                          className={
                            log.severity === 'ERROR' ||
                            log.severity === 'CRITICAL' ||
                            log.severity === 'ALERT' ||
                            log.severity === 'EMERGENCY'
                              ? 'text-red-700 font-semibold'
                              : log.severity === 'WARNING' || log.severity === 'NOTICE'
                              ? 'text-amber-700 font-semibold'
                              : 'text-slate-800'
                          }
                        >
                          {log.severity}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{log.status}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-800 max-w-[220px] truncate">
                      {log.principalEmail}
                    </td>
                    <td className="py-3 px-4 max-w-[260px]">
                      <div className="font-semibold text-slate-900 truncate">{log.methodName}</div>
                      <div className="text-[11px] text-slate-500 truncate">{log.serviceName}</div>
                    </td>
                    <td className="py-3 px-4 max-w-[260px]">
                      <div className="font-mono text-slate-700 truncate">{log.resourceName}</div>
                      <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                        IP: {log.callerIp || 'internal'}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedLog(log);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-sky-700 hover:bg-sky-50 rounded-md transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>JSON</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-sm text-slate-500">
                    No audit log entries match the current filters. Try clicking &ldquo;Reset Filters&rdquo;.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-xs text-slate-600">
            Rows per page:{' '}
            <select
              value={filters.pageSize || 12}
              onChange={(e) =>
                setFilters((p) => ({ ...p, pageSize: Number(e.target.value), page: 1 }))
              }
              className="ml-1 px-2 py-1 bg-white border border-slate-200 rounded text-xs font-mono"
            >
              <option value={10}>10</option>
              <option value={12}>12</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={(filters.page || 1) <= 1}
              onClick={() => setFilters((p) => ({ ...p, page: Math.max(1, (p.page || 1) - 1) }))}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-100 disabled:opacity-40"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Previous</span>
            </button>
            <button
              type="button"
              disabled={(filters.page || 1) >= totalPages}
              onClick={() =>
                setFilters((p) => ({ ...p, page: Math.min(totalPages, (p.page || 1) + 1) }))
              }
              className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-100 disabled:opacity-40"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Slide-Over Detail Drawer */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/40 backdrop-blur-xs">
          <div className="w-full max-w-2xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col">
            <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-slate-900">Audit Log Entry Inspection</h2>
                <p className="text-xs font-mono text-slate-500 mt-0.5">{selectedLog.id}</p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSelectedLog(null);
                  onClearInitialLog();
                }}
                className="p-1.5 text-slate-500 hover:text-slate-900 rounded-lg hover:bg-slate-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Structured Metadata Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs">
                <div>
                  <div className="text-slate-500">Timestamp (UTC)</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5">
                    {selectedLog.timestamp}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Data Source & Category</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5">
                    {selectedLog.source} · {selectedLog.category}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Severity & Status</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5">
                    {selectedLog.severity} · {selectedLog.status} (Code {selectedLog.statusCode})
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Caller Source IP</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5">
                    {selectedLog.callerIp}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <div className="text-slate-500">Principal Email</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5 break-all">
                    {selectedLog.principalEmail}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <div className="text-slate-500">Service & Method</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5 break-all">
                    {selectedLog.serviceName} / {selectedLog.methodName}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <div className="text-slate-500">Target Resource Name</div>
                  <div className="font-mono font-medium text-slate-900 mt-0.5 break-all">
                    {selectedLog.resourceName}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <div className="text-slate-500">Status Message</div>
                  <div className="font-medium text-slate-900 mt-0.5">
                    {selectedLog.statusMessage}
                  </div>
                </div>
              </div>

              {/* Full Raw JSON Payload */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold text-slate-700">
                    Full Normalized & Raw Audit Log Payload (JSON)
                  </h3>
                  <button
                    type="button"
                    onClick={handleCopyPayload}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors"
                  >
                    {copiedJson ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy JSON</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-950 text-slate-100 p-4 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed">
                  {JSON.stringify(selectedLog, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
