/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  onAuthStateChanged,
  signInWithPopup,
  signOut,
  User as FirebaseUser,
} from 'firebase/auth';
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore';
import {
  Shield,
  LayoutDashboard,
  FileSearch,
  Clock,
  ShieldAlert,
  BarChart3,
  Settings,
  LogOut,
  Lock,
  CheckCircle2,
  AlertCircle,
  Info,
  X,
} from 'lucide-react';
import {
  auth,
  db,
  googleProvider,
  OperationType,
  handleFirestoreError,
} from './firebase';
import {
  UserProfile,
  DashboardStats,
  AuditLogRecord,
  SecurityAlertRecord,
} from './types';
import {
  apiFetchStats,
  apiFetchAlerts,
  apiDownloadCsvReport,
  seedOrResetDemoDataInFirestore,
} from './apiClient';
import { OverviewView } from './components/OverviewView';
import { LogsExplorerView } from './components/LogsExplorerView';
import { RetentionView } from './components/RetentionView';
import { AlertsView } from './components/AlertsView';
import { ReportsView } from './components/ReportsView';
import { IntegrationView } from './components/IntegrationView';

const BOOTSTRAPPED_ADMIN_EMAIL = '2400560511bba@gmail.com';

interface ToastNotification {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

export default function App() {
  const [authReady, setAuthReady] = useState(false);
  const [firebaseUser, setFirebaseUser] = useState<FirebaseUser | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<
    'overview' | 'logs' | 'retention' | 'alerts' | 'reports' | 'integration'
  >('overview');
  const [sourceFilter, setSourceFilter] = useState<'ALL' | 'GCP_LIVE' | 'DEMO'>('ALL');

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlertRecord[]>([]);
  const [loadingStats, setLoadingStats] = useState(false);
  const [selectedLogForDrawer, setSelectedLogForDrawer] = useState<AuditLogRecord | null>(null);

  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  const addNotification = useCallback(
    (message: string, type: 'success' | 'error' | 'info' = 'info') => {
      const id = `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      setToasts((prev) => [...prev, { id, message, type }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4500);
    },
    []
  );

  // Sync Firebase Auth state & user profile in Firestore
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (u) => {
      setFirebaseUser(u);
      if (!u) {
        setUserProfile(null);
        setAuthReady(true);
        return;
      }

      try {
        const userRef = doc(db, 'users', u.uid);
        const snap = await getDoc(userRef);
        const isBootstrappedAdmin = u.email === BOOTSTRAPPED_ADMIN_EMAIL;

        let resolvedProfile: UserProfile;
        if (!snap.exists()) {
          const initialRole = isBootstrappedAdmin ? 'admin' : 'viewer';
          resolvedProfile = {
            uid: u.uid,
            email: u.email || 'user@example.com',
            displayName: (u.displayName || u.email?.split('@')[0] || 'Security User').slice(0, 128),
            role: initialRole,
          };
          await setDoc(userRef, {
            ...resolvedProfile,
            createdAt: serverTimestamp(),
            lastLoginAt: serverTimestamp(),
          });
        } else {
          const data = snap.data() as UserProfile;
          resolvedProfile = {
            uid: u.uid,
            email: data.email || u.email || 'user@example.com',
            displayName: data.displayName || u.displayName || 'Security User',
            role: isBootstrappedAdmin ? 'admin' : data.role || 'viewer',
          };
        }

        setUserProfile(resolvedProfile);

        // If user is admin and database is empty, automatically seed realistic demo records once
        if (resolvedProfile.role === 'admin') {
          const seedResult = await seedOrResetDemoDataInFirestore(
            resolvedProfile.uid,
            resolvedProfile.email,
            false
          );
          if (seedResult.seededLogs > 0) {
            addNotification(
              `Initialized Demo Mode with ${seedResult.seededLogs} audit logs, ${seedResult.seededPolicies} retention policies, and ${seedResult.seededAlerts} security alerts.`,
              'info'
            );
          }
        }
      } catch (err) {
        handleFirestoreError(err, OperationType.GET, `users/${u.uid}`);
      } finally {
        setAuthReady(true);
      }
    });

    return () => unsub();
  }, [addNotification]);

  const loadDashboardAndAlerts = useCallback(async () => {
    if (!auth.currentUser) return;
    setLoadingStats(true);
    try {
      const [statsRes, alertsRes] = await Promise.all([
        apiFetchStats(sourceFilter),
        apiFetchAlerts({ source: sourceFilter }),
      ]);
      setStats(statsRes);
      setAlerts(alertsRes.alerts);
    } catch (err) {
      addNotification(
        err instanceof Error ? err.message : 'Failed to load dashboard telemetry',
        'error'
      );
    } finally {
      setLoadingStats(false);
    }
  }, [sourceFilter, addNotification]);

  useEffect(() => {
    if (authReady && firebaseUser && userProfile) {
      loadDashboardAndAlerts();
    }
  }, [authReady, firebaseUser, userProfile, loadDashboardAndAlerts]);

  const handleGoogleSignIn = async () => {
    setSigningIn(true);
    setAuthError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Google Sign-In failed');
    } finally {
      setSigningIn(false);
    }
  };

  const handleSignOut = async () => {
    await signOut(auth);
    setStats(null);
    setAlerts([]);
  };

  const handleInspectLogFromAnywhere = (log: AuditLogRecord) => {
    setSelectedLogForDrawer(log);
    setActiveTab('logs');
  };

  // Loading state while checking auth
  if (!authReady) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
        <div className="flex items-center gap-3">
          <div className="w-5 h-5 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm font-medium tracking-wide">
            Initializing Cloud Security Operations Console...
          </span>
        </div>
      </div>
    );
  }

  // 1. Login Page with Google Sign-In
  if (!firebaseUser || !userProfile) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between p-6 lg:p-12">
        <header className="flex items-center justify-between max-w-6xl w-full mx-auto">
          <div className="flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-sky-400" />
            <span className="text-base font-bold tracking-tight text-white">
              Cloud Audit Logs Retention & Analysis Design
            </span>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            B.Tech Cloud Security Project Console
          </span>
        </header>

        <main className="max-w-5xl w-full mx-auto grid grid-cols-1 lg:grid-cols-12 gap-10 items-center my-12">
          <div className="lg:col-span-7 space-y-6">
            <div className="text-xs font-mono text-sky-400 tracking-wide">
              GOOGLE CLOUD AUDIT LOGGING · FIRESTORE RETENTION · THREAT ANALYTICS
            </div>
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-tight">
              Centralized Audit Log Retention &amp; Rule-Based Threat Analysis
            </h1>
            <p className="text-slate-300 text-sm sm:text-base leading-relaxed max-w-2xl">
              Collect and normalize Google Cloud Audit Logs (<code className="font-mono text-sky-300">cloudaudit.googleapis.com</code>), enforce application-level Firestore retention policies with batch execution tracking, and detect suspicious IAM mutations, repeated failures, and anomalous IP activity.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
                <div className="text-xs font-semibold text-white">Persistent Storage</div>
                <p className="text-xs text-slate-400 mt-1">
                  Normalized schema in Cloud Firestore with deduplicated insert IDs and hardened security rules.
                </p>
              </div>
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
                <div className="text-xs font-semibold text-white">Lifecycle Retention</div>
                <p className="text-xs text-slate-400 mt-1">
                  Category-aware retention policies with dry-run simulation and immutable cleanup logs.
                </p>
              </div>
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
                <div className="text-xs font-semibold text-white">5 Detection Rules</div>
                <p className="text-xs text-slate-400 mt-1">
                  Deterministic alerts for repeated failures, IAM changes, sensitive ops, bursts, and outlier IPs.
                </p>
              </div>
            </div>
          </div>

          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-2 text-xs font-medium text-sky-400">
                <Lock className="w-4 h-4" />
                <span>Role-Aware Security Console Access</span>
              </div>
              <h2 className="text-xl font-bold text-white">Sign in to Security Console</h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                Authenticate with your Google account via Firebase Authentication. Administrator privileges are automatically provisioned for the project owner.
              </p>
            </div>

            {authError && (
              <div className="p-3 rounded-lg bg-red-950/80 border border-red-800 text-xs text-red-200">
                {authError}
              </div>
            )}

            <button
              type="button"
              onClick={handleGoogleSignIn}
              disabled={signingIn}
              className="w-full py-3 px-4 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm rounded-xl transition-colors flex items-center justify-center gap-2.5 cursor-pointer disabled:opacity-50"
            >
              <Shield className="w-4 h-4" />
              <span>{signingIn ? 'Authenticating with Google...' : 'Sign in with Google'}</span>
            </button>

            <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-400 space-y-1">
              <div>
                <strong>RBAC Tiers:</strong> Administrator (full policy &amp; sync control) · Security Analyst (alert triage &amp; export) · Viewer (read-only audit inspection)
              </div>
            </div>
          </div>
        </main>

        <footer className="max-w-6xl w-full mx-auto text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 border-t border-slate-900 pt-6">
          <span>Cloud Audit Logs Retention &amp; Analysis Design</span>
          <span>Firebase Cloud Firestore · Google Cloud Logging API</span>
        </footer>
      </div>
    );
  }

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'logs', label: 'Audit Logs Explorer', icon: FileSearch },
    { id: 'retention', label: 'Retention Policies', icon: Clock },
    { id: 'alerts', label: 'Security Alerts', icon: ShieldAlert },
    { id: 'reports', label: 'Analytics & Reports', icon: BarChart3 },
    { id: 'integration', label: 'Cloud Integration', icon: Settings },
  ] as const;

  const activeBreadcrumbLabel =
    navItems.find((n) => n.id === activeTab)?.label || 'Overview';

  return (
    <div className="min-h-screen flex bg-slate-50 text-slate-900">
      {/* Dark Navy Sidebar (260px on desktop) */}
      <aside className="w-64 bg-slate-950 text-slate-200 flex flex-col justify-between shrink-0 border-r border-slate-900">
        <div>
          {/* Sidebar Brand Header */}
          <div className="px-5 py-5 border-b border-slate-800/80 flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-sky-400 shrink-0" />
            <div className="min-w-0">
              <div className="text-sm font-bold text-white truncate">Cloud Audit SecOps</div>
              <div className="text-[11px] text-slate-400 truncate">
                Retention &amp; Threat Analysis
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-sky-500/15 text-sky-300 font-semibold'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-400' : ''}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Account Footer in Sidebar */}
        <div className="p-4 border-t border-slate-900 bg-slate-950/60 space-y-3">
          <div className="text-xs">
            <div className="font-semibold text-white truncate">{userProfile.displayName}</div>
            <div className="font-mono text-[11px] text-slate-400 truncate mt-0.5">
              {userProfile.email}
            </div>
            <div className="text-[11px] font-mono text-sky-400 mt-1 uppercase">
              Role: {userProfile.role}
            </div>
          </div>

          <button
            type="button"
            onClick={handleSignOut}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar Contract: Zone 1 Breadcrumb — Zone 2 Quick Nav — Zone 3 Primary Action */}
        <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-white border-b border-slate-200">
          <div className="text-sm font-semibold text-slate-900 whitespace-nowrap shrink-0">
            SecOps Console / {activeBreadcrumbLabel}
          </div>

          <nav className="hidden xl:flex items-center gap-6 text-xs font-medium text-slate-600">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('logs')}
              className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
            >
              Logs Explorer
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('retention')}
              className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
            >
              Retention
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('alerts')}
              className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
            >
              Alerts
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('integration')}
              className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
            >
              Cloud Setup
            </button>
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() =>
                apiDownloadCsvReport({
                  type: 'full_report',
                  source: sourceFilter,
                }).then(() => addNotification('Downloaded CSV security report.', 'success'))
              }
              className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              Export Report
            </button>
          </div>
        </header>

        {/* Active View Viewport */}
        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto">
          {activeTab === 'overview' && (
            <OverviewView
              stats={stats}
              loading={loadingStats}
              sourceFilter={sourceFilter}
              onSourceFilterChange={setSourceFilter}
              onRefresh={loadDashboardAndAlerts}
              onNavigate={(t) => setActiveTab(t as typeof activeTab)}
              onSelectLog={handleInspectLogFromAnywhere}
              onExportCsv={() =>
                apiDownloadCsvReport({
                  type: 'full_report',
                  source: sourceFilter,
                }).then(() => addNotification('Downloaded CSV security report.', 'success'))
              }
            />
          )}

          {activeTab === 'logs' && (
            <LogsExplorerView
              initialSelectedLog={selectedLogForDrawer}
              onClearInitialLog={() => setSelectedLogForDrawer(null)}
              onNotify={addNotification}
            />
          )}

          {activeTab === 'retention' && (
            <RetentionView
              userRole={userProfile.role}
              onNotify={addNotification}
              onDataChanged={loadDashboardAndAlerts}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsView
              userRole={userProfile.role}
              onNotify={addNotification}
              onInspectLog={handleInspectLogFromAnywhere}
              onDataChanged={loadDashboardAndAlerts}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView
              stats={stats}
              alerts={alerts}
              onNotify={addNotification}
            />
          )}

          {activeTab === 'integration' && (
            <IntegrationView
              currentUser={userProfile}
              onNotify={addNotification}
              onDataChanged={loadDashboardAndAlerts}
            />
          )}
        </main>
      </div>

      {/* Toast Notifications */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start justify-between gap-3 p-3.5 rounded-xl shadow-lg border text-xs ${
              t.type === 'success'
                ? 'bg-slate-900 border-emerald-500/40 text-white'
                : t.type === 'error'
                ? 'bg-red-950 border-red-700 text-red-100'
                : 'bg-slate-900 border-slate-700 text-slate-100'
            }`}
          >
            <div className="flex items-start gap-2">
              {t.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : t.type === 'error' ? (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              ) : (
                <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
              )}
              <span className="leading-relaxed">{t.message}</span>
            </div>
            <button
              type="button"
              onClick={() => setToasts((prev) => prev.filter((item) => item.id !== t.id))}
              className="text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
