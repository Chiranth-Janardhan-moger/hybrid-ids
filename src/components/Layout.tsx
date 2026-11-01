import React, { useEffect, useState, useCallback } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { Activity, UploadCloud, ShieldAlert, BarChart3, AlertTriangle } from 'lucide-react';
import { fetchHealth } from '../api';
import type { EngineHealthStatus } from '../types';

export const CATEGORY_BADGE_CLASSES: Record<string, string> = {
  Low: 'bg-emerald-50 text-emerald-800 border border-emerald-200',
  Medium: 'bg-amber-50 text-amber-800 border border-amber-200',
  High: 'bg-orange-50 text-orange-800 border border-orange-200',
  Critical: 'bg-rose-50 text-rose-800 border border-rose-200',
};

export const METHOD_BADGE_CLASSES: Record<string, string> = {
  signature: 'bg-sky-50 text-sky-800 border border-sky-200',
  ml: 'bg-purple-50 text-purple-800 border border-purple-200',
};

export function Layout() {
  const [health, setHealth] = useState<EngineHealthStatus | null>(null);
  const [backendUnreachable, setBackendUnreachable] = useState(false);

  const loadHealth = useCallback(async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
      setBackendUnreachable(false);
    } catch {
      setBackendUnreachable(true);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    const timer = window.setInterval(loadHealth, 5000);
    return () => window.clearInterval(timer);
  }, [loadHealth]);

  const navItems = [
    { to: '/', label: 'Dashboard', icon: Activity, end: true },
    { to: '/upload', label: 'Upload PCAP', icon: UploadCloud, end: false },
    { to: '/alerts', label: 'Alerts', icon: ShieldAlert, end: false },
    { to: '/evaluation', label: 'Model Evaluation', icon: BarChart3, end: false },
  ];

  return (
    <div className="min-h-screen flex bg-[var(--color-paper)] text-[var(--color-ink)]">
      {/* Left Sidebar */}
      <aside className="w-60 shrink-0 bg-[var(--color-paper-2)] border-r border-[var(--color-rule)] sticky top-0 h-screen flex flex-col justify-between shadow-xs">
        <div>
          <div className="h-16 px-6 flex items-center justify-between border-b border-[var(--color-rule)]">
            <div className="flex items-center gap-2">
              <span className="text-base font-semibold tracking-tight text-[var(--color-ink)] whitespace-nowrap">
                Hybrid IDS
              </span>
              <span className="font-mono text-[10px] text-[var(--color-accent)] px-1.5 py-0.5 rounded border border-[var(--color-rule)] bg-[var(--color-paper-3)] font-semibold">
                v1.1
              </span>
            </div>
          </div>

          <nav className="p-3 space-y-1" aria-label="Main Navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded text-sm font-medium whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 ${
                      isActive
                        ? 'bg-[var(--color-paper-3)] text-[var(--color-accent)] font-semibold border border-[var(--color-rule-2)]'
                        : 'text-[var(--color-muted)] hover:bg-[var(--color-paper-3)]/60 hover:text-[var(--color-ink)] border border-transparent'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Engine Health Status in Sidebar Footer */}
        <div className="p-4 border-t border-[var(--color-rule)] text-xs space-y-2 bg-[var(--color-paper-2)]">
          <div className="text-[11px] text-[var(--color-muted)] font-mono">Engine Status</div>
          <div className="space-y-1 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-muted)]">Suricata L1</span>
              <span className={health?.suricata === 'ok' ? 'text-emerald-700 font-semibold' : 'text-rose-700 font-semibold'}>
                {health?.suricata === 'ok' ? 'Active' : 'Offline'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-muted)]">Random Forest L2</span>
              <span className={health?.model === 'ok' ? 'text-emerald-700 font-semibold' : 'text-rose-700 font-semibold'}>
                {health?.model === 'ok' ? 'Active' : 'Offline'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--color-muted)]">IPS Auto-Block</span>
              <span className="text-[var(--color-accent)] font-semibold">Stateful</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {backendUnreachable && (
          <div
            role="alert"
            className="bg-rose-50 text-rose-800 border-b border-rose-200 px-6 py-2.5 text-sm font-medium flex items-center justify-between"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>Cannot reach Hybrid IDS backend server at http://localhost:3000</span>
            </div>
            <button
              type="button"
              onClick={loadHealth}
              className="px-2.5 py-1 bg-rose-100 hover:bg-rose-200 border border-rose-300 rounded text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 active:translate-y-0.5 disabled:opacity-50"
            >
              Retry
            </button>
          </div>
        )}

        <main className="flex-1 p-6 lg:p-8 max-w-[1360px] w-full mx-auto">
          <Outlet context={{ health, refreshHealth: loadHealth }} />
        </main>
      </div>
    </div>
  );
}
