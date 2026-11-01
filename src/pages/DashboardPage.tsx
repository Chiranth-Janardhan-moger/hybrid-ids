import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
} from 'recharts';
import { Loader2, Shield, ShieldOff, RefreshCw } from 'lucide-react';
import {
  fetchAlerts,
  fetchIpsStatus,
  fetchJobs,
  fetchSummary,
  toggleIpsBlockMode,
} from '../api';
import type {
  Alert,
  IpsStatusResponse,
  JobListItem,
  SummaryResponse,
} from '../types';
import { CATEGORY_BADGE_CLASSES, METHOD_BADGE_CLASSES } from '../components/Layout';

const CATEGORY_COLORS: Record<string, string> = {
  Low: '#10b981',
  Medium: '#eab308',
  High: '#f97316',
  Critical: '#ef4444',
};

export function DashboardPage() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string>('');
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [ipsStatus, setIpsStatus] = useState<IpsStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lastQueriesCountRef = useRef<number>(-1);
  const selectedJobIdRef = useRef<string>(selectedJobId);
  selectedJobIdRef.current = selectedJobId;

  const loadData = useCallback(async (jobId: string) => {
    setError(null);
    try {
      const [jobsData, summaryData, alertsData, ipsData] = await Promise.all([
        fetchJobs(),
        fetchSummary(jobId || undefined),
        fetchAlerts({ job_id: jobId || undefined, page: 1, page_size: 8 }),
        fetchIpsStatus(),
      ]);
      setJobs(jobsData);
      setSummary(summaryData);
      setRecentAlerts(alertsData.items);
      setIpsStatus(ipsData);
      lastQueriesCountRef.current = ipsData.stats.total_queries;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const handleManualSync = async () => {
    setRefreshing(true);
    await loadData(selectedJobId);
  };

  useEffect(() => {
    loadData(selectedJobId);
  }, [selectedJobId, loadData]);

  // Robust live sync: polls every 1800ms so running `python live_demo.py` in terminal immediately refreshes the entire UI
  useEffect(() => {
    const timer = window.setInterval(async () => {
      try {
        const nextIps = await fetchIpsStatus();
        setIpsStatus(nextIps);

        if (
          lastQueriesCountRef.current !== -1 &&
          lastQueriesCountRef.current !== nextIps.stats.total_queries
        ) {
          lastQueriesCountRef.current = nextIps.stats.total_queries;
          await loadData(selectedJobIdRef.current);
        } else {
          lastQueriesCountRef.current = nextIps.stats.total_queries;
        }
      } catch {
        // ignore transient poll error
      }
    }, 1800);
    return () => window.clearInterval(timer);
  }, [loadData]);

  const handleToggleIpsBlock = async () => {
    const nextEnabled = !ipsStatus?.block_mode_enabled;
    const updated = await toggleIpsBlockMode({ block_mode_enabled: nextEnabled });
    setIpsStatus(updated);
  };

  const handleClearIpsLogs = async () => {
    const updated = await toggleIpsBlockMode({ clear_logs: true });
    setIpsStatus(updated);
  };

  const handleUnbanIp = async (ip: string) => {
    const updated = await toggleIpsBlockMode({ unblock_ip: ip });
    setIpsStatus(updated);
  };

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-indigo-600 animate-spin motion-reduce:animate-none" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white rounded-lg border border-slate-200 p-6 shadow-xs">
        <p className="text-sm text-red-600 font-medium">{error}</p>
        <button
          type="button"
          onClick={() => loadData(selectedJobId)}
          className="mt-3 px-4 py-2 bg-indigo-600 text-white text-xs font-medium rounded-lg hover:bg-indigo-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 active:translate-y-0.5 disabled:opacity-50"
        >
          Retry
        </button>
      </div>
    );
  }

  if (jobs.length === 0 || (summary && summary.total_flows === 0 && !selectedJobId)) {
    return (
      <div className="bg-white rounded-lg border border-slate-200 p-12 text-center shadow-xs">
        <p className="text-sm text-slate-600 mb-4">No analysis yet. Upload a PCAP to get started.</p>
        <Link
          to="/upload"
          className="inline-flex items-center px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 active:translate-y-0.5"
        >
          Upload PCAP
        </Link>
      </div>
    );
  }

  const critCount = summary?.by_category.Critical ?? 0;
  const highCount = summary?.by_category.High ?? 0;
  const medCount = summary?.by_category.Medium ?? 0;
  const lowCount = summary?.by_category.Low ?? 0;
  const critHighCount = critCount + highCount;

  const sigCount = summary?.by_method.signature ?? 0;
  const mlCount = summary?.by_method.ml ?? 0;
  const totalFlows = summary?.total_flows ?? 0;
  const totalAlerts = summary?.total_alerts ?? 0;
  const alertRate = totalFlows > 0 ? ((totalAlerts / totalFlows) * 100).toFixed(1) : '0.0';

  const totalByMethod = sigCount + mlCount;
  const sigPct = totalByMethod > 0 ? Math.round((sigCount / totalByMethod) * 100) : 50;
  const mlPct = totalByMethod > 0 ? 100 - sigPct : 50;

  const categoryChartData = [
    { name: 'Low', value: lowCount },
    { name: 'Medium', value: medCount },
    { name: 'High', value: highCount },
    { name: 'Critical', value: critCount },
  ];

  const methodChartData = [
    { name: 'Signature', count: sigCount, fill: '#4f46e5' },
    { name: 'ML', count: mlCount, fill: '#9333ea' },
  ];

  return (
    <div className="space-y-5">
      {/* Top Bar with Job Selector & Live Telemetry Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Dashboard</h1>
          <p className="text-xs text-slate-500 mt-0.5">Real-time intrusion detection telemetry and IPS mitigation</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse motion-reduce:animate-none" />
            <span>Live Telemetry Active</span>
          </div>

          <button
            type="button"
            onClick={handleManualSync}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 active:translate-y-0.5 disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${
                refreshing ? 'animate-spin motion-reduce:animate-none text-indigo-600' : 'text-slate-500'
              }`}
            />
            <span>{refreshing ? 'Syncing...' : 'Sync'}</span>
          </button>

          <div className="flex items-center gap-2">
            <label htmlFor="dashboard-job-select" className="text-xs font-medium text-slate-600 whitespace-nowrap">
              Job
            </label>
            <select
              id="dashboard-job-select"
              value={selectedJobId}
              onChange={(e) => setSelectedJobId(e.target.value)}
              className="bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600"
            >
              <option value="">All jobs (Global view)</option>
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.filename} ({j.id})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Active IPS Firewall Control & Terminal Traffic Monitor (`python live_demo.py`) */}
      <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              {ipsStatus?.block_mode_enabled ? (
                <Shield className="w-4 h-4 text-emerald-600 shrink-0" />
              ) : (
                <ShieldOff className="w-4 h-4 text-amber-600 shrink-0" />
              )}
              <span className="text-sm font-bold text-slate-900">Active IPS Firewall</span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-bold border ${
                  ipsStatus?.block_mode_enabled
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-300'
                    : 'bg-amber-50 text-amber-900 border-amber-300'
                }`}
              >
                {ipsStatus?.block_mode_enabled ? 'BLOCK MODE: ON' : 'BLOCK MODE: OFF'}
              </span>
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  L0 IP Quarantine
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  L1 Suricata
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  L2 RF ML
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  L3 Entropy DPI &amp; Decoys
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-500">
              Run <code className="bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-800">python live_demo.py</code>{' '}
              to simulate queries. OFF allows all; ON blocks attacks (403) and auto-quarantines repeat attacker IPs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleToggleIpsBlock}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors shadow-2xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 active:translate-y-0.5 disabled:opacity-50 ${
                ipsStatus?.block_mode_enabled
                  ? 'bg-amber-600 text-white hover:bg-amber-700'
                  : 'bg-emerald-600 text-white hover:bg-emerald-700'
              }`}
            >
              {ipsStatus?.block_mode_enabled ? 'Disable Blocking' : 'Enable Blocking'}
            </button>

            {ipsStatus && ipsStatus.recent_logs.length > 0 && (
              <button
                type="button"
                onClick={handleClearIpsLogs}
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 active:translate-y-0.5 disabled:opacity-50"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Quarantined Blacklist IPs Bar (Layer 0 Reputation Memory) */}
        {ipsStatus && ipsStatus.quarantined_ips && ipsStatus.quarantined_ips.length > 0 && (
          <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-semibold text-fuchsia-900">
              Quarantined IPs ({ipsStatus.quarantined_ips.length}):
            </span>
            {ipsStatus.quarantined_ips.map((q) => (
              <span
                key={q.ip}
                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-fuchsia-50 text-fuchsia-900 border border-fuchsia-300 text-xs"
              >
                <strong className="font-mono text-[11px]">{q.ip}</strong>
                <span className="text-fuchsia-700">
                  [{q.trigger_layer.toUpperCase()}
                  {q.blocked_attempts > 0 ? `, ${q.blocked_attempts} dropped` : ''}]
                </span>
                <button
                  type="button"
                  onClick={() => handleUnbanIp(q.ip)}
                  className="ml-1 text-fuchsia-800 hover:text-red-700 font-semibold underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-fuchsia-600 active:opacity-70 rounded px-1"
                >
                  Unban
                </button>
              </span>
            ))}
          </div>
        )}

        {/* Summary Counters + Live Query Verdict Table */}
        {ipsStatus && ipsStatus.recent_logs.length > 0 && (
          <div className="pt-2 border-t border-slate-200 space-y-2">
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
              <span className="text-slate-600">
                Queries: <strong className="text-slate-900">{ipsStatus.stats.total_queries}</strong>
              </span>
              <span className="text-emerald-700">
                Safe Allowed: <strong>{ipsStatus.stats.safe_allowed}</strong>
              </span>
              <span className="text-amber-700">
                Attacks Allowed (Block OFF): <strong>{ipsStatus.stats.attacks_unblocked}</strong>
              </span>
              <span className="text-red-700">
                Attacks Blocked (Block ON): <strong>{ipsStatus.stats.attacks_blocked}</strong>
              </span>
              {ipsStatus.stats.quarantine_drops > 0 && (
                <span className="text-fuchsia-800">
                  Quarantine Pre-Filter Drops: <strong>{ipsStatus.stats.quarantine_drops}</strong>
                </span>
              )}
            </div>

            <div className="overflow-x-auto max-h-60 overflow-y-auto border border-slate-200 rounded-lg">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-slate-50 border-b border-slate-200 sticky top-0">
                  <tr className="text-xs font-medium text-slate-500">
                    <th className="py-1.5 px-3">Type</th>
                    <th className="py-1.5 px-3">Source IP</th>
                    <th className="py-1.5 px-3">Query</th>
                    <th className="py-1.5 px-3">Security Layer &amp; Entropy</th>
                    <th className="py-1.5 px-3">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {ipsStatus.recent_logs.slice(0, 12).map((item) => (
                    <tr key={item.id} className="hover:bg-slate-50">
                      <td className="py-1.5 px-3 font-semibold">
                        {item.query_type === 'SAFE' ? (
                          <span className="text-emerald-700">SAFE</span>
                        ) : (
                          <span className="text-red-700">ATTACK</span>
                        )}
                      </td>
                      <td className="py-1.5 px-3 font-mono text-slate-700">{item.src_ip}</td>
                      <td className="py-1.5 px-3">
                        <span className="font-medium text-slate-900">{item.label}</span>
                      </td>
                      <td className="py-1.5 px-3 text-slate-700">
                        {item.detection_engine === 'none' ? (
                          <span className="text-emerald-700">{item.detection_detail}</span>
                        ) : (
                          <span>
                            <span className="font-medium text-slate-900">{item.detection_detail}</span>
                            <span className="ml-1 font-mono text-[11px] text-red-700">({item.risk_score})</span>
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 px-3 font-mono font-bold whitespace-nowrap">
                        {item.action === 'ALLOWED' && (
                          <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200">
                            ALLOWED
                          </span>
                        )}
                        {item.action === 'ALLOWED_UNBLOCKED' && (
                          <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-300">
                            ALLOWED (Block OFF)
                          </span>
                        )}
                        {item.action === 'BLOCKED' && (
                          <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-200">
                            BLOCKED
                          </span>
                        )}
                        {item.action === 'QUARANTINED' && (
                          <span className="px-2 py-0.5 rounded bg-fuchsia-50 text-fuchsia-800 border border-fuchsia-200">
                            403 QUARANTINED
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg border border-slate-200 border-t-2 border-t-slate-400 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span className="font-medium text-slate-700">Total Flows</span>
            <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 text-[11px] font-medium">L3/L4 Inspection</span>
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900 tabular-nums font-mono">
            {totalFlows}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between pt-2 border-t border-slate-100">
            <span>Suricata &amp; RF Ingest</span>
            <span className="font-semibold text-emerald-700">100% Ingested</span>
          </div>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 border-t-2 border-t-indigo-500 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span className="font-medium text-slate-700">Total Alerts</span>
            <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 text-[11px] font-medium">
              {alertRate}% Attack Rate
            </span>
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900 tabular-nums font-mono">
            {totalAlerts}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between pt-2 border-t border-slate-100">
            <span>Threats Prioritized</span>
            <span className="font-semibold text-indigo-700">{totalAlerts} Flagged</span>
          </div>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 border-t-2 border-t-rose-500 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span className="font-medium text-slate-700">Critical + High Alerts</span>
            <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[11px] font-semibold">
              High Urgency
            </span>
          </div>
          <div className="mt-3 text-3xl font-bold text-rose-600 tabular-nums font-mono">
            {critHighCount}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center gap-3 pt-2 border-t border-slate-100">
            <span className="text-rose-700 font-semibold">{critCount} Critical</span>
            <span className="text-orange-700 font-medium">{highCount} High</span>
            {medCount > 0 && <span className="text-amber-700">{medCount} Medium</span>}
          </div>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 border-t-2 border-t-purple-500 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span className="font-medium text-slate-700">Signature vs ML</span>
            <span className="px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 text-[11px] font-medium">
              Hybrid Balance
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-slate-900 tabular-nums font-mono">{sigCount}</span>
            <span className="text-slate-400 font-light">/</span>
            <span className="text-3xl font-bold text-purple-700 tabular-nums font-mono">{mlCount}</span>
          </div>
          <div className="mt-2 pt-2 border-t border-slate-100 space-y-1">
            <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden flex">
              <div className="bg-indigo-600 h-full" style={{ width: `${sigPct}%` }} />
              <div className="bg-purple-600 h-full" style={{ width: `${mlPct}%` }} />
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-500">
              <span className="text-indigo-700 font-medium">{sigPct}% Sig</span>
              <span className="text-purple-700 font-medium">{mlPct}% ML</span>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row: Category Donut + Detection Method Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-slate-900">Alerts by Category</h2>
            <span className="text-xs text-slate-500">{totalAlerts} threats classified</span>
          </div>
          <div className="h-44 flex items-center justify-between gap-4">
            <div className="h-full w-44 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={categoryChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={46}
                    outerRadius={68}
                    paddingAngle={3}
                    isAnimationActive={false}
                  >
                    {categoryChartData.map((entry) => (
                      <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'var(--color-paper-2)',
                      borderColor: 'var(--color-rule)',
                      borderRadius: '8px',
                      color: 'var(--color-ink)',
                      fontSize: '12px',
                      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                    }}
                    itemStyle={{ color: 'var(--color-ink)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 space-y-2 text-xs">
              {categoryChartData.map((c) => {
                const pct = totalAlerts > 0 ? Math.round((c.value / totalAlerts) * 100) : 0;
                return (
                  <div key={c.name} className="space-y-0.5">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-1.5 text-slate-700">
                        <span
                          className="w-2.5 h-2.5 rounded-xs inline-block"
                          style={{ backgroundColor: CATEGORY_COLORS[c.name] }}
                        />
                        <span className="font-medium">{c.name}</span>
                      </span>
                      <span className="text-slate-500">
                        <strong className="font-mono text-slate-900 tabular-nums">{c.value}</strong>{' '}
                        <span>({pct}%)</span>
                      </span>
                    </div>
                    <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: CATEGORY_COLORS[c.name],
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-slate-900">Alerts by Detection Method</h2>
            <span className="text-xs text-slate-500">Dual-Engine Attribution</span>
          </div>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={methodChartData} barSize={42}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-rule)" />
                <XAxis dataKey="name" tick={{ fontSize: 12, fill: 'var(--color-ink-2, #475569)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: 'var(--color-ink-2, #475569)' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--color-paper-2)',
                    borderColor: 'var(--color-rule)',
                    borderRadius: '8px',
                    color: 'var(--color-ink)',
                    fontSize: '12px',
                    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                  }}
                  itemStyle={{ color: 'var(--color-ink)' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                  {methodChartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Line Chart: Alerts Over Time */}
      <div className="bg-white rounded-lg border border-slate-200 p-4 shadow-xs">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-slate-900">Alerts Timeline</h2>
          <span className="text-xs text-slate-500">Chronological incident frequency (1-min intervals)</span>
        </div>
        <div className="h-36">
          {summary && summary.timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={summary.timeline}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-rule)" />
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 11, fill: 'var(--color-ink-2, #475569)' }}
                  interval="preserveStartEnd"
                  minTickGap={28}
                />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--color-ink-2, #475569)' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--color-paper-2)',
                    borderColor: 'var(--color-rule)',
                    borderRadius: '8px',
                    color: 'var(--color-ink)',
                    fontSize: '12px',
                    boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                  }}
                  itemStyle={{ color: 'var(--color-ink)' }}
                />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#4f46e5"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#4f46e5' }}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-400">
              No alert events for selected scope
            </div>
          )}
        </div>
      </div>

      {/* Bottom Tables: Top Source IPs + Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Source IPs */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200">
            <h2 className="text-sm font-semibold text-slate-900">Top Source IPs</h2>
          </div>
          {summary && summary.top_source_ips.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-500 border-b border-slate-200">
                <tr>
                  <th className="px-5 py-2.5 font-medium">Source IP</th>
                  <th className="px-5 py-2.5 font-medium text-right">Alerts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {summary.top_source_ips.map((item) => (
                  <tr key={item.ip} className="hover:bg-slate-50">
                    <td className="px-5 py-2.5 font-mono text-slate-900">{item.ip}</td>
                    <td className="px-5 py-2.5 font-mono text-right text-slate-700 tabular-nums">
                      {item.count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-6 text-center text-xs text-slate-400">No source IP alerts</div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="lg:col-span-2 bg-white rounded-lg border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">Recent Alerts</h2>
            <Link to="/alerts" className="text-xs font-medium text-indigo-600 hover:text-indigo-700">
              View all
            </Link>
          </div>
          {recentAlerts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-500 border-b border-slate-200">
                  <tr>
                    <th className="px-3 py-2.5 font-medium">Source</th>
                    <th className="px-3 py-2.5 font-medium">Destination</th>
                    <th className="px-3 py-2.5 font-medium">Method</th>
                    <th className="px-3 py-2.5 font-medium">Description</th>
                    <th className="px-3 py-2.5 font-medium text-right">Score</th>
                    <th className="px-3 py-2.5 font-medium">Category</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {recentAlerts.map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => navigate(`/alerts/${a.id}`)}
                      className="hover:bg-slate-50 cursor-pointer"
                    >
                      <td className="px-3 py-2.5 font-mono text-slate-800 whitespace-nowrap tabular-nums">
                        {a.src_ip}:{a.src_port}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-slate-800 whitespace-nowrap tabular-nums">
                        {a.dst_ip}:{a.dst_port}
                      </td>
                      <td className="px-3 py-2.5 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                            METHOD_BADGE_CLASSES[a.detection_method]
                          }`}
                        >
                          {a.detection_method === 'signature' ? 'Signature' : 'ML'}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-slate-800 max-w-[190px] truncate">
                        {a.detection_method === 'signature'
                          ? a.signature_msg
                          : `ML: ${a.ml_label || 'malicious'} (p=${
                              a.ml_probability !== null ? a.ml_probability.toFixed(2) : '—'
                            })`}
                      </td>
                      <td className="px-3 py-2.5 font-mono font-semibold text-right text-slate-900 tabular-nums">
                        {a.risk_score}
                      </td>
                      <td className="px-3 py-2.5 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                            CATEGORY_BADGE_CLASSES[a.category]
                          }`}
                        >
                          {a.category}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-slate-400">No alerts recorded</div>
          )}
        </div>
      </div>
    </div>
  );
}
