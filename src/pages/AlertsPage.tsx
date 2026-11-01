import React, { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Loader2, X, ExternalLink } from 'lucide-react';
import { fetchAlerts, fetchJobs } from '../api';
import type { Alert, JobListItem } from '../types';
import { CATEGORY_BADGE_CLASSES, METHOD_BADGE_CLASSES } from '../components/Layout';
import { AlertDetailContent } from '../components/AlertDetailContent';

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const jobId = searchParams.get('job_id') || '';
  const category = searchParams.get('category') || '';
  const method = searchParams.get('method') || '';
  const search = searchParams.get('search') || '';
  const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10) || 1);
  const pageSize = 20;

  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [items, setItems] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [jobsList, alertsRes] = await Promise.all([
        fetchJobs(),
        fetchAlerts({
          job_id: jobId || undefined,
          category: category || undefined,
          method: method || undefined,
          search: search || undefined,
          page,
          page_size: pageSize,
        }),
      ]);
      setJobs(jobsList);
      setItems(alertsRes.items);
      setTotal(alertsRes.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [jobId, category, method, search, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const updateFilter = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    if (key !== 'page') {
      next.set('page', '1');
    }
    setSearchParams(next);
  };

  const handleReset = () => {
    setSearchParams(new URLSearchParams());
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-[var(--color-ink)]">Security Alerts</h1>
          <p className="text-xs text-[var(--color-muted)] mt-1">
            Suricata signature exploits and Random Forest flow anomaly detections.
          </p>
        </div>
        <span className="text-xs text-[var(--color-muted)]">
          <strong className="font-mono tabular-nums text-[var(--color-ink)]">{total}</strong> total alerts
        </span>
      </div>

      {/* Filter Bar */}
      <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] p-3.5 flex flex-wrap items-center gap-2.5">
        <select
          aria-label="Filter by Job"
          value={jobId}
          onChange={(e) => updateFilter('job_id', e.target.value)}
          className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-xs text-[var(--color-ink)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <option value="">All traces &amp; jobs</option>
          {jobs.map((j) => (
            <option key={j.id} value={j.id}>
              {j.filename} ({j.id})
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by Category"
          value={category}
          onChange={(e) => updateFilter('category', e.target.value)}
          className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-xs text-[var(--color-ink)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <option value="">All severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          aria-label="Filter by Method"
          value={method}
          onChange={(e) => updateFilter('method', e.target.value)}
          className="bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-xs text-[var(--color-ink)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <option value="">All engines</option>
          <option value="signature">Suricata L1 Signature</option>
          <option value="ml">Random Forest L2 ML</option>
        </select>

        <input
          type="text"
          aria-label="Search IP or signature text"
          placeholder="Filter IP, SID, or pattern..."
          value={search}
          onChange={(e) => updateFilter('search', e.target.value)}
          className="flex-1 min-w-[180px] bg-[var(--color-paper-3)] border border-[var(--color-rule)] rounded px-3 py-1.5 text-xs text-[var(--color-ink)] placeholder-[var(--color-muted)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        />

        <button
          type="button"
          onClick={handleReset}
          className="px-3 py-1.5 bg-[var(--color-paper-3)] hover:bg-[var(--color-paper-3)]/80 text-[var(--color-muted)] hover:text-[var(--color-ink)] border border-[var(--color-rule)] text-xs font-medium rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
        >
          Reset
        </button>
      </div>

      {/* Table */}
      <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] overflow-hidden">
        {loading ? (
          <div className="p-12 flex justify-center">
            <Loader2 className="w-6 h-6 text-[var(--color-accent)] animate-spin motion-reduce:animate-none" />
          </div>
        ) : error ? (
          <div className="p-6">
            <p className="text-sm text-rose-700">{error}</p>
            <button
              type="button"
              onClick={loadData}
              className="mt-3 px-3 py-1.5 bg-[var(--color-accent)] text-[var(--color-accent-ink)] text-xs font-semibold rounded hover:bg-[var(--color-accent-hi)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
            >
              Retry
            </button>
          </div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center text-xs text-[var(--color-muted)]">No alerts match these filters.</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--color-paper-3)]/60 text-[var(--color-muted)] border-b border-[var(--color-rule)]">
                  <tr>
                    <th className="px-4 py-3 font-medium">Timestamp</th>
                    <th className="px-4 py-3 font-medium">Source</th>
                    <th className="px-4 py-3 font-medium">Destination</th>
                    <th className="px-4 py-3 font-medium">Protocol</th>
                    <th className="px-4 py-3 font-medium">Detection engine</th>
                    <th className="px-4 py-3 font-medium">Attack description / signature</th>
                    <th className="px-4 py-3 font-medium text-right">Risk</th>
                    <th className="px-4 py-3 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-rule)]">
                  {items.map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedAlert(a)}
                      className="hover:bg-[var(--color-paper-3)]/40 cursor-pointer"
                    >
                      <td className="px-4 py-3 font-mono text-[var(--color-muted)] whitespace-nowrap tabular-nums">
                        {a.timestamp.slice(11, 19)}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--color-ink)] whitespace-nowrap tabular-nums">
                        {a.src_ip}:{a.src_port}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--color-muted)] whitespace-nowrap tabular-nums">
                        {a.dst_ip}:{a.dst_port}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--color-muted)] whitespace-nowrap">
                        {a.protocol}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                            METHOD_BADGE_CLASSES[a.detection_method]
                          }`}
                        >
                          {a.detection_method === 'signature' ? 'Signature L1' : 'Flow ML L2'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[var(--color-ink-2)] max-w-sm truncate">
                        {a.detection_method === 'signature'
                          ? a.signature_msg
                          : `ML: ${a.ml_label || 'anomaly'} (p=${
                              a.ml_probability !== null ? a.ml_probability.toFixed(2) : '—'
                            })`}
                      </td>
                      <td className="px-4 py-3 font-mono font-bold text-right text-[var(--color-ink)] tabular-nums">
                        {a.risk_score}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
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

            {/* Pagination */}
            <div className="px-4 py-3 border-t border-[var(--color-rule)] flex items-center justify-between text-xs">
              <span className="text-[var(--color-muted)] tabular-nums">
                Page {page} of {totalPages}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => updateFilter('page', String(page - 1))}
                  className="px-3 py-1 bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink)] rounded hover:bg-[var(--color-paper-3)]/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Prev
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => updateFilter('page', String(page + 1))}
                  className="px-3 py-1 bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink)] rounded hover:bg-[var(--color-paper-3)]/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Right-Side Drawer for Alert Detail */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/40">
          <div
            role="dialog"
            aria-label="Alert Detail Drawer"
            className="w-full max-w-lg bg-[var(--color-paper-2)] h-full border-l border-[var(--color-rule)] flex flex-col overflow-hidden text-[var(--color-ink)] shadow-2xl"
          >
            <div className="px-6 py-4 border-b border-[var(--color-rule)] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">Alert {selectedAlert.id}</h2>
                <Link
                  to={`/alerts/${selectedAlert.id}`}
                  className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)] hover:underline font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
                >
                  <span>Full page</span>
                  <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
              <button
                type="button"
                aria-label="Close drawer"
                onClick={() => setSelectedAlert(null)}
                className="p-1 text-[var(--color-muted)] hover:text-[var(--color-ink)] rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-6 overflow-y-auto flex-1">
              <AlertDetailContent alert={selectedAlert} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
