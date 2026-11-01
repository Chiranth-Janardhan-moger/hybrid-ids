import React, { useEffect, useState, useCallback } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { fetchAlertDetail } from '../api';
import type { Alert } from '../types';
import { AlertDetailContent } from '../components/AlertDetailContent';

export function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAlert = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAlertDetail(id);
      setAlert(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alert');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadAlert();
  }, [loadAlert]);

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <Link
          to="/alerts"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--color-muted)] hover:text-[var(--color-ink)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 rounded"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Alerts</span>
        </Link>
        {alert && <span className="text-xs font-mono text-[var(--color-muted)]">{alert.id}</span>}
      </div>

      <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] p-6">
        {loading ? (
          <div className="py-12 flex justify-center">
            <Loader2 className="w-6 h-6 text-[var(--color-accent)] animate-spin motion-reduce:animate-none" />
          </div>
        ) : error ? (
          <div>
            <p className="text-sm text-rose-400">{error}</p>
            <button
              type="button"
              onClick={loadAlert}
              className="mt-3 px-3 py-1.5 bg-[var(--color-accent)] text-[var(--color-accent-ink)] text-xs font-semibold rounded hover:bg-[var(--color-accent-hi)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
            >
              Retry
            </button>
          </div>
        ) : alert ? (
          <AlertDetailContent alert={alert} />
        ) : null}
      </div>
    </div>
  );
}
