import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Link, useOutletContext } from 'react-router-dom';
import { UploadCloud, Loader2, AlertCircle, Download, ArrowRight, ShieldCheck, Cpu, CheckCircle2 } from 'lucide-react';
import {
  fetchJobDetail,
  fetchJobs,
  getExportUrl,
  runSamplePcapJob,
  updateEngineSimulation,
  uploadPcapJob,
} from '../api';
import type { EngineHealthStatus, JobDetail, JobListItem } from '../types';

const MAX_BYTES = 100 * 1024 * 1024;

type OutletCtx = {
  health: EngineHealthStatus | null;
  refreshHealth: () => Promise<void>;
};

export function UploadPage() {
  const { health, refreshHealth } = useOutletContext<OutletCtx>();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [activeJob, setActiveJob] = useState<JobDetail | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [loadingJobs, setLoadingJobs] = useState(true);

  const loadJobsList = useCallback(async () => {
    try {
      const list = await fetchJobs();
      setJobs(list);
      if (!activeJob && list.length > 0) {
        const latest = await fetchJobDetail(list[0].id);
        setActiveJob(latest);
      }
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Failed to load jobs');
    } finally {
      setLoadingJobs(false);
    }
  }, [activeJob]);

  useEffect(() => {
    loadJobsList();
  }, [loadJobsList]);

  // Poll every 2 seconds while activeJob is queued or running; stop when completed or failed
  useEffect(() => {
    if (!activeJob || (activeJob.status !== 'queued' && activeJob.status !== 'running')) {
      return;
    }
    const timer = window.setInterval(async () => {
      try {
        const updated = await fetchJobDetail(activeJob.id);
        setActiveJob(updated);
        if (updated.status === 'completed' || updated.status === 'failed') {
          const list = await fetchJobs();
          setJobs(list);
        }
      } catch {
        // ignore transient poll error
      }
    }, 2000);

    return () => window.clearInterval(timer);
  }, [activeJob]);

  const handleFileSelected = async (file: File) => {
    setUploadError(null);
    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng')) {
      setUploadError('Invalid file format. Only .pcap and .pcapng network traces are accepted.');
      return;
    }
    if (file.size === 0) {
      setUploadError('Selected file is empty (0 bytes).');
      return;
    }
    if (file.size > MAX_BYTES) {
      setUploadError('File exceeds maximum allowed size of 100 MB.');
      return;
    }

    setUploading(true);
    try {
      const { job_id } = await uploadPcapJob(file);
      const detail = await fetchJobDetail(job_id);
      setActiveJob(detail);
      const list = await fetchJobs();
      setJobs(list);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleRunSample = async (sampleName: string) => {
    setUploadError(null);
    setUploading(true);
    try {
      const { job_id } = await runSamplePcapJob(sampleName);
      const detail = await fetchJobDetail(job_id);
      setActiveJob(detail);
      const list = await fetchJobs();
      setJobs(list);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Sample execution failed');
    } finally {
      setUploading(false);
    }
  };

  const handleSelectPreviousJob = async (jobId: string) => {
    setUploadError(null);
    try {
      const detail = await fetchJobDetail(jobId);
      setActiveJob(detail);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Failed to load job details');
    }
  };

  const handleToggleEngine = async (field: 'suricata' | 'model') => {
    if (!health) return;
    const nextConfig =
      field === 'suricata'
        ? { suricata_unavailable: health.suricata === 'ok' }
        : { model_missing: health.model === 'ok' };
    await updateEngineSimulation(nextConfig);
    await refreshHealth();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-[var(--color-ink)]">PCAP Analysis Pipeline</h1>
          <p className="text-xs text-[var(--color-muted)] mt-1">
            Ingest packet capture traces for dual-engine Suricata signature matching and Random Forest flow anomaly extraction.
          </p>
        </div>

        {/* Engine Degraded Simulation Toggles */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <button
            type="button"
            onClick={() => handleToggleEngine('suricata')}
            className={`px-3 py-1.5 rounded border font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50 ${
              health?.suricata === 'unavailable'
                ? 'bg-rose-50 border-rose-200 text-rose-800'
                : 'bg-[var(--color-paper-2)] border-[var(--color-rule)] text-[var(--color-ink-2)] hover:border-[var(--color-rule-2)]'
            }`}
          >
            {health?.suricata === 'unavailable' ? 'Restore Suricata L1' : 'Simulate Suricata Offline'}
          </button>
          <button
            type="button"
            onClick={() => handleToggleEngine('model')}
            className={`px-3 py-1.5 rounded border font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50 ${
              health?.model === 'missing'
                ? 'bg-rose-50 border-rose-200 text-rose-800'
                : 'bg-[var(--color-paper-2)] border-[var(--color-rule)] text-[var(--color-ink-2)] hover:border-[var(--color-rule-2)]'
            }`}
          >
            {health?.model === 'missing' ? 'Restore Random Forest L2' : 'Simulate ML Model Missing'}
          </button>
        </div>
      </div>

      {/* Main Dropzone Card */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileSelected(e.dataTransfer.files[0]);
          }
        }}
        className="bg-[var(--color-paper-2)] rounded border-2 border-dashed border-[var(--color-rule-2)] p-8 text-center hover:border-[var(--color-accent)] shadow-xs"
      >
        <UploadCloud className="w-10 h-10 text-[var(--color-muted)] mx-auto mb-3" />
        <p className="text-sm font-medium text-[var(--color-ink)]">
          Drag and drop a .pcap or .pcapng capture file here
        </p>
        <p className="text-xs text-[var(--color-muted)] mt-1">
          Supports full Ethernet / IP / TCP / UDP packet captures up to 100 MB
        </p>

        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          aria-label="Select PCAP file"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileSelected(e.target.files[0]);
              e.target.value = '';
            }
          }}
          className="hidden"
        />

        <div className="mt-5 flex justify-center">
          <button
            type="button"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
            className="px-5 py-2.5 bg-[var(--color-accent)] text-[var(--color-accent-ink)] text-xs font-semibold rounded hover:bg-[var(--color-accent-hi)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed shadow-xs"
          >
            {uploading ? 'Processing Capture...' : 'Browse PCAP File'}
          </button>
        </div>

        {uploadError && (
          <div
            role="alert"
            className="mt-4 p-3 bg-rose-50 border border-rose-200 rounded text-xs text-rose-800 inline-flex items-center gap-2"
          >
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{uploadError}</span>
          </div>
        )}
      </div>

      {/* Preset Evaluation Scenarios */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-[var(--color-ink)]">
            Preset Evaluation Scenarios
          </h2>
          <span className="text-xs text-[var(--color-muted)]">
            Download or trigger verification traces
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Scenario A Card */}
          <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 flex flex-col justify-between shadow-xs">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-[var(--color-ink)]">Scenario A</span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-sky-50 text-sky-800 border border-sky-200 font-medium">
                  Layer 1 Signature
                </span>
              </div>
              <h3 className="text-sm font-medium text-[var(--color-ink)] mb-1">
                Known L7 Exploit Payloads
              </h3>
              <p className="text-xs text-[var(--color-muted)] leading-relaxed mb-4">
                SQL Injection (UNION SELECT) and Apache Log4j JNDI RCE. Proves deterministic Suricata rule matching with exact Emerging Threats SID attribution.
              </p>
              <div className="text-[11px] text-[var(--color-muted)] mb-4">
                Payload trace: <span className="font-mono tabular-nums">12</span> flows · <span className="font-mono tabular-nums">1.9</span> KB
              </div>
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-rule)]">
              <button
                type="button"
                disabled={uploading}
                onClick={() => handleRunSample('attack_signature.pcap')}
                className="flex-1 py-1.5 px-3 bg-[var(--color-paper-3)] border border-[var(--color-rule-2)] text-[var(--color-ink)] text-xs font-medium rounded hover:bg-[var(--color-paper-3)]/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
              >
                Run Preset
              </button>
              <a
                href="/api/samples/attack_signature.pcap"
                download="attack_signature.pcap"
                className="inline-flex items-center gap-1 py-1.5 px-3 rounded border border-[var(--color-rule)] text-[var(--color-muted)] hover:text-[var(--color-ink)] text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                title="Download attack_signature.pcap"
              >
                <Download className="w-3.5 h-3.5" />
                <span>PCAP</span>
              </a>
            </div>
          </div>

          {/* Scenario B Card */}
          <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 flex flex-col justify-between shadow-xs">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-[var(--color-ink)]">Scenario B</span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-purple-50 text-purple-800 border border-purple-200 font-medium">
                  Layer 2 Random Forest
                </span>
              </div>
              <h3 className="text-sm font-medium text-[var(--color-ink)] mb-1">
                Zero-Day Volumetric Flood
              </h3>
              <p className="text-xs text-[var(--color-muted)] leading-relaxed mb-4">
                TCP SYN/PSH burst with 220µs inter-arrival times. Zero string signatures present. Proves ML flow anomaly detection with tree-path feature attribution.
              </p>
              <div className="text-[11px] text-[var(--color-muted)] mb-4">
                Payload trace: <span className="font-mono tabular-nums">64</span> flows · <span className="font-mono tabular-nums">88.2</span> KB
              </div>
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-rule)]">
              <button
                type="button"
                disabled={uploading}
                onClick={() => handleRunSample('suspicious_unmatched_ml.pcap')}
                className="flex-1 py-1.5 px-3 bg-[var(--color-paper-3)] border border-[var(--color-rule-2)] text-[var(--color-ink)] text-xs font-medium rounded hover:bg-[var(--color-paper-3)]/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
              >
                Run Preset
              </button>
              <a
                href="/api/samples/suspicious_unmatched_ml.pcap"
                download="suspicious_unmatched_ml.pcap"
                className="inline-flex items-center gap-1 py-1.5 px-3 rounded border border-[var(--color-rule)] text-[var(--color-muted)] hover:text-[var(--color-ink)] text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                title="Download suspicious_unmatched_ml.pcap"
              >
                <Download className="w-3.5 h-3.5" />
                <span>PCAP</span>
              </a>
            </div>
          </div>

          {/* Scenario C Card */}
          <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 flex flex-col justify-between shadow-xs">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-[var(--color-ink)]">Scenario C</span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-medium">
                  Benign Baseline
                </span>
              </div>
              <h3 className="text-sm font-medium text-[var(--color-ink)] mb-1">
                Legitimate Web Traffic
              </h3>
              <p className="text-xs text-[var(--color-muted)] leading-relaxed mb-4">
                Standard HTTP GET requests, product catalog queries, and normal TLS handshakes. Demonstrates 0 false alarms with 100% allowed throughput.
              </p>
              <div className="text-[11px] text-[var(--color-muted)] mb-4">
                Payload trace: <span className="font-mono tabular-nums">10</span> flows · <span className="font-mono tabular-nums">992</span> B
              </div>
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-rule)]">
              <button
                type="button"
                disabled={uploading}
                onClick={() => handleRunSample('benign_traffic.pcap')}
                className="flex-1 py-1.5 px-3 bg-[var(--color-paper-3)] border border-[var(--color-rule-2)] text-[var(--color-ink)] text-xs font-medium rounded hover:bg-[var(--color-paper-3)]/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
              >
                Run Preset
              </button>
              <a
                href="/api/samples/benign_traffic.pcap"
                download="benign_traffic.pcap"
                className="inline-flex items-center gap-1 py-1.5 px-3 rounded border border-[var(--color-rule)] text-[var(--color-muted)] hover:text-[var(--color-ink)] text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                title="Download benign_traffic.pcap"
              >
                <Download className="w-3.5 h-3.5" />
                <span>PCAP</span>
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Active Job Inspection Card */}
      {activeJob && (
        <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-5 space-y-4 shadow-xs">
          {/* Degraded Engine Banners */}
          {activeJob.engine_status.suricata === 'unavailable' && (
            <div
              role="alert"
              className="p-3 bg-rose-50 border border-rose-200 rounded text-xs text-rose-800 flex items-center gap-2"
            >
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>Signature engine offline. Flows were evaluated solely via Layer 2 ML anomaly classifier.</span>
            </div>
          )}

          {activeJob.engine_status.model === 'missing' && (
            <div
              role="alert"
              className="p-3 bg-rose-50 border border-rose-200 rounded text-xs text-rose-800 flex items-center gap-2"
            >
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>Random Forest model offline. Unmatched signature traffic was not classified.</span>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">{activeJob.filename}</h2>
                <span
                  className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                    activeJob.status === 'completed'
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      : activeJob.status === 'failed'
                        ? 'bg-rose-50 text-rose-800 border border-rose-200'
                        : 'bg-sky-50 text-sky-800 border border-sky-200'
                  }`}
                >
                  {activeJob.status}
                </span>
              </div>
              <div className="text-xs text-[var(--color-muted)] font-mono mt-0.5 tabular-nums">
                {activeJob.id} · {activeJob.created_at}
              </div>
            </div>

            {activeJob.status === 'completed' && (
              <div className="flex items-center gap-2">
                <Link
                  to={`/alerts?job_id=${encodeURIComponent(activeJob.id)}`}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[var(--color-accent)] text-[var(--color-accent-ink)] text-xs font-semibold rounded hover:bg-[var(--color-accent-hi)] shadow-xs"
                >
                  <span>View alerts</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <a
                  href={getExportUrl(activeJob.id, 'csv')}
                  download
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink)] text-xs font-medium rounded hover:bg-[var(--color-paper-3)]/80"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>CSV</span>
                </a>
                <a
                  href={getExportUrl(activeJob.id, 'json')}
                  download
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink)] text-xs font-medium rounded hover:bg-[var(--color-paper-3)]/80"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>JSON</span>
                </a>
              </div>
            )}
          </div>

          {/* Progress Bar */}
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-[var(--color-muted)]">
              <span>Pipeline progress</span>
              <span className="font-mono tabular-nums">{activeJob.progress}%</span>
            </div>
            <div className="h-1.5 w-full bg-[var(--color-paper-3)] rounded overflow-hidden">
              <div
                className="h-full bg-[var(--color-accent)] origin-left"
                style={{ transform: `scaleX(${activeJob.progress / 100})` }}
              />
            </div>
          </div>

          {activeJob.status === 'failed' && activeJob.error && (
            <div role="alert" className="p-3 bg-rose-50 border border-rose-200 rounded text-xs text-rose-800">
              {activeJob.error}
            </div>
          )}

          {/* Counts & Throughput */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-3 border-t border-[var(--color-rule)] text-xs">
            <div>
              <span className="text-[var(--color-muted)]">Total flows</span>
              <div className="font-mono font-semibold text-[var(--color-ink)] text-sm mt-0.5 tabular-nums">
                {activeJob.total_flows}
              </div>
            </div>
            <div>
              <span className="text-[var(--color-muted)]">Total alerts</span>
              <div className="font-mono font-semibold text-[var(--color-ink)] text-sm mt-0.5 tabular-nums">
                {activeJob.total_alerts}
              </div>
            </div>
            <div>
              <span className="text-[var(--color-muted)]">Signature alerts</span>
              <div className="font-mono font-semibold text-sky-700 text-sm mt-0.5 tabular-nums">
                {activeJob.signature_alerts}
              </div>
            </div>
            <div>
              <span className="text-[var(--color-muted)]">ML anomaly alerts</span>
              <div className="font-mono font-semibold text-purple-700 text-sm mt-0.5 tabular-nums">
                {activeJob.ml_alerts}
              </div>
            </div>
            <div>
              <span className="text-[var(--color-muted)]">Pipeline throughput</span>
              <div className="text-[var(--color-ink-2)] text-sm mt-0.5">
                <span className="font-mono font-semibold tabular-nums">{activeJob.processing_time_ms ?? 0}</span> ms,{' '}
                <span className="font-mono font-semibold tabular-nums">{activeJob.flows_per_sec ?? 0}</span> fl/s
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Previous Jobs Table */}
      <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] overflow-hidden shadow-xs">
        <div className="px-5 py-3.5 border-b border-[var(--color-rule)] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-[var(--color-ink)]">Execution History</h2>
          <span className="text-xs text-[var(--color-muted)]">Suricata L1 + Random Forest L2</span>
        </div>

        {loadingJobs ? (
          <div className="p-8 flex justify-center">
            <Loader2 className="w-5 h-5 text-[var(--color-accent)] animate-spin motion-reduce:animate-none" />
          </div>
        ) : jobs.length === 0 ? (
          <div className="p-8 text-center text-xs text-[var(--color-muted)]">No jobs recorded yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--color-paper-3)]/60 text-[var(--color-muted)] border-b border-[var(--color-rule)]">
                <tr>
                  <th className="px-5 py-2.5 font-medium">Trace filename</th>
                  <th className="px-5 py-2.5 font-medium">Status</th>
                  <th className="px-5 py-2.5 font-medium text-right">Size</th>
                  <th className="px-5 py-2.5 font-medium text-right">Flows</th>
                  <th className="px-5 py-2.5 font-medium text-right">Alerts</th>
                  <th className="px-5 py-2.5 font-medium text-right">Throughput</th>
                  <th className="px-5 py-2.5 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-rule)]">
                {jobs.map((j) => (
                  <tr
                    key={j.id}
                    onClick={() => handleSelectPreviousJob(j.id)}
                    className={`hover:bg-[var(--color-paper-3)]/50 cursor-pointer ${
                      activeJob?.id === j.id ? 'bg-[var(--color-paper-3)]' : ''
                    }`}
                  >
                    <td className="px-5 py-3 font-medium text-[var(--color-ink)]">{j.filename}</td>
                    <td className="px-5 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-mono font-medium ${
                          j.status === 'completed'
                            ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                            : j.status === 'failed'
                              ? 'bg-rose-50 text-rose-800 border border-rose-200'
                              : 'bg-sky-50 text-sky-800 border border-sky-200'
                        }`}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-mono text-right text-[var(--color-muted)] tabular-nums">
                      {j.pcap_size_bytes ? `${(j.pcap_size_bytes / 1024).toFixed(1)} KB` : '—'}
                    </td>
                    <td className="px-5 py-3 font-mono text-right text-[var(--color-ink-2)] tabular-nums">
                      {j.total_flows}
                    </td>
                    <td className="px-5 py-3 font-mono text-right font-semibold text-[var(--color-ink)] tabular-nums">
                      {j.total_alerts}
                    </td>
                    <td className="px-5 py-3 font-mono text-right text-[var(--color-muted)] tabular-nums">
                      {j.flows_per_sec ? `${j.flows_per_sec} fl/s (${j.processing_time_ms} ms)` : '—'}
                    </td>
                    <td className="px-5 py-3 font-mono text-[var(--color-muted)] tabular-nums">{j.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
