import type {
  Alert,
  AlertsPaginatedResponse,
  AnalystStatus,
  EngineHealthStatus,
  EvaluationResponse,
  IpsQueryLogEntry,
  IpsStatusResponse,
  JobDetail,
  JobListItem,
  LiveCaptureMode,
  LiveCaptureStatus,
  SystemConfigResponse,
  SummaryResponse,
} from './types';

const ADMIN_API_KEY =
  (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_ADMIN_API_KEY) || 'hybrid-ids-admin-secret';

const ADMIN_HEADERS = {
  'Content-Type': 'application/json',
  'X-API-Key': ADMIN_API_KEY,
};

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // ignore non-json error body
    }
    const err = new Error(detail) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

export async function fetchHealth(): Promise<EngineHealthStatus> {
  const res = await fetch('/api/health');
  return handleResponse<EngineHealthStatus>(res);
}

export async function fetchSystemConfig(): Promise<SystemConfigResponse> {
  const res = await fetch('/api/config');
  return handleResponse<SystemConfigResponse>(res);
}

export async function updateEngineSimulation(config: {
  suricata_unavailable?: boolean;
  model_missing?: boolean;
}): Promise<EngineHealthStatus> {
  const res = await fetch('/api/engine-config', {
    method: 'POST',
    headers: ADMIN_HEADERS,
    body: JSON.stringify(config),
  });
  return handleResponse<EngineHealthStatus>(res);
}

export async function uploadPcapJob(file: File): Promise<{ job_id: string }> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch('/api/jobs', {
    method: 'POST',
    body: form,
  });
  return handleResponse<{ job_id: string }>(res);
}

export async function runSamplePcapJob(sampleName: string): Promise<{ job_id: string }> {
  const res = await fetch('/api/jobs/sample', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample_name: sampleName }),
  });
  return handleResponse<{ job_id: string }>(res);
}

export async function fetchJobs(): Promise<JobListItem[]> {
  const res = await fetch('/api/jobs');
  return handleResponse<JobListItem[]>(res);
}

export async function fetchJobDetail(id: string): Promise<JobDetail> {
  const res = await fetch(`/api/jobs/${encodeURIComponent(id)}`);
  return handleResponse<JobDetail>(res);
}

export async function fetchSummary(jobId?: string): Promise<SummaryResponse> {
  const qs = jobId ? `?job_id=${encodeURIComponent(jobId)}` : '';
  const res = await fetch(`/api/summary${qs}`);
  return handleResponse<SummaryResponse>(res);
}

export async function fetchAlerts(params: {
  job_id?: string;
  category?: string;
  method?: string;
  search?: string;
  page?: number;
  page_size?: number;
}): Promise<AlertsPaginatedResponse> {
  const sp = new URLSearchParams();
  if (params.job_id) sp.set('job_id', params.job_id);
  if (params.category) sp.set('category', params.category);
  if (params.method) sp.set('method', params.method);
  if (params.search) sp.set('search', params.search);
  sp.set('page', String(params.page ?? 1));
  sp.set('page_size', String(params.page_size ?? 20));

  const res = await fetch(`/api/alerts?${sp.toString()}`);
  return handleResponse<AlertsPaginatedResponse>(res);
}

export async function fetchAlertDetail(id: string): Promise<Alert> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}`);
  return handleResponse<Alert>(res);
}

export async function updateAlertTriage(
  id: string,
  payload: { analyst_status: AnalystStatus; analyst_notes?: string },
): Promise<Alert> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}/triage`, {
    method: 'PATCH',
    headers: ADMIN_HEADERS,
    body: JSON.stringify(payload),
  });
  return handleResponse<Alert>(res);
}

export async function fetchEvaluation(): Promise<EvaluationResponse> {
  const res = await fetch('/api/evaluation');
  return handleResponse<EvaluationResponse>(res);
}

export function getExportUrl(jobId: string, format: 'csv' | 'json'): string {
  return `/api/jobs/${encodeURIComponent(jobId)}/export?format=${format}`;
}

export async function fetchLiveStatus(): Promise<LiveCaptureStatus> {
  const res = await fetch('/api/live/status');
  return handleResponse<LiveCaptureStatus>(res);
}

export async function configureLiveCapture(params: {
  active?: boolean;
  mode?: LiveCaptureMode;
}): Promise<LiveCaptureStatus> {
  const res = await fetch('/api/live/toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return handleResponse<LiveCaptureStatus>(res);
}

export async function triggerLiveCaptureTick(modeOverride?: LiveCaptureMode): Promise<LiveCaptureStatus> {
  const res = await fetch('/api/live/tick', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(modeOverride ? { mode: modeOverride } : {}),
  });
  return handleResponse<LiveCaptureStatus>(res);
}

export async function fetchIpsStatus(): Promise<IpsStatusResponse> {
  const res = await fetch('/api/ips/status');
  return handleResponse<IpsStatusResponse>(res);
}

export async function toggleIpsBlockMode(params: {
  block_mode_enabled?: boolean;
  block_ip?: string;
  unblock_ip?: string;
  clear_logs?: boolean;
}): Promise<IpsStatusResponse> {
  const res = await fetch('/api/ips/toggle', {
    method: 'POST',
    headers: ADMIN_HEADERS,
    body: JSON.stringify(params),
  });
  return handleResponse<IpsStatusResponse>(res);
}

export async function runIpsBatchSuite(): Promise<{
  status: IpsStatusResponse;
  batch_results: IpsQueryLogEntry[];
}> {
  const res = await fetch('/api/ips/run-suite', {
    method: 'POST',
  });
  return handleResponse<{
    status: IpsStatusResponse;
    batch_results: IpsQueryLogEntry[];
  }>(res);
}

