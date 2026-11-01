import React, { useState, useEffect } from 'react';
import { CheckCircle2, XCircle, ShieldAlert, Copy, Check, Lock, GitMerge } from 'lucide-react';
import { updateAlertTriage } from '../api';
import type {
  Alert,
  AnalystStatus,
  CampaignCorrelationMetadata,
  FeatureContribution,
  TlsFingerprintMetadata,
} from '../types';
import { CATEGORY_BADGE_CLASSES, METHOD_BADGE_CLASSES } from './Layout';

export function AlertDetailContent({
  alert,
  onAlertUpdated,
}: {
  alert: Alert;
  onAlertUpdated?: (updated: Alert) => void;
}) {
  const [status, setStatus] = useState<AnalystStatus>(alert.analyst_status || 'open');
  const [savingTriage, setSavingTriage] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);

  useEffect(() => {
    setStatus(alert.analyst_status || 'open');
  }, [alert.id, alert.analyst_status]);

  const { score_breakdown } = alert;
  const weights = score_breakdown?.weights || {
    severity: 0.4,
    confidence: 0.3,
    behavior: 0.2,
    context: 0.1,
  };

  const components = [
    { key: 'severity', label: 'Severity', value: score_breakdown?.severity ?? 0, weight: weights.severity },
    { key: 'confidence', label: 'Confidence', value: score_breakdown?.confidence ?? 0, weight: weights.confidence },
    { key: 'behavior', label: 'Behavior', value: score_breakdown?.behavior ?? 0, weight: weights.behavior },
    { key: 'context', label: 'Context', value: score_breakdown?.context ?? 0, weight: weights.context },
  ];

  const topFeatures: FeatureContribution[] = Array.isArray(alert.evidence?.top_contributing_features)
    ? (alert.evidence.top_contributing_features as FeatureContribution[])
    : [];

  const tlsMeta = (alert.evidence?.tls_fingerprint as TlsFingerprintMetadata | undefined) || undefined;
  const campaignMeta =
    (alert.evidence?.campaign_correlation as CampaignCorrelationMetadata | undefined) || undefined;

  const handleTriage = async (nextStatus: AnalystStatus) => {
    setSavingTriage(true);
    try {
      const updated = await updateAlertTriage(alert.id, { analyst_status: nextStatus });
      setStatus(updated.analyst_status || nextStatus);
      if (onAlertUpdated) onAlertUpdated(updated);
    } finally {
      setSavingTriage(false);
    }
  };

  const protoLower = alert.protocol.toLowerCase();
  const iptablesRule = `iptables -I INPUT -s ${alert.src_ip} -d ${alert.dst_ip} -p ${protoLower} --dport ${alert.dst_port} -j DROP`;
  const suricataDropRule = tlsMeta?.ja3_hash
    ? `drop tls ${alert.src_ip} any -> ${alert.dst_ip} ${alert.dst_port} (msg:"HYBRID-IDS Auto-Block ${alert.src_ip} JA3"; ja3.hash; content:"${tlsMeta.ja3_hash}"; sid:990001; rev:1;)`
    : `drop ${protoLower} ${alert.src_ip} any -> ${alert.dst_ip} ${alert.dst_port} (msg:"HYBRID-IDS Auto-Block ${alert.src_ip} (${alert.category})"; sid:990001; rev:1;)`;

  const handleCopyRules = () => {
    navigator.clipboard?.writeText(`${iptablesRule}\n${suricataDropRule}`);
    setCopiedRule(true);
    window.setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header: Large Risk Score & Category Badge */}
      <div className="flex items-center justify-between pb-4 border-b border-[var(--color-rule)]">
        <div>
          <div className="text-xs text-[var(--color-muted)]">Risk score</div>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-4xl font-bold tracking-tight text-[var(--color-ink)] font-mono tabular-nums">
              {alert.risk_score}
            </span>
            <span className="text-sm text-[var(--color-muted)] font-mono tabular-nums">/ 100</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`px-2.5 py-1 rounded text-xs font-mono font-medium ${
              status === 'confirmed'
                ? 'bg-rose-50 text-rose-800 border border-rose-200'
                : status === 'false_positive'
                  ? 'bg-amber-50 text-amber-800 border border-amber-200 line-through'
                  : 'bg-[var(--color-paper-3)] text-[var(--color-muted)] border border-[var(--color-rule)]'
            }`}
          >
            {status === 'confirmed'
              ? 'Confirmed Threat'
              : status === 'false_positive'
                ? 'False Positive'
                : 'Unreviewed'}
          </span>
          <span
            className={`px-3 py-1 rounded text-xs font-mono font-medium ${
              CATEGORY_BADGE_CLASSES[alert.category] || 'bg-[var(--color-paper-3)] text-[var(--color-ink)]'
            }`}
          >
            {alert.category}
          </span>
        </div>
      </div>

      {/* Analyst Incident Triage */}
      <section className="p-3.5 bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] space-y-2 shadow-xs">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-[var(--color-ink)]">Analyst Triage</h3>
          <span className="text-xs text-[var(--color-muted)]">Stateful ledger</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={savingTriage}
            onClick={() => handleTriage('confirmed')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400 active:translate-y-0.5 disabled:opacity-50 ${
              status === 'confirmed'
                ? 'bg-rose-600 text-white border-rose-600 shadow-xs'
                : 'bg-[var(--color-paper-2)] text-rose-700 border-rose-200 hover:bg-rose-50'
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-rose-500" />
            <span>Confirm Threat</span>
          </button>

          <button
            type="button"
            disabled={savingTriage}
            onClick={() => handleTriage('false_positive')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 active:translate-y-0.5 disabled:opacity-50 ${
              status === 'false_positive'
                ? 'bg-amber-600 text-white border-amber-600 shadow-xs'
                : 'bg-[var(--color-paper-2)] text-amber-800 border-amber-200 hover:bg-amber-50'
            }`}
          >
            <XCircle className="w-3.5 h-3.5 text-amber-500" />
            <span>Mark False Positive</span>
          </button>

          {status !== 'open' && (
            <button
              type="button"
              disabled={savingTriage}
              onClick={() => handleTriage('open')}
              className="px-2.5 py-1.5 rounded text-xs text-[var(--color-muted)] hover:text-[var(--color-ink)] focus-visible:outline-none active:translate-y-0.5 disabled:opacity-50"
            >
              Reset
            </button>
          )}
        </div>
        {status === 'false_positive' && (
          <p className="text-[11px] text-amber-800 font-medium">
            Queued as benign (0) for next retraining cycle.
          </p>
        )}
      </section>

      {/* Multi-Stage Kill-Chain Campaign Correlation Banner */}
      {campaignMeta?.is_multi_stage_campaign && (
        <section className="p-3.5 bg-rose-50 rounded border border-rose-200 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-800">
              <GitMerge className="w-4 h-4 text-rose-600 shrink-0" />
              <span>Kill-Chain Campaign ({campaignMeta.campaign_id})</span>
            </div>
            <span className="px-2 py-0.5 bg-rose-100 text-rose-800 border border-rose-200 rounded text-xs font-mono">
              Context {campaignMeta.context_boosted_from.toFixed(2)} &rarr; 1.00
            </span>
          </div>
          <p className="text-xs text-rose-800">
            Attacker IP <span className="font-mono font-semibold">{campaignMeta.attacker_ip}</span> ({campaignMeta.correlated_alert_count}{' '}
            correlated alerts on ports <span className="font-mono">[{campaignMeta.target_ports.join(', ')}]</span>):
          </p>
          <ul className="text-[11px] text-rose-300 list-disc list-inside space-y-0.5">
            {campaignMeta.stages_detected.map((st) => (
              <li key={st}>{st}</li>
            ))}
          </ul>
        </section>
      )}

      {/* Why this score */}
      <section className="space-y-2.5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-[var(--color-ink)]">Score Breakdown</h3>
          <span className="text-xs text-[var(--color-muted)]">4-Factor Linear Triage</span>
        </div>
        <div className="p-3.5 bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] space-y-2.5">
          {components.map((c) => {
            const pct = Math.min(100, Math.max(0, Math.round(c.value * 100)));
            return (
              <div key={c.key} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[var(--color-ink-2)]">
                    {c.label} <span className="text-[var(--color-muted)]">(w={c.weight.toFixed(2)})</span>
                  </span>
                  <span className="font-mono text-[var(--color-ink)] tabular-nums">{c.value.toFixed(2)}</span>
                </div>
                <div className="h-1.5 w-full bg-[var(--color-paper-3)] rounded overflow-hidden">
                  <div className="h-full bg-[var(--color-accent)] rounded" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}

          <div className="pt-2 border-t border-[var(--color-rule)] text-[11px] font-mono text-[var(--color-muted)]">
            score = 100 * ({weights.severity.toFixed(2)}*sev + {weights.confidence.toFixed(2)}*conf +{' '}
            {weights.behavior.toFixed(2)}*beh + {weights.context.toFixed(2)}*ctx)
          </div>
        </div>

        <p className="text-xs text-[var(--color-muted)] leading-relaxed">{alert.explanation}</p>
      </section>

      {/* Per-Alert ML Feature Attribution */}
      {topFeatures.length > 0 && (
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--color-ink)]">Feature Attribution (Tree-Path ΔP)</h3>
            <span className="text-xs text-[var(--color-muted)]">25 Trees</span>
          </div>
          <div className="p-3.5 bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] space-y-2.5">
            {typeof alert.evidence?.tree_base_probability === 'number' && (
              <div className="text-xs font-mono text-[var(--color-muted)] pb-1.5 border-b border-[var(--color-rule)]">
                base_prob = {Number(alert.evidence.tree_base_probability).toFixed(4)} + &Sigma; &Delta;P ={' '}
                {alert.ml_probability !== null ? alert.ml_probability.toFixed(4) : '&mdash;'}
              </div>
            )}
            {topFeatures.map((tf) => {
              const deltaP = tf.tree_prob_delta ?? 0;
              const sign = deltaP >= 0 ? '+' : '';
              return (
                <div key={tf.feature} className="space-y-1">
                  <div className="flex items-center justify-between text-xs gap-2">
                    <span className="font-mono text-[var(--color-ink)]">{tf.feature}</span>
                    <span className="text-[var(--color-ink-2)] text-right">
                      <span className="font-mono tabular-nums">{tf.value}</span>{' '}
                      <span className="text-[var(--color-muted)]">
                        (&mu;={tf.benign_mean}, {tf.z_score}&sigma;)
                      </span>,{' '}
                      <span className="font-semibold text-purple-400">
                        &Delta;P={sign}
                        <span className="font-mono tabular-nums">{deltaP.toFixed(4)}</span> ({tf.share_pct}%)
                      </span>
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-[var(--color-paper-3)] rounded overflow-hidden">
                    <div
                      className="h-full bg-purple-400 rounded"
                      style={{ width: `${Math.min(100, Math.max(6, tf.share_pct))}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* TLS ClientHello / JA3 Fingerprint Metadata */}
      {tlsMeta && (
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--color-ink)] flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-sky-400" />
              <span>TLS ClientHello / JA3</span>
            </h3>
            <span className="text-xs text-emerald-400">Cleartext Handshake</span>
          </div>
          <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] divide-y divide-[var(--color-rule)] text-xs">
            <div className="px-3.5 py-2 flex items-center justify-between">
              <span className="text-[var(--color-muted)]">TLS Version</span>
              <span className="font-mono text-[var(--color-ink)]">{tlsMeta.tls_version}</span>
            </div>
            <div className="px-3.5 py-2 flex items-center justify-between">
              <span className="text-[var(--color-muted)]">SNI</span>
              <span className="font-mono text-[var(--color-accent)]">{tlsMeta.sni}</span>
            </div>
            <div className="px-3.5 py-2 flex items-center justify-between gap-3">
              <span className="text-[var(--color-muted)] shrink-0">JA3 (MD5)</span>
              <span className="font-mono text-[var(--color-ink)] truncate">{tlsMeta.ja3_hash}</span>
            </div>
            <div className="px-3.5 py-2 flex items-center justify-between">
              <span className="text-[var(--color-muted)]">Ciphers</span>
              <span className="font-mono text-[var(--color-ink-2)]">{tlsMeta.cipher_count}</span>
            </div>
          </div>
        </section>
      )}

      {/* Mitigation Rule Generator */}
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-[var(--color-ink)] flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[var(--color-accent)]" />
            <span>Mitigation Rules</span>
          </h3>
          <button
            type="button"
            onClick={handleCopyRules}
            className="inline-flex items-center gap-1 px-2.5 py-1 bg-[var(--color-paper-3)] border border-[var(--color-rule)] hover:border-[var(--color-rule-2)] text-[var(--color-ink)] rounded text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
          >
            {copiedRule ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copiedRule ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
        <div className="p-3 bg-slate-950 text-slate-100 rounded text-xs space-y-2 overflow-x-auto shadow-xs border border-slate-800">
          <div>
            <div className="text-slate-400 font-mono text-xs"># iptables firewall rule</div>
            <code className="text-emerald-400 break-all font-mono block">{iptablesRule}</code>
          </div>
          <div>
            <div className="text-slate-400 font-mono text-xs"># Suricata drop rule</div>
            <code className="text-sky-300 break-all font-mono block">{suricataDropRule}</code>
          </div>
        </div>
      </section>

      {/* Detection */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-[var(--color-ink)]">Detection Attribution</h3>
        <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] divide-y divide-[var(--color-rule)] text-xs">
          <div className="px-3.5 py-2.5 flex items-center justify-between">
            <span className="text-[var(--color-muted)]">Engine</span>
            <span
              className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                METHOD_BADGE_CLASSES[alert.detection_method] || 'bg-[var(--color-paper-3)] text-[var(--color-ink)]'
              }`}
            >
              {alert.detection_method === 'signature' ? 'Signature L1' : 'Flow ML L2'}
            </span>
          </div>

          {alert.detection_method === 'signature' ? (
            <>
              <div className="px-3.5 py-2.5 flex items-center justify-between gap-4">
                <span className="text-[var(--color-muted)] shrink-0">Signature ID</span>
                <span className="font-mono text-[var(--color-ink)]">{alert.signature_id || '—'}</span>
              </div>
              <div className="px-3.5 py-2.5 flex items-center justify-between gap-4">
                <span className="text-[var(--color-muted)] shrink-0">Message</span>
                <span className="text-[var(--color-ink)] text-right font-medium">{alert.signature_msg || '—'}</span>
              </div>
              <div className="px-3.5 py-2.5 flex items-center justify-between gap-4">
                <span className="text-[var(--color-muted)] shrink-0">Rule Version</span>
                <span className="font-mono text-[var(--color-muted)]">{alert.rule_version || '—'}</span>
              </div>
            </>
          ) : (
            <>
              <div className="px-3.5 py-2.5 flex items-center justify-between gap-4">
                <span className="text-[var(--color-muted)] shrink-0">Prediction</span>
                <span className="text-[var(--color-ink)] font-medium">
                  {alert.ml_label || 'anomaly'} (p={alert.ml_probability !== null ? alert.ml_probability.toFixed(2) : '—'})
                </span>
              </div>
              <div className="px-3.5 py-2.5 flex items-center justify-between gap-4">
                <span className="text-[var(--color-muted)] shrink-0">Model Version</span>
                <span className="font-mono text-[var(--color-muted)]">{alert.model_version || '—'}</span>
              </div>
            </>
          )}
        </div>
      </section>

      {/* Flow 5-Tuple */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-[var(--color-ink)]">Flow 5-Tuple</h3>
        <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] divide-y divide-[var(--color-rule)] text-xs">
          <div className="px-3.5 py-2.5 flex items-center justify-between">
            <span className="text-[var(--color-muted)]">Source</span>
            <span className="font-mono text-[var(--color-ink)] tabular-nums">
              {alert.src_ip}:{alert.src_port}
            </span>
          </div>
          <div className="px-3.5 py-2.5 flex items-center justify-between">
            <span className="text-[var(--color-muted)]">Destination</span>
            <span className="font-mono text-[var(--color-ink)] tabular-nums">
              {alert.dst_ip}:{alert.dst_port}
            </span>
          </div>
          <div className="px-3.5 py-2.5 flex items-center justify-between">
            <span className="text-[var(--color-muted)]">Protocol</span>
            <span className="font-mono text-[var(--color-ink)]">{alert.protocol}</span>
          </div>
          <div className="px-3.5 py-2.5 flex items-center justify-between">
            <span className="text-[var(--color-muted)]">Timestamp</span>
            <span className="font-mono text-[var(--color-muted)] tabular-nums">{alert.timestamp}</span>
          </div>
        </div>
      </section>

      {/* Evidence */}
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-[var(--color-ink)]">Raw Evidence</h3>
        <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] divide-y divide-[var(--color-rule)] text-xs overflow-hidden">
          {Object.entries(alert.evidence || {}).map(([key, value]) => (
            <div key={key} className="px-3.5 py-2.5 flex flex-col gap-1">
              <span className="font-mono text-[var(--color-muted)]">{key}</span>
              {typeof value === 'object' && value !== null ? (
                <pre className="p-2 bg-[var(--color-paper-3)] rounded border border-[var(--color-rule)] text-[11px] font-mono text-[var(--color-ink)] overflow-x-auto">
                  {JSON.stringify(value, null, 2)}
                </pre>
              ) : (
                <span className="font-mono text-[var(--color-ink)] break-all">{String(value)}</span>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
