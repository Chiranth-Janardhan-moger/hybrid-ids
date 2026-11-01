import React, { useEffect, useState, useCallback } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts';
import { Loader2, Sliders, ShieldCheck, Cpu, ArrowUpRight, CheckCircle2 } from 'lucide-react';
import { fetchEvaluation, fetchSystemConfig } from '../api';
import type { EvaluationResponse, SystemConfigResponse } from '../types';

export function EvaluationPage() {
  const [data, setData] = useState<EvaluationResponse | null>(null);
  const [sysConfig, setSysConfig] = useState<SystemConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Tab State: 'hybrid' (Core Proof) | 'simulator' (Threshold & Base-Rate) | 'benchmark' (Models & Evasion)
  const [activeTab, setActiveTab] = useState<'hybrid' | 'simulator' | 'benchmark'>('hybrid');

  // Interactive "What-If" Simulator State
  const [simThreshold, setSimThreshold] = useState<number>(0.64);
  const [simPrevalencePct, setSimPrevalencePct] = useState<number>(1.0);

  const loadEval = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotFound(false);
    try {
      const [res, cfg] = await Promise.all([fetchEvaluation(), fetchSystemConfig().catch(() => null)]);
      setData(res);
      if (res.selected_threshold) {
        setSimThreshold(res.selected_threshold);
      }
      if (cfg) setSysConfig(cfg);
    } catch (err) {
      const status = (err as Error & { status?: number }).status;
      if (status === 404) {
        setNotFound(true);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to load evaluation data');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEval();
  }, [loadEval]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-[var(--color-accent)] animate-spin motion-reduce:animate-none" />
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] p-10 text-center">
        <p className="text-sm font-medium text-[var(--color-ink)]">No evaluation found. Run the training script first.</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-[var(--color-paper-2)] rounded border border-[var(--color-rule)] p-6">
        <p className="text-sm text-rose-400">{error || 'Evaluation unavailable'}</p>
        <button
          type="button"
          onClick={loadEval}
          className="mt-3 px-4 py-2 bg-[var(--color-accent)] text-[var(--color-accent-ink)] text-xs font-semibold rounded hover:bg-[var(--color-accent-hi)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] active:translate-y-0.5 disabled:opacity-50"
        >
          Retry
        </button>
      </div>
    );
  }

  const ci = data.metrics.confidence_intervals_95;
  const falseAlarmsPer1k =
    data.metrics.false_alarms_per_1k_benign ?? Number((data.metrics.false_positive_rate * 1000).toFixed(2));

  const metricCards = [
    {
      label: 'Precision',
      value: (data.metrics.precision * 100).toFixed(1) + '%',
      sub: ci ? `95% CI [${(ci.precision[0] * 100).toFixed(0)}%, ${(ci.precision[1] * 100).toFixed(0)}%]` : undefined,
    },
    {
      label: 'Recall (TPR)',
      value: (data.metrics.recall * 100).toFixed(1) + '%',
      sub: ci ? `95% CI [${(ci.recall[0] * 100).toFixed(0)}%, ${(ci.recall[1] * 100).toFixed(0)}%]` : undefined,
    },
    {
      label: 'F1 Score',
      value: data.metrics.f1.toFixed(4),
      sub: `τ* = ${(data.selected_threshold ?? 0.64).toFixed(2)} (Val)`,
    },
    {
      label: 'ROC-AUC',
      value: data.metrics.roc_auc.toFixed(4),
      sub: 'Rank metric',
    },
    {
      label: 'False Positive Rate',
      value: (data.metrics.false_positive_rate * 100).toFixed(2) + '%',
      sub: ci ? `95% CI [${(ci.fpr[0] * 100).toFixed(1)}%, ${(ci.fpr[1] * 100).toFixed(1)}%]` : undefined,
    },
    {
      label: 'FP / 1k Benign',
      value: `${falseAlarmsPer1k.toFixed(1)}`,
      sub: '21 / 720 flows',
    },
  ];

  const [[tn, fp], [fn, tp]] = data.confusion_matrix;

  // Lookup exact held-out test point from test_threshold_curve for the Interactive Simulator
  const simPoint =
    data.test_threshold_curve?.find((pt) => Math.abs(pt.threshold - simThreshold) < 0.005) || {
      threshold: simThreshold,
      tp,
      fp,
      tn,
      fn,
      precision: data.metrics.precision,
      recall: data.metrics.recall,
      f1: data.metrics.f1,
      fpr: data.metrics.false_positive_rate,
    };

  const pi = simPrevalencePct / 100.0;
  const simBayesNumerator = simPoint.recall * pi;
  const simBayesDenom = simBayesNumerator + simPoint.fpr * (1.0 - pi);
  const simBayesPpv = simBayesDenom > 0 ? simBayesNumerator / simBayesDenom : 0;
  const simTpPer1k = simPoint.recall * pi * 1000.0;
  const simFpPer1k = simPoint.fpr * (1.0 - pi) * 1000.0;

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-[var(--color-ink)]">Model Evaluation &amp; Benchmarks</h1>
          <p className="text-xs text-[var(--color-muted)] mt-1">
            Empirical validation on held-out Friday traffic (CICIDS2017) comparing Suricata L1 and Random Forest L2.
          </p>
        </div>
        <div className="text-xs text-[var(--color-muted)]">
          Dataset: <span className="text-[var(--color-ink)] font-medium">CICIDS2017 Temporal Split</span>
        </div>
      </div>

      {/* Presentation Headline Card */}
      <div className="rounded border border-[var(--color-rule-2)] bg-[var(--color-paper-2)] p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="text-xs text-[var(--color-accent)] font-medium">
            Production Model Finding
          </div>
          <p className="text-sm text-[var(--color-ink)] leading-snug">
            Balanced Random Forest (<span className="font-mono tabular-nums">25</span> trees) achieves{' '}
            <strong className="text-[var(--color-ink)] font-semibold">94.6% Precision</strong> and{' '}
            <strong className="text-[var(--color-ink)] font-semibold">87.6% Recall</strong> on unseen Friday DDoS traffic while cutting false alarms by{' '}
            <strong className="text-[var(--color-accent)] font-semibold">2.4x</strong> vs standard decision trees.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs px-2.5 py-1 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink-2)]">
            τ* = <span className="font-mono tabular-nums">{(data.selected_threshold ?? 0.64).toFixed(2)}</span>
          </span>
          <span className="text-xs px-2.5 py-1 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)] text-[var(--color-ink-2)]">
            ROC-AUC = <span className="font-mono tabular-nums">{data.metrics.roc_auc.toFixed(4)}</span>
          </span>
        </div>
      </div>

      {/* 6 Top Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {metricCards.map((m) => (
          <div key={m.label} className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-3.5">
            <div className="text-xs text-[var(--color-muted)]">{m.label}</div>
            <div className="mt-1 text-lg font-bold font-mono text-[var(--color-ink)] tabular-nums">{m.value}</div>
            {m.sub && <div className="mt-0.5 text-[11px] text-[var(--color-muted)]">{m.sub}</div>}
          </div>
        ))}
      </div>

      {/* Segmented Presentation Tabs */}
      <div className="flex border-b border-[var(--color-rule)] gap-2 overflow-x-auto">
        <button
          type="button"
          onClick={() => setActiveTab('hybrid')}
          className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
            activeTab === 'hybrid'
              ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
              : 'border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]'
          }`}
        >
          1. Hybrid Defense Proof
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('simulator')}
          className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
            activeTab === 'simulator'
              ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
              : 'border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]'
          }`}
        >
          2. Threshold Simulator
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('benchmark')}
          className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
            activeTab === 'benchmark'
              ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
              : 'border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]'
          }`}
        >
          3. Model Benchmark
        </button>
      </div>

      {/* TAB 1: HYBRID DEFENSE PROOF */}
      {activeTab === 'hybrid' && (
        <div className="space-y-6">
          {/* Hybrid Ablation + Confusion Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Hybrid Ablation Card */}
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-sm font-semibold text-[var(--color-ink)]">Hybrid Defense Ablation (124-Flow PCAP)</h2>
                  <span className="text-xs text-[var(--color-muted)]">64 Attack, 60 Benign</span>
                </div>
                <p className="text-xs text-[var(--color-muted)] leading-relaxed mb-3">
                  Demonstrates why defense-in-depth is mandatory: Signatures alone miss zero-day volumetric floods (56.3% recall), while ML alone misses low-rate L7 exploits (40.6% recall). Combined, hybrid achieves 96.9% recall.
                </p>

                {data.hybrid_comparison && data.hybrid_comparison.length > 0 && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left border-collapse">
                      <thead>
                        <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                          <th className="py-2 font-medium">Architecture</th>
                          <th className="py-2 font-medium text-right">Precision</th>
                          <th className="py-2 font-medium text-right">Recall (95% CI)</th>
                          <th className="py-2 font-medium text-right">F1 Score</th>
                          <th className="py-2 font-medium text-right">FP / 60</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--color-rule)]">
                        {data.hybrid_comparison.map((item) => (
                          <tr
                            key={item.mode}
                            className={item.mode === 'hybrid' ? 'bg-[var(--color-paper-3)] font-semibold text-[var(--color-ink)]' : 'text-[var(--color-ink-2)]'}
                          >
                            <td className="py-2 capitalize">{item.mode.replace('_', ' ')}</td>
                            <td className="py-2 text-right font-mono tabular-nums">{item.precision.toFixed(4)}</td>
                            <td className="py-2 text-right font-mono tabular-nums">
                              {item.recall.toFixed(4)}
                              {item.recall_ci95 && (
                                <span className="text-[11px] text-[var(--color-muted)] ml-1">
                                  [{item.recall_ci95[0].toFixed(2)}-{item.recall_ci95[1].toFixed(2)}]
                                </span>
                              )}
                            </td>
                            <td className="py-2 text-right font-mono tabular-nums">{item.f1.toFixed(4)}</td>
                            <td className="py-2 text-right font-mono tabular-nums">
                              {item.fp ?? Math.round(item.false_positive_rate * 60)} ({item.false_positive_rate.toFixed(3)})
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Chart */}
              <div className="h-40 pt-2 border-t border-[var(--color-rule)]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.hybrid_comparison}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-rule)" />
                    <XAxis dataKey="mode" tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
                    <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: 'var(--color-muted)' }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'var(--color-paper-2)',
                        borderColor: 'var(--color-rule)',
                        color: 'var(--color-ink)',
                        fontSize: '12px',
                        borderRadius: '4px',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar dataKey="precision" fill="#38bdf8" name="Precision" />
                    <Bar dataKey="recall" fill="#c084fc" name="Recall" />
                    <Bar dataKey="f1" fill="#4ade80" name="F1 Score" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Confusion Matrix Card */}
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-sm font-semibold text-[var(--color-ink)]">Confusion Matrix (Friday Test, N=1,140)</h2>
                  <span className="text-xs text-[var(--color-muted)]">
                    Decision threshold τ* = {(data.selected_threshold ?? 0.64).toFixed(2)}
                  </span>
                </div>
                <p className="text-xs text-[var(--color-muted)] leading-relaxed mb-4">
                  Classification of 1,140 unseen Friday flows. 699 of 720 benign flows correctly admitted (97.1% specificity). 368 of 420 attacks intercepted.
                </p>

                <div className="grid grid-cols-3 gap-2.5 text-xs text-center items-center">
                  <div />
                  <div className="font-medium text-[var(--color-muted)] py-1">Predicted Benign</div>
                  <div className="font-medium text-[var(--color-muted)] py-1">Predicted Attack</div>

                  <div className="font-medium text-[var(--color-muted)] text-left">Actual Benign (720)</div>
                  <div className="p-3.5 rounded bg-emerald-50 border border-emerald-200">
                    <div className="text-[11px] text-emerald-800 font-medium">True Negative (TN)</div>
                    <div className="text-xl font-bold font-mono text-emerald-950 mt-0.5 tabular-nums">{tn}</div>
                    <div className="text-[10px] text-[var(--color-muted)] mt-0.5">Admitted safe</div>
                  </div>
                  <div className="p-3.5 rounded bg-amber-50 border border-amber-200">
                    <div className="text-[11px] text-amber-800 font-medium">False Positive (FP)</div>
                    <div className="text-xl font-bold font-mono text-amber-950 mt-0.5 tabular-nums">{fp}</div>
                    <div className="text-[10px] text-[var(--color-muted)] mt-0.5">False alarms (2.9%)</div>
                  </div>

                  <div className="font-medium text-[var(--color-muted)] text-left">Actual Malicious (420)</div>
                  <div className="p-3.5 rounded bg-rose-50 border border-rose-200">
                    <div className="text-[11px] text-rose-800 font-medium">False Negative (FN)</div>
                    <div className="text-xl font-bold font-mono text-rose-950 mt-0.5 tabular-nums">{fn}</div>
                    <div className="text-[10px] text-[var(--color-muted)] mt-0.5">Missed (low-rate)</div>
                  </div>
                  <div className="p-3.5 rounded bg-sky-50 border border-sky-200">
                    <div className="text-[11px] text-sky-800 font-medium">True Positive (TP)</div>
                    <div className="text-xl font-bold font-mono text-sky-950 mt-0.5 tabular-nums">{tp}</div>
                    <div className="text-[10px] text-[var(--color-muted)] mt-0.5">Intercepted (87.6%)</div>
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-[var(--color-rule)] text-xs text-[var(--color-muted)] flex justify-between">
                <span>Accuracy: <strong className="text-[var(--color-ink)] font-mono tabular-nums">{(((tn + tp) / 1140) * 100).toFixed(1)}%</strong></span>
                <span>FPR on Benign: <strong className="text-[var(--color-ink)] font-mono tabular-nums">{((fp / 720) * 100).toFixed(2)}%</strong></span>
                <span>Recall on Attacks: <strong className="text-[var(--color-ink)] font-mono tabular-nums">{((tp / 420) * 100).toFixed(1)}%</strong></span>
              </div>
            </div>
          </div>

          {/* Per-Class Recall Table */}
          {data.per_class_recall && data.per_class_recall.length > 0 && (
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">Per-Attack-Class Detection Breakdown</h2>
                <span className="text-xs text-[var(--color-muted)]">Suricata Signature vs. Random Forest ML</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                      <th className="py-2 font-medium">Attack Class</th>
                      <th className="py-2 font-medium text-right">Flow Count</th>
                      <th className="py-2 font-medium text-right">Signature Only</th>
                      <th className="py-2 font-medium text-right">ML Only</th>
                      <th className="py-2 font-medium text-right text-[var(--color-accent)]">Hybrid Combined (95% CI)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-rule)]">
                    {data.per_class_recall.map((row) => (
                      <tr key={row.attack_class} className="hover:bg-[var(--color-paper-3)]/30 text-[var(--color-ink-2)]">
                        <td className="py-2.5 font-medium text-[var(--color-ink)]">{row.attack_class}</td>
                        <td className="py-2.5 text-right font-mono tabular-nums text-[var(--color-muted)]">{row.flows}</td>
                        <td className="py-2.5 text-right font-mono tabular-nums">
                          {(row.signature_only_recall * 100).toFixed(1)}%
                        </td>
                        <td className="py-2.5 text-right font-mono tabular-nums">
                          {(row.ml_only_recall * 100).toFixed(1)}%
                        </td>
                        <td className="py-2.5 text-right font-bold text-[var(--color-accent)]">
                          <span className="font-mono tabular-nums">{(row.hybrid_recall * 100).toFixed(1)}%</span>{' '}
                          {row.hybrid_ci95 && (
                            <span className="text-[11px] text-[var(--color-muted)] font-normal ml-1">
                              [<span className="font-mono tabular-nums">{(row.hybrid_ci95[0] * 100).toFixed(0)}</span>-
                              <span className="font-mono tabular-nums">{(row.hybrid_ci95[1] * 100).toFixed(0)}%</span>]
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
      )}

      {/* TAB 2: THRESHOLD & BASE-RATE SIMULATOR */}
      {activeTab === 'simulator' && (
        <div className="space-y-6">
          <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-[var(--color-accent)]" />
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">
                  Interactive Threshold (τ) &amp; Base-Rate (π) Simulator
                </h2>
              </div>
              <span className="text-xs text-[var(--color-muted)]">Held-Out Friday Test (1,140 Flows)</span>
            </div>

            <p className="text-xs text-[var(--color-muted)] leading-relaxed">
              In real-world networks, attack traffic is sparse (&pi; &approx; 0.1% to 1.0%). Even with 97% specificity (2.9% FPR), the Base-Rate Fallacy means false alarms outnumber true attacks if alerts are blocked raw. Adjust the sliders to see Bayesian Positive Predictive Value (PPV) live.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
              {/* Tau Slider */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <label htmlFor="sim-tau-slider" className="font-medium text-[var(--color-ink)]">
                    Decision Threshold (τ)
                  </label>
                  <span className="font-mono font-bold text-[var(--color-accent)] tabular-nums">
                    τ = {simThreshold.toFixed(2)}{' '}
                    {Math.abs(simThreshold - (data.selected_threshold ?? 0.64)) < 0.005 ? '(τ* locked)' : ''}
                  </span>
                </div>
                <input
                  id="sim-tau-slider"
                  type="range"
                  min={0.5}
                  max={0.9}
                  step={0.02}
                  value={simThreshold}
                  onChange={(e) => setSimThreshold(parseFloat(e.target.value))}
                  className="w-full accent-[var(--color-accent)]"
                />
                <div className="flex justify-between text-[11px] text-[var(--color-muted)]">
                  <span>0.50 (Max Recall)</span>
                  <span>0.64 (Operating τ*)</span>
                  <span>0.90 (Low False Alarms)</span>
                </div>
              </div>

              {/* Pi Slider */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <label htmlFor="sim-pi-slider" className="font-medium text-[var(--color-ink)]">
                    Attack Prevalence / Base-Rate (π)
                  </label>
                  <span className="font-mono font-bold text-purple-700 tabular-nums">
                    π = {simPrevalencePct.toFixed(1)}%
                  </span>
                </div>
                <input
                  id="sim-pi-slider"
                  type="range"
                  min={0.1}
                  max={36.8}
                  step={0.1}
                  value={simPrevalencePct}
                  onChange={(e) => setSimPrevalencePct(parseFloat(e.target.value))}
                  className="w-full accent-purple-600"
                />
                <div className="flex justify-between text-xs text-[var(--color-muted)]">
                  <button
                    type="button"
                    onClick={() => setSimPrevalencePct(0.1)}
                    className="hover:text-[var(--color-accent)] underline focus-visible:outline-none"
                  >
                    0.1% LAN
                  </button>
                  <button
                    type="button"
                    onClick={() => setSimPrevalencePct(1.0)}
                    className="hover:text-[var(--color-accent)] underline focus-visible:outline-none"
                  >
                    1.0% Subnet
                  </button>
                  <button
                    type="button"
                    onClick={() => setSimPrevalencePct(5.0)}
                    className="hover:text-[var(--color-accent)] underline focus-visible:outline-none"
                  >
                    5.0% Incident
                  </button>
                  <button
                    type="button"
                    onClick={() => setSimPrevalencePct(36.8)}
                    className="hover:text-[var(--color-accent)] underline focus-visible:outline-none"
                  >
                    36.8% Test Split
                  </button>
                </div>
              </div>
            </div>

            {/* Simulator Output Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-3 border-t border-[var(--color-rule)] text-xs">
              <div className="p-3 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule-2)]">
                <div className="text-[var(--color-muted)]">Bayes Precision (PPV)</div>
                <div className="text-base font-bold font-mono text-[var(--color-accent)] mt-0.5 tabular-nums">
                  {(simBayesPpv * 100).toFixed(2)}%
                </div>
              </div>
              <div className="p-3 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)]">
                <div className="text-[var(--color-muted)]">Recall (TPR)</div>
                <div className="text-base font-bold font-mono text-[var(--color-ink)] mt-0.5 tabular-nums">
                  {(simPoint.recall * 100).toFixed(2)}%
                </div>
              </div>
              <div className="p-3 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)]">
                <div className="text-[var(--color-muted)]">FPR on Benign</div>
                <div className="text-base font-bold font-mono text-[var(--color-ink)] mt-0.5 tabular-nums">
                  {(simPoint.fpr * 100).toFixed(2)}%
                </div>
              </div>
              <div className="p-3 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)]">
                <div className="text-[var(--color-muted)]">TP / 1k Flows</div>
                <div className="text-base font-bold font-mono text-emerald-700 mt-0.5 tabular-nums">
                  {simTpPer1k.toFixed(2)}
                </div>
              </div>
              <div className="p-3 rounded bg-[var(--color-paper-3)] border border-[var(--color-rule)]">
                <div className="text-[var(--color-muted)]">FP / 1k Flows</div>
                <div className="text-base font-bold font-mono text-amber-700 mt-0.5 tabular-nums">
                  {simFpPer1k.toFixed(2)}
                </div>
              </div>
            </div>
          </div>

          {/* Prevalence Analysis & Validation Threshold Sweep Tables */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {data.prevalence_analysis && data.prevalence_analysis.length > 0 && (
              <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-[var(--color-ink)]">Real-World Deployment Prevalence Matrix</h2>
                  <span className="text-xs text-[var(--color-muted)]">FPR = {falseAlarmsPer1k} / 1k benign</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                        <th className="py-2 font-medium">Network Context (π)</th>
                        <th className="py-2 font-medium text-right">Bayes PPV</th>
                        <th className="py-2 font-medium text-right">TP / 1k</th>
                        <th className="py-2 font-medium text-right">FP / 1k</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--color-rule)]">
                      {data.prevalence_analysis.map((row) => (
                        <tr
                          key={row.scenario}
                          className={row.prevalence_pct === 1.0 ? 'bg-[var(--color-paper-3)] font-semibold text-[var(--color-ink)]' : 'text-[var(--color-ink-2)]'}
                        >
                          <td className="py-2">{row.scenario}</td>
                          <td className="py-2 text-right font-mono tabular-nums">{(row.expected_precision * 100).toFixed(2)}%</td>
                          <td className="py-2 text-right font-mono tabular-nums">{row.expected_tp_per_1k_flows.toFixed(2)}</td>
                          <td className="py-2 text-right font-mono tabular-nums">{row.expected_fp_per_1k_flows.toFixed(2)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {data.validation_threshold_curve && data.validation_threshold_curve.length > 0 && (
              <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-[var(--color-ink)]">Validation Threshold Sweep (Mon+Wed)</h2>
                  <span className="text-xs text-[var(--color-muted)]">Locked at τ* = 0.64 (FPR ≤ 1.5%)</span>
                </div>
                <div className="overflow-x-auto max-h-56">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                        <th className="py-2 font-medium">Threshold (τ)</th>
                        <th className="py-2 font-medium text-right">Val Precision</th>
                        <th className="py-2 font-medium text-right">Val Recall</th>
                        <th className="py-2 font-medium text-right">Val F0.5</th>
                        <th className="py-2 font-medium text-right">Val FPR</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--color-rule)]">
                      {data.validation_threshold_curve.map((pt) => {
                        const isSelected = Math.abs(pt.threshold - (data.selected_threshold ?? 0.64)) < 0.005;
                        return (
                          <tr
                            key={pt.threshold}
                            className={isSelected ? 'bg-[var(--color-paper-3)] font-bold text-[var(--color-accent)]' : 'text-[var(--color-ink-2)]'}
                          >
                            <td className="py-2 font-mono tabular-nums">
                              {pt.threshold.toFixed(2)} {isSelected ? '← τ*' : ''}
                            </td>
                            <td className="py-2 text-right font-mono tabular-nums">{pt.val_precision.toFixed(4)}</td>
                            <td className="py-2 text-right font-mono tabular-nums">{pt.val_recall.toFixed(4)}</td>
                            <td className="py-2 text-right font-mono tabular-nums">{pt.val_f05.toFixed(4)}</td>
                            <td className="py-2 text-right font-mono tabular-nums">{pt.val_fpr.toFixed(4)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: MODEL BENCHMARK & EVASION TESTS */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          {/* Classifier Benchmark */}
          {data.model_baselines && data.model_baselines.length > 0 && (
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">Multi-Model Classifier Benchmark (Friday DDoS, N=1,140)</h2>
                <span className="text-xs text-[var(--color-accent)] font-medium">Balanced RF cuts FPR by &gt; 2.4x</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                      <th className="py-2 font-medium">Classifier Architecture</th>
                      <th className="py-2 font-medium text-right">Precision</th>
                      <th className="py-2 font-medium text-right">Recall</th>
                      <th className="py-2 font-medium text-right">F1 Score</th>
                      <th className="py-2 font-medium text-right">FPR</th>
                      <th className="py-2 font-medium text-right">ROC-AUC</th>
                      <th className="py-2 font-medium text-right">Latency / Flow</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-rule)]">
                    {data.model_baselines.map((mb, idx) => (
                      <tr
                        key={mb.model_name}
                        className={idx === 0 ? 'bg-[var(--color-paper-3)] font-semibold text-[var(--color-ink)]' : 'text-[var(--color-ink-2)]'}
                      >
                        <td className="py-2.5">
                          <div className="font-semibold text-[var(--color-ink)]">{mb.model_name}</div>
                          <div className="text-[11px] text-[var(--color-muted)]">{mb.notes}</div>
                        </td>
                        <td className="py-2.5 text-right font-mono tabular-nums">{(mb.precision * 100).toFixed(2)}%</td>
                        <td className="py-2.5 text-right font-mono tabular-nums">{(mb.recall * 100).toFixed(2)}%</td>
                        <td className="py-2.5 text-right font-mono font-bold tabular-nums">{mb.f1.toFixed(4)}</td>
                        <td className={`py-2.5 text-right font-mono tabular-nums ${mb.fpr <= 0.03 ? 'text-emerald-700 font-semibold' : 'text-amber-700'}`}>
                          {(mb.fpr * 100).toFixed(2)}%
                        </td>
                        <td className="py-2.5 text-right font-mono tabular-nums">{mb.roc_auc.toFixed(4)}</td>
                        <td className="py-2.5 text-right">
                          <span className="font-mono tabular-nums">{mb.latency_us_per_flow.toFixed(1)}</span>{' '}
                          <span className="text-[var(--color-muted)]">µs</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Adversarial Evasion Stress Test */}
          {data.adversarial_stress_test && data.adversarial_stress_test.length > 0 && (
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-[var(--color-ink)]">Adversarial Evasion Stress Testing (N=420 Attacks)</h2>
                <span className="text-xs text-[var(--color-muted)]">Byte Padding &amp; Inter-Arrival Time Delay</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[var(--color-rule)] text-[var(--color-muted)]">
                      <th className="py-2 font-medium">Perturbation Scenario</th>
                      <th className="py-2 font-medium text-right">Detected Flows</th>
                      <th className="py-2 font-medium text-right">Recall (95% CI)</th>
                      <th className="py-2 font-medium text-right">Mean Anomaly Prob (p̂)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-rule)]">
                    {data.adversarial_stress_test.map((row) => (
                      <tr key={row.scenario} className="text-[var(--color-ink-2)]">
                        <td className="py-2.5 pr-2">
                          <div className="font-medium text-[var(--color-ink)]">{row.scenario}</div>
                          <div className="text-[11px] text-[var(--color-muted)]">{row.defense_note}</div>
                        </td>
                        <td className="py-2.5 text-right font-mono tabular-nums">
                          {row.detected_flows}/{row.attack_flows}
                        </td>
                        <td className="py-2.5 text-right font-semibold text-[var(--color-accent)] whitespace-nowrap">
                          <span className="font-mono tabular-nums">{(row.ml_recall * 100).toFixed(1)}%</span>{' '}
                          <span className="font-normal text-xs text-[var(--color-muted)] ml-1">
                            [<span className="font-mono tabular-nums">{(row.recall_ci95[0] * 100).toFixed(0)}</span>-
                            <span className="font-mono tabular-nums">{(row.recall_ci95[1] * 100).toFixed(0)}%</span>]
                          </span>
                        </td>
                        <td className="py-2.5 text-right font-mono tabular-nums">{row.mean_ml_probability.toFixed(3)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Top Feature Importances & Scope & Limitations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {data.feature_importances && data.feature_importances.length > 0 && (
              <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-[var(--color-ink)]">Top Flow Feature Importances (Gini Index)</h2>
                  <span className="text-xs text-[var(--color-muted)]">25-Tree Ensemble</span>
                </div>
                <div className="space-y-2.5">
                  {data.feature_importances.slice(0, 7).map((fi) => {
                    const pct = Math.min(100, Math.round(fi.importance * 100 * 3.5));
                    return (
                      <div key={fi.feature} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-[var(--color-ink)] font-mono">{fi.feature}</span>
                          <span className="font-mono text-[var(--color-muted)] tabular-nums">
                            {(fi.importance * 100).toFixed(2)}%
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-[var(--color-paper-3)] rounded overflow-hidden">
                          <div className="h-full bg-[var(--color-accent)] rounded" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Scope & Limitations Card */}
            <div className="rounded border border-[var(--color-rule)] bg-[var(--color-paper-2)] p-4 space-y-3 text-xs">
              <h2 className="text-sm font-semibold text-[var(--color-ink)]">Production Scope &amp; Assumptions</h2>
              <ul className="space-y-2 text-[var(--color-muted)] list-disc list-inside leading-relaxed">
                <li>
                  <strong className="text-[var(--color-ink)]">Base-Rate Fallacy:</strong> 2.92% FPR yields 23.3% PPV at 1% attack prevalence; risk scoring is applied before quarantine.
                </li>
                <li>
                  <strong className="text-[var(--color-ink)]">Training &amp; Serving Schema Contract:</strong> Shared 19-feature vector with 120s/30s flow timeouts prevents data drift.
                </li>
                <li>
                  <strong className="text-[var(--color-ink)]">Encrypted Traffic Inspection:</strong> Evaluates unencrypted TLS ClientHello (JA3 + SNI) alongside statistical packet timing.
                </li>
                <li>
                  <strong className="text-[var(--color-ink)]">Slow-Rate Attack Evasion:</strong> Extreme 5x IAT throttling lowers ML recall to 65.5%; caught by Layer 1 Suricata signatures and kill-chain correlation.
                </li>
              </ul>
              <div className="pt-2 border-t border-[var(--color-rule)] text-[var(--color-muted)]">
                Evaluation conducted on held-out Friday test split (CICIDS2017).
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
