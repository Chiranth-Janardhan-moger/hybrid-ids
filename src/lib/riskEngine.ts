import type { AlertCategory, FlowFeatures, ScoreBreakdown, ScoreWeights } from '../types';
import { getSystemConfig } from './configLoader';

const SENSITIVE_PORTS = new Set([21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]);

export function computeBehaviorScore(features: Partial<FlowFeatures>): number {
  const pktRate = Number(features.flow_packets_s ?? 0);
  const byteRate = Number(features.flow_bytes_s ?? 0);
  const synCnt = Number(features.syn_flag_count ?? 0);
  const rstCnt = Number(features.rst_flag_count ?? 0);
  const pshCnt = Number(features.psh_flag_count ?? 0);
  const fwdPkts = Math.max(1, Number(features.total_fwd_packets ?? 1));
  const bwdPkts = Number(features.total_bwd_packets ?? 0);
  const pktStd = Number(features.packet_length_std ?? 0);

  const rateFactor = Math.min(1.0, pktRate / 1200.0) * 0.4 + Math.min(1.0, byteRate / 800000.0) * 0.3;
  const flagFactor = Math.min(1.0, (synCnt + rstCnt + pshCnt * 0.5) / 22.0) * 0.18;
  const asymmetryFactor = (1.0 - Math.min(1.0, bwdPkts / fwdPkts)) * 0.07;
  const varianceFactor = Math.min(1.0, pktStd / 350.0) * 0.05;

  const raw = Math.min(1.0, Math.max(0.06, rateFactor + flagFactor + asymmetryFactor + varianceFactor));
  return Number(raw.toFixed(4));
}

export function computeContextScore(dstPort: number, protocol: number, features?: Partial<FlowFeatures>): number {
  let score = 0.32;
  if ([22, 3389, 445, 1433, 3306, 5432].includes(dstPort)) {
    score = 0.86;
  } else if ([80, 443, 8080, 8443].includes(dstPort)) {
    score = 0.72;
  } else if (SENSITIVE_PORTS.has(dstPort) || (dstPort > 0 && dstPort < 1024)) {
    score = 0.58;
  }
  if (protocol === 6) {
    score += 0.05;
  }
  if (features) {
    const fwdBytes = Number(features.total_length_of_fwd_packets ?? 0);
    if (fwdBytes > 500) {
      score += Math.min(0.08, fwdBytes / 25000.0);
    }
  }
  return Number(Math.min(1.0, score).toFixed(4));
}

export function computeSignatureConfidence(
  baseConfidence: number,
  matchedPatternsCount: number,
  dstPort: number,
  features: Partial<FlowFeatures>,
): number {
  const patternBonus = Math.min(0.12, Math.max(0, matchedPatternsCount - 1) * 0.06);
  const portBonus = SENSITIVE_PORTS.has(dstPort) ? 0.04 : 0.01;
  const bwdBonus = Number(features.total_bwd_packets ?? 0) > 0 ? 0.03 : 0.0;
  return Number(Math.min(0.98, Math.max(0.5, baseConfidence + patternBonus + portBonus + bwdBonus)).toFixed(4));
}

export function mapCategory(riskScore: number): AlertCategory {
  const cats = getSystemConfig().risk_scoring.categories;
  if (riskScore >= cats.critical_min) return 'Critical';
  if (riskScore >= cats.medium_max + 1) return 'High';
  if (riskScore >= cats.low_max + 1) return 'Medium';
  return 'Low';
}

export function scoreSignatureAlert(
  suricataSeverity: number,
  features: Partial<FlowFeatures>,
  signatureId: string,
  signatureMsg: string,
  matchedPatternsCount = 1,
  confidenceOverride?: number,
  weightsOverride?: ScoreWeights,
): {
  risk_score: number;
  category: AlertCategory;
  score_breakdown: ScoreBreakdown;
  explanation: string;
} {
  const cfg = getSystemConfig();
  const weights = weightsOverride || cfg.risk_scoring.weights;
  const sevMap = cfg.risk_scoring.signature_defaults.severity_map;
  const baseConf = cfg.risk_scoring.signature_defaults.base_confidence;

  const severity = sevMap[suricataSeverity] ?? 0.36;
  const dstPort = Number(features.destination_port ?? 0);
  const proto = Number(features.protocol ?? 6);
  const confidence =
    confidenceOverride !== undefined
      ? Number(confidenceOverride.toFixed(4))
      : computeSignatureConfidence(baseConf, matchedPatternsCount, dstPort, features);

  const behavior = computeBehaviorScore(features);
  const context = computeContextScore(dstPort, proto, features);

  const rawScore =
    100.0 *
    (weights.severity * severity +
      weights.confidence * confidence +
      weights.behavior * behavior +
      weights.context * context);

  const finalScore = Number(Math.min(100.0, Math.max(0.0, rawScore)).toFixed(1));
  const category = mapCategory(finalScore);

  const explanation = `Analyst prioritization heuristic: Matched Suricata rule [${signatureId}] '${signatureMsg}' (priority ${suricataSeverity} -> severity=${severity.toFixed(2)}, rule specificity confidence=${confidence.toFixed(2)} from ${matchedPatternsCount} content pattern(s)). Flow behavior=${behavior.toFixed(2)} and port ${dstPort} context=${context.toFixed(2)} yielded ${finalScore}/100 (${category}).`;

  return {
    risk_score: finalScore,
    category,
    score_breakdown: {
      severity,
      confidence,
      behavior,
      context,
      weights: { ...weights },
    },
    explanation,
  };
}

export function scoreMlAlert(
  mlProbability: number,
  features: Partial<FlowFeatures>,
  severityOverride?: number,
  weightsOverride?: ScoreWeights,
): {
  risk_score: number;
  category: AlertCategory;
  score_breakdown: ScoreBreakdown;
  explanation: string;
} {
  const cfg = getSystemConfig();
  const weights = weightsOverride || cfg.risk_scoring.weights;
  const threshold = cfg.ml.probability_threshold;
  const baseSev = cfg.risk_scoring.ml_defaults.base_severity;

  const dstPort = Number(features.destination_port ?? 0);
  const proto = Number(features.protocol ?? 6);
  const behavior = computeBehaviorScore(features);
  const context = computeContextScore(dstPort, proto, features);

  const severity =
    severityOverride !== undefined
      ? Number(severityOverride.toFixed(4))
      : Number(Math.min(0.88, baseSev + behavior * 0.28).toFixed(4));
  const confidence = Number(mlProbability.toFixed(4));

  const rawScore =
    100.0 *
    (weights.severity * severity +
      weights.confidence * confidence +
      weights.behavior * behavior +
      weights.context * context);

  const finalScore = Number(Math.min(100.0, Math.max(0.0, rawScore)).toFixed(1));
  const category = mapCategory(finalScore);
  const pktRate = Number(features.flow_packets_s ?? 0).toFixed(1);

  const explanation = `Analyst prioritization heuristic: Unmatched flow classified malicious by Random Forest (p=${confidence.toFixed(2)} >= τ*=${threshold.toFixed(2)}). Volumetric-adjusted severity=${severity.toFixed(2)}, confidence=${confidence.toFixed(2)}, behavior=${behavior.toFixed(2)} (${pktRate} pkts/s), and port ${dstPort} context=${context.toFixed(2)} yielded ${finalScore}/100 (${category}).`;

  return {
    risk_score: finalScore,
    category,
    score_breakdown: {
      severity,
      confidence,
      behavior,
      context,
      weights: { ...weights },
    },
    explanation,
  };
}
