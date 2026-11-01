export type EngineHealthStatus = {
  suricata: 'ok' | 'unavailable';
  model: 'ok' | 'missing';
  database: 'ok' | 'error';
};

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export type JobListItem = {
  id: string;
  filename: string;
  status: JobStatus;
  created_at: string;
  total_flows: number;
  total_alerts: number;
  processing_time_ms?: number;
  flows_per_sec?: number;
  pcap_size_bytes?: number;
};

export type JobDetail = {
  id: string;
  filename: string;
  status: JobStatus;
  progress: number;
  error: string | null;
  engine_status: {
    suricata: 'ok' | 'unavailable';
    model: 'ok' | 'missing';
  };
  created_at: string;
  total_flows: number;
  total_alerts: number;
  signature_alerts: number;
  ml_alerts: number;
  processing_time_ms?: number;
  flows_per_sec?: number;
  pcap_size_bytes?: number;
};

export type AlertCategory = 'Low' | 'Medium' | 'High' | 'Critical';
export type DetectionMethod = 'signature' | 'ml';
export type AnalystStatus = 'open' | 'confirmed' | 'false_positive';

export type ScoreWeights = {
  severity: number;
  confidence: number;
  behavior: number;
  context: number;
};

export type ScoreBreakdown = {
  severity: number;
  confidence: number;
  behavior: number;
  context: number;
  weights: ScoreWeights;
};

export type FeatureContribution = {
  feature: string;
  value: number;
  benign_mean: number;
  z_score: number;
  importance: number;
  tree_prob_delta?: number;
  base_prob?: number;
  contribution: number;
  share_pct: number;
};

export type TlsFingerprintMetadata = {
  tls_version: string;
  ja3_hash: string;
  ja3_string: string;
  sni: string;
  cipher_count: number;
  encrypted_payload_inspected: boolean;
};

export type CampaignCorrelationMetadata = {
  is_multi_stage_campaign: boolean;
  campaign_id: string;
  attacker_ip: string;
  correlated_alert_count: number;
  stages_detected: string[];
  target_ports: number[];
  context_boosted_from: number;
  context_boosted_to: number;
};

export type Alert = {
  id: string;
  job_id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  detection_method: DetectionMethod;
  signature_id: string | null;
  signature_msg: string | null;
  ml_label: string | null;
  ml_probability: number | null;
  risk_score: number;
  category: AlertCategory;
  score_breakdown: ScoreBreakdown;
  explanation: string;
  evidence: Record<string, unknown>;
  rule_version: string | null;
  model_version: string | null;
  analyst_status?: AnalystStatus;
  analyst_notes?: string | null;
};

export type AlertsPaginatedResponse = {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
};

export type SummaryResponse = {
  total_flows: number;
  total_alerts: number;
  by_category: {
    Low: number;
    Medium: number;
    High: number;
    Critical: number;
  };
  by_method: {
    signature: number;
    ml: number;
  };
  top_source_ips: Array<{
    ip: string;
    count: number;
  }>;
  timeline: Array<{
    time: string;
    count: number;
  }>;
};

export type HybridComparisonItem = {
  mode: 'signature_only' | 'ml_only' | 'hybrid';
  precision: number;
  precision_ci95?: [number, number];
  recall: number;
  recall_ci95?: [number, number];
  f1: number;
  false_positive_rate: number;
  tp?: number;
  fp?: number;
  fn?: number;
  tn?: number;
};

export type PerClassRecallItem = {
  attack_class: string;
  flows: number;
  signature_only_recall: number;
  ml_only_recall: number;
  hybrid_recall: number;
  hybrid_ci95?: [number, number];
};

export type FeatureImportanceItem = {
  feature: string;
  importance: number;
};

export type PrevalenceAnalysisItem = {
  prevalence_pct: number;
  scenario: string;
  expected_precision: number;
  expected_tp_per_1k_flows: number;
  expected_fp_per_1k_flows: number;
};

export type ValidationThresholdPoint = {
  threshold: number;
  val_precision: number;
  val_recall: number;
  val_f1: number;
  val_f05: number;
  val_fpr: number;
};

export type TestThresholdSimulatorPoint = {
  threshold: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
};

export type ReliabilityBinItem = {
  bin_label: string;
  flow_count: number;
  mean_raw_prob: number;
  mean_calibrated_prob: number;
  empirical_positive_rate: number;
};

export type CalibrationAnalysis = {
  method: string;
  platt_slope_a: number;
  platt_intercept_b: number;
  val_brier_raw: number;
  val_brier_calibrated: number;
  test_brier_raw: number;
  test_brier_calibrated: number;
  reliability_bins: ReliabilityBinItem[];
};

export type AdversarialStressTestItem = {
  scenario: string;
  perturbation: string;
  attack_flows: number;
  detected_flows: number;
  ml_recall: number;
  recall_ci95: [number, number];
  mean_ml_probability: number;
  defense_note: string;
};

export type ModelBaselineItem = {
  model_name: string;
  family: string;
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  roc_auc: number;
  latency_us_per_flow: number;
  notes: string;
};

export type ConceptDriftPsiItem = {
  feature: string;
  importance: number;
  train_mean: number;
  test_mean: number;
  std_mean_shift: number;
  psi: number;
  drift_status: string;
};

export type WeightSensitivityItem = {
  preset: string;
  mean_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
};

export type CrossDomainEvaluation = {
  benchmark_name: string;
  total_flows: number;
  benign_flows: number;
  attack_flows: number;
  ml_only_f1_on_raw_pcap: number;
  hybrid_f1_on_raw_pcap: number;
  skew_analysis: string;
};

export type EvaluationResponse = {
  dataset: string;
  model_name: string;
  model_version: string;
  split_strategy: string;
  trained_at: string;
  selected_threshold?: number;
  validation_threshold_curve?: ValidationThresholdPoint[];
  test_threshold_curve?: TestThresholdSimulatorPoint[];
  calibration_analysis?: CalibrationAnalysis;
  adversarial_stress_test?: AdversarialStressTestItem[];
  model_baselines?: ModelBaselineItem[];
  concept_drift_psi?: ConceptDriftPsiItem[];
  metrics: {
    precision: number;
    recall: number;
    f1: number;
    roc_auc: number;
    false_positive_rate: number;
    accuracy: number;
    false_alarms_per_1k_benign?: number;
    confidence_intervals_95?: {
      precision: [number, number];
      recall: [number, number];
      fpr: [number, number];
      accuracy: [number, number];
    };
  };
  confusion_matrix: [[number, number], [number, number]];
  prevalence_analysis?: PrevalenceAnalysisItem[];
  hybrid_comparison: HybridComparisonItem[] | null;
  per_class_recall?: PerClassRecallItem[];
  feature_importances?: FeatureImportanceItem[];
  weight_sensitivity?: WeightSensitivityItem[];
  cross_domain_evaluation?: CrossDomainEvaluation;
  notes: string;
};

export type SystemConfigResponse = {
  flow_timeouts?: {
    active_timeout_sec: number;
    idle_timeout_sec: number;
    campaign_correlation_window_sec: number;
  };
  risk_scoring: {
    weights: ScoreWeights;
    signature_defaults: {
      base_confidence: number;
      severity_map: Record<string, number>;
    };
    ml_defaults: {
      base_severity: number;
    };
    categories: {
      low_max: number;
      medium_max: number;
      high_max: number;
      critical_min: number;
    };
  };
  ml: {
    probability_threshold: number;
    model_path: string;
    feature_schema_path: string;
    evaluation_path: string;
    model_version: string;
  };
  suricata: {
    rules_path: string;
    correlation_time_window_sec: number;
    rule_version: string;
  };
};

export type FlowFeatures = {
  destination_port: number;
  protocol: number;
  flow_duration: number;
  total_fwd_packets: number;
  total_bwd_packets: number;
  total_length_of_fwd_packets: number;
  total_length_of_bwd_packets: number;
  min_packet_length: number;
  max_packet_length: number;
  packet_length_mean: number;
  packet_length_std: number;
  flow_bytes_s: number;
  flow_packets_s: number;
  flow_iat_mean: number;
  fin_flag_count: number;
  syn_flag_count: number;
  rst_flag_count: number;
  psh_flag_count: number;
  ack_flag_count: number;
};

export type LiveCaptureMode =
  | 'mixed'
  | 'benign'
  | 'attack_sig'
  | 'attack_ml'
  | 'inject_sqli'
  | 'inject_syn_flood'
  | 'inject_slowloris'
  | 'inject_killchain';

export type LiveCaptureStatus = {
  active: boolean;
  mode: LiveCaptureMode;
  window_count: number;
  packets_captured: number;
  flows_analyzed: number;
  threats_detected: number;
  is_fishy: boolean;
  status_headline: string;
  status_detail: string;
  latest_alert: Alert | null;
  last_job_id: string | null;
};

export type QuarantinedIpEntry = {
  ip: string;
  reason: string;
  quarantined_at: string;
  trigger_layer: 'signature' | 'ml' | 'entropy' | 'honeypot';
  risk_score: number;
  blocked_attempts: number;
};

export type IpsQueryLogEntry = {
  id: string;
  timestamp: string;
  query_type: 'SAFE' | 'ATTACK';
  scenario: string;
  label: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  payload_summary: string;
  detection_engine: 'none' | 'signature' | 'ml' | 'entropy' | 'honeypot' | 'quarantine';
  detection_detail: string;
  shannon_entropy?: number;
  risk_score: number;
  category: string;
  action: 'ALLOWED' | 'ALLOWED_UNBLOCKED' | 'BLOCKED' | 'QUARANTINED';
  http_status: 200 | 403;
  alert_id: string | null;
};

export type IpsStatusResponse = {
  block_mode_enabled: boolean;
  blocked_ips: string[];
  quarantined_ips: QuarantinedIpEntry[];
  stats: {
    total_queries: number;
    safe_allowed: number;
    attacks_unblocked: number;
    attacks_blocked: number;
    quarantine_drops: number;
  };
  recent_logs: IpsQueryLogEntry[];
};


