import fs from 'fs';
import path from 'path';

export type SystemConfig = {
  suricata: {
    rules_path: string;
    correlation_time_window_sec: number;
    rule_version: string;
  };
  ml: {
    model_path: string;
    feature_schema_path: string;
    evaluation_path: string;
    model_version: string;
    probability_threshold: number;
  };
  risk_scoring: {
    weights: {
      severity: number;
      confidence: number;
      behavior: number;
      context: number;
    };
    signature_defaults: {
      severity_map: Record<number, number>;
      base_confidence: number;
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
};

let cachedConfig: SystemConfig | null = null;

export function loadSystemConfig(configPath = path.resolve(process.cwd(), 'config.yaml')): SystemConfig {
  const defaults: SystemConfig = {
    suricata: {
      rules_path: 'suricata/rules/local.rules',
      correlation_time_window_sec: 5.0,
      rule_version: 'ET-Open-2026.10-local-v1',
    },
    ml: {
      model_path: 'models/rf_model.json',
      feature_schema_path: 'models/feature_schema.json',
      evaluation_path: 'models/evaluation.json',
      model_version: 'rf-cicids2017-v1.1',
      probability_threshold: 0.68,
    },
    risk_scoring: {
      weights: {
        severity: 0.4,
        confidence: 0.3,
        behavior: 0.2,
        context: 0.1,
      },
      signature_defaults: {
        severity_map: { 1: 0.95, 2: 0.68, 3: 0.36, 4: 0.18 },
        base_confidence: 0.78,
      },
      ml_defaults: {
        base_severity: 0.58,
      },
      categories: {
        low_max: 29,
        medium_max: 59,
        high_max: 79,
        critical_min: 80,
      },
    },
  };

  if (!fs.existsSync(configPath)) {
    cachedConfig = defaults;
    return defaults;
  }

  const text = fs.readFileSync(configPath, 'utf-8');
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || !line.includes(':')) continue;
    const idx = line.indexOf(':');
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim().replace(/^"|"$/g, '');
    if (!val) continue;

    if (key === 'correlation_time_window_sec') defaults.suricata.correlation_time_window_sec = Number(val);
    else if (key === 'rule_version') defaults.suricata.rule_version = val;
    else if (key === 'probability_threshold') defaults.ml.probability_threshold = Number(val);
    else if (key === 'model_version') defaults.ml.model_version = val;
    else if (key === 'base_confidence') defaults.risk_scoring.signature_defaults.base_confidence = Number(val);
    else if (key === 'base_severity') defaults.risk_scoring.ml_defaults.base_severity = Number(val);
    else if (key === 'severity' || key === 'confidence' || key === 'behavior' || key === 'context') {
      defaults.risk_scoring.weights[key] = Number(val);
    } else if (key === 'low_max' || key === 'medium_max' || key === 'high_max' || key === 'critical_min') {
      defaults.risk_scoring.categories[key] = Number(val);
    }
  }

  cachedConfig = defaults;
  return defaults;
}

export function getSystemConfig(): SystemConfig {
  return cachedConfig || loadSystemConfig();
}
