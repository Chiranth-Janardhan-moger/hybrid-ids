import fs from 'fs';
import type { FeatureContribution, FlowFeatures } from '../types';
import { loadSystemConfig } from './configLoader';

type TreeNode =
  | { leaf: true; prob: number }
  | { leaf: false; prob?: number; feature: number; threshold: number; left: TreeNode; right: TreeNode };

type RfModelArtifact = {
  model_name: string;
  model_version: string;
  trained_at: string;
  probability_threshold: number;
  feature_names: Array<keyof FlowFeatures>;
  feature_importances?: Array<{ feature: string; importance: number }>;
  feature_stats?: Record<string, { benign_mean: number; benign_std: number }>;
  trees: TreeNode[];
};

function predictTree(node: TreeNode, vec: number[]): number {
  let curr = node;
  while (!curr.leaf) {
    if (vec[curr.feature] <= curr.threshold) {
      curr = curr.left;
    } else {
      curr = curr.right;
    }
  }
  return curr.prob;
}

function explainForestTreePath(
  trees: TreeNode[],
  vec: number[],
  featureCount: number,
): { baseProb: number; contribs: number[] } {
  const nTrees = Math.max(trees.length, 1);
  const contribs = new Array<number>(featureCount).fill(0);
  let baseProbSum = 0;

  for (const tree of trees) {
    let node = tree;
    baseProbSum += Number(node.prob ?? 0.5);
    while (!node.leaf) {
      const parentP = Number(node.prob ?? 0.5);
      const featIdx = node.feature;
      const child = vec[featIdx] <= node.threshold ? node.left : node.right;
      const childP = Number(child.prob ?? parentP);
      contribs[featIdx] += (childP - parentP) / nTrees;
      node = child;
    }
  }

  return {
    baseProb: Number((baseProbSum / nTrees).toFixed(4)),
    contribs,
  };
}

function computeTopContributingFeatures(
  features: FlowFeatures,
  model: RfModelArtifact,
  topK = 4,
): FeatureContribution[] {
  const vec = model.feature_names.map((fname) => Number(features[fname] ?? 0));
  const { baseProb, contribs } = explainForestTreePath(model.trees, vec, model.feature_names.length);

  const impMap = new Map<string, number>();
  for (const item of model.feature_importances || []) {
    impMap.set(item.feature, Number(item.importance));
  }
  const statsMap = model.feature_stats || {};

  const rawList = model.feature_names.map((fname, idx) => {
    const val = vec[idx];
    const imp = impMap.get(fname) ?? 0.01;
    const st = statsMap[fname] || { benign_mean: 0, benign_std: 1 };
    const bMean = Number(st.benign_mean ?? 0);
    const bStd = Math.max(Number(st.benign_std ?? 1), 1e-3);
    const zScore = Math.abs(val - bMean) / bStd;
    const treeDelta = Number(contribs[idx].toFixed(4));
    return {
      feature: String(fname),
      value: Number(val.toFixed(2)),
      benign_mean: Number(bMean.toFixed(2)),
      z_score: Number(zScore.toFixed(2)),
      importance: Number(imp.toFixed(4)),
      tree_prob_delta: treeDelta,
      base_prob: baseProb,
      contribution: Number(Math.max(0, treeDelta).toFixed(4)),
      share_pct: 0,
    };
  });

  rawList.sort((a, b) => (b.tree_prob_delta ?? 0) - (a.tree_prob_delta ?? 0) || b.z_score - a.z_score);
  const topItems = rawList.slice(0, topK);
  const totalPos = Math.max(
    topItems.reduce((acc, x) => acc + Math.max(0.0001, x.tree_prob_delta ?? 0), 0),
    1e-6,
  );
  for (const item of topItems) {
    item.share_pct = Number(((Math.max(0.0001, item.tree_prob_delta ?? 0) / totalPos) * 100).toFixed(1));
  }
  return topItems;
}

export function runMlInferenceOnFlow(
  features: FlowFeatures,
  modelPath = 'models/rf_model.json',
  forceMissing = false,
): {
  status: 'ok' | 'missing';
  ml_label: 'malicious' | 'benign' | 'unclassified';
  ml_probability: number | null;
  is_alert: boolean;
  model_version: string | null;
  threshold: number;
  top_contributing_features: FeatureContribution[];
} {
  const cfg = loadSystemConfig();
  const cfgThreshold = cfg.ml.probability_threshold;

  if (forceMissing || !fs.existsSync(modelPath)) {
    return {
      status: 'missing',
      ml_label: 'unclassified',
      ml_probability: null,
      is_alert: false,
      model_version: null,
      threshold: cfgThreshold,
      top_contributing_features: [],
    };
  }

  const model = JSON.parse(fs.readFileSync(modelPath, 'utf-8')) as RfModelArtifact;
  const vec = model.feature_names.map((fname) => Number(features[fname] ?? 0));
  const sumProb = model.trees.reduce((acc, tree) => acc + predictTree(tree, vec), 0);
  const prob = Number((sumProb / Math.max(model.trees.length, 1)).toFixed(4));
  const threshold = Number(model.probability_threshold ?? cfgThreshold);
  const isMalicious = prob >= threshold;
  const topFeatures = isMalicious ? computeTopContributingFeatures(features, model, 4) : [];

  return {
    status: 'ok',
    ml_label: isMalicious ? 'malicious' : 'benign',
    ml_probability: prob,
    is_alert: isMalicious,
    model_version: model.model_version || cfg.ml.model_version,
    threshold,
    top_contributing_features: topFeatures,
  };
}
