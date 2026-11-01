import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { extractFlowsFromPcapBuffer, PcapValidationError } from './pcapExtractor';
import { correlateAlertsToFlows, runSuricataOnFlows } from './suricataEngine';
import { runMlInferenceOnFlow } from './mlEngine';
import { mapCategory, scoreMlAlert, scoreSignatureAlert } from './riskEngine';

test('feature schema compatibility: PCAP flow extractor produces exact 19 features', () => {
  const schema = JSON.parse(fs.readFileSync('models/feature_schema.json', 'utf-8')) as {
    features: Array<{ name: string }>;
  };
  const expectedNames = schema.features.map((f) => f.name);
  assert.equal(expectedNames.length, 19);

  const buf = fs.readFileSync('samples/attack_signature.pcap');
  const flows = extractFlowsFromPcapBuffer('attack_signature.pcap', buf);
  assert.ok(flows.length >= 4);
  for (const fl of flows) {
    assert.deepEqual(Object.keys(fl.features), expectedNames);
  }
});

test('risk scoring formula and category boundaries adhere to contract', () => {
  const sampleFeatures = {
    destination_port: 80,
    protocol: 6,
    flow_packets_s: 600,
    flow_bytes_s: 400000,
    syn_flag_count: 10,
    rst_flag_count: 5,
    psh_flag_count: 4,
  };
  const sigScored = scoreSignatureAlert(1, sampleFeatures, '2010935', 'SQL Injection');
  const bd = sigScored.score_breakdown;
  const expected = Number(
    (100 * (0.4 * bd.severity + 0.3 * bd.confidence + 0.2 * bd.behavior + 0.1 * bd.context)).toFixed(1),
  );
  assert.equal(sigScored.risk_score, expected);
  assert.equal(mapCategory(29.9), 'Low');
  assert.equal(mapCategory(30.0), 'Medium');
  assert.equal(mapCategory(60.0), 'High');
  assert.equal(mapCategory(80.0), 'Critical');

  // Low-confidence ML prediction does not become Critical
  const mlLow = scoreMlAlert(0.71, { destination_port: 8080, protocol: 6, flow_packets_s: 40, flow_bytes_s: 4000 });
  assert.ok(mlLow.risk_score < 80);
});

test('Suricata 5-tuple + time window correlation matches within window and rejects out-of-window', () => {
  const flows = [
    { src_ip: '192.168.1.10', src_port: 50000, dst_ip: '10.0.0.5', dst_port: 80, protocol: 6, start_ts: 100, end_ts: 102 },
    { src_ip: '192.168.1.11', src_port: 50001, dst_ip: '10.0.0.5', dst_port: 443, protocol: 6, start_ts: 200, end_ts: 201 },
  ];
  const alerts = [
    {
      timestamp: 101.5,
      src_ip: '192.168.1.10',
      src_port: 50000,
      dst_ip: '10.0.0.5',
      dst_port: 80,
      protocol: 6,
      signature_id: '2010935',
      signature_msg: 'SQLi',
      severity: 1,
      classtype: 'web-application-attack',
      matched_contents: ['UNION', 'SELECT'],
    },
    {
      timestamp: 250.0,
      src_ip: '192.168.1.11',
      src_port: 50001,
      dst_ip: '10.0.0.5',
      dst_port: 443,
      protocol: 6,
      signature_id: '2024364',
      signature_msg: 'Scan',
      severity: 2,
      classtype: 'attempted-recon',
      matched_contents: ['Nmap'],
    },
  ];
  const correlated = correlateAlertsToFlows(flows, alerts, 5.0);
  assert.equal(correlated.has(0), true);
  assert.equal(correlated.has(1), false);
});

test('Scenarios A, B, C, and D behave deterministically across extractor, Suricata, and ML engines', () => {
  // Scenario A: attack_signature.pcap -> 4 signature matches
  const attackFlows = extractFlowsFromPcapBuffer('attack_signature.pcap', fs.readFileSync('samples/attack_signature.pcap'));
  const suriA = runSuricataOnFlows(attackFlows);
  assert.equal(suriA.status, 'ok');
  assert.equal(suriA.matches.size, 4);

  // Scenario B: suspicious_unmatched_ml.pcap -> 0 signature matches, >= 2 ML malicious alerts
  const suspFlows = extractFlowsFromPcapBuffer('suspicious_unmatched_ml.pcap', fs.readFileSync('samples/suspicious_unmatched_ml.pcap'));
  const suriB = runSuricataOnFlows(suspFlows);
  assert.equal(suriB.matches.size, 0);
  const mlAlerts = suspFlows.map((f) => runMlInferenceOnFlow(f.features)).filter((r) => r.is_alert);
  assert.ok(mlAlerts.length >= 2);

  // Scenario C: benign_traffic.pcap -> 0 signature matches, 0 ML alerts
  const benignFlows = extractFlowsFromPcapBuffer('benign_traffic.pcap', fs.readFileSync('samples/benign_traffic.pcap'));
  const suriC = runSuricataOnFlows(benignFlows);
  assert.equal(suriC.matches.size, 0);
  const benignMlAlerts = benignFlows.map((f) => runMlInferenceOnFlow(f.features)).filter((r) => r.is_alert);
  assert.equal(benignMlAlerts.length, 0);

  // Scenario D: degraded engine status when Suricata unavailable or ML model missing
  const suriD = runSuricataOnFlows(attackFlows, 'suricata/rules/local.rules', true);
  assert.equal(suriD.status, 'unavailable');
  const mlD = runMlInferenceOnFlow(suspFlows[0].features, 'models/rf_model.json', true);
  assert.equal(mlD.status, 'missing');
  assert.equal(mlD.ml_label, 'unclassified');

  // Validation error on invalid file
  assert.throws(() => extractFlowsFromPcapBuffer('bad.txt', Buffer.from('hello')), PcapValidationError);
});


import { buildLivePcapMicroBatch } from './liveGenerator';

test('live capture micro-batch generator produces valid PCAP packets for benign, signature, and ML flood streams', () => {
  const mlBatch = buildLivePcapMicroBatch('attack_ml', 1);
  const mlFlows = extractFlowsFromPcapBuffer(mlBatch.filename, mlBatch.buffer);
  assert.ok(mlFlows.length >= 3);
  const mlTriggered = mlFlows.some((f) => runMlInferenceOnFlow(f.features).is_alert);
  assert.equal(mlTriggered, true);

  const sigBatch = buildLivePcapMicroBatch('attack_sig', 1);
  const sigFlows = extractFlowsFromPcapBuffer(sigBatch.filename, sigBatch.buffer);
  const suriRes = runSuricataOnFlows(sigFlows);
  assert.ok(suriRes.matches.size >= 1);

  const benignBatch = buildLivePcapMicroBatch('benign', 1);
  const benignFlows = extractFlowsFromPcapBuffer(benignBatch.filename, benignBatch.buffer);
  assert.equal(runSuricataOnFlows(benignFlows).matches.size, 0);
  assert.equal(benignFlows.some((f) => runMlInferenceOnFlow(f.features).is_alert), false);
});

import {
  computeShannonEntropy,
  inspectEntropyAndObfuscation,
  inspectHoneypotTrap,
} from './securityLayers';

test('Layer 3 security: Shannon Entropy DPI and Zero-Trust Honeypot Trap accurately distinguish benign vs attack payloads', () => {
  // Normal HTTP request has low entropy and does not trigger
  const normalPayload = 'GET /api/catalog/products?q=laptop HTTP/1.1';
  const normalEntropy = inspectEntropyAndObfuscation(normalPayload);
  assert.equal(normalEntropy.triggered, false);
  assert.ok(computeShannonEntropy(normalPayload) < 4.8);

  // High-entropy XOR/Base64 shellcode triggers Entropy DPI
  const shellcodePayload =
    'POST /api/v2/telemetry HTTP/1.1\r\n\r\npayload=q8f3Z9mK2xP7vL4nJ1wR8tY5uI0oE6aS3dF9gH2jK5lZ8xC1vB4nM7qW0eR3tY6u!@#$%^&*()_+~`={}[]|\\:;"<>,.?/9876543210abcdefABCDEF';
  const entropyRes = inspectEntropyAndObfuscation(shellcodePayload);
  assert.equal(entropyRes.triggered, true);
  assert.ok(entropyRes.entropy >= 4.85);
  assert.ok(entropyRes.risk_score >= 82);

  // Honeypot decoy paths trigger instant Risk Score = 100
  const honeypotHit = inspectHoneypotTrap('GET /.env & /admin/config.bak HTTP/1.1');
  assert.equal(honeypotHit.triggered, true);
  assert.equal(honeypotHit.risk_score, 100);

  const safePath = inspectHoneypotTrap('GET /portal/session/keepalive HTTP/1.1');
  assert.equal(safePath.triggered, false);
});

