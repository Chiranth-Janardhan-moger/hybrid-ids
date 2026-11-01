import fs from 'fs';
import type { ExtractedFlow } from './pcapExtractor';
import { loadSystemConfig } from './configLoader';

export type SuricataRule = {
  sid: string;
  msg: string;
  severity: number;
  classtype: string;
  proto: number;
  dst_port: number | null;
  contents: string[];
};

export type SuricataAlertMatch = {
  timestamp: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  signature_id: string;
  signature_msg: string;
  severity: number;
  classtype: string;
  matched_contents: string[];
};

export function parseSuricataRulesFile(rulesPath: string): SuricataRule[] {
  if (!fs.existsSync(rulesPath)) return [];
  const content = fs.readFileSync(rulesPath, 'utf-8');
  const rules: SuricataRule[] = [];

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^alert\s+(\w+)\s+\S+\s+\S+\s+->\s+\S+\s+(\S+)\s*\((.+)\)$/);
    if (!m) continue;
    const [, protoStr, dstPortStr, optsStr] = m;
    const msgMatch = optsStr.match(/msg:"([^"]+)"/);
    const sidMatch = optsStr.match(/sid:(\d+)/);
    const prioMatch = optsStr.match(/priority:(\d+)/);
    const classMatch = optsStr.match(/classtype:([^;]+)/);
    const contents = Array.from(optsStr.matchAll(/content:"([^"]+)"/g)).map((x) => x[1]);

    if (sidMatch && msgMatch && contents.length > 0) {
      rules.push({
        sid: sidMatch[1],
        msg: msgMatch[1],
        severity: prioMatch ? parseInt(prioMatch[1], 10) : 2,
        classtype: classMatch ? classMatch[1].trim() : 'unknown',
        proto: protoStr.toLowerCase() === 'tcp' ? 6 : protoStr.toLowerCase() === 'udp' ? 17 : 0,
        dst_port: /^\d+$/.test(dstPortStr) ? parseInt(dstPortStr, 10) : null,
        contents,
      });
    }
  }
  return rules;
}

export function correlateAlertsToFlows(
  flows: Array<Pick<ExtractedFlow, 'src_ip' | 'src_port' | 'dst_ip' | 'dst_port' | 'protocol' | 'start_ts' | 'end_ts'>>,
  eveAlerts: SuricataAlertMatch[],
  timeWindowSec?: number,
): Map<number, SuricataAlertMatch> {
  const effectiveWindow = timeWindowSec ?? loadSystemConfig().suricata.correlation_time_window_sec;
  const matches = new Map<number, SuricataAlertMatch>();
  flows.forEach((fl, idx) => {
    const fwd = `${fl.src_ip}:${fl.src_port}-${fl.dst_ip}:${fl.dst_port}-${fl.protocol}`;
    const bwd = `${fl.dst_ip}:${fl.dst_port}-${fl.src_ip}:${fl.src_port}-${fl.protocol}`;
    for (const alert of eveAlerts) {
      const aTuple = `${alert.src_ip}:${alert.src_port}-${alert.dst_ip}:${alert.dst_port}-${alert.protocol}`;
      if (aTuple === fwd || aTuple === bwd) {
        if (alert.timestamp >= fl.start_ts - effectiveWindow && alert.timestamp <= fl.end_ts + effectiveWindow) {
          matches.set(idx, alert);
          break;
        }
      }
    }
  });
  return matches;
}

export function runSuricataOnFlows(
  flows: ExtractedFlow[],
  rulesPath = 'suricata/rules/local.rules',
  forceUnavailable = false,
): { status: 'ok' | 'unavailable'; matches: Map<number, SuricataAlertMatch> } {
  if (forceUnavailable || !fs.existsSync(rulesPath)) {
    return { status: 'unavailable', matches: new Map() };
  }
  const rules = parseSuricataRulesFile(rulesPath);
  if (rules.length === 0) {
    return { status: 'unavailable', matches: new Map() };
  }

  const eveAlerts: SuricataAlertMatch[] = [];
  for (const fl of flows) {
    const upperPayload = (fl.payload_text || '').toUpperCase();
    if (!upperPayload) continue;
    for (const rule of rules) {
      if (rule.proto !== 0 && rule.proto !== fl.protocol) continue;
      if (rule.dst_port !== null && rule.dst_port !== fl.dst_port && rule.dst_port !== fl.src_port) continue;
      if (rule.contents.every((c) => upperPayload.includes(c.toUpperCase()))) {
        eveAlerts.push({
          timestamp: fl.start_ts,
          src_ip: fl.src_ip,
          src_port: fl.src_port,
          dst_ip: fl.dst_ip,
          dst_port: fl.dst_port,
          protocol: fl.protocol,
          signature_id: rule.sid,
          signature_msg: rule.msg,
          severity: rule.severity,
          classtype: rule.classtype,
          matched_contents: rule.contents,
        });
        break;
      }
    }
  }

  const winSec = loadSystemConfig().suricata.correlation_time_window_sec;
  const correlated = correlateAlertsToFlows(flows, eveAlerts, winSec);
  return { status: 'ok', matches: correlated };
}
