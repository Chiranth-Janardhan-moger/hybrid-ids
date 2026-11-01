import type { FlowFeatures } from '../types';

export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB

export class PcapValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PcapValidationError';
  }
}

export type ExtractedFlow = {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  start_ts: number;
  end_ts: number;
  features: FlowFeatures;
  payload_text: string;
};

type DecodedPacket = {
  ts: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  length: number;
  flags: number;
  payload: string;
};

export function validatePcapBuffer(filename: string, buf: Buffer): void {
  const lower = filename.toLowerCase();
  if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng')) {
    throw new PcapValidationError(`Unsupported file extension in '${filename}'. Only .pcap and .pcapng are allowed.`);
  }
  if (buf.length === 0) {
    throw new PcapValidationError('Uploaded PCAP file is empty (0 bytes).');
  }
  if (buf.length > MAX_UPLOAD_BYTES) {
    throw new PcapValidationError(`Uploaded file exceeds maximum size limit of 100 MB (${buf.length} bytes).`);
  }
  if (buf.length < 24) {
    throw new PcapValidationError('Malformed PCAP file: shorter than 24-byte global header.');
  }

  const magic = buf.readUInt32LE(0);
  const validMagics = new Set([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a]);
  if (!validMagics.has(magic)) {
    throw new PcapValidationError(
      `Invalid PCAP/PCAPNG magic header (0x${magic.toString(16).padStart(8, '0')}). File is corrupt or not a packet capture.`,
    );
  }
}

function decodeEthIpv4(ts: number, raw: Buffer): DecodedPacket | null {
  if (raw.length < 34) return null;
  let ethType = raw.readUInt16BE(12);
  let ipOffset = 14;
  if (ethType === 0x8100 && raw.length >= 38) {
    ethType = raw.readUInt16BE(16);
    ipOffset = 18;
  }
  if (ethType !== 0x0800) return null;

  const ipHdr = raw.subarray(ipOffset);
  if (ipHdr.length < 20) return null;
  const ihl = (ipHdr[0] & 0x0f) * 4;
  if (ihl < 20 || ipHdr.length < ihl) return null;

  const proto = ipHdr[9];
  const src_ip = `${ipHdr[12]}.${ipHdr[13]}.${ipHdr[14]}.${ipHdr[15]}`;
  const dst_ip = `${ipHdr[16]}.${ipHdr[17]}.${ipHdr[18]}.${ipHdr[19]}`;
  const l4 = ipHdr.subarray(ihl);

  let src_port = 0;
  let dst_port = 0;
  let flags = 0;
  let payloadBuf: Buffer = Buffer.alloc(0);

  if (proto === 6 && l4.length >= 20) {
    src_port = l4.readUInt16BE(0);
    dst_port = l4.readUInt16BE(2);
    const doff = ((l4[12] >> 4) & 0x0f) * 4;
    flags = l4[13];
    if (doff <= l4.length) {
      payloadBuf = l4.subarray(doff);
    }
  } else if (proto === 17 && l4.length >= 8) {
    src_port = l4.readUInt16BE(0);
    dst_port = l4.readUInt16BE(2);
    payloadBuf = l4.subarray(8);
  } else if (proto === 1 && l4.length >= 4) {
    payloadBuf = l4.subarray(4);
  } else {
    return null;
  }

  return {
    ts,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol: proto,
    length: raw.length,
    flags,
    payload: payloadBuf.toString('latin1'),
  };
}

export function extractFlowsFromPcapBuffer(filename: string, buf: Buffer): ExtractedFlow[] {
  validatePcapBuffer(filename, buf);
  const magic = buf.readUInt32LE(0);
  const packets: DecodedPacket[] = [];

  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
    const isLE = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
    const isNano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    let offset = 24;
    while (offset + 16 <= buf.length) {
      const tsSec = isLE ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
      const tsSub = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
      const inclLen = isLE ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
      offset += 16;
      if (inclLen === 0 || offset + inclLen > buf.length) break;
      const rawPkt = buf.subarray(offset, offset + inclLen);
      offset += inclLen;
      const ts = tsSec + tsSub / (isNano ? 1e9 : 1e6);
      const decoded = decodeEthIpv4(ts, rawPkt);
      if (decoded) packets.push(decoded);
    }
  } else if (magic === 0x0a0d0d0a) {
    let offset = 0;
    while (offset + 12 <= buf.length) {
      const blockType = buf.readUInt32LE(offset);
      const blockLen = buf.readUInt32LE(offset + 4);
      if (blockLen < 12 || offset + blockLen > buf.length) break;
      if (blockType === 0x00000006 && blockLen >= 32) {
        const tsHigh = buf.readUInt32LE(offset + 12);
        const tsLow = buf.readUInt32LE(offset + 16);
        const capLen = buf.readUInt32LE(offset + 20);
        const ts = (tsHigh * 4294967296 + tsLow) / 1e6;
        const rawPkt = buf.subarray(offset + 28, offset + 28 + capLen);
        const decoded = decodeEthIpv4(ts, rawPkt);
        if (decoded) packets.push(decoded);
      }
      offset += blockLen;
    }
  }

  if (packets.length === 0) {
    throw new PcapValidationError('No valid IPv4 TCP/UDP/ICMP packets found in capture file.');
  }

  type FlowAccumulator = {
    src_ip: string;
    src_port: number;
    dst_ip: string;
    dst_port: number;
    protocol: number;
    start_ts: number;
    end_ts: number;
    timestamps: number[];
    lengths: number[];
    fwd_packets: number;
    bwd_packets: number;
    fwd_bytes: number;
    bwd_bytes: number;
    fin_count: number;
    syn_count: number;
    rst_count: number;
    psh_count: number;
    ack_count: number;
    payloads: string[];
  };

  const flowsMap = new Map<string, FlowAccumulator>();

  for (const pkt of packets) {
    const fwdKey = `${pkt.src_ip}:${pkt.src_port}-${pkt.dst_ip}:${pkt.dst_port}-${pkt.protocol}`;
    const bwdKey = `${pkt.dst_ip}:${pkt.dst_port}-${pkt.src_ip}:${pkt.src_port}-${pkt.protocol}`;

    let key = fwdKey;
    let isFwd = true;
    if (flowsMap.has(fwdKey)) {
      key = fwdKey;
      isFwd = true;
    } else if (flowsMap.has(bwdKey)) {
      key = bwdKey;
      isFwd = false;
    } else {
      flowsMap.set(fwdKey, {
        src_ip: pkt.src_ip,
        src_port: pkt.src_port,
        dst_ip: pkt.dst_ip,
        dst_port: pkt.dst_port,
        protocol: pkt.protocol,
        start_ts: pkt.ts,
        end_ts: pkt.ts,
        timestamps: [],
        lengths: [],
        fwd_packets: 0,
        bwd_packets: 0,
        fwd_bytes: 0,
        bwd_bytes: 0,
        fin_count: 0,
        syn_count: 0,
        rst_count: 0,
        psh_count: 0,
        ack_count: 0,
        payloads: [],
      });
    }

    const fl = flowsMap.get(key)!;
    fl.start_ts = Math.min(fl.start_ts, pkt.ts);
    fl.end_ts = Math.max(fl.end_ts, pkt.ts);
    fl.timestamps.push(pkt.ts);
    fl.lengths.push(pkt.length);
    if (isFwd) {
      fl.fwd_packets += 1;
      fl.fwd_bytes += pkt.length;
    } else {
      fl.bwd_packets += 1;
      fl.bwd_bytes += pkt.length;
    }

    if (pkt.flags & 0x01) fl.fin_count += 1;
    if (pkt.flags & 0x02) fl.syn_count += 1;
    if (pkt.flags & 0x04) fl.rst_count += 1;
    if (pkt.flags & 0x08) fl.psh_count += 1;
    if (pkt.flags & 0x10) fl.ack_count += 1;

    if (pkt.payload && fl.payloads.length < 8) {
      fl.payloads.push(pkt.payload);
    }
  }

  const extracted: ExtractedFlow[] = [];
  for (const fl of flowsMap.values()) {
    const durSec = Math.max(fl.end_ts - fl.start_ts, 0.0001);
    const durUs = durSec * 1_000_000.0;
    const totPkts = fl.lengths.length;
    const totBytes = fl.fwd_bytes + fl.bwd_bytes;
    const meanLen = totBytes / Math.max(totPkts, 1);
    const variance = fl.lengths.reduce((acc, l) => acc + (l - meanLen) ** 2, 0) / Math.max(totPkts, 1);
    const stdLen = Math.sqrt(variance);

    const sortedTs = [...fl.timestamps].sort((a, b) => a - b);
    let iatMean = 0.0;
    if (sortedTs.length > 1) {
      let iatSum = 0.0;
      for (let i = 0; i < sortedTs.length - 1; i++) {
        iatSum += (sortedTs[i + 1] - sortedTs[i]) * 1_000_000.0;
      }
      iatMean = iatSum / (sortedTs.length - 1);
    }

    const features: FlowFeatures = {
      destination_port: fl.dst_port,
      protocol: fl.protocol,
      flow_duration: Number(durUs.toFixed(2)),
      total_fwd_packets: fl.fwd_packets,
      total_bwd_packets: fl.bwd_packets,
      total_length_of_fwd_packets: fl.fwd_bytes,
      total_length_of_bwd_packets: fl.bwd_bytes,
      min_packet_length: Math.min(...fl.lengths),
      max_packet_length: Math.max(...fl.lengths),
      packet_length_mean: Number(meanLen.toFixed(2)),
      packet_length_std: Number(stdLen.toFixed(2)),
      flow_bytes_s: Number((totBytes / durSec).toFixed(2)),
      flow_packets_s: Number((totPkts / durSec).toFixed(2)),
      flow_iat_mean: Number(iatMean.toFixed(2)),
      fin_flag_count: fl.fin_count,
      syn_flag_count: fl.syn_count,
      rst_flag_count: fl.rst_count,
      psh_flag_count: fl.psh_count,
      ack_flag_count: fl.ack_count,
    };

    extracted.push({
      src_ip: fl.src_ip,
      src_port: fl.src_port,
      dst_ip: fl.dst_ip,
      dst_port: fl.dst_port,
      protocol: fl.protocol,
      start_ts: fl.start_ts,
      end_ts: fl.end_ts,
      features,
      payload_text: fl.payloads.join('\n'),
    });
  }

  return extracted;
}
