export type QuarantinedIpEntry = {
  ip: string;
  reason: string;
  quarantined_at: string;
  trigger_layer: 'signature' | 'ml' | 'entropy' | 'honeypot';
  risk_score: number;
  blocked_attempts: number;
};

export const HONEYPOT_PATHS: readonly string[] = [
  '/.env',
  '/.aws/credentials',
  '/.aws/config',
  '/admin/config.bak',
  '/.git/config',
  '/wp-config.php.bak',
  '/backup/db_dump.sql',
];

export const ENTROPY_THRESHOLD_BITS = 4.85;

/**
 * Computes mathematical Shannon Entropy H(X) = -sum P(x) * log2(P(x)) in bits/byte [0.0 - 8.0]
 * over the HTTP body / high-entropy token segment of the payload.
 */
export function computeShannonEntropy(payload: string): number {
  if (!payload || payload.length === 0) return 0;

  // Extract body or high-entropy token if HTTP headers are present so standard headers don't dilute payload entropy
  let target = payload;
  const bodySplit = payload.indexOf('\r\n\r\n');
  if (bodySplit !== -1 && bodySplit + 4 < payload.length) {
    const body = payload.slice(bodySplit + 4).trim();
    if (body.length >= 16) {
      target = body;
    }
  } else {
    const tokenMatch = payload.match(/(?:payload|exec|data|cmd|token)=([A-Za-z0-9+/=%_-]{24,})/i);
    if (tokenMatch && tokenMatch[1]) {
      target = tokenMatch[1];
    }
  }

  const len = target.length;
  if (len === 0) return 0;

  const freq = new Map<number, number>();
  for (let i = 0; i < len; i++) {
    const code = target.charCodeAt(i) & 0xff;
    freq.set(code, (freq.get(code) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(2));
}

/**
 * Layer 3A: Zero-Trust Honeypot Decoy Trap Inspector.
 * Any request probing a decoy endpoint (/.env, /admin/config.bak, etc.) receives
 * an immediate Risk Score = 100 (Critical) and permanent IP quarantine.
 */
export function inspectHoneypotTrap(payload: string): {
  triggered: boolean;
  matched_trap: string | null;
  detail: string;
  risk_score: number;
} {
  const lower = payload.toLowerCase();
  for (const trap of HONEYPOT_PATHS) {
    if (lower.includes(trap.toLowerCase())) {
      return {
        triggered: true,
        matched_trap: trap,
        detail: `Honeypot Trap Triggered (${trap})`,
        risk_score: 100,
      };
    }
  }
  return {
    triggered: false,
    matched_trap: null,
    detail: '',
    risk_score: 0,
  };
}

/**
 * Layer 3B: Shannon Entropy & Obfuscation Deep Packet Inspector.
 * Catches Base64/XOR-obfuscated shellcode that evades Layer 1 (Signatures) and Layer 2 (Flow ML).
 */
export function inspectEntropyAndObfuscation(payload: string): {
  triggered: boolean;
  entropy: number;
  detail: string;
  risk_score: number;
} {
  const entropy = computeShannonEntropy(payload);
  const isWebshell =
    /eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|assert)/i.test(payload) ||
    /base64_decode\s*\(\s*["'][A-Za-z0-9+/=]{16,}["']\s*\)/i.test(payload);
  const hasObfuscatedBlob =
    isWebshell ||
    /(?:payload|exec|data|shellcode)=([A-Za-z0-9+/=]{24,})/i.test(payload) ||
    /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}/.test(payload);

  if ((entropy >= ENTROPY_THRESHOLD_BITS && (hasObfuscatedBlob || entropy >= 5.15)) || isWebshell) {
    const score = Math.min(98, Number((82 + Math.max(0, entropy - ENTROPY_THRESHOLD_BITS) * 14).toFixed(1)));
    const tag = isWebshell
      ? `Entropy DPI: Obfuscated Web Shell (H=${entropy} bits/B)`
      : `Entropy DPI: H(X)=${entropy} bits/B (> ${ENTROPY_THRESHOLD_BITS})`;
    return {
      triggered: true,
      entropy,
      detail: tag,
      risk_score: score,
    };
  }

  return {
    triggered: false,
    entropy,
    detail: `H(X)=${entropy} bits/B`,
    risk_score: 0,
  };
}
