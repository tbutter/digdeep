const HEX_CHARS = '0123456789ABCDEF';
const BASE32HEX_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 0x0f];
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...sub);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '');
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(b64u: string): Uint8Array {
  let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return base64ToBytes(b64);
}

/**
 * RFC 4648 §7 Extended Hex ("base32hex") without padding, used by RFC 5155 NSEC3.
 */
export function bytesToBase32Hex(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32HEX_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32HEX_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const min = Math.min(a.length, b.length);
  for (let i = 0; i < min; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Splits a presentation-format DNS name into raw label strings while respecting RFC 1035 `\.` and `\\` escapes.
 */
export function splitPresentationLabels(name: string): string[] {
  const trimmed = name.trim();
  if (!trimmed || trimmed === '.') return [];
  const labels: string[] = [];
  let cur = '';
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (ch === '\\' && i + 1 < trimmed.length) {
      if (
        i + 3 < trimmed.length &&
        trimmed[i + 1] >= '0' &&
        trimmed[i + 1] <= '9' &&
        trimmed[i + 2] >= '0' &&
        trimmed[i + 2] <= '9' &&
        trimmed[i + 3] >= '0' &&
        trimmed[i + 3] <= '9'
      ) {
        cur += trimmed.slice(i, i + 4);
        i += 3;
      } else {
        cur += trimmed.slice(i, i + 2);
        i += 1;
      }
    } else if (ch === '.') {
      if (cur.length > 0) {
        labels.push(cur);
        cur = '';
      }
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) {
    labels.push(cur);
  }
  return labels;
}

/**
 * Decodes an RFC 1035 §5.1 presentation label (including `\DDD` decimal octets and `\X` escapes) into wire bytes.
 * When `canonicalLower=true` (RFC 4034 §6.2), ASCII uppercase letters (0x41..0x5A) are lowercased.
 */
export function unescapePresentationLabel(label: string, canonicalLower = true): Uint8Array {
  const out: number[] = [];
  const encoder = new TextEncoder();
  for (let i = 0; i < label.length; i++) {
    const ch = label[i];
    if (ch === '\\' && i + 1 < label.length) {
      if (
        i + 3 < label.length &&
        label[i + 1] >= '0' &&
        label[i + 1] <= '9' &&
        label[i + 2] >= '0' &&
        label[i + 2] <= '9' &&
        label[i + 3] >= '0' &&
        label[i + 3] <= '9'
      ) {
        let byte = Number.parseInt(label.slice(i + 1, i + 4), 10) & 0xff;
        if (canonicalLower && byte >= 0x41 && byte <= 0x5a) byte += 32;
        out.push(byte);
        i += 3;
      } else {
        let byte = label.charCodeAt(i + 1) & 0xff;
        if (canonicalLower && byte >= 0x41 && byte <= 0x5a) byte += 32;
        out.push(byte);
        i += 1;
      }
    } else {
      const encoded = encoder.encode(ch);
      for (let k = 0; k < encoded.length; k++) {
        let byte = encoded[k];
        if (canonicalLower && byte >= 0x41 && byte <= 0x5a) byte += 32;
        out.push(byte);
      }
    }
  }
  return new Uint8Array(out);
}

/**
 * Normalizes a DNS domain name to lowercase FQDN ending with '.' (e.g. '.' or 'cloudflare.com.').
 */
export function normalizeFqdn(name: string): string {
  const trimmed = name.trim();
  if (!trimmed || trimmed === '.') return '.';
  // Strip protocol or path if someone pastes a URL
  let cleaned = trimmed;
  if (cleaned.includes('://')) {
    try {
      cleaned = new URL(cleaned).hostname;
    } catch {
      cleaned = cleaned.replace(/^https?:\/\//i, '').split('/')[0];
    }
  } else if (cleaned.includes('/') && !cleaned.includes('\\')) {
    cleaned = cleaned.split('/')[0];
  }
  const labels = splitPresentationLabels(cleaned.toLowerCase());
  return labels.length > 0 ? `${labels.join('.')}.` : '.';
}

export function displayFqdn(fqdn: string): string {
  const norm = normalizeFqdn(fqdn);
  return norm === '.' ? '.' : norm.slice(0, -1);
}

/**
 * Counts DNS labels per RFC 4034 §3.1.3 (root '.' has 0 labels; '*' wildcard label is NOT counted in RRSIG labels,
 * though this helper returns actual non-root non-wildcard label count when ignoreWildcard=true).
 */
export function countDnsLabels(fqdn: string, ignoreLeadingWildcard = true): number {
  const norm = normalizeFqdn(fqdn);
  if (norm === '.') return 0;
  const labels = splitPresentationLabels(norm);
  if (ignoreLeadingWildcard && labels[0] === '*') {
    return labels.length - 1;
  }
  return labels.length;
}

/**
 * Returns ancestor domain names from root '.' down to the target FQDN inclusive.
 * e.g. 'www.ietf.org.' -> ['.', 'org.', 'ietf.org.', 'www.ietf.org.']
 */
export function getDomainHierarchy(fqdn: string): string[] {
  const norm = normalizeFqdn(fqdn);
  if (norm === '.') return ['.'];
  const labels = splitPresentationLabels(norm);
  const chain: string[] = ['.'];
  for (let i = labels.length - 1; i >= 0; i--) {
    chain.push(`${labels.slice(i).join('.')}.`);
  }
  return chain;
}

/**
 * RFC 4034 §6.1 Canonical DNS Name Order comparison.
 * Compares labels from right (highest-level) to left (lowest-level) as unsigned lowercase wire octets.
 */
export function compareCanonicalDnsNames(a: string, b: string): number {
  const la = splitPresentationLabels(normalizeFqdn(a));
  const lb = splitPresentationLabels(normalizeFqdn(b));
  let ia = la.length - 1;
  let ib = lb.length - 1;
  while (ia >= 0 && ib >= 0) {
    if (la[ia] !== lb[ib]) {
      const bytesA = unescapePresentationLabel(la[ia], true);
      const bytesB = unescapePresentationLabel(lb[ib], true);
      const cmp = compareBytes(bytesA, bytesB);
      if (cmp !== 0) return cmp;
    }
    ia--;
    ib--;
  }
  return la.length - lb.length;
}

export function isSubdomainOrEqual(name: string, zone: string): boolean {
  const n = normalizeFqdn(name);
  const z = normalizeFqdn(zone);
  if (z === '.') return true;
  return n === z || n.endsWith(`.${z}`);
}

/**
 * RFC 4034 Appendix B Key Tag Calculation
 */
export function computeKeyTag(dnskeyRdata: Uint8Array): number {
  if (dnskeyRdata.length < 4) return 0;
  const algorithm = dnskeyRdata[3];
  if (algorithm === 1) {
    // Appendix B.1 RSAMD5 special case
    if (dnskeyRdata.length < 7) return 0;
    return ((dnskeyRdata[dnskeyRdata.length - 3] << 8) | dnskeyRdata[dnskeyRdata.length - 2]) & 0xffff;
  }
  let ac = 0;
  for (let i = 0; i < dnskeyRdata.length; i++) {
    ac += (i & 1) !== 0 ? dnskeyRdata[i] : dnskeyRdata[i] << 8;
  }
  ac += (ac >>> 16) & 0xffff;
  return ac & 0xffff;
}

export function getKeySizeInfo(algorithm: number, publicKey: Uint8Array): string {
  if ([1, 5, 7, 8, 10].includes(algorithm)) {
    if (publicKey.length < 3) return 'RSA';
    let offset = 0;
    let expLen = publicKey[0];
    offset = 1;
    if (expLen === 0) {
      if (publicKey.length < 3) return 'RSA';
      expLen = (publicKey[1] << 8) | publicKey[2];
      offset = 3;
    }
    let modStart = offset + expLen;
    while (modStart < publicKey.length - 1 && publicKey[modStart] === 0) {
      modStart++;
    }
    const modLen = publicKey.length - modStart;
    if (modLen <= 0) return 'RSA';
    const firstByte = publicKey[modStart];
    const leadingZeros = firstByte === 0 ? 8 : Math.clz32(firstByte) - 24;
    const bits = modLen * 8 - leadingZeros;
    return `${bits}-bit RSA`;
  }
  if (algorithm === 13) return '256-bit P-256';
  if (algorithm === 14) return '384-bit P-384';
  if (algorithm === 15) return '256-bit Ed25519';
  if (algorithm === 16) return '456-bit Ed448';
  return `${publicKey.length * 8}-bit`;
}

export function formatDnsTimestamp(epochSec: number): string {
  const d = new Date(epochSec * 1000);
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
  );
}
