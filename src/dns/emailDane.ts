import {
  formatDohShortLabel,
  RR_TYPES,
  TLSA_MATCHING_TYPES,
  TLSA_SELECTORS,
  TLSA_USAGES,
} from './constants';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  displayFqdn,
  hexToBytes,
  normalizeFqdn,
} from './encoding';
import type {
  AnalyzedRrset,
  AuditFinding,
  CnameEdge,
  DecodedOpenPgpTransferableKey,
  DecodedX509Certificate,
  DohQueryLog,
  EmailDaneAnalysis,
  EmailDaneOpenPgpRecord,
  EmailDaneProtocolResult,
  EmailDaneSmimeaRecord,
  NegativeNode,
  OpenPgpSubkeyInfo,
  SnapshotStatus,
  ValidationStatus,
  ZoneAnalysis,
} from './types';

export interface ParsedEmailDaneInput {
  inputKind: 'email' | 'openpgpkey-owner' | 'smimea-owner';
  /** Canonical display input, e.g. `paul@nohats.ca` or `<56hex>._openpgpkey.nohats.ca` */
  canonicalInput: string;
  /** Unquoted UTF-8 local-part when `inputKind === 'email'` */
  localPart?: string;
  /** Normalized domain FQDN with trailing dot, e.g. `nohats.ca.` */
  domain: string;
  /** Pre-supplied 56-hex hash when input is already `_openpgpkey` / `_smimecert` */
  presetHashHex?: string;
}

export interface DerivedEmailDaneTargets extends ParsedEmailDaneInput {
  exactHashHex: string;
  lowercaseHashHex?: string;
  openpgpkeyQname?: string;
  smimeaQname?: string;
  lowercaseOpenpgpkeyQname?: string;
  lowercaseSmimeaQname?: string;
}

/**
 * Unquotes a quoted RFC 5322 local-part per RFC 7929 §3:
 * "If the local-part is quoted, the quotes MUST be removed and any backslash-escaped characters unescaped before hashing."
 */
function normalizeEmailLocalPart(rawLocalPart: string): string {
  let lp = rawLocalPart;
  if (lp.length >= 2 && lp.startsWith('"') && lp.endsWith('"')) {
    lp = lp.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return typeof lp.normalize === 'function' ? lp.normalize('NFC') : lp;
}

function isPlausibleDnsDomain(domainCandidate: string): boolean {
  const trimmed = domainCandidate.trim().replace(/\.$/, '');
  if (!trimmed || trimmed.length > 253) return false;
  if (/[\s/@:?#[\]\\]/.test(trimmed)) return false;
  const labels = trimmed.split('.');
  if (labels.length < 1) return false;
  return labels.every((lbl) => lbl.length >= 1 && lbl.length <= 63);
}

/**
 * Synchronous detector for `user@domain` email inputs (as well as pre-hashed
 * `<56-hex>._openpgpkey.<domain>` and `<56-hex>._smimecert.<domain>` owner names).
 */
export function parseEmailDaneInput(rawInput: string): ParsedEmailDaneInput | null {
  if (!rawInput) return null;
  let trimmed = rawInput.trim();
  if (!trimmed) return null;

  // Strip optional RFC 5322 header label (`From:`, `To:`, etc.), `<...>` angle brackets, or `mailto:` URI scheme
  trimmed = trimmed.replace(/^(?:from|to|cc|bcc|reply-to|sender)\s*:\s*/i, '').trim();
  const extractAngleAddr = (s: string): string => {
    if (!s.endsWith('>')) return s;
    const m = /^[^<>]*<([^<>]+)>\s*$/.exec(s);
    if (m && (m[1].includes('@') || /^mailto:/i.test(m[1].trim()))) {
      return m[1].trim();
    }
    return s;
  };
  trimmed = extractAngleAddr(trimmed);
  if (/^mailto:/i.test(trimmed)) {
    let afterMailto = trimmed.slice(7).split(/[?#]/)[0]?.trim() ?? '';
    if (afterMailto.includes('%')) {
      try {
        afterMailto = decodeURIComponent(afterMailto).trim();
      } catch {
        // keep raw if malformed percent-encoding
      }
    }
    trimmed = extractAngleAddr(afterMailto);
  }

  // 1. Check pre-hashed `<56-hex>._openpgpkey.<domain>` or `<56-hex>._smimecert.<domain>`
  const hashedOwnerMatch = /^([0-9a-fA-F]{56})\._(openpgpkey|smimecert)\.(.+?)\.?$/i.exec(trimmed);
  if (hashedOwnerMatch) {
    const hashHex = hashedOwnerMatch[1].toLowerCase();
    const proto = hashedOwnerMatch[2].toLowerCase();
    const domPart = hashedOwnerMatch[3];
    if (!isPlausibleDnsDomain(domPart)) return null;
    const domain = normalizeFqdn(domPart);
    const kind = proto === 'openpgpkey' ? 'openpgpkey-owner' : 'smimea-owner';
    return {
      inputKind: kind,
      canonicalInput: `${hashHex}._${proto}.${displayFqdn(domain)}`,
      domain,
      presetHashHex: hashHex,
    };
  }

  // 2. Check `local-part@domain`
  const atIdx = trimmed.lastIndexOf('@');
  if (atIdx <= 0 || atIdx === trimmed.length - 1) return null;
  if (trimmed.includes('://')) return null;

  const rawLocalPart = trimmed.slice(0, atIdx);
  const rawDomainPart = trimmed.slice(atIdx + 1);
  if (!rawLocalPart || /\s/.test(rawDomainPart) || !isPlausibleDnsDomain(rawDomainPart)) {
    return null;
  }
  // Require at least one dot in domain for `user@domain.tld` (avoids false positives on weird tokens)
  const cleanDomainNoDot = rawDomainPart.replace(/\.$/, '');
  if (!cleanDomainNoDot.includes('.')) return null;

  const localPart = normalizeEmailLocalPart(rawLocalPart);
  if (!localPart) return null;
  const domain = normalizeFqdn(rawDomainPart);
  const canonicalInput = `${localPart}@${displayFqdn(domain)}`;

  return {
    inputKind: 'email',
    canonicalInput,
    localPart,
    domain,
  };
}

/**
 * Computes the RFC 7929 §3 / RFC 8162 §3 local-part identifier:
 * SHA-256 over the UTF-8 local-part truncated to the leftmost 28 octets (56 lowercase hex chars).
 */
export async function computeDaneLocalPartHash(localPart: string): Promise<string> {
  const utf8Bytes = new TextEncoder().encode(localPart);
  const fullDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Bytes));
  return bytesToHex(fullDigest.subarray(0, 28)).toLowerCase();
}

/**
 * Derives full `OPENPGPKEY` (`_openpgpkey.<domain>`) and `SMIMEA` (`_smimecert.<domain>`)
 * query targets (plus lowercase local-part fallback owners per RFC 7929 §4 when uppercase ASCII is present).
 */
export async function deriveEmailDaneTargets(
  rawInput: string
): Promise<DerivedEmailDaneTargets | null> {
  const parsed = parseEmailDaneInput(rawInput);
  if (!parsed) return null;

  if (parsed.inputKind === 'openpgpkey-owner' && parsed.presetHashHex) {
    return {
      ...parsed,
      exactHashHex: parsed.presetHashHex,
      openpgpkeyQname: `${parsed.presetHashHex}._openpgpkey.${parsed.domain}`,
    };
  }

  if (parsed.inputKind === 'smimea-owner' && parsed.presetHashHex) {
    return {
      ...parsed,
      exactHashHex: parsed.presetHashHex,
      smimeaQname: `${parsed.presetHashHex}._smimecert.${parsed.domain}`,
    };
  }

  const localPart = parsed.localPart!;
  const exactHashHex = await computeDaneLocalPartHash(localPart);
  const lowerLocal = localPart.toLowerCase();
  const hasUppercase = lowerLocal !== localPart;
  const lowercaseHashHex = hasUppercase ? await computeDaneLocalPartHash(lowerLocal) : undefined;

  return {
    ...parsed,
    exactHashHex,
    lowercaseHashHex,
    openpgpkeyQname: `${exactHashHex}._openpgpkey.${parsed.domain}`,
    smimeaQname: `${exactHashHex}._smimecert.${parsed.domain}`,
    lowercaseOpenpgpkeyQname: lowercaseHashHex
      ? `${lowercaseHashHex}._openpgpkey.${parsed.domain}`
      : undefined,
    lowercaseSmimeaQname: lowercaseHashHex
      ? `${lowercaseHashHex}._smimecert.${parsed.domain}`
      : undefined,
  };
}

// ============================================================================
// OpenPGP Transferable Public Key Decoder (RFC 4880 / RFC 6637 / RFC 9580)
// ============================================================================

const OPENPGP_PUBKEY_ALGS: Record<number, string> = {
  1: 'RSA (Encrypt or Sign)',
  2: 'RSA (Encrypt-Only)',
  3: 'RSA (Sign-Only)',
  16: 'Elgamal (Encrypt-Only)',
  17: 'DSA',
  18: 'ECDH',
  19: 'ECDSA',
  22: 'EdDSA (Legacy)',
  25: 'X25519 (RFC 9580)',
  26: 'X448 (RFC 9580)',
  27: 'Ed25519 (RFC 9580)',
  28: 'Ed448 (RFC 9580)',
};

const OPENPGP_CURVE_OIDS: Record<string, string> = {
  '2B060104019755010501': 'Curve25519 (Cv25519)',
  '2B06010401DA470F01': 'Ed25519',
  '2A8648CE3D030107': 'NIST P-256',
  '2B81040022': 'NIST P-384',
  '2B81040023': 'NIST P-521',
  '2B2403030208010107': 'BrainpoolP256r1',
  '2B240303020801010B': 'BrainpoolP384r1',
  '2B240303020801010D': 'BrainpoolP512r1',
  '2B8104000A': 'secp256k1',
};

/**
 * Computes the 24-bit OpenPGP Radix-64 CRC24 checksum per RFC 4880 §6.1.
 */
export function computeOpenPgpCrc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i] << 16;
    for (let bit = 0; bit < 8; bit++) {
      crc <<= 1;
      if ((crc & 0x1000000) !== 0) {
        crc ^= 0x1864cfb;
      }
    }
  }
  return crc & 0xffffff;
}

/**
 * Formats binary OpenPGP public key bytes as an RFC 4880 §6 ASCII-armored block with CRC24.
 */
export function armorOpenPgpPublicKey(rawBytes: Uint8Array): string {
  const b64 = bytesToBase64(rawBytes);
  const lines: string[] = ['-----BEGIN PGP PUBLIC KEY BLOCK-----', ''];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  const crc = computeOpenPgpCrc24(rawBytes);
  const crcBytes = new Uint8Array([(crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff]);
  lines.push(`=${bytesToBase64(crcBytes)}`);
  lines.push('-----END PGP PUBLIC KEY BLOCK-----');
  return lines.join('\n');
}

interface RawOpenPgpPacket {
  tag: number;
  body: Uint8Array;
}

function readOpenPgpPackets(buf: Uint8Array): RawOpenPgpPacket[] {
  const packets: RawOpenPgpPacket[] = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let pos = 0;

  while (pos < buf.length) {
    const ctb = buf[pos++];
    if ((ctb & 0x80) === 0) {
      throw new Error(`Invalid OpenPGP packet header byte 0x${ctb.toString(16)} at offset ${pos - 1}`);
    }

    if ((ctb & 0x40) !== 0) {
      // New packet format (RFC 4880 §4.2.2)
      const tag = ctb & 0x3f;
      const chunks: Uint8Array[] = [];
      while (true) {
        if (pos >= buf.length) throw new Error('Truncated OpenPGP new-format packet length');
        const b0 = buf[pos++];
        if (b0 < 192) {
          if (pos + b0 > buf.length) throw new Error('Truncated OpenPGP packet body');
          chunks.push(buf.subarray(pos, pos + b0));
          pos += b0;
          break;
        }
        if (b0 >= 192 && b0 <= 223) {
          if (pos >= buf.length) throw new Error('Truncated OpenPGP 2-byte packet length');
          const b1 = buf[pos++];
          const len = ((b0 - 192) << 8) + b1 + 192;
          if (pos + len > buf.length) throw new Error('Truncated OpenPGP packet body');
          chunks.push(buf.subarray(pos, pos + len));
          pos += len;
          break;
        }
        if (b0 === 255) {
          if (pos + 4 > buf.length) throw new Error('Truncated OpenPGP 5-byte packet length');
          const len = view.getUint32(pos, false);
          pos += 4;
          if (pos + len > buf.length) throw new Error('Truncated OpenPGP packet body');
          chunks.push(buf.subarray(pos, pos + len));
          pos += len;
          break;
        }
        // Partial body length (224..254)
        const partLen = 1 << (b0 & 0x1f);
        if (pos + partLen > buf.length) throw new Error('Truncated OpenPGP partial body chunk');
        chunks.push(buf.subarray(pos, pos + partLen));
        pos += partLen;
      }

      if (chunks.length === 1) {
        packets.push({ tag, body: chunks[0] });
      } else {
        const total = chunks.reduce((acc, c) => acc + c.length, 0);
        const merged = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
          merged.set(c, off);
          off += c.length;
        }
        packets.push({ tag, body: merged });
      }
    } else {
      // Old packet format (RFC 4880 §4.2.1)
      const tag = (ctb >> 2) & 0x0f;
      const lenType = ctb & 0x03;
      let len = 0;
      if (lenType === 0) {
        if (pos >= buf.length) throw new Error('Truncated OpenPGP old-format 1-byte length');
        len = buf[pos++];
      } else if (lenType === 1) {
        if (pos + 2 > buf.length) throw new Error('Truncated OpenPGP old-format 2-byte length');
        len = view.getUint16(pos, false);
        pos += 2;
      } else if (lenType === 2) {
        if (pos + 4 > buf.length) throw new Error('Truncated OpenPGP old-format 4-byte length');
        len = view.getUint32(pos, false);
        pos += 4;
      } else {
        len = buf.length - pos;
      }
      if (pos + len > buf.length) {
        throw new Error('Truncated OpenPGP old-format packet body');
      }
      packets.push({ tag, body: buf.subarray(pos, pos + len) });
      pos += len;
    }
  }

  return packets;
}

interface ParsedSigMetadata {
  sigType: number;
  sigCreatedSec?: number;
  keyExpirationOffsetSec?: number;
  keyFlags?: string[];
}

function decodeKeyFlagsByte(flagByte: number): string[] {
  const flags: string[] = [];
  if (flagByte & 0x01) flags.push('Certify');
  if (flagByte & 0x02) flags.push('Sign');
  if (flagByte & 0x04) flags.push('Encrypt Comm');
  if (flagByte & 0x08) flags.push('Encrypt Storage');
  if (flagByte & 0x20) flags.push('Authenticate');
  return flags;
}

function parseSignatureSubpackets(body: Uint8Array): ParsedSigMetadata | null {
  if (body.length < 6) return null;
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const version = body[0];
  if (version !== 4 && version !== 6) return null;

  const sigType = body[1];
  let hashedLen = 0;
  let subStart = 0;
  if (version === 4) {
    hashedLen = view.getUint16(4, false);
    subStart = 6;
  } else {
    if (body.length < 8) return null;
    hashedLen = view.getUint32(4, false);
    subStart = 8;
  }

  const subEnd = Math.min(body.length, subStart + hashedLen);
  let pos = subStart;
  let sigCreatedSec: number | undefined;
  let keyExpirationOffsetSec: number | undefined;
  let keyFlags: string[] | undefined;

  while (pos < subEnd) {
    const b0 = body[pos++];
    let spLen = 0;
    if (b0 < 192) {
      spLen = b0;
    } else if (b0 < 255) {
      if (pos >= subEnd) break;
      const b1 = body[pos++];
      spLen = ((b0 - 192) << 8) + b1 + 192;
    } else {
      if (pos + 4 > subEnd) break;
      spLen = view.getUint32(pos, false);
      pos += 4;
    }
    if (spLen === 0 || pos + spLen > subEnd) break;

    const spType = body[pos] & 0x7f;
    const spDataStart = pos + 1;
    const spDataLen = spLen - 1;
    if (spType === 2 && spDataLen >= 4) {
      sigCreatedSec = view.getUint32(spDataStart, false);
    } else if (spType === 9 && spDataLen >= 4) {
      keyExpirationOffsetSec = view.getUint32(spDataStart, false);
    } else if (spType === 27 && spDataLen >= 1) {
      keyFlags = decodeKeyFlagsByte(body[spDataStart]);
    }

    pos += spLen;
  }

  return {
    sigType,
    sigCreatedSec,
    keyExpirationOffsetSec,
    keyFlags,
  };
}

async function parsePublicKeyPacketBody(body: Uint8Array): Promise<{
  version: number;
  createdAtSec: number;
  algorithmId: number;
  algorithmName: string;
  curveOrBits: string;
  fingerprintHex: string;
  keyIdHex: string;
}> {
  if (body.length < 6) {
    throw new Error('OpenPGP public-key packet body too short (< 6 bytes)');
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const version = body[0];
  const createdAtSec = view.getUint32(1, false);

  if (version !== 4 && version !== 6) {
    throw new Error(`Unsupported OpenPGP public-key packet version v${version}`);
  }

  const algorithmId = body[5];
  const algorithmName = OPENPGP_PUBKEY_ALGS[algorithmId] ?? `Algorithm ${algorithmId}`;
  const matOffset = version === 6 ? 10 : 6;
  let curveOrBits = '';

  if (matOffset < body.length) {
    if (
      algorithmId === 1 ||
      algorithmId === 2 ||
      algorithmId === 3 ||
      algorithmId === 16 ||
      algorithmId === 17
    ) {
      if (matOffset + 2 <= body.length) {
        const mpiBits = view.getUint16(matOffset, false);
        curveOrBits = `${mpiBits}-bit`;
      }
    } else if (algorithmId === 18 || algorithmId === 19 || algorithmId === 22) {
      const oidLen = body[matOffset];
      if (oidLen > 0 && matOffset + 1 + oidLen <= body.length) {
        const oidHex = bytesToHex(body.subarray(matOffset + 1, matOffset + 1 + oidLen)).toUpperCase();
        curveOrBits = OPENPGP_CURVE_OIDS[oidHex] ?? `OID 0x${oidHex}`;
      }
    } else if (algorithmId === 25 || algorithmId === 27) {
      curveOrBits = '256-bit';
    } else if (algorithmId === 26 || algorithmId === 28) {
      curveOrBits = '448-bit';
    }
  }

  let fingerprintHex = '';
  let keyIdHex = '';
  if (version === 4) {
    const fpInput = new Uint8Array(3 + body.length);
    fpInput[0] = 0x99;
    fpInput[1] = (body.length >>> 8) & 0xff;
    fpInput[2] = body.length & 0xff;
    fpInput.set(body, 3);
    const sha1 = new Uint8Array(await crypto.subtle.digest('SHA-1', fpInput));
    fingerprintHex = bytesToHex(sha1).toUpperCase();
    keyIdHex = fingerprintHex.slice(-16);
  } else {
    const fpInput = new Uint8Array(5 + body.length);
    fpInput[0] = 0x9b;
    fpInput[1] = (body.length >>> 24) & 0xff;
    fpInput[2] = (body.length >>> 16) & 0xff;
    fpInput[3] = (body.length >>> 8) & 0xff;
    fpInput[4] = body.length & 0xff;
    fpInput.set(body, 5);
    const sha256 = new Uint8Array(await crypto.subtle.digest('SHA-256', fpInput));
    fingerprintHex = bytesToHex(sha256).toUpperCase();
    keyIdHex = fingerprintHex.slice(0, 16);
  }

  return {
    version,
    createdAtSec,
    algorithmId,
    algorithmName,
    curveOrBits,
    fingerprintHex,
    keyIdHex,
  };
}

function doesUidMatchEmail(userIds: string[], email: string): boolean {
  const targetLower = email.trim().toLowerCase();
  for (const uid of userIds) {
    const angleMatch = /<([^>]+)>/.exec(uid);
    const candidate = (angleMatch ? angleMatch[1] : uid).trim().toLowerCase();
    if (candidate === targetLower || uid.toLowerCase().includes(targetLower)) {
      return true;
    }
  }
  return false;
}

/**
 * Parses a binary OpenPGP Transferable Public Key (RFC 4880 §11.1 / RFC 9580) from an `OPENPGPKEY` RR.
 */
export async function decodeOpenPgpTransferablePublicKey(
  rawBytes: Uint8Array,
  options: { queriedEmail?: string; validationTimeSec?: number } = {}
): Promise<DecodedOpenPgpTransferableKey> {
  const nowSec = options.validationTimeSec ?? Math.floor(Date.now() / 1000);
  const packets = readOpenPgpPackets(rawBytes);
  const primaryPkt = packets.find((p) => p.tag === 6);
  if (!primaryPkt) {
    throw new Error('OPENPGPKEY RDATA does not contain a Primary Public-Key packet (Tag 6)');
  }

  const primaryParsed = await parsePublicKeyPacketBody(primaryPkt.body);
  const userIds: string[] = [];
  let userAttributeCount = 0;
  const subkeys: OpenPgpSubkeyInfo[] = [];

  let primaryBestSigSec = -1;
  let primaryExpOffset: number | undefined;
  const primaryFlags = new Set<string>();
  let primaryRevoked = false;

  let currentSubkey:
    | (OpenPgpSubkeyInfo & { bestSigSec: number; expOffset?: number; flagSet: Set<string> })
    | null = null;

  const dec = new TextDecoder('utf-8', { fatal: false });

  for (const pkt of packets) {
    if (pkt.tag === 6) {
      currentSubkey = null;
    } else if (pkt.tag === 13) {
      currentSubkey = null;
      const uid = dec.decode(pkt.body).trim();
      if (uid && !userIds.includes(uid)) {
        userIds.push(uid);
      }
    } else if (pkt.tag === 17) {
      currentSubkey = null;
      userAttributeCount++;
    } else if (pkt.tag === 14) {
      const subParsed = await parsePublicKeyPacketBody(pkt.body);
      const subObj = {
        ...subParsed,
        isExpired: false,
        isRevoked: false,
        keyFlags: [] as string[],
        bestSigSec: -1,
        expOffset: undefined as number | undefined,
        flagSet: new Set<string>(),
      };
      subkeys.push(subObj);
      currentSubkey = subObj;
    } else if (pkt.tag === 2) {
      const sig = parseSignatureSubpackets(pkt.body);
      if (!sig) continue;
      const sigSec = sig.sigCreatedSec ?? 0;

      if (sig.sigType === 0x20) {
        primaryRevoked = true;
      } else if (sig.sigType === 0x28 && currentSubkey) {
        currentSubkey.isRevoked = true;
      } else if (sig.sigType === 0x18 && currentSubkey) {
        if (sig.keyFlags) {
          for (const f of sig.keyFlags) currentSubkey.flagSet.add(f);
        }
        if (sigSec >= currentSubkey.bestSigSec) {
          currentSubkey.bestSigSec = sigSec;
          if (sig.keyExpirationOffsetSec !== undefined) {
            currentSubkey.expOffset = sig.keyExpirationOffsetSec;
          }
        }
      } else if (
        (sig.sigType >= 0x10 && sig.sigType <= 0x13) ||
        sig.sigType === 0x1f
      ) {
        if (sig.keyFlags) {
          for (const f of sig.keyFlags) primaryFlags.add(f);
        }
        if (sigSec >= primaryBestSigSec) {
          primaryBestSigSec = sigSec;
          if (sig.keyExpirationOffsetSec !== undefined) {
            primaryExpOffset = sig.keyExpirationOffsetSec;
          }
        }
      }
    }
  }

  const cleanSubkeys: OpenPgpSubkeyInfo[] = subkeys.map((sk) => {
    const rawSk = sk as OpenPgpSubkeyInfo & {
      expOffset?: number;
      flagSet: Set<string>;
    };
    const expiresAtSec =
      rawSk.expOffset && rawSk.expOffset > 0 ? rawSk.createdAtSec + rawSk.expOffset : undefined;
    return {
      version: rawSk.version,
      algorithmId: rawSk.algorithmId,
      algorithmName: rawSk.algorithmName,
      curveOrBits: rawSk.curveOrBits,
      fingerprintHex: rawSk.fingerprintHex,
      keyIdHex: rawSk.keyIdHex,
      createdAtSec: rawSk.createdAtSec,
      expiresAtSec,
      isExpired: expiresAtSec !== undefined && nowSec > expiresAtSec,
      isRevoked: rawSk.isRevoked,
      keyFlags: Array.from(rawSk.flagSet),
    };
  });

  const primaryExpiresAtSec =
    primaryExpOffset && primaryExpOffset > 0
      ? primaryParsed.createdAtSec + primaryExpOffset
      : undefined;

  return {
    version: primaryParsed.version,
    algorithmId: primaryParsed.algorithmId,
    algorithmName: primaryParsed.algorithmName,
    curveOrBits: primaryParsed.curveOrBits,
    fingerprintHex: primaryParsed.fingerprintHex,
    keyIdHex: primaryParsed.keyIdHex,
    createdAtSec: primaryParsed.createdAtSec,
    expiresAtSec: primaryExpiresAtSec,
    isExpired: primaryExpiresAtSec !== undefined && nowSec > primaryExpiresAtSec,
    isRevoked: primaryRevoked,
    keyFlags: Array.from(primaryFlags),
    userIds,
    userAttributeCount,
    subkeys: cleanSubkeys,
    armoredPublicKey: armorOpenPgpPublicKey(rawBytes),
    byteLength: rawBytes.length,
    ...(options.queriedEmail && userIds.length > 0
      ? { matchesQueriedEmail: doesUidMatchEmail(userIds, options.queriedEmail) }
      : {}),
  };
}

// ============================================================================
// ASN.1 DER X.509 & SPKI Decoder for SMIMEA (RFC 8162 / RFC 5280)
// ============================================================================

interface DerElement {
  offset: number;
  tag: number;
  tagClass: number;
  isConstructed: boolean;
  tagNumber: number;
  contentStart: number;
  contentEnd: number;
  nextOffset: number;
}

function readDerElement(buf: Uint8Array, offset: number): DerElement {
  if (offset + 2 > buf.length) {
    throw new Error(`Truncated ASN.1 DER header at offset ${offset}`);
  }
  const tag = buf[offset];
  const tagClass = (tag >>> 6) & 0x03;
  const isConstructed = (tag & 0x20) !== 0;
  const tagNumber = tag & 0x1f;

  let pos = offset + 1;
  const lenByte = buf[pos++];
  let length = 0;
  if ((lenByte & 0x80) === 0) {
    length = lenByte;
  } else {
    const numOctets = lenByte & 0x7f;
    if (numOctets === 0 || numOctets > 4 || pos + numOctets > buf.length) {
      throw new Error(`Invalid ASN.1 DER length encoding at offset ${offset}`);
    }
    for (let i = 0; i < numOctets; i++) {
      length = (length << 8) | buf[pos++];
    }
  }

  const contentStart = pos;
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) {
    throw new Error(`ASN.1 DER element overflows buffer (${contentEnd} > ${buf.length})`);
  }

  return {
    offset,
    tag,
    tagClass,
    isConstructed,
    tagNumber,
    contentStart,
    contentEnd,
    nextOffset: contentEnd,
  };
}

function readDerChildren(buf: Uint8Array, parent: DerElement): DerElement[] {
  const children: DerElement[] = [];
  let pos = parent.contentStart;
  while (pos < parent.contentEnd) {
    const el = readDerElement(buf, pos);
    children.push(el);
    pos = el.nextOffset;
  }
  return children;
}

function decodeDerOid(oidBytes: Uint8Array): string {
  if (oidBytes.length === 0) return '';
  const parts: number[] = [Math.floor(oidBytes[0] / 40), oidBytes[0] % 40];
  let val = 0;
  for (let i = 1; i < oidBytes.length; i++) {
    val = val * 128 + (oidBytes[i] & 0x7f);
    if ((oidBytes[i] & 0x80) === 0) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join('.');
}

const OID_NAMES: Record<string, string> = {
  // DN attributes
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.42': 'givenName',
  '2.5.4.4': 'SN',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC',
  // Signature & Public Key Algorithms
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'ECDSA / EC',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  // Named Elliptic Curves
  '1.2.840.10045.3.1.7': 'NIST P-256',
  '1.3.132.0.34': 'NIST P-384',
  '1.3.132.0.35': 'NIST P-521',
  '1.3.132.0.10': 'secp256k1',
};

function decodeDerString(buf: Uint8Array, el: DerElement): string {
  const bytes = buf.subarray(el.contentStart, el.contentEnd);
  if (el.tag === 0x1e) {
    // BMPString (UTF-16BE)
    let out = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function parseDerDistinguishedName(
  buf: Uint8Array,
  nameEl: DerElement
): { dn: string; emails: string[] } {
  const parts: string[] = [];
  const emails: string[] = [];
  const rdnSets = readDerChildren(buf, nameEl);
  for (const rdnSet of rdnSets) {
    for (const atvSeq of readDerChildren(buf, rdnSet)) {
      const pair = readDerChildren(buf, atvSeq);
      if (pair.length >= 2 && pair[0].tag === 0x06) {
        const oid = decodeDerOid(buf.subarray(pair[0].contentStart, pair[0].contentEnd));
        const attrName = OID_NAMES[oid] ?? oid;
        const val = decodeDerString(buf, pair[1]);
        parts.push(`${attrName}=${val}`);
        if (oid === '1.2.840.113549.1.9.1' && val) {
          emails.push(val);
        }
      }
    }
  }
  return { dn: parts.join(', '), emails };
}

function parseDerTime(buf: Uint8Array, el: DerElement): number {
  const raw = new TextDecoder('ascii').decode(buf.subarray(el.contentStart, el.contentEnd)).trim();
  if (el.tag === 0x17) {
    // UTCTime: YYMMDDHHMM[SS]Z
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(raw);
    if (!m) throw new Error(`Invalid X.509 UTCTime "${raw}"`);
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return Math.floor(
      Date.UTC(
        year,
        Number(m[2]) - 1,
        Number(m[3]),
        Number(m[4]),
        Number(m[5]),
        Number(m[6] ?? '0')
      ) / 1000
    );
  }
  if (el.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMM[SS]Z
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(raw);
    if (!m) throw new Error(`Invalid X.509 GeneralizedTime "${raw}"`);
    return Math.floor(
      Date.UTC(
        Number(m[1]),
        Number(m[2]) - 1,
        Number(m[3]),
        Number(m[4]),
        Number(m[5]),
        Number(m[6] ?? '0')
      ) / 1000
    );
  }
  throw new Error(`Unsupported X.509 Time ASN.1 tag 0x${el.tag.toString(16)}`);
}

export function formatPemBlock(derBytes: Uint8Array, label: 'CERTIFICATE' | 'PUBLIC KEY'): string {
  const b64 = bytesToBase64(derBytes);
  const lines: string[] = [`-----BEGIN ${label}-----`];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  lines.push(`-----END ${label}-----`);
  return lines.join('\n');
}

export async function decodeSpkiDer(
  spkiBytes: Uint8Array
): Promise<{
  publicKeyAlgorithm: string;
  publicKeyBitsOrCurve?: string;
  spkiSha256Hex: string;
  pem: string;
}> {
  const spkiEl = readDerElement(spkiBytes, 0);
  if (spkiEl.tag !== 0x30) {
    throw new Error('SubjectPublicKeyInfo is not an ASN.1 SEQUENCE');
  }
  const children = readDerChildren(spkiBytes, spkiEl);
  if (children.length < 2 || children[0].tag !== 0x30 || children[1].tag !== 0x03) {
    throw new Error('Malformed SubjectPublicKeyInfo children');
  }

  const algChildren = readDerChildren(spkiBytes, children[0]);
  const algOid =
    algChildren[0]?.tag === 0x06
      ? decodeDerOid(spkiBytes.subarray(algChildren[0].contentStart, algChildren[0].contentEnd))
      : '';
  const publicKeyAlgorithm = OID_NAMES[algOid] ?? (algOid || 'Unknown');
  let publicKeyBitsOrCurve: string | undefined;

  if (algOid === '1.2.840.10045.2.1' && algChildren[1]?.tag === 0x06) {
    const curveOid = decodeDerOid(
      spkiBytes.subarray(algChildren[1].contentStart, algChildren[1].contentEnd)
    );
    publicKeyBitsOrCurve = OID_NAMES[curveOid] ?? curveOid;
  } else if (algOid === '1.2.840.113549.1.1.1') {
    // Parse BIT STRING -> RSAPublicKey SEQUENCE { modulus INTEGER, exponent INTEGER }
    const bitStrStart = children[1].contentStart;
    if (bitStrStart + 2 < children[1].contentEnd && spkiBytes[bitStrStart] === 0x00) {
      try {
        const rsaSeq = readDerElement(spkiBytes, bitStrStart + 1);
        const rsaParts = readDerChildren(spkiBytes, rsaSeq);
        if (rsaParts[0]?.tag === 0x02) {
          let modStart = rsaParts[0].contentStart;
          while (modStart < rsaParts[0].contentEnd && spkiBytes[modStart] === 0x00) {
            modStart++;
          }
          const modBytes = rsaParts[0].contentEnd - modStart;
          if (modBytes > 0) {
            const topByte = spkiBytes[modStart];
            const leadingZeros = Math.clz32(topByte) - 24;
            const bits = modBytes * 8 - leadingZeros;
            publicKeyBitsOrCurve = `${bits}-bit`;
          }
        }
      } catch {
        // Ignore inner RSA modulus parse failure
      }
    }
  } else if (algOid === '1.3.101.112' || algOid === '1.3.101.110') {
    publicKeyBitsOrCurve = '256-bit';
  }

  const digest = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      spkiBytes.slice(spkiEl.offset, spkiEl.nextOffset)
    )
  );
  return {
    publicKeyAlgorithm,
    publicKeyBitsOrCurve,
    spkiSha256Hex: bytesToHex(digest).toLowerCase(),
    pem: formatPemBlock(spkiBytes.subarray(spkiEl.offset, spkiEl.nextOffset), 'PUBLIC KEY'),
  };
}

/**
 * Parses a full ASN.1 DER X.509 Certificate (`SMIMEA` with `selector=0, matchingType=0`).
 */
export async function decodeX509CertificateDer(
  derBytes: Uint8Array,
  options: { queriedEmail?: string; validationTimeSec?: number } = {}
): Promise<DecodedX509Certificate> {
  const nowSec = options.validationTimeSec ?? Math.floor(Date.now() / 1000);
  const certEl = readDerElement(derBytes, 0);
  if (certEl.tag !== 0x30) {
    throw new Error('X.509 Certificate is not an ASN.1 DER SEQUENCE');
  }
  const certParts = readDerChildren(derBytes, certEl);
  if (certParts.length < 3 || certParts[0].tag !== 0x30 || certParts[1].tag !== 0x30) {
    throw new Error('Malformed outer X.509 Certificate structure');
  }

  const tbsChildren = readDerChildren(derBytes, certParts[0]);
  let idx = 0;
  let version = 1;
  if (tbsChildren[0]?.tag === 0xa0) {
    const verInner = readDerChildren(derBytes, tbsChildren[0])[0];
    if (verInner?.tag === 0x02 && verInner.contentEnd > verInner.contentStart) {
      version = derBytes[verInner.contentStart] + 1;
    }
    idx = 1;
  }

  if (tbsChildren.length < idx + 6) {
    throw new Error('Truncated X.509 TBSCertificate fields');
  }

  const serialEl = tbsChildren[idx];
  const sigAlgEl = tbsChildren[idx + 1];
  const issuerEl = tbsChildren[idx + 2];
  const validityEl = tbsChildren[idx + 3];
  const subjectEl = tbsChildren[idx + 4];
  const spkiEl = tbsChildren[idx + 5];

  const serialBytes = derBytes.subarray(serialEl.contentStart, serialEl.contentEnd);
  const serialHex = Array.from(serialBytes)
    .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(':');

  const sigAlgChildren = readDerChildren(derBytes, sigAlgEl);
  const sigOid =
    sigAlgChildren[0]?.tag === 0x06
      ? decodeDerOid(derBytes.subarray(sigAlgChildren[0].contentStart, sigAlgChildren[0].contentEnd))
      : '';
  const signatureAlgorithm = OID_NAMES[sigOid] ?? (sigOid || 'Unknown');

  const issuerParsed = parseDerDistinguishedName(derBytes, issuerEl);
  const subjectParsed = parseDerDistinguishedName(derBytes, subjectEl);

  const valChildren = readDerChildren(derBytes, validityEl);
  if (valChildren.length < 2) {
    throw new Error('Malformed X.509 Validity period');
  }
  const notBeforeSec = parseDerTime(derBytes, valChildren[0]);
  const notAfterSec = parseDerTime(derBytes, valChildren[1]);

  const spkiSlice = derBytes.subarray(spkiEl.offset, spkiEl.nextOffset);
  const spkiDecoded = await decodeSpkiDer(spkiSlice);

  const sanRfc822Names: string[] = [];
  const sanDnsNames: string[] = [];
  let hasEmailProtectionEku = false;
  let isCa: boolean | undefined;

  for (let k = idx + 6; k < tbsChildren.length; k++) {
    const extWrapper = tbsChildren[k];
    if (extWrapper.tag === 0xa3) {
      const extSeq = readDerChildren(derBytes, extWrapper)[0];
      if (!extSeq || extSeq.tag !== 0x30) continue;
      for (const ext of readDerChildren(derBytes, extSeq)) {
        if (ext.tag !== 0x30) continue;
        const extFields = readDerChildren(derBytes, ext);
        if (extFields.length < 2 || extFields[0].tag !== 0x06) continue;
        const extOid = decodeDerOid(
          derBytes.subarray(extFields[0].contentStart, extFields[0].contentEnd)
        );
        const octEl = extFields[extFields.length - 1];
        if (octEl.tag !== 0x04) continue;
        const extValBytes = derBytes.subarray(octEl.contentStart, octEl.contentEnd);

        try {
          if (extOid === '2.5.29.17' && extValBytes.length >= 2) {
            // subjectAltName ::= GeneralNames
            const gnSeq = readDerElement(extValBytes, 0);
            for (const gn of readDerChildren(extValBytes, gnSeq)) {
              if (gn.tag === 0x81) {
                // [1] rfc822Name (IA5String)
                const mail = new TextDecoder('utf-8', { fatal: false })
                  .decode(extValBytes.subarray(gn.contentStart, gn.contentEnd))
                  .trim();
                if (mail && !sanRfc822Names.includes(mail)) sanRfc822Names.push(mail);
              } else if (gn.tag === 0x82) {
                // [2] dNSName (IA5String)
                const dns = new TextDecoder('utf-8', { fatal: false })
                  .decode(extValBytes.subarray(gn.contentStart, gn.contentEnd))
                  .trim();
                if (dns && !sanDnsNames.includes(dns)) sanDnsNames.push(dns);
              }
            }
          } else if (extOid === '2.5.29.19' && extValBytes.length >= 2) {
            // basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
            const bcSeq = readDerElement(extValBytes, 0);
            const bcChildren = readDerChildren(extValBytes, bcSeq);
            isCa = bcChildren[0]?.tag === 0x01 && extValBytes[bcChildren[0].contentStart] !== 0;
          } else if (extOid === '2.5.29.37' && extValBytes.length >= 2) {
            // extKeyUsage ::= SEQUENCE OF KeyPurposeId
            const ekuSeq = readDerElement(extValBytes, 0);
            for (const kp of readDerChildren(extValBytes, ekuSeq)) {
              if (kp.tag === 0x06) {
                const kpOid = decodeDerOid(extValBytes.subarray(kp.contentStart, kp.contentEnd));
                if (kpOid === '1.3.6.1.5.5.7.3.4') {
                  hasEmailProtectionEku = true;
                }
              }
            }
          }
        } catch {
          // Ignore malformed individual X.509 extension
        }
      }
    }
  }

  const certSha256 = new Uint8Array(
    await crypto.subtle.digest('SHA-256', derBytes.slice(certEl.offset, certEl.nextOffset))
  );
  const allEmails = [...sanRfc822Names, ...subjectParsed.emails].map((e) => e.toLowerCase());
  const matchesQueriedEmail = options.queriedEmail
    ? allEmails.includes(options.queriedEmail.toLowerCase())
    : undefined;

  return {
    version,
    serialHex,
    signatureAlgorithm,
    subject: subjectParsed.dn || '(Empty Subject DN)',
    subjectEmailAddresses: subjectParsed.emails,
    sanRfc822Names,
    sanDnsNames,
    issuer: issuerParsed.dn || '(Empty Issuer DN)',
    isSelfIssued: Boolean(subjectParsed.dn && subjectParsed.dn === issuerParsed.dn),
    notBeforeSec,
    notBeforeIso: new Date(notBeforeSec * 1000).toISOString(),
    notAfterSec,
    notAfterIso: new Date(notAfterSec * 1000).toISOString(),
    isExpired: nowSec > notAfterSec,
    isNotYetValid: nowSec < notBeforeSec,
    publicKeyAlgorithm: spkiDecoded.publicKeyAlgorithm,
    publicKeyBitsOrCurve: spkiDecoded.publicKeyBitsOrCurve,
    hasEmailProtectionEku,
    isCa,
    sha256FingerprintHex: bytesToHex(certSha256).toUpperCase(),
    spkiSha256Hex: spkiDecoded.spkiSha256Hex,
    pem: formatPemBlock(derBytes.subarray(certEl.offset, certEl.nextOffset), 'CERTIFICATE'),
    ...(matchesQueriedEmail !== undefined && allEmails.length > 0 ? { matchesQueriedEmail } : {}),
  };
}

// ============================================================================
// Snapshot Evaluator for OPENPGPKEY (RFC 7929) & SMIMEA (RFC 8162)
// ============================================================================

function walkCnameFromSnapshot(
  startOwner: string,
  rrtype: number,
  zones: ZoneAnalysis[],
  cnameEdges: CnameEdge[]
): { terminalOwner: string; cnameChain: string[]; rrset?: AnalyzedRrset; negNode?: NegativeNode } {
  const qtypeName = rrtype === RR_TYPES.OPENPGPKEY ? 'OPENPGPKEY' : 'SMIMEA';
  let cur = startOwner;
  const visited = new Set<string>([cur]);
  const chain: string[] = [];

  for (let hop = 0; hop < 8; hop++) {
    const edge = cnameEdges.find(
      (e) => e.fromName === cur && e.qtypeName === qtypeName
    );
    if (edge) {
      if (visited.has(edge.toName)) break;
      visited.add(edge.toName);
      chain.push(edge.toName);
      cur = edge.toName;
      continue;
    }
    let cnameRr: AnalyzedRrset | undefined;
    for (const z of zones) {
      cnameRr = z.rrsets.find((r) => r.name === cur && r.type === RR_TYPES.CNAME);
      if (cnameRr) break;
    }
    const nextTarget =
      cnameRr?.records[0]?.parsed.kind === 'GENERIC' ? cnameRr.records[0].parsed.target : undefined;
    if (!nextTarget) break;
    const normNext = normalizeFqdn(nextTarget);
    if (visited.has(normNext)) break;
    visited.add(normNext);
    chain.push(normNext);
    cur = normNext;
  }

  let rrset: AnalyzedRrset | undefined;
  let negNode: NegativeNode | undefined;
  for (const z of zones) {
    if (!rrset) {
      rrset = z.rrsets.find((r) => r.name === cur && r.type === rrtype);
    }
    if (!negNode) {
      negNode = z.negativeNodes.find((n) => n.qname === cur && n.qtypeName === qtypeName);
    }
  }

  return { terminalOwner: cur, cnameChain: chain, rrset, negNode };
}

function resolveAuthoritativeZoneStatus(owner: string, zones: ZoneAnalysis[]): ValidationStatus {
  const matching = zones
    .filter((z) => z.zoneName === '.' || owner === z.zoneName || owner.endsWith(`.${z.zoneName}`))
    .sort((a, b) => b.depth - a.depth);
  return matching[0]?.status ?? 'indeterminate';
}

export async function evaluateEmailDaneFromSnapshotData(params: {
  derivedTargets: DerivedEmailDaneTargets;
  queries: DohQueryLog[];
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  dohEndpoint: string;
  validatedAt: number;
}): Promise<{
  emailDane: EmailDaneAnalysis;
  findings: AuditFinding[];
  overallStatusOverride?: SnapshotStatus;
  overallSummaryOverride?: string;
}> {
  const { derivedTargets, queries, zones, cnameEdges, dohEndpoint, validatedAt } = params;
  const validationTimeSec = Math.floor(validatedAt / 1000);
  const findings: AuditFinding[] = [];
  const cdLogs = queries.filter((q) => q.cd);
  const dohShort = formatDohShortLabel(dohEndpoint);

  let openpgpkeyResult: EmailDaneProtocolResult<EmailDaneOpenPgpRecord> | undefined;
  let smimeaResult: EmailDaneProtocolResult<EmailDaneSmimeaRecord> | undefined;

  // 1. Evaluate OPENPGPKEY (RFC 7929)
  if (derivedTargets.openpgpkeyQname) {
    let activeOwner = derivedTargets.openpgpkeyQname;
    let usedLowercase = false;
    let walked = walkCnameFromSnapshot(activeOwner, RR_TYPES.OPENPGPKEY, zones, cnameEdges);

    if (
      !walked.rrset &&
      derivedTargets.lowercaseOpenpgpkeyQname &&
      cdLogs.some(
        (q) =>
          q.qname === derivedTargets.lowercaseOpenpgpkeyQname && q.qtype === RR_TYPES.OPENPGPKEY
      )
    ) {
      const lowerWalked = walkCnameFromSnapshot(
        derivedTargets.lowercaseOpenpgpkeyQname,
        RR_TYPES.OPENPGPKEY,
        zones,
        cnameEdges
      );
      if (lowerWalked.rrset) {
        activeOwner = derivedTargets.lowercaseOpenpgpkeyQname;
        usedLowercase = true;
        walked = lowerWalked;
      }
    }

    const log = cdLogs.find(
      (q) => q.qname === walked.terminalOwner && q.qtype === RR_TYPES.OPENPGPKEY
    ) ?? cdLogs.find((q) => q.qname === activeOwner && q.qtype === RR_TYPES.OPENPGPKEY);

    const rawAnswers =
      walked.rrset?.records ??
      (log?.packet.answers ?? []).filter(
        (r) => r.name === walked.terminalOwner && r.type === RR_TYPES.OPENPGPKEY
      );

    let status: EmailDaneProtocolResult<EmailDaneOpenPgpRecord>['status'] = 'nodata';
    if (rawAnswers.length > 0) {
      status = 'present';
    } else if (walked.negNode) {
      status = walked.negNode.kind === 'NXDOMAIN' ? 'nxdomain' : 'nodata';
    } else if (log) {
      status =
        log.packet.flags.rcode === 3
          ? 'nxdomain'
          : log.packet.flags.rcode === 0
            ? 'nodata'
            : 'error';
    }

    const dnssecStatus: ValidationStatus =
      walked.rrset?.status ??
      walked.negNode?.status ??
      resolveAuthoritativeZoneStatus(walked.terminalOwner, zones);

    const daneUsable =
      status === 'present' && (dnssecStatus === 'secure' || dnssecStatus === 'warning');

    const records: EmailDaneOpenPgpRecord[] = [];
    for (let i = 0; i < rawAnswers.length; i++) {
      const rec = rawAnswers[i];
      const keyBase64 =
        rec.parsed.kind === 'OPENPGPKEY' ? rec.parsed.keyBase64 : rec.canonicalRdataBase64;
      const rawBytes = base64ToBytes(keyBase64);
      try {
        const decodedKey = await decodeOpenPgpTransferablePublicKey(rawBytes, {
          queriedEmail: derivedTargets.canonicalInput,
          validationTimeSec,
        });
        records.push({
          index: i + 1,
          ttl: rec.ttl,
          byteLength: rawBytes.length,
          keyBase64,
          decodedKey,
        });
      } catch (err) {
        records.push({
          index: i + 1,
          ttl: rec.ttl,
          byteLength: rawBytes.length,
          keyBase64,
          parseError: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const cleanQname = displayFqdn(activeOwner);
    const cliVerifyCommand = derivedTargets.localPart
      ? `dig +dnssec +short ${cleanQname} OPENPGPKEY @${dohShort === '1.1.1.1' || dohShort === '8.8.8.8' || dohShort === '9.9.9.9' ? dohShort : '1.1.1.1'} | tr -d ' \\n' | base64 -d | gpg --show-keys --with-fingerprint`
      : `dig +dnssec +short ${cleanQname} OPENPGPKEY @1.1.1.1 | tr -d ' \\n' | base64 -d | gpg --show-keys --with-fingerprint`;

    openpgpkeyResult = {
      protocol: 'OPENPGPKEY',
      rfc: 'RFC 7929',
      queriedOwner: derivedTargets.openpgpkeyQname,
      resolvedOwner: walked.terminalOwner,
      usedLowercaseFallback: usedLowercase,
      cnameChain: walked.cnameChain,
      status,
      dnssecStatus,
      daneUsable,
      rrsetId: walked.rrset?.id,
      negativeNodeId: walked.negNode?.id,
      records,
      cliVerifyCommand,
    };

    if (status === 'present') {
      if (dnssecStatus === 'insecure') {
        findings.push({
          id: `warn-openpgpkey-unsigned-${walked.terminalOwner}`,
          severity: 'warning',
          code: 'EMAIL_DANE_UNSIGNED_IGNORE',
          title: `OPENPGPKEY published in unsigned zone (${displayFqdn(walked.terminalOwner)}) — MUST NOT be used`,
          detail: `RFC 7929 §1.1 & §5 mandate DNSSEC validation for OPENPGPKEY records. Because ${displayFqdn(walked.terminalOwner)} is unsigned (INSECURE), clients MUST ignore this OpenPGP key to prevent active network MitM key substitution.`,
          rfc: 'RFC 7929 §5',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      } else if (dnssecStatus === 'bogus') {
        findings.push({
          id: `err-openpgpkey-bogus-${walked.terminalOwner}`,
          severity: 'error',
          code: 'EMAIL_DANE_BOGUS_DNSSEC',
          title: `OPENPGPKEY failed DNSSEC cryptographic validation (${displayFqdn(walked.terminalOwner)})`,
          detail: `DNSSEC validation returned BOGUS for ${displayFqdn(walked.terminalOwner)} OPENPGPKEY. Per RFC 7929 §5, the OpenPGP public key MUST be rejected.`,
          rfc: 'RFC 7929 §5',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      } else if (daneUsable) {
        findings.push({
          id: `info-openpgpkey-secure-${walked.terminalOwner}`,
          severity: 'info',
          code: 'OPENPGPKEY_DANE_VERIFIED',
          title: `Authenticated RFC 7929 OPENPGPKEY verified via DNSSEC (${records.length} key${records.length === 1 ? '' : 's'})`,
          detail: `Cryptographically verified ${records.length} OpenPGP Transferable Public Key RR(s) at ${displayFqdn(walked.terminalOwner)}${usedLowercase ? ' (matched via lowercase local-part fallback per RFC 7929 §4)' : ''}.`,
          rfc: 'RFC 7929 §3',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      }

      for (const rec of records) {
        if (rec.parseError) {
          findings.push({
            id: `err-openpgpkey-parse-${walked.terminalOwner}-${rec.index}`,
            severity: 'error',
            code: 'OPENPGPKEY_MALFORMED_PACKET',
            title: `Malformed OpenPGP Transferable Public Key in OPENPGPKEY RR #${rec.index}`,
            detail: rec.parseError,
            rfc: 'RFC 7929 §2.1 / RFC 4880',
            zone: derivedTargets.domain,
            targetId: walked.rrset?.id,
          });
        } else if (rec.decodedKey) {
          const dk = rec.decodedKey;
          if (dk.isRevoked || dk.isExpired) {
            findings.push({
              id: `warn-openpgpkey-lifecycle-${walked.terminalOwner}-${rec.index}`,
              severity: 'warning',
              code: 'OPENPGPKEY_EXPIRED_OR_REVOKED',
              title: `OpenPGP key ${dk.keyIdHex} in OPENPGPKEY is ${dk.isRevoked ? 'REVOKED' : 'EXPIRED'}`,
              detail: dk.isRevoked
                ? `Primary key ${dk.fingerprintHex} carries a key revocation signature (0x20).`
                : `Primary key ${dk.fingerprintHex} expired at ${new Date((dk.expiresAtSec ?? 0) * 1000).toISOString()}.`,
              rfc: 'RFC 4880 §5.2.3.6',
              zone: derivedTargets.domain,
              targetId: walked.rrset?.id,
            });
          }
          if (dk.matchesQueriedEmail === false) {
            findings.push({
              id: `warn-openpgpkey-uid-${walked.terminalOwner}-${rec.index}`,
              severity: 'warning',
              code: 'OPENPGPKEY_UID_MISMATCH',
              title: `OpenPGP User ID does not list ${derivedTargets.canonicalInput}`,
              detail: `RFC 7929 §5 recommends verifying that a User ID packet matches the target email address. Published User IDs: ${dk.userIds.join('; ')}.`,
              rfc: 'RFC 7929 §5',
              zone: derivedTargets.domain,
              targetId: walked.rrset?.id,
            });
          }
        }
      }
    }
  }

  // 2. Evaluate SMIMEA (RFC 8162)
  if (derivedTargets.smimeaQname) {
    let activeOwner = derivedTargets.smimeaQname;
    let usedLowercase = false;
    let walked = walkCnameFromSnapshot(activeOwner, RR_TYPES.SMIMEA, zones, cnameEdges);

    if (
      !walked.rrset &&
      derivedTargets.lowercaseSmimeaQname &&
      cdLogs.some(
        (q) => q.qname === derivedTargets.lowercaseSmimeaQname && q.qtype === RR_TYPES.SMIMEA
      )
    ) {
      const lowerWalked = walkCnameFromSnapshot(
        derivedTargets.lowercaseSmimeaQname,
        RR_TYPES.SMIMEA,
        zones,
        cnameEdges
      );
      if (lowerWalked.rrset) {
        activeOwner = derivedTargets.lowercaseSmimeaQname;
        usedLowercase = true;
        walked = lowerWalked;
      }
    }

    const log = cdLogs.find(
      (q) => q.qname === walked.terminalOwner && q.qtype === RR_TYPES.SMIMEA
    ) ?? cdLogs.find((q) => q.qname === activeOwner && q.qtype === RR_TYPES.SMIMEA);

    const rawAnswers =
      walked.rrset?.records ??
      (log?.packet.answers ?? []).filter(
        (r) => r.name === walked.terminalOwner && r.type === RR_TYPES.SMIMEA
      );

    let status: EmailDaneProtocolResult<EmailDaneSmimeaRecord>['status'] = 'nodata';
    if (rawAnswers.length > 0) {
      status = 'present';
    } else if (walked.negNode) {
      status = walked.negNode.kind === 'NXDOMAIN' ? 'nxdomain' : 'nodata';
    } else if (log) {
      status =
        log.packet.flags.rcode === 3
          ? 'nxdomain'
          : log.packet.flags.rcode === 0
            ? 'nodata'
            : 'error';
    }

    const dnssecStatus: ValidationStatus =
      walked.rrset?.status ??
      walked.negNode?.status ??
      resolveAuthoritativeZoneStatus(walked.terminalOwner, zones);

    const daneUsable =
      status === 'present' && (dnssecStatus === 'secure' || dnssecStatus === 'warning');

    const records: EmailDaneSmimeaRecord[] = [];
    for (let i = 0; i < rawAnswers.length; i++) {
      const rec = rawAnswers[i];
      if (rec.parsed.kind !== 'TLSA') continue;
      const { usage, selector, matchingType, certAssociationHex } = rec.parsed;
      const usageMeta = TLSA_USAGES[usage];
      const selMeta = TLSA_SELECTORS[selector];
      const matchMeta = TLSA_MATCHING_TYPES[matchingType];
      const assocBytes = hexToBytes(certAssociationHex);
      const expectedHexLen = matchMeta?.expectedHexLength;
      const digestLengthValid = expectedHexLen
        ? certAssociationHex.length === expectedHexLen
        : assocBytes.length > 0;

      let decodedCert: DecodedX509Certificate | undefined;
      let decodedSpki: EmailDaneSmimeaRecord['decodedSpki'];
      let parseError: string | undefined;

      if (matchingType === 0 && assocBytes.length > 0) {
        try {
          if (selector === 0) {
            decodedCert = await decodeX509CertificateDer(assocBytes, {
              queriedEmail:
                derivedTargets.inputKind === 'email' ? derivedTargets.canonicalInput : undefined,
              validationTimeSec,
            });
          } else if (selector === 1) {
            decodedSpki = await decodeSpkiDer(assocBytes);
          }
        } catch (err) {
          parseError = err instanceof Error ? err.message : String(err);
        }
      }

      records.push({
        index: i + 1,
        ttl: rec.ttl,
        usage,
        usageMnemonic: usageMeta?.mnemonic ?? `USAGE-${usage}`,
        usageName: usageMeta?.name ?? `Certificate Usage ${usage}`,
        selector,
        selectorMnemonic: selMeta?.mnemonic ?? `SEL-${selector}`,
        selectorName: selMeta?.name ?? `Selector ${selector}`,
        matchingType,
        matchingMnemonic: matchMeta?.mnemonic ?? `MATCH-${matchingType}`,
        matchingName: matchMeta?.name ?? `Matching Type ${matchingType}`,
        certAssociationHex,
        byteLength: assocBytes.length,
        digestLengthValid,
        decodedCert,
        decodedSpki,
        parseError,
      });
    }

    const cleanQname = displayFqdn(activeOwner);
    const firstRec = records[0];
    const cliVerifyCommand =
      firstRec?.matchingType === 0 && firstRec.selector === 0
        ? `dig +dnssec +short ${cleanQname} SMIMEA @1.1.1.1 | awk '{$1=$2=$3=""; gsub(/ /,""); print}' | xxd -r -p | openssl x509 -inform DER -noout -text`
        : `dig +dnssec +multi ${cleanQname} SMIMEA @1.1.1.1`;

    smimeaResult = {
      protocol: 'SMIMEA',
      rfc: 'RFC 8162',
      queriedOwner: derivedTargets.smimeaQname,
      resolvedOwner: walked.terminalOwner,
      usedLowercaseFallback: usedLowercase,
      cnameChain: walked.cnameChain,
      status,
      dnssecStatus,
      daneUsable,
      rrsetId: walked.rrset?.id,
      negativeNodeId: walked.negNode?.id,
      records,
      cliVerifyCommand,
    };

    if (status === 'present') {
      if (dnssecStatus === 'insecure') {
        findings.push({
          id: `warn-smimea-unsigned-${walked.terminalOwner}`,
          severity: 'warning',
          code: 'EMAIL_DANE_UNSIGNED_IGNORE',
          title: `SMIMEA published in unsigned zone (${displayFqdn(walked.terminalOwner)}) — MUST NOT be used`,
          detail: `RFC 8162 §1.2 & §5 require DNSSEC validation for SMIMEA records. Because ${displayFqdn(walked.terminalOwner)} is unsigned (INSECURE), S/MIME clients MUST NOT trust this certificate association.`,
          rfc: 'RFC 8162 §5',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      } else if (dnssecStatus === 'bogus') {
        findings.push({
          id: `err-smimea-bogus-${walked.terminalOwner}`,
          severity: 'error',
          code: 'EMAIL_DANE_BOGUS_DNSSEC',
          title: `SMIMEA failed DNSSEC cryptographic validation (${displayFqdn(walked.terminalOwner)})`,
          detail: `DNSSEC validation returned BOGUS for ${displayFqdn(walked.terminalOwner)} SMIMEA. Per RFC 8162 §5, the S/MIME certificate association MUST be rejected.`,
          rfc: 'RFC 8162 §5',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      } else if (daneUsable) {
        findings.push({
          id: `info-smimea-secure-${walked.terminalOwner}`,
          severity: 'info',
          code: 'SMIMEA_DANE_VERIFIED',
          title: `Authenticated RFC 8162 SMIMEA verified via DNSSEC (${records.length} association${records.length === 1 ? '' : 's'})`,
          detail: `Cryptographically verified ${records.length} S/MIME certificate association RR(s) at ${displayFqdn(walked.terminalOwner)}.`,
          rfc: 'RFC 8162 §3',
          zone: derivedTargets.domain,
          targetId: walked.rrset?.id,
        });
      }

      for (const rec of records) {
        if (!rec.digestLengthValid) {
          findings.push({
            id: `err-smimea-digest-${walked.terminalOwner}-${rec.index}`,
            severity: 'error',
            code: 'SMIMEA_INVALID_DIGEST_LENGTH',
            title: `Malformed SMIMEA digest length in RR #${rec.index} (${rec.matchingMnemonic})`,
            detail: `SMIMEA matching type ${rec.matchingType} (${rec.matchingMnemonic}) received ${rec.byteLength} bytes of association data.`,
            rfc: 'RFC 8162 §2 / RFC 6698',
            zone: derivedTargets.domain,
            targetId: walked.rrset?.id,
          });
        }
        if (rec.parseError) {
          findings.push({
            id: `err-smimea-der-${walked.terminalOwner}-${rec.index}`,
            severity: 'error',
            code: 'SMIMEA_MALFORMED_DER',
            title: `Malformed ASN.1 DER payload in SMIMEA RR #${rec.index}`,
            detail: rec.parseError,
            rfc: 'RFC 8162 §2 / RFC 5280',
            zone: derivedTargets.domain,
            targetId: walked.rrset?.id,
          });
        }
        if (rec.decodedCert) {
          if (rec.decodedCert.isExpired || rec.decodedCert.isNotYetValid) {
            findings.push({
              id: `warn-smimea-validity-${walked.terminalOwner}-${rec.index}`,
              severity: 'warning',
              code: 'SMIMEA_CERT_VALIDITY',
              title: `SMIMEA X.509 certificate in RR #${rec.index} is ${rec.decodedCert.isExpired ? 'EXPIRED' : 'NOT YET VALID'}`,
              detail: `Certificate validity window is ${rec.decodedCert.notBeforeIso} .. ${rec.decodedCert.notAfterIso}.`,
              rfc: 'RFC 8162 §4 / RFC 5280',
              zone: derivedTargets.domain,
              targetId: walked.rrset?.id,
            });
          }
          if (rec.decodedCert.matchesQueriedEmail === false) {
            findings.push({
              id: `warn-smimea-email-${walked.terminalOwner}-${rec.index}`,
              severity: 'warning',
              code: 'SMIMEA_EMAIL_MISMATCH',
              title: `SMIMEA X.509 certificate SAN/Subject does not match ${derivedTargets.canonicalInput}`,
              detail: `Published X.509 certificate SAN rfc822Name (${rec.decodedCert.sanRfc822Names.join(', ') || 'none'}) / Subject (${rec.decodedCert.subject}) does not include ${derivedTargets.canonicalInput}.`,
              rfc: 'RFC 8162 §4',
              zone: derivedTargets.domain,
              targetId: walked.rrset?.id,
            });
          }
        }
      }
    }
  }

  // Build concise human-readable summary & check if unsigned published DANE records warrant warning upgrade
  const pgpPresent = openpgpkeyResult?.status === 'present';
  const smimePresent = smimeaResult?.status === 'present';
  const hasUnsignedPublished =
    (pgpPresent && openpgpkeyResult?.dnssecStatus === 'insecure') ||
    (smimePresent && smimeaResult?.dnssecStatus === 'insecure');
  const hasLifecycleOrMismatchWarning = findings.some((f) => f.severity === 'warning');
  const hasSpecError = findings.some((f) => f.severity === 'error');

  let summary = '';
  const targetDisplay = derivedTargets.canonicalInput;
  if (pgpPresent && smimePresent) {
    summary =
      openpgpkeyResult?.daneUsable && smimeaResult?.daneUsable
        ? `DNSSEC-authenticated OPENPGPKEY (${openpgpkeyResult.records.length}) and SMIMEA (${smimeaResult.records.length}) cryptographic identities verified for ${targetDisplay}.`
        : `Published OPENPGPKEY and SMIMEA records found for ${targetDisplay}, but DNSSEC validation is ${openpgpkeyResult?.dnssecStatus.toUpperCase()} — RFC 7929 / 8162 require DNSSEC!`;
  } else if (pgpPresent && openpgpkeyResult) {
    summary = openpgpkeyResult.daneUsable
      ? `DNSSEC-authenticated RFC 7929 OPENPGPKEY verified for ${targetDisplay} (${openpgpkeyResult.records.length} key${openpgpkeyResult.records.length === 1 ? '' : 's'})${smimeaResult ? `; no SMIMEA (${smimeaResult.status.toUpperCase()})` : ''}.`
      : `OPENPGPKEY found for ${targetDisplay}, but zone is ${openpgpkeyResult.dnssecStatus.toUpperCase()} — unusable for DANE per RFC 7929 §5.`;
  } else if (smimePresent && smimeaResult) {
    summary = smimeaResult.daneUsable
      ? `DNSSEC-authenticated RFC 8162 SMIMEA verified for ${targetDisplay} (${smimeaResult.records.length} cert association${smimeaResult.records.length === 1 ? '' : 's'})${openpgpkeyResult ? `; no OPENPGPKEY (${openpgpkeyResult.status.toUpperCase()})` : ''}.`
      : `SMIMEA found for ${targetDisplay}, but zone is ${smimeaResult.dnssecStatus.toUpperCase()} — unusable for DANE per RFC 8162 §5.`;
  } else {
    const domStatus =
      openpgpkeyResult?.dnssecStatus ?? smimeaResult?.dnssecStatus ?? 'indeterminate';
    summary = `No OPENPGPKEY or SMIMEA records published for ${targetDisplay} (${domStatus === 'secure' ? 'authenticated denial of existence verified via NSEC/NSEC3' : domStatus.toUpperCase()}).`;
  }

  const hasEmailDnssecBogus =
    openpgpkeyResult?.dnssecStatus === 'bogus' || smimeaResult?.dnssecStatus === 'bogus';

  let overallStatusOverride: SnapshotStatus | undefined;
  if (hasEmailDnssecBogus) {
    overallStatusOverride = 'bogus';
  } else if (hasSpecError) {
    overallStatusOverride = 'policy-error';
  } else if (hasUnsignedPublished || hasLifecycleOrMismatchWarning) {
    overallStatusOverride = 'warning';
  }

  return {
    emailDane: {
      inputKind: derivedTargets.inputKind,
      email: derivedTargets.inputKind === 'email' ? derivedTargets.canonicalInput : undefined,
      localPart: derivedTargets.localPart,
      domain: derivedTargets.domain,
      exactHashHex: derivedTargets.exactHashHex,
      lowercaseHashHex: derivedTargets.lowercaseHashHex,
      openpgpkey: openpgpkeyResult,
      smimea: smimeaResult,
      summary,
    },
    findings,
    overallStatusOverride,
    overallSummaryOverride: summary,
  };
}
