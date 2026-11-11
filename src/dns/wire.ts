import {
  EDE_CODES,
  HPKE_AEAD_IDS,
  HPKE_KDF_IDS,
  HPKE_KEM_IDS,
  RR_TYPES,
  SSHFP_ALGORITHMS,
  SSHFP_FP_TYPES,
  ZONEMD_HASH_ALGORITHMS,
  formatZonemdHashAlgorithm,
  formatZonemdScheme,
  rrTypeToString,
  svcParamKeyToString,
} from './constants';
import {
  bytesToBase32Hex,
  bytesToBase64,
  bytesToHex,
  computeKeyTag,
  concatBytes,
  formatDnsTimestamp,
  getKeySizeInfo,
  normalizeFqdn,
  splitPresentationLabels,
  unescapePresentationLabel,
} from './encoding';
import type {
  ClientSubnetQueryOption,
  DnsHeaderFlags,
  DnsPacket,
  DnsQuestion,
  DnsRecord,
  EchCipherSuite,
  EchConfigEntry,
  EdeEntry,
  EdnsClientSubnet,
  EdnsInfo,
  ParsedRdata,
  SvcParamEntry,
} from './types';

const textDecoder = new TextDecoder('utf-8', { fatal: false });

/**
 * Encodes a domain name into uncompressed DNS wire format.
 * Supports RFC 1035 `\DDD` and `\X` escapes; when canonicalLower=true (RFC 4034 §6.2), ASCII uppercase letters are lowercased.
 */
export function encodeDnsName(name: string, canonicalLower = true): Uint8Array {
  const labels = splitPresentationLabels(name);
  if (labels.length === 0) {
    return new Uint8Array([0]);
  }
  const parts: Uint8Array[] = [];
  for (const label of labels) {
    const bytes = unescapePresentationLabel(label, canonicalLower);
    if (bytes.length === 0 || bytes.length > 63) {
      throw new Error(`Invalid DNS label length in "${name}"`);
    }
    const seg = new Uint8Array(1 + bytes.length);
    seg[0] = bytes.length;
    seg.set(bytes, 1);
    parts.push(seg);
  }
  parts.push(new Uint8Array([0]));
  return concatBytes(...parts);
}

/**
 * Decodes a DNS wire domain name (supporting RFC 1035 §4.1.4 compression pointers).
 * Returns the FQDN ending with '.' (or '.' for root) and how many bytes were consumed at `offset`.
 */
export function decodeDnsName(
  buf: Uint8Array,
  offset: number
): { name: string; bytesRead: number; uncompressedWire: Uint8Array } {
  const labels: string[] = [];
  const rawLabelChunks: Uint8Array[] = [];
  let pos = offset;
  let bytesRead = 0;
  let jumped = false;
  let jumps = 0;

  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) bytesRead += 1;
      rawLabelChunks.push(new Uint8Array([0]));
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) {
        throw new Error('Truncated DNS compression pointer');
      }
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) {
        bytesRead += 2;
        jumped = true;
      }
      jumps++;
      if (jumps > 64) {
        throw new Error('DNS compression pointer loop detected');
      }
      pos = ptr;
      continue;
    }
    if ((len & 0xc0) !== 0) {
      throw new Error(`Unsupported DNS label type 0x${len.toString(16)}`);
    }
    if (pos + 1 + len > buf.length) {
      throw new Error('Truncated DNS label');
    }
    const labelBytes = buf.subarray(pos + 1, pos + 1 + len);
    // Preserve escaped presentation for unusual octets or decode ASCII cleanly
    let labelStr = '';
    for (let i = 0; i < labelBytes.length; i++) {
      const c = labelBytes[i];
      if (c === 0x2e || c === 0x5c) {
        labelStr += `\\${String.fromCharCode(c)}`;
      } else if (c >= 0x21 && c <= 0x7e) {
        labelStr += String.fromCharCode(c);
      } else {
        labelStr += `\\${String(c).padStart(3, '0')}`;
      }
    }
    labels.push(labelStr);
    const chunk = new Uint8Array(1 + len);
    chunk[0] = len;
    chunk.set(labelBytes, 1);
    rawLabelChunks.push(chunk);

    pos += 1 + len;
    if (!jumped) bytesRead += 1 + len;
  }

  const fqdn = labels.length === 0 ? '.' : `${labels.join('.')}.`;
  return {
    name: fqdn,
    bytesRead,
    uncompressedWire: concatBytes(...rawLabelChunks),
  };
}

function lowercaseWireName(uncompressedWire: Uint8Array): Uint8Array {
  const out = new Uint8Array(uncompressedWire);
  let pos = 0;
  while (pos < out.length) {
    const len = out[pos];
    if (len === 0) break;
    for (let i = 1; i <= len && pos + i < out.length; i++) {
      const b = out[pos + i];
      if (b >= 0x41 && b <= 0x5a) {
        out[pos + i] = b + 32;
      }
    }
    pos += 1 + len;
  }
  return out;
}

function parseIpv4BytesForWire(raw: string): Uint8Array | null {
  const parts = raw.trim().split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i];
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p.startsWith('0'))) return null;
    const n = Number.parseInt(p, 10);
    if (n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIpv6BytesForWire(raw: string): Uint8Array | null {
  const clean = raw.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!clean || !clean.includes(':')) return null;
  if (clean.split('::').length > 2) return null;

  let working = clean;
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4 = parseIpv4BytesForWire(working.slice(lastColon + 1));
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    working = `${working.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  let groups: string[];
  if (working.includes('::')) {
    const [leftRaw, rightRaw] = working.split('::');
    const left = leftRaw ? leftRaw.split(':') : [];
    const right = rightRaw ? rightRaw.split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
  } else {
    groups = working.split(':');
  }
  if (groups.length !== 8) return null;

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
    const val = Number.parseInt(groups[i], 16);
    out[i * 2] = (val >>> 8) & 0xff;
    out[i * 2 + 1] = val & 0xff;
  }
  return out;
}

function maskAddressBytes(fullBytes: Uint8Array, prefixLen: number): Uint8Array {
  const out = new Uint8Array(fullBytes.length);
  const fullOctets = Math.floor(prefixLen / 8);
  const remBits = prefixLen % 8;
  for (let i = 0; i < Math.min(fullOctets, out.length); i++) {
    out[i] = fullBytes[i];
  }
  if (remBits > 0 && fullOctets < out.length) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    out[fullOctets] = fullBytes[fullOctets] & mask;
  }
  return out;
}

/**
 * Parses a user or preset CIDR/IP string (e.g. `"71.252.0.0/24"`, `"2601:140:4000::/56"`, `"0.0.0.0/0"`, `"::/0"`)
 * into a canonical masked `ClientSubnetQueryOption` per RFC 7871 §6.
 */
export function parseEcsSubnetInput(raw: string): ClientSubnetQueryOption | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  let addrPart = trimmed;
  let explicitPrefix: number | null = null;
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx !== -1) {
    addrPart = trimmed.slice(0, slashIdx).trim();
    const prefixStr = trimmed.slice(slashIdx + 1).trim();
    if (!/^\d{1,3}$/.test(prefixStr)) return null;
    explicitPrefix = Number.parseInt(prefixStr, 10);
  }

  const v4 = parseIpv4BytesForWire(addrPart);
  if (v4) {
    const isAllZero = v4.every((b) => b === 0);
    const prefixLen = explicitPrefix !== null ? explicitPrefix : isAllZero ? 0 : 24;
    if (prefixLen < 0 || prefixLen > 32) return null;
    const masked = maskAddressBytes(v4, prefixLen);
    return {
      family: 1,
      address: `${masked[0]}.${masked[1]}.${masked[2]}.${masked[3]}`,
      sourcePrefixLength: prefixLen,
      scopePrefixLength: 0,
    };
  }

  const v6 = parseIpv6BytesForWire(addrPart);
  if (v6) {
    const isAllZero = v6.every((b) => b === 0);
    const prefixLen = explicitPrefix !== null ? explicitPrefix : isAllZero ? 0 : 56;
    if (prefixLen < 0 || prefixLen > 128) return null;
    const masked = maskAddressBytes(v6, prefixLen);
    return {
      family: 2,
      address: formatIpv6(masked),
      sourcePrefixLength: prefixLen,
      scopePrefixLength: 0,
    };
  }

  return null;
}

export function formatEcsQuerySubnet(ecs: ClientSubnetQueryOption): string {
  return `${ecs.address}/${ecs.sourcePrefixLength}`;
}

/**
 * Encodes an RFC 7871 §6 EDNS0 `CLIENT-SUBNET` (`OPTION-CODE = 8`) TLV option
 * (`OPTION-CODE` 2B + `OPTION-LENGTH` 2B + `FAMILY` 2B + `SOURCE` 1B + `SCOPE` 1B + truncated `ADDRESS`).
 */
export function encodeEdnsClientSubnetOption(ecs: ClientSubnetQueryOption): Uint8Array {
  const maxBits = ecs.family === 1 ? 32 : 128;
  if (ecs.sourcePrefixLength < 0 || ecs.sourcePrefixLength > maxBits) {
    throw new Error(`Invalid ECS sourcePrefixLength ${ecs.sourcePrefixLength} for family ${ecs.family}`);
  }
  const scope = ecs.scopePrefixLength ?? 0;
  if (scope < 0 || scope > maxBits) {
    throw new Error(`Invalid ECS scopePrefixLength ${scope} for family ${ecs.family}`);
  }

  const fullBytes =
    ecs.family === 1 ? parseIpv4BytesForWire(ecs.address) : parseIpv6BytesForWire(ecs.address);
  if (!fullBytes) {
    throw new Error(`Invalid ECS IP address "${ecs.address}" for family ${ecs.family}`);
  }

  const masked = maskAddressBytes(fullBytes, ecs.sourcePrefixLength);
  const addrByteLen = Math.ceil(ecs.sourcePrefixLength / 8);
  const addrBytes = masked.subarray(0, addrByteLen);

  const optLen = 4 + addrBytes.length;
  const tlv = new Uint8Array(4 + optLen);
  const view = new DataView(tlv.buffer);
  view.setUint16(0, 8, false); // OPTION-CODE = 8 (CLIENT-SUBNET)
  view.setUint16(2, optLen, false); // OPTION-LENGTH
  view.setUint16(4, ecs.family, false); // FAMILY (1 = IPv4, 2 = IPv6)
  tlv[6] = ecs.sourcePrefixLength & 0xff;
  tlv[7] = scope & 0xff;
  tlv.set(addrBytes, 8);
  return tlv;
}

/**
 * Decodes the payload (`FAMILY` + `SOURCE` + `SCOPE` + `ADDRESS`) of an RFC 7871 §6 EDNS0 Option 8 (`CLIENT-SUBNET`).
 */
export function decodeEdnsClientSubnetOption(optData: Uint8Array): EdnsClientSubnet {
  if (optData.length < 4) {
    const rawHex = bytesToHex(optData);
    return {
      family: 0,
      familyName: 'MALFORMED',
      sourcePrefixLength: 0,
      scopePrefixLength: 0,
      address: `0x${rawHex}`,
      rawAddressHex: rawHex,
      addressByteLength: 0,
      presentation: `malformed(${rawHex})`,
      invalidPrefixLength: true,
    };
  }

  const view = new DataView(optData.buffer, optData.byteOffset, optData.byteLength);
  const family = view.getUint16(0, false);
  const sourcePrefixLength = optData[2];
  const scopePrefixLength = optData[3];
  const rawAddr = optData.subarray(4);
  const rawAddressHex = bytesToHex(rawAddr);

  const familyName = family === 1 ? 'IPv4' : family === 2 ? 'IPv6' : `FAMILY-${family}`;
  const maxBits = family === 1 ? 32 : family === 2 ? 128 : 0;
  const expectedByteLen = Math.ceil(sourcePrefixLength / 8);

  let invalidPrefixLength = false;
  let hasExcessAddressBytes = false;
  let hasNonZeroTailBits = false;

  if (maxBits === 0 || sourcePrefixLength > maxBits || scopePrefixLength > maxBits) {
    invalidPrefixLength = true;
  }
  if (rawAddr.length < expectedByteLen) {
    invalidPrefixLength = true;
  } else if (rawAddr.length > expectedByteLen) {
    hasExcessAddressBytes = true;
    for (let i = expectedByteLen; i < rawAddr.length; i++) {
      if (rawAddr[i] !== 0) {
        hasNonZeroTailBits = true;
      }
    }
  }

  if (sourcePrefixLength > 0 && sourcePrefixLength % 8 !== 0 && expectedByteLen <= rawAddr.length) {
    const remBits = sourcePrefixLength % 8;
    const tailMask = 0xff >>> remBits;
    if ((rawAddr[expectedByteLen - 1] & tailMask) !== 0) {
      hasNonZeroTailBits = true;
    }
  }

  let address: string;
  if (family === 1) {
    const full = new Uint8Array(4);
    full.set(rawAddr.subarray(0, Math.min(rawAddr.length, 4)));
    address = `${full[0]}.${full[1]}.${full[2]}.${full[3]}`;
  } else if (family === 2) {
    const full = new Uint8Array(16);
    full.set(rawAddr.subarray(0, Math.min(rawAddr.length, 16)));
    address = formatIpv6(full);
  } else {
    address = rawAddressHex ? `0x${rawAddressHex}` : '0';
  }

  return {
    family,
    familyName,
    sourcePrefixLength,
    scopePrefixLength,
    address,
    rawAddressHex,
    addressByteLength: rawAddr.length,
    presentation: `${address}/${sourcePrefixLength}/${scopePrefixLength}`,
    ...(hasNonZeroTailBits ? { hasNonZeroTailBits: true } : {}),
    ...(hasExcessAddressBytes ? { hasExcessAddressBytes: true } : {}),
    ...(invalidPrefixLength ? { invalidPrefixLength: true } : {}),
  };
}

export interface BuildQueryOptions {
  cd?: boolean;
  doBit?: boolean;
  rd?: boolean;
  udpPayloadSize?: number;
  id?: number;
  ecs?: ClientSubnetQueryOption;
}

/**
 * Builds an RFC 1035 + RFC 6891 EDNS0 wire query suitable for RFC 8484 DoH (`application/dns-message`).
 * Supports optional RFC 7871 EDNS0 Option 8 (`CLIENT-SUBNET`).
 * Note: RFC 8484 §4.1 recommends ID = 0 for HTTP cache friendliness.
 */
export function buildDnsQuery(
  qname: string,
  qtype: number,
  options: BuildQueryOptions = {}
): Uint8Array {
  const { cd = true, doBit = true, rd = true, udpPayloadSize = 4096, id = 0, ecs } = options;
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);

  let flags = 0;
  if (rd) flags |= 0x0100;
  if (cd) flags |= 0x0010;

  view.setUint16(0, id & 0xffff, false);
  view.setUint16(2, flags, false);
  view.setUint16(4, 1, false); // QDCOUNT = 1
  view.setUint16(6, 0, false); // ANCOUNT = 0
  view.setUint16(8, 0, false); // NSCOUNT = 0
  view.setUint16(10, 1, false); // ARCOUNT = 1 (EDNS0 OPT)

  const nameWire = encodeDnsName(qname, true);
  const qTail = new Uint8Array(4);
  const qView = new DataView(qTail.buffer);
  qView.setUint16(0, qtype, false);
  qView.setUint16(2, 1, false); // IN class

  const optRdata = ecs ? encodeEdnsClientSubnetOption(ecs) : new Uint8Array(0);

  // EDNS0 OPT pseudo-RR: root(0x00), type=41, class=udpPayloadSize, ttl=(extRcode<<24 | ver<<16 | flags), rdlen=optRdata.length
  const optHeader = new Uint8Array(11);
  const optView = new DataView(optHeader.buffer);
  optHeader[0] = 0; // root owner
  optView.setUint16(1, RR_TYPES.OPT, false);
  optView.setUint16(3, udpPayloadSize, false);
  optView.setUint32(5, doBit ? 0x00008000 : 0x00000000, false);
  optView.setUint16(9, optRdata.length, false);

  return optRdata.length > 0
    ? concatBytes(header, nameWire, qTail, optHeader, optRdata)
    : concatBytes(header, nameWire, qTail, optHeader);
}

function decodeTypeBitmaps(buf: Uint8Array): number[] {
  const types: number[] = [];
  let pos = 0;
  while (pos + 2 <= buf.length) {
    const windowBlock = buf[pos];
    const bitmapLen = buf[pos + 1];
    pos += 2;
    if (bitmapLen < 1 || bitmapLen > 32 || pos + bitmapLen > buf.length) {
      break;
    }
    for (let byteIdx = 0; byteIdx < bitmapLen; byteIdx++) {
      const b = buf[pos + byteIdx];
      if (b === 0) continue;
      for (let bit = 0; bit < 8; bit++) {
        if ((b & (0x80 >>> bit)) !== 0) {
          types.push(windowBlock * 256 + byteIdx * 8 + bit);
        }
      }
    }
    pos += bitmapLen;
  }
  return types;
}

function formatIpv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) return bytesToHex(bytes);
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }
  // Find longest run of zero groups for :: compression
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen && curLen >= 2) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestStart === -1) {
    return groups.map((g) => g.toString(16)).join(':');
  }
  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(':');
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(':');
  return `${left}::${right}`;
}

function decodeCharacterStringChunks(rdata: Uint8Array): string[] {
  const chunks: string[] = [];
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos];
    const strBytes = rdata.subarray(pos + 1, Math.min(rdata.length, pos + 1 + len));
    chunks.push(textDecoder.decode(strBytes));
    pos += 1 + len;
  }
  return chunks;
}

function parseCharacterStrings(rdata: Uint8Array): string {
  return decodeCharacterStringChunks(rdata)
    .map((s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(' ');
}

/**
 * Decodes an RFC 9460 / draft-ietf-tls-esni `ECHConfigList` binary structure (SvcParamKey 5 `ech`).
 */
export function parseEchConfigList(buf: Uint8Array): EchConfigEntry[] {
  if (buf.length < 4) return [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const totalLen = view.getUint16(0, false);
  const limit = Math.min(buf.length, 2 + totalLen);
  let pos = 2;
  const entries: EchConfigEntry[] = [];

  while (pos + 4 <= limit) {
    const version = view.getUint16(pos, false);
    const configLen = view.getUint16(pos + 2, false);
    pos += 4;
    if (pos + configLen > limit) break;

    const contents = buf.subarray(pos, pos + configLen);
    pos += configLen;

    // Draft-13+ / RFC ECH version 0xfe0d
    if (contents.length >= 8) {
      const cView = new DataView(contents.buffer, contents.byteOffset, contents.byteLength);
      let cPos = 0;
      const configId = contents[cPos++];
      const kemId = cView.getUint16(cPos, false);
      cPos += 2;
      if (cPos + 2 > contents.length) continue;
      const pubKeyLen = cView.getUint16(cPos, false);
      cPos += 2;
      if (cPos + pubKeyLen + 2 > contents.length) continue;
      const pubKeyBytes = contents.subarray(cPos, cPos + pubKeyLen);
      cPos += pubKeyLen;

      const suitesByteLen = cView.getUint16(cPos, false);
      cPos += 2;
      if (cPos + suitesByteLen + 2 > contents.length) continue;
      const cipherSuites: EchCipherSuite[] = [];
      for (let s = 0; s + 4 <= suitesByteLen; s += 4) {
        const kdfId = cView.getUint16(cPos + s, false);
        const aeadId = cView.getUint16(cPos + s + 2, false);
        cipherSuites.push({
          kdfId,
          kdfName: HPKE_KDF_IDS[kdfId] ?? `KDF-0x${kdfId.toString(16).padStart(4, '0')}`,
          aeadId,
          aeadName: HPKE_AEAD_IDS[aeadId] ?? `AEAD-0x${aeadId.toString(16).padStart(4, '0')}`,
        });
      }
      cPos += suitesByteLen;

      const maximumNameLength = contents[cPos++];
      if (cPos >= contents.length) continue;
      const publicNameLen = contents[cPos++];
      if (cPos + publicNameLen > contents.length) continue;
      const publicName = textDecoder.decode(contents.subarray(cPos, cPos + publicNameLen));

      entries.push({
        version,
        versionHex: `0x${version.toString(16).padStart(4, '0')}`,
        configId,
        kemId,
        kemName: HPKE_KEM_IDS[kemId] ?? `KEM-0x${kemId.toString(16).padStart(4, '0')}`,
        publicKeyLength: pubKeyLen,
        publicKeyHex: bytesToHex(pubKeyBytes),
        cipherSuites,
        maximumNameLength,
        publicName,
      });
    }
  }

  return entries;
}

/**
 * Computes RFC 4034 §6.2 & RFC 6840 §5.1 canonical RDATA AND human-readable / structured representation.
 */
function parseRecordRdata(
  packetBuf: Uint8Array,
  rdataOffset: number,
  rdlength: number,
  rrtype: number
): { canonicalRdata: Uint8Array; rdataText: string; parsed: ParsedRdata } {
  const rawRdata = packetBuf.subarray(rdataOffset, rdataOffset + rdlength);
  const view = new DataView(packetBuf.buffer, packetBuf.byteOffset + rdataOffset, rdlength);

  // 1. Single compressed/lowercased domain-name RDATA types (RFC 4034 §6.2)
  if (
    rrtype === RR_TYPES.NS ||
    rrtype === RR_TYPES.MD ||
    rrtype === RR_TYPES.MF ||
    rrtype === RR_TYPES.CNAME ||
    rrtype === RR_TYPES.MB ||
    rrtype === RR_TYPES.MG ||
    rrtype === RR_TYPES.MR ||
    rrtype === RR_TYPES.PTR ||
    rrtype === RR_TYPES.DNAME
  ) {
    const decoded = decodeDnsName(packetBuf, rdataOffset);
    const target = normalizeFqdn(decoded.name);
    return {
      canonicalRdata: lowercaseWireName(decoded.uncompressedWire),
      rdataText: target,
      parsed: { kind: 'GENERIC', target },
    };
  }

  // 2. SOA (6): MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
  if (rrtype === RR_TYPES.SOA) {
    const mnameDec = decodeDnsName(packetBuf, rdataOffset);
    const rnameDec = decodeDnsName(packetBuf, rdataOffset + mnameDec.bytesRead);
    const timersOffset = mnameDec.bytesRead + rnameDec.bytesRead;
    const timers = rawRdata.subarray(timersOffset, timersOffset + 20);
    const tView = new DataView(timers.buffer, timers.byteOffset, timers.byteLength);
    const serial = timers.length >= 4 ? tView.getUint32(0, false) : 0;
    const refresh = timers.length >= 8 ? tView.getUint32(4, false) : 0;
    const retry = timers.length >= 12 ? tView.getUint32(8, false) : 0;
    const expire = timers.length >= 16 ? tView.getUint32(12, false) : 0;
    const minimum = timers.length >= 20 ? tView.getUint32(16, false) : 0;
    const mname = normalizeFqdn(mnameDec.name);
    const rname = normalizeFqdn(rnameDec.name);

    return {
      canonicalRdata: concatBytes(
        lowercaseWireName(mnameDec.uncompressedWire),
        lowercaseWireName(rnameDec.uncompressedWire),
        timers
      ),
      rdataText: `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`,
      parsed: { kind: 'SOA', mname, rname, serial, refresh, retry, expire, minimum },
    };
  }

  // 3. MX (15), AFSDB (18), RT (21), KX (36): uint16 + domain-name (canonical lowercased)
  if (rrtype === RR_TYPES.MX || rrtype === RR_TYPES.AFSDB || rrtype === 21 || rrtype === RR_TYPES.KX) {
    const pref = view.getUint16(0, false);
    const exchDec = decodeDnsName(packetBuf, rdataOffset + 2);
    const exchange = normalizeFqdn(exchDec.name);
    return {
      canonicalRdata: concatBytes(rawRdata.subarray(0, 2), lowercaseWireName(exchDec.uncompressedWire)),
      rdataText: `${pref} ${exchange}`,
      parsed: rrtype === RR_TYPES.MX ? { kind: 'MX', preference: pref, exchange } : { kind: 'GENERIC', target: exchange },
    };
  }

  // 4. Two domain names: MINFO (14), RP (17)
  if (rrtype === RR_TYPES.MINFO || rrtype === RR_TYPES.RP) {
    const d1 = decodeDnsName(packetBuf, rdataOffset);
    const d2 = decodeDnsName(packetBuf, rdataOffset + d1.bytesRead);
    return {
      canonicalRdata: concatBytes(lowercaseWireName(d1.uncompressedWire), lowercaseWireName(d2.uncompressedWire)),
      rdataText: `${normalizeFqdn(d1.name)} ${normalizeFqdn(d2.name)}`,
      parsed: { kind: 'GENERIC' },
    };
  }

  // 5. SRV (33): priority, weight, port, target (canonical lowercased per RFC 4034 §6.2)
  if (rrtype === RR_TYPES.SRV && rdlength >= 7) {
    const priority = view.getUint16(0, false);
    const weight = view.getUint16(2, false);
    const port = view.getUint16(4, false);
    const targetDec = decodeDnsName(packetBuf, rdataOffset + 6);
    const target = normalizeFqdn(targetDec.name);
    return {
      canonicalRdata: concatBytes(rawRdata.subarray(0, 6), lowercaseWireName(targetDec.uncompressedWire)),
      rdataText: `${priority} ${weight} ${port} ${target}`,
      parsed: { kind: 'SRV', priority, weight, port, target },
    };
  }

  // 6. NAPTR (35): order(2), pref(2), flags(str), services(str), regexp(str), replacement(domain)
  if (rrtype === RR_TYPES.NAPTR && rdlength >= 7) {
    let pos = 4;
    const order = view.getUint16(0, false);
    const pref = view.getUint16(2, false);
    const strs: string[] = [];
    for (let i = 0; i < 3 && pos < rdlength; i++) {
      const slen = rawRdata[pos];
      strs.push(`"${textDecoder.decode(rawRdata.subarray(pos + 1, pos + 1 + slen))}"`);
      pos += 1 + slen;
    }
    const repDec = decodeDnsName(packetBuf, rdataOffset + pos);
    const rep = normalizeFqdn(repDec.name);
    return {
      canonicalRdata: concatBytes(rawRdata.subarray(0, pos), lowercaseWireName(repDec.uncompressedWire)),
      rdataText: `${order} ${pref} ${strs.join(' ')} ${rep}`,
      parsed: { kind: 'GENERIC', target: rep },
    };
  }

  // 7. A (1)
  if (rrtype === RR_TYPES.A && rdlength === 4) {
    const ip = `${rawRdata[0]}.${rawRdata[1]}.${rawRdata[2]}.${rawRdata[3]}`;
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: ip,
      parsed: { kind: 'GENERIC', target: ip },
    };
  }

  // 8. AAAA (28)
  if (rrtype === RR_TYPES.AAAA && rdlength === 16) {
    const ip6 = formatIpv6(rawRdata);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: ip6,
      parsed: { kind: 'GENERIC', target: ip6 },
    };
  }

  // 9. TXT (16) & SPF (99) & HINFO (13)
  if (rrtype === RR_TYPES.TXT || rrtype === RR_TYPES.SPF) {
    const strings = decodeCharacterStringChunks(rawRdata);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: parseCharacterStrings(rawRdata),
      parsed: {
        kind: 'TXT',
        strings,
        joinedText: strings.join(''),
      },
    };
  }
  if (rrtype === RR_TYPES.HINFO) {
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: parseCharacterStrings(rawRdata),
      parsed: { kind: 'GENERIC' },
    };
  }

  // 10. DNSKEY (48) & CDNSKEY (60)
  if ((rrtype === RR_TYPES.DNSKEY || rrtype === RR_TYPES.CDNSKEY) && rdlength >= 4) {
    const flags = view.getUint16(0, false);
    const protocol = rawRdata[2];
    const algorithm = rawRdata[3];
    const pubKey = rawRdata.subarray(4);
    const pubKeyB64 = bytesToBase64(pubKey);
    const keyTag = computeKeyTag(rawRdata);
    const isZoneKey = (flags & 0x0100) !== 0;
    const isSep = (flags & 0x0001) !== 0;
    const isRevoked = (flags & 0x0080) !== 0;
    const keySizeInfo = getKeySizeInfo(algorithm, pubKey);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${flags} ${protocol} ${algorithm} ${pubKeyB64} ; key tag = ${keyTag}`,
      parsed: {
        kind: 'DNSKEY',
        flags,
        protocol,
        algorithm,
        publicKeyBase64: pubKeyB64,
        publicKeyHex: bytesToHex(pubKey),
        keyTag,
        isZoneKey,
        isSep,
        isRevoked,
        keySizeInfo,
      },
    };
  }

  // 11. DS (43) & CDS (59)
  if ((rrtype === RR_TYPES.DS || rrtype === RR_TYPES.CDS) && rdlength >= 4) {
    const keyTag = view.getUint16(0, false);
    const algorithm = rawRdata[2];
    const digestType = rawRdata[3];
    const digestHex = bytesToHex(rawRdata.subarray(4));
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${keyTag} ${algorithm} ${digestType} ${digestHex}`,
      parsed: {
        kind: 'DS',
        keyTag,
        algorithm,
        digestType,
        digestHex,
      },
    };
  }

  // 12. RRSIG (46)
  if (rrtype === RR_TYPES.RRSIG && rdlength >= 19) {
    const typeCovered = view.getUint16(0, false);
    const typeCoveredName = rrTypeToString(typeCovered);
    const algorithm = rawRdata[2];
    const labels = rawRdata[3];
    const originalTtl = view.getUint32(4, false);
    const expiration = view.getUint32(8, false);
    const inception = view.getUint32(12, false);
    const keyTag = view.getUint16(16, false);
    const signerDec = decodeDnsName(packetBuf, rdataOffset + 18);
    const signerName = normalizeFqdn(signerDec.name);
    const sigOffset = 18 + signerDec.bytesRead;
    const signature = rawRdata.subarray(sigOffset);
    const signatureBase64 = bytesToBase64(signature);

    // Canonical RRSIG prefix per RFC 4034 §3.1.8.1: 18-byte fixed header + lowercased uncompressed signer wire name
    const signedHeader = concatBytes(rawRdata.subarray(0, 18), lowercaseWireName(signerDec.uncompressedWire));

    return {
      canonicalRdata: concatBytes(signedHeader, signature),
      rdataText: `${typeCoveredName} ${algorithm} ${labels} ${originalTtl} ${formatDnsTimestamp(expiration)} ${formatDnsTimestamp(inception)} ${keyTag} ${signerName} ${signatureBase64}`,
      parsed: {
        kind: 'RRSIG',
        typeCovered,
        typeCoveredName,
        algorithm,
        labels,
        originalTtl,
        expiration,
        inception,
        keyTag,
        signerName,
        signatureBase64,
        signedHeaderBase64: bytesToBase64(signedHeader),
      },
    };
  }

  // 13. NSEC (47) — Note RFC 6840 §5.1: NSEC next domain name is NOT downcased for canonical form!
  if (rrtype === RR_TYPES.NSEC && rdlength >= 2) {
    const nextDec = decodeDnsName(packetBuf, rdataOffset);
    const nextDomainName = nextDec.name; // preserve case on display, normalize where needed
    const bitmapSlice = rawRdata.subarray(nextDec.bytesRead);
    const types = decodeTypeBitmaps(bitmapSlice);
    const typeNames = types.map(rrTypeToString);
    return {
      canonicalRdata: concatBytes(nextDec.uncompressedWire, bitmapSlice),
      rdataText: `${nextDomainName} ${typeNames.join(' ')}`,
      parsed: {
        kind: 'NSEC',
        nextDomainName,
        types,
        typeNames,
      },
    };
  }

  // 14. NSEC3 (50)
  if (rrtype === RR_TYPES.NSEC3 && rdlength >= 6) {
    const hashAlgorithm = rawRdata[0];
    const flags = rawRdata[1];
    const optOut = (flags & 0x01) !== 0;
    const iterations = view.getUint16(2, false);
    const saltLen = rawRdata[4];
    const saltBytes = rawRdata.subarray(5, 5 + saltLen);
    const saltHex = saltLen === 0 ? '-' : bytesToHex(saltBytes);
    const hashLenPos = 5 + saltLen;
    const hashLen = rawRdata[hashLenPos] ?? 0;
    const nextHashBytes = rawRdata.subarray(hashLenPos + 1, hashLenPos + 1 + hashLen);
    const nextHashedOwnerBase32 = bytesToBase32Hex(nextHashBytes);
    const types = decodeTypeBitmaps(rawRdata.subarray(hashLenPos + 1 + hashLen));
    const typeNames = types.map(rrTypeToString);

    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${hashAlgorithm} ${flags} ${iterations} ${saltHex} ${nextHashedOwnerBase32} ${typeNames.join(' ')}`,
      parsed: {
        kind: 'NSEC3',
        hashAlgorithm,
        flags,
        optOut,
        iterations,
        saltHex: saltLen === 0 ? '' : saltHex,
        nextHashedOwnerBase32,
        types,
        typeNames,
      },
    };
  }

  // 15. NSEC3PARAM (51)
  if (rrtype === RR_TYPES.NSEC3PARAM && rdlength >= 5) {
    const hashAlgorithm = rawRdata[0];
    const flags = rawRdata[1];
    const iterations = view.getUint16(2, false);
    const saltLen = rawRdata[4];
    const saltHex = saltLen === 0 ? '' : bytesToHex(rawRdata.subarray(5, 5 + saltLen));
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${hashAlgorithm} ${flags} ${iterations} ${saltHex || '-'}`,
      parsed: {
        kind: 'NSEC3PARAM',
        hashAlgorithm,
        flags,
        iterations,
        saltHex,
      },
    };
  }

  // 16. CAA (257)
  if (rrtype === RR_TYPES.CAA && rdlength >= 2) {
    const flags = rawRdata[0];
    const tagLen = rawRdata[1];
    const tag = textDecoder.decode(rawRdata.subarray(2, 2 + tagLen));
    const value = textDecoder.decode(rawRdata.subarray(2 + tagLen));
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${flags} ${tag} "${value}"`,
      parsed: { kind: 'CAA', flags, tag, value },
    };
  }

  // 17. TLSA (52), SMIMEA (53) & SSHFP (44)
  if ((rrtype === RR_TYPES.TLSA || rrtype === RR_TYPES.SMIMEA) && rdlength >= 3) {
    const usage = rawRdata[0];
    const selector = rawRdata[1];
    const matchingType = rawRdata[2];
    const certData = bytesToHex(rawRdata.subarray(3));
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${usage} ${selector} ${matchingType} ${certData}`,
      parsed: {
        kind: 'TLSA',
        usage,
        selector,
        matchingType,
        certAssociationHex: certData,
      },
    };
  }
  if (rrtype === RR_TYPES.SSHFP && rdlength >= 3) {
    const alg = rawRdata[0];
    const fpType = rawRdata[1];
    const fp = bytesToHex(rawRdata.subarray(2));
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${alg} ${fpType} ${fp}`,
      parsed: {
        kind: 'SSHFP',
        algorithm: alg,
        algorithmName: SSHFP_ALGORITHMS[alg]?.name ?? `ALG-${alg}`,
        fpType,
        fpTypeName: SSHFP_FP_TYPES[fpType]?.name ?? `TYPE-${fpType}`,
        fingerprintHex: fp,
      },
    };
  }

  // 17b. OPENPGPKEY (61, RFC 7929): Base64-encoded OpenPGP transferable public key packet
  if (rrtype === RR_TYPES.OPENPGPKEY && rdlength >= 1) {
    const keyBase64 = bytesToBase64(rawRdata);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: keyBase64,
      parsed: {
        kind: 'OPENPGPKEY',
        keyBase64,
        byteLength: rawRdata.length,
      },
    };
  }

  // 18. CSYNC (62): SOA Serial (4), Flags (2), Type Bit Maps (RFC 7477 §2.1.1)
  if (rrtype === RR_TYPES.CSYNC && rdlength >= 6) {
    const soaSerial = view.getUint32(0, false);
    const flags = view.getUint16(4, false);
    const immediate = (flags & 0x0001) !== 0;
    const soaMinimum = (flags & 0x0002) !== 0;
    const types = decodeTypeBitmaps(rawRdata.subarray(6));
    const typeNames = types.map(rrTypeToString);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${soaSerial} ${flags}${typeNames.length > 0 ? ` ${typeNames.join(' ')}` : ''}`,
      parsed: {
        kind: 'CSYNC',
        soaSerial,
        flags,
        immediate,
        soaMinimum,
        types,
        typeNames,
      },
    };
  }

  // 18b. ZONEMD (63, RFC 8976 §2): Serial (4), Scheme (1), Hash Algorithm (1), Digest (variable, >= 12 bytes)
  if (rrtype === RR_TYPES.ZONEMD && rdlength >= 6) {
    const serial = view.getUint32(0, false);
    const scheme = rawRdata[4];
    const hashAlgorithm = rawRdata[5];
    const digestBytes = rawRdata.subarray(6);
    const digestHex = bytesToHex(digestBytes);
    const expectedBytes = ZONEMD_HASH_ALGORITHMS[hashAlgorithm]?.expectedByteLength;
    const digestLengthValid =
      digestBytes.length >= 12 && (expectedBytes === undefined || digestBytes.length === expectedBytes);
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${serial} ${scheme} ${hashAlgorithm} ${digestHex}`,
      parsed: {
        kind: 'ZONEMD',
        serial,
        scheme,
        schemeName: formatZonemdScheme(scheme),
        hashAlgorithm,
        hashAlgorithmName: formatZonemdHashAlgorithm(hashAlgorithm),
        digestHex,
        digestByteLength: digestBytes.length,
        digestLengthValid,
      },
    };
  }

  // 19. SVCB (64) & HTTPS (65) full RFC 9460 SvcParams & ECHConfigList decoding
  if ((rrtype === RR_TYPES.SVCB || rrtype === RR_TYPES.HTTPS) && rdlength >= 3) {
    const svcPriority = view.getUint16(0, false);
    const targetDec = decodeDnsName(packetBuf, rdataOffset + 2);
    const targetName = normalizeFqdn(targetDec.name);
    const paramsBuf = rawRdata.subarray(2 + targetDec.bytesRead);
    const paramStrs: string[] = [];
    const params: SvcParamEntry[] = [];
    let pPos = 0;
    while (pPos + 4 <= paramsBuf.length) {
      const pView = new DataView(paramsBuf.buffer, paramsBuf.byteOffset + pPos, 4);
      const key = pView.getUint16(0, false);
      const vLen = pView.getUint16(2, false);
      const val = paramsBuf.subarray(pPos + 4, Math.min(paramsBuf.length, pPos + 4 + vLen));
      const keyName = svcParamKeyToString(key);
      const rawHex = bytesToHex(val);

      if (key === 0 && val.length >= 2 && val.length % 2 === 0) {
        // mandatory (key 0): list of uint16 SvcParamKeys
        const mKeys: string[] = [];
        const mView = new DataView(val.buffer, val.byteOffset, val.byteLength);
        for (let k = 0; k < val.length; k += 2) {
          mKeys.push(svcParamKeyToString(mView.getUint16(k, false)));
        }
        const valueText = mKeys.join(',');
        paramStrs.push(`mandatory=${valueText}`);
        params.push({ key, keyName, rawHex, valueText, mandatoryKeys: mKeys });
      } else if (key === 1) {
        // alpn (key 1)
        const alpns: string[] = [];
        let aPos = 0;
        while (aPos < val.length) {
          const al = val[aPos];
          alpns.push(textDecoder.decode(val.subarray(aPos + 1, aPos + 1 + al)));
          aPos += 1 + al;
        }
        const valueText = alpns.join(',');
        paramStrs.push(`alpn="${valueText}"`);
        params.push({ key, keyName, rawHex, valueText, alpns });
      } else if (key === 2) {
        // no-default-alpn (key 2)
        paramStrs.push('no-default-alpn');
        params.push({ key, keyName, rawHex, valueText: '' });
      } else if (key === 3 && val.length === 2) {
        // port (key 3)
        const portView = new DataView(val.buffer, val.byteOffset, 2);
        const port = portView.getUint16(0, false);
        paramStrs.push(`port=${port}`);
        params.push({ key, keyName, rawHex, valueText: String(port), port });
      } else if (key === 4 && val.length >= 4 && val.length % 4 === 0) {
        // ipv4hint (key 4)
        const ips: string[] = [];
        for (let k = 0; k < val.length; k += 4) {
          ips.push(`${val[k]}.${val[k + 1]}.${val[k + 2]}.${val[k + 3]}`);
        }
        const valueText = ips.join(',');
        paramStrs.push(`ipv4hint=${valueText}`);
        params.push({ key, keyName, rawHex, valueText, ipv4Hints: ips });
      } else if (key === 5) {
        // ech (key 5): TLS Encrypted ClientHello ECHConfigList
        const echB64 = bytesToBase64(val);
        const echConfigs = parseEchConfigList(val);
        paramStrs.push(`ech="${echB64}"`);
        params.push({
          key,
          keyName,
          rawHex,
          valueText: echB64,
          echConfigListBase64: echB64,
          echConfigs,
        });
      } else if (key === 6 && val.length >= 16 && val.length % 16 === 0) {
        // ipv6hint (key 6)
        const ip6s: string[] = [];
        for (let k = 0; k < val.length; k += 16) {
          ip6s.push(formatIpv6(val.subarray(k, k + 16)));
        }
        const valueText = ip6s.join(',');
        paramStrs.push(`ipv6hint=${valueText}`);
        params.push({ key, keyName, rawHex, valueText, ipv6Hints: ip6s });
      } else if (key === 7) {
        // dohpath (key 7, RFC 9461)
        const dohPath = textDecoder.decode(val);
        paramStrs.push(`dohpath="${dohPath}"`);
        params.push({ key, keyName, rawHex, valueText: dohPath, dohPath });
      } else {
        const valueText = val.length > 0 ? `0x${rawHex}` : '';
        paramStrs.push(val.length > 0 ? `${keyName}=${valueText}` : keyName);
        params.push({ key, keyName, rawHex, valueText });
      }
      pPos += 4 + vLen;
    }
    return {
      canonicalRdata: new Uint8Array(rawRdata),
      rdataText: `${svcPriority} ${targetName}${paramStrs.length ? ` ${paramStrs.join(' ')}` : ''}`,
      parsed: {
        kind: 'SVCB',
        rrtypeName: rrtype === RR_TYPES.HTTPS ? 'HTTPS' : 'SVCB',
        priority: svcPriority,
        isAliasMode: svcPriority === 0,
        target: targetName,
        params,
      },
    };
  }

  // RFC 3597 generic unknown RR format
  return {
    canonicalRdata: new Uint8Array(rawRdata),
    rdataText: `\\# ${rdlength} ${bytesToHex(rawRdata)}`,
    parsed: { kind: 'GENERIC' },
  };
}

function parseEdnsOpt(rdataBuf: Uint8Array, rrclass: number, ttl: number): EdnsInfo {
  const extendedRcode = (ttl >>> 24) & 0xff;
  const version = (ttl >>> 16) & 0xff;
  const flags = ttl & 0xffff;
  const doBit = (flags & 0x8000) !== 0;
  const ede: EdeEntry[] = [];
  let ecs: EdnsClientSubnet | undefined;

  let pos = 0;
  while (pos + 4 <= rdataBuf.length) {
    const view = new DataView(rdataBuf.buffer, rdataBuf.byteOffset + pos, 4);
    const optCode = view.getUint16(0, false);
    const optLen = view.getUint16(2, false);
    pos += 4;
    if (pos + optLen > rdataBuf.length) break;
    const optData = rdataBuf.subarray(pos, pos + optLen);
    // Option 8 = RFC 7871 EDNS Client Subnet (CLIENT-SUBNET)
    if (optCode === 8) {
      ecs = decodeEdnsClientSubnetOption(optData);
    } else if (optCode === 15 && optData.length >= 2) {
      // Option 15 = RFC 8914 Extended DNS Error
      const edeView = new DataView(optData.buffer, optData.byteOffset, optData.byteLength);
      const infoCode = edeView.getUint16(0, false);
      const extraText = optData.length > 2 ? textDecoder.decode(optData.subarray(2)).replace(/\0+$/, '') : '';
      const meta = EDE_CODES[infoCode];
      ede.push({
        infoCode,
        name: meta ? meta.name : `EDE-${infoCode}`,
        extraText,
      });
    }
    pos += optLen;
  }

  return {
    udpPayloadSize: rrclass,
    extendedRcode,
    version,
    doBit,
    flags,
    ede,
    ...(ecs ? { ecs } : {}),
  };
}

export function parseDnsPacket(buf: Uint8Array): DnsPacket {
  if (buf.length < 12) {
    throw new Error(`DNS packet too short (${buf.length} bytes)`);
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = view.getUint16(0, false);
  const flagWord = view.getUint16(2, false);
  const qdCount = view.getUint16(4, false);
  const anCount = view.getUint16(6, false);
  const nsCount = view.getUint16(8, false);
  const arCount = view.getUint16(10, false);

  const baseRcode = flagWord & 0x0f;
  const flags: DnsHeaderFlags = {
    qr: (flagWord & 0x8000) !== 0,
    opcode: (flagWord >>> 11) & 0x0f,
    aa: (flagWord & 0x0400) !== 0,
    tc: (flagWord & 0x0200) !== 0,
    rd: (flagWord & 0x0100) !== 0,
    ra: (flagWord & 0x0080) !== 0,
    z: (flagWord >>> 6) & 0x01,
    ad: (flagWord & 0x0020) !== 0,
    cd: (flagWord & 0x0010) !== 0,
    rcode: baseRcode,
  };

  let offset = 12;
  const questions: DnsQuestion[] = [];
  for (let i = 0; i < qdCount; i++) {
    const dec = decodeDnsName(buf, offset);
    offset += dec.bytesRead;
    if (offset + 4 > buf.length) throw new Error('Truncated DNS Question section');
    const qtype = view.getUint16(offset, false);
    const qclass = view.getUint16(offset + 2, false);
    offset += 4;
    questions.push({
      name: normalizeFqdn(dec.name),
      type: qtype,
      typeName: rrTypeToString(qtype),
      qclass,
    });
  }

  let edns: EdnsInfo | undefined;

  const readSection = (
    count: number,
    section: 'answer' | 'authority' | 'additional'
  ): DnsRecord[] => {
    const records: DnsRecord[] = [];
    for (let i = 0; i < count; i++) {
      if (offset >= buf.length) break;
      const dec = decodeDnsName(buf, offset);
      offset += dec.bytesRead;
      if (offset + 10 > buf.length) throw new Error(`Truncated RR header in ${section}`);
      const rrtype = view.getUint16(offset, false);
      const rrclass = view.getUint16(offset + 2, false);
      const ttl = view.getUint32(offset + 4, false);
      const rdlength = view.getUint16(offset + 8, false);
      offset += 10;
      if (offset + rdlength > buf.length) {
        throw new Error(`Truncated RDATA in ${section} (expected ${rdlength} bytes)`);
      }

      if (rrtype === RR_TYPES.OPT) {
        edns = parseEdnsOpt(buf.subarray(offset, offset + rdlength), rrclass, ttl);
        if (edns.extendedRcode > 0) {
          flags.rcode = (edns.extendedRcode << 4) | baseRcode;
        }
        offset += rdlength;
        continue;
      }

      const rawRdata = buf.subarray(offset, offset + rdlength);
      const { canonicalRdata, rdataText, parsed } = parseRecordRdata(buf, offset, rdlength, rrtype);
      offset += rdlength;

      records.push({
        name: normalizeFqdn(dec.name),
        type: rrtype,
        typeName: rrTypeToString(rrtype),
        rrclass,
        ttl,
        rdataBase64: bytesToBase64(rawRdata),
        canonicalRdataBase64: bytesToBase64(canonicalRdata),
        rdataText,
        parsed,
        section,
      });
    }
    return records;
  };

  const answers = readSection(anCount, 'answer');
  const authorities = readSection(nsCount, 'authority');
  const additionals = readSection(arCount, 'additional');

  return {
    id,
    flags,
    questions,
    answers,
    authorities,
    additionals,
    edns,
    wireSize: buf.length,
  };
}
