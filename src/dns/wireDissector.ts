import { EDE_CODES, RR_TYPES, rcodeToString, rrTypeToString, svcParamKeyToString } from './constants';
import {
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  computeKeyTag,
  formatDnsTimestamp,
  hexToBytes,
  normalizeFqdn,
} from './encoding';
import type { DnsPacket, DohQueryLog } from './types';
import { parseDnsPacket } from './wire';

export type WireSpanCategory =
  | 'header'
  | 'question'
  | 'answer'
  | 'authority'
  | 'additional'
  | 'edns';

export interface WireHeaderBitField {
  name: string;
  bitsLabel: string;
  maskHex: string;
  binaryValue: string;
  numericValue: number;
  summary: string;
  active: boolean;
}

export interface WireCompressionHop {
  /** Byte offset in the packet where the 2-byte `0xC0xx` pointer sits */
  pointerOffset: number;
  /** Raw 16-bit pointer value (e.g. `0xC00C`) */
  pointerHex: string;
  /** Target offset (`0..16383`) jumped to by the pointer */
  targetOffset: number;
  /** Target byte span length at `targetOffset` (labels read before end or next pointer) */
  targetSpanLength: number;
  /** Domain suffix resolved starting from `targetOffset` */
  resolvedSuffix: string;
}

export interface WireCompressionJump {
  id: string;
  section: WireSpanCategory;
  fieldLabel: string;
  /** Start offset of the whole owner/target domain name field */
  nameStartOffset: number;
  /** Byte offset of the first `0xC0xx` pointer encountered in this name */
  pointerOffset: number;
  /** Target offset of the first `0xC0xx` pointer */
  targetOffset: number;
  /** Total hops in pointer chain (1 for direct pointer, >1 for chained pointers) */
  hops: WireCompressionHop[];
  /** Full reconstructed domain name */
  fullName: string;
  /** Suffix contributed by the compression pointer */
  resolvedSuffix: string;
  /** Actual bytes consumed inline at `nameStartOffset` */
  inlineBytes: number;
  /** Bytes that an uncompressed wire encoding of `fullName` would occupy */
  uncompressedBytes: number;
  /** Wire octets saved by compression (`max(0, uncompressedBytes - inlineBytes)`) */
  savedBytes: number;
}

export interface WireSubfieldSpan {
  id: string;
  label: string;
  startOffset: number;
  endOffset: number; // exclusive
  valueSummary: string;
  detail?: string;
  isCompressionPointer?: boolean;
  pointerTargetOffset?: number;
}

export interface WireSectionSpan {
  id: string;
  category: WireSpanCategory;
  title: string;
  subtitle: string;
  startOffset: number;
  endOffset: number; // exclusive
  fields: WireSubfieldSpan[];
}

export interface DissectedWirePacket {
  bytes: Uint8Array;
  wireSize: number;
  base64: string;
  base64Url: string;
  id: number;
  flagWord: number;
  flagWordHex: string;
  flagWordBinary: string;
  headerBits: WireHeaderBitField[];
  counts: {
    qdCount: number;
    anCount: number;
    nsCount: number;
    arCount: number;
  };
  spans: WireSectionSpan[];
  compressionJumps: WireCompressionJump[];
  compressionStats: {
    pointerCount: number;
    compressedWireSize: number;
    uncompressedEquivalentSize: number;
    totalSavedBytes: number;
    savingsPercent: number;
  };
  parsedPacket?: DnsPacket;
  parseWarning?: string;
}

const OPCODE_NAMES: Record<number, string> = {
  0: 'QUERY',
  1: 'IQUERY',
  2: 'STATUS',
  4: 'NOTIFY',
  5: 'UPDATE',
  6: 'DSO',
};

const EDNS_OPTION_NAMES: Record<number, string> = {
  1: 'LLQ',
  3: 'NSID (RFC 5001)',
  5: 'DAU (RFC 6975)',
  6: 'DHU (RFC 6975)',
  7: 'N3U (RFC 6975)',
  8: 'CLIENT-SUBNET / ECS (RFC 7871)',
  9: 'EXPIRE (RFC 7314)',
  10: 'COOKIE (RFC 7873)',
  11: 'edns-tcp-keepalive (RFC 7828)',
  12: 'PADDING (RFC 7830)',
  13: 'CHAIN (RFC 7901)',
  14: 'edns-key-tag (RFC 8145)',
  15: 'Extended DNS Error / EDE (RFC 8914)',
};

function formatOffsetHex(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(4, '0')}`;
}

function formatLabelBytes(labelBytes: Uint8Array): string {
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
  return labelStr;
}

interface TracedWireName {
  fullName: string;
  bytesRead: number;
  uncompressedBytes: number;
  hops: WireCompressionHop[];
  inlineLabelBytes: number;
}

/**
 * Decodes a DNS wire name at `startOffset`, recording every `0xC0xx` compression pointer hop
 * and computing exact compressed vs. uncompressed byte lengths.
 */
export function decodeWireNameWithTrace(buf: Uint8Array, startOffset: number): TracedWireName {
  const labels: string[] = [];
  let uncompressedBytes = 0;
  let pos = startOffset;
  let bytesRead = 0;
  let inlineLabelBytes = 0;
  let jumped = false;
  let jumps = 0;

  interface RawHop {
    pointerOffset: number;
    pointerHex: string;
    targetOffset: number;
    labelIndexAtJump: number;
    targetSpanLength: number;
  }
  const rawHops: RawHop[] = [];

  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) {
        bytesRead += 1;
        inlineLabelBytes += 1;
      } else if (rawHops.length > 0) {
        rawHops[rawHops.length - 1].targetSpanLength += 1;
      }
      uncompressedBytes += 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) {
        throw new Error(`Truncated DNS compression pointer at ${formatOffsetHex(pos)}`);
      }
      const b1 = buf[pos + 1];
      const ptrWord = (len << 8) | b1;
      const targetOffset = ((len & 0x3f) << 8) | b1;
      if (targetOffset >= buf.length) {
        throw new Error(
          `Out-of-bounds DNS compression pointer ${formatOffsetHex(ptrWord)} → ${formatOffsetHex(targetOffset)} (packet length ${buf.length}B)`
        );
      }
      if (!jumped) {
        bytesRead += 2;
        jumped = true;
      } else if (rawHops.length > 0) {
        rawHops[rawHops.length - 1].targetSpanLength += 2;
      }
      jumps++;
      if (jumps > 64) {
        throw new Error(`DNS compression pointer loop detected at ${formatOffsetHex(pos)}`);
      }
      rawHops.push({
        pointerOffset: pos,
        pointerHex: `0x${ptrWord.toString(16).toUpperCase().padStart(4, '0')}`,
        targetOffset,
        labelIndexAtJump: labels.length,
        targetSpanLength: 0,
      });
      pos = targetOffset;
      continue;
    }

    if ((len & 0xc0) !== 0) {
      throw new Error(`Unsupported DNS label type 0x${len.toString(16)} at ${formatOffsetHex(pos)}`);
    }
    if (pos + 1 + len > buf.length) {
      throw new Error(`Truncated DNS label at ${formatOffsetHex(pos)}`);
    }

    const labelBytes = buf.subarray(pos + 1, pos + 1 + len);
    labels.push(formatLabelBytes(labelBytes));
    uncompressedBytes += 1 + len;
    if (!jumped) {
      bytesRead += 1 + len;
      inlineLabelBytes += 1 + len;
    } else if (rawHops.length > 0) {
      rawHops[rawHops.length - 1].targetSpanLength += 1 + len;
    }
    pos += 1 + len;
  }

  const fullName = labels.length === 0 ? '.' : `${labels.join('.')}.`;
  const hops: WireCompressionHop[] = rawHops.map((h) => {
    const suffixLabels = labels.slice(h.labelIndexAtJump);
    const resolvedSuffix = suffixLabels.length === 0 ? '.' : `${suffixLabels.join('.')}.`;
    return {
      pointerOffset: h.pointerOffset,
      pointerHex: h.pointerHex,
      targetOffset: h.targetOffset,
      targetSpanLength: Math.max(1, h.targetSpanLength),
      resolvedSuffix,
    };
  });

  return {
    fullName,
    bytesRead,
    uncompressedBytes: Math.max(1, uncompressedBytes),
    hops,
    inlineLabelBytes,
  };
}

export function buildHeaderBitFields(flagWord: number, extendedRcode = 0): WireHeaderBitField[] {
  const qr = (flagWord >>> 15) & 0x1;
  const opcode = (flagWord >>> 11) & 0x0f;
  const aa = (flagWord >>> 10) & 0x1;
  const tc = (flagWord >>> 9) & 0x1;
  const rd = (flagWord >>> 8) & 0x1;
  const ra = (flagWord >>> 7) & 0x1;
  const z = (flagWord >>> 6) & 0x1;
  const ad = (flagWord >>> 5) & 0x1;
  const cd = (flagWord >>> 4) & 0x1;
  const baseRcode = flagWord & 0x0f;
  const fullRcode = extendedRcode > 0 ? (extendedRcode << 4) | baseRcode : baseRcode;

  return [
    {
      name: 'QR',
      bitsLabel: 'bit 0',
      maskHex: '0x8000',
      binaryValue: String(qr),
      numericValue: qr,
      summary: qr ? 'Response (1)' : 'Query (0)',
      active: qr === 1,
    },
    {
      name: 'OPCODE',
      bitsLabel: 'bits 1..4',
      maskHex: '0x7800',
      binaryValue: opcode.toString(2).padStart(4, '0'),
      numericValue: opcode,
      summary: `${OPCODE_NAMES[opcode] ?? 'RESERVED'} (${opcode})`,
      active: opcode !== 0,
    },
    {
      name: 'AA',
      bitsLabel: 'bit 5',
      maskHex: '0x0400',
      binaryValue: String(aa),
      numericValue: aa,
      summary: aa ? 'Authoritative Answer (1)' : 'Non-authoritative (0)',
      active: aa === 1,
    },
    {
      name: 'TC',
      bitsLabel: 'bit 6',
      maskHex: '0x0200',
      binaryValue: String(tc),
      numericValue: tc,
      summary: tc ? 'Truncated (1)' : 'Not truncated (0)',
      active: tc === 1,
    },
    {
      name: 'RD',
      bitsLabel: 'bit 7',
      maskHex: '0x0100',
      binaryValue: String(rd),
      numericValue: rd,
      summary: rd ? 'Recursion Desired (1)' : 'Iterative (0)',
      active: rd === 1,
    },
    {
      name: 'RA',
      bitsLabel: 'bit 8',
      maskHex: '0x0080',
      binaryValue: String(ra),
      numericValue: ra,
      summary: ra ? 'Recursion Available (1)' : 'No recursion (0)',
      active: ra === 1,
    },
    {
      name: 'Z',
      bitsLabel: 'bit 9',
      maskHex: '0x0040',
      binaryValue: String(z),
      numericValue: z,
      summary: z === 0 ? 'Reserved MBZ (0)' : 'Non-zero reserved bit! (1)',
      active: z === 1,
    },
    {
      name: 'AD',
      bitsLabel: 'bit 10',
      maskHex: '0x0020',
      binaryValue: String(ad),
      numericValue: ad,
      summary: ad ? 'Authenticated Data — DNSSEC validated (1)' : 'Not authenticated (0)',
      active: ad === 1,
    },
    {
      name: 'CD',
      bitsLabel: 'bit 11',
      maskHex: '0x0010',
      binaryValue: String(cd),
      numericValue: cd,
      summary: cd ? 'Checking Disabled — raw DNSSEC records (1)' : 'Validation enabled (0)',
      active: cd === 1,
    },
    {
      name: 'RCODE',
      bitsLabel: 'bits 12..15',
      maskHex: '0x000F',
      binaryValue: baseRcode.toString(2).padStart(4, '0'),
      numericValue: fullRcode,
      summary: `${rcodeToString(fullRcode)} (${fullRcode})`,
      active: fullRcode !== 0,
    },
  ];
}

function appendNameSubfields(
  fields: WireSubfieldSpan[],
  compressionJumps: WireCompressionJump[],
  params: {
    prefixId: string;
    section: WireSpanCategory;
    fieldLabel: string;
    startOffset: number;
    traced: TracedWireName;
  }
): void {
  const { prefixId, section, fieldLabel, startOffset, traced } = params;
  const endOffset = startOffset + traced.bytesRead;

  if (traced.hops.length === 0) {
    fields.push({
      id: `${prefixId}-name`,
      label: fieldLabel,
      startOffset,
      endOffset,
      valueSummary: `${traced.fullName} (${traced.bytesRead}B uncompressed)`,
    });
    return;
  }

  const firstHop = traced.hops[0];
  const savedBytes = Math.max(0, traced.uncompressedBytes - traced.bytesRead);

  if (firstHop.pointerOffset > startOffset) {
    fields.push({
      id: `${prefixId}-name-prefix`,
      label: `${fieldLabel} (Inline Prefix)`,
      startOffset,
      endOffset: firstHop.pointerOffset,
      valueSummary: `${firstHop.pointerOffset - startOffset}B inline label(s) before pointer`,
    });
  }

  fields.push({
    id: `${prefixId}-name-ptr`,
    label: `${fieldLabel} Pointer (${firstHop.pointerHex})`,
    startOffset: firstHop.pointerOffset,
    endOffset: firstHop.pointerOffset + 2,
    valueSummary: `Jumps to ${formatOffsetHex(firstHop.targetOffset)} → "${firstHop.resolvedSuffix}" (full: ${traced.fullName}, saves ${savedBytes}B)`,
    detail:
      traced.hops.length > 1
        ? `Chained pointer (${traced.hops.length} hops): ${traced.hops.map((h) => `${formatOffsetHex(h.pointerOffset)}→${formatOffsetHex(h.targetOffset)}`).join(' → ')}`
        : undefined,
    isCompressionPointer: true,
    pointerTargetOffset: firstHop.targetOffset,
  });

  compressionJumps.push({
    id: `jump-${compressionJumps.length}-${firstHop.pointerOffset}`,
    section,
    fieldLabel,
    nameStartOffset: startOffset,
    pointerOffset: firstHop.pointerOffset,
    targetOffset: firstHop.targetOffset,
    hops: traced.hops,
    fullName: traced.fullName,
    resolvedSuffix: firstHop.resolvedSuffix,
    inlineBytes: traced.bytesRead,
    uncompressedBytes: traced.uncompressedBytes,
    savedBytes,
  });
}

function dissectRdataSubfields(
  buf: Uint8Array,
  rdataOffset: number,
  rdlength: number,
  rrtype: number,
  prefixId: string,
  section: WireSpanCategory,
  compressionJumps: WireCompressionJump[]
): WireSubfieldSpan[] {
  const fields: WireSubfieldSpan[] = [];
  const end = rdataOffset + rdlength;
  if (rdlength === 0) return fields;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  try {
    if (rrtype === RR_TYPES.A && rdlength === 4) {
      const ip = `${buf[rdataOffset]}.${buf[rdataOffset + 1]}.${buf[rdataOffset + 2]}.${buf[rdataOffset + 3]}`;
      fields.push({
        id: `${prefixId}-a`,
        label: 'IPv4 Address',
        startOffset: rdataOffset,
        endOffset: end,
        valueSummary: ip,
      });
      return fields;
    }

    if (rrtype === RR_TYPES.AAAA && rdlength === 16) {
      const groups: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(view.getUint16(rdataOffset + i, false).toString(16));
      }
      fields.push({
        id: `${prefixId}-aaaa`,
        label: 'IPv6 Address',
        startOffset: rdataOffset,
        endOffset: end,
        valueSummary: groups.join(':'),
      });
      return fields;
    }

    if (
      rrtype === RR_TYPES.NS ||
      rrtype === RR_TYPES.CNAME ||
      rrtype === RR_TYPES.PTR ||
      rrtype === RR_TYPES.DNAME
    ) {
      const traced = decodeWireNameWithTrace(buf, rdataOffset);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-target`,
        section,
        fieldLabel: `${rrTypeToString(rrtype)} Target`,
        startOffset: rdataOffset,
        traced,
      });
      return fields;
    }

    if (rrtype === RR_TYPES.MX && rdlength >= 3) {
      const pref = view.getUint16(rdataOffset, false);
      fields.push({
        id: `${prefixId}-mx-pref`,
        label: 'MX Preference',
        startOffset: rdataOffset,
        endOffset: rdataOffset + 2,
        valueSummary: String(pref),
      });
      const traced = decodeWireNameWithTrace(buf, rdataOffset + 2);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-mx-exch`,
        section,
        fieldLabel: 'MX Exchange',
        startOffset: rdataOffset + 2,
        traced,
      });
      return fields;
    }

    if (rrtype === RR_TYPES.SOA && rdlength >= 22) {
      const mname = decodeWireNameWithTrace(buf, rdataOffset);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-soa-mname`,
        section,
        fieldLabel: 'SOA MNAME',
        startOffset: rdataOffset,
        traced: mname,
      });
      const rnameStart = rdataOffset + mname.bytesRead;
      const rname = decodeWireNameWithTrace(buf, rnameStart);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-soa-rname`,
        section,
        fieldLabel: 'SOA RNAME',
        startOffset: rnameStart,
        traced: rname,
      });
      const timersOffset = rnameStart + rname.bytesRead;
      if (timersOffset + 20 <= end) {
        const timerLabels = ['Serial', 'Refresh', 'Retry', 'Expire', 'Minimum TTL'] as const;
        timerLabels.forEach((lbl, idx) => {
          const off = timersOffset + idx * 4;
          const val = view.getUint32(off, false);
          fields.push({
            id: `${prefixId}-soa-${idx}`,
            label: `SOA ${lbl}`,
            startOffset: off,
            endOffset: off + 4,
            valueSummary: idx === 0 ? String(val) : `${val}s`,
          });
        });
      }
      return fields;
    }

    if (rrtype === RR_TYPES.SRV && rdlength >= 7) {
      const prio = view.getUint16(rdataOffset, false);
      const weight = view.getUint16(rdataOffset + 2, false);
      const port = view.getUint16(rdataOffset + 4, false);
      fields.push(
        {
          id: `${prefixId}-srv-prio`,
          label: 'SRV Priority',
          startOffset: rdataOffset,
          endOffset: rdataOffset + 2,
          valueSummary: String(prio),
        },
        {
          id: `${prefixId}-srv-weight`,
          label: 'SRV Weight',
          startOffset: rdataOffset + 2,
          endOffset: rdataOffset + 4,
          valueSummary: String(weight),
        },
        {
          id: `${prefixId}-srv-port`,
          label: 'SRV Port',
          startOffset: rdataOffset + 4,
          endOffset: rdataOffset + 6,
          valueSummary: String(port),
        }
      );
      const traced = decodeWireNameWithTrace(buf, rdataOffset + 6);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-srv-target`,
        section,
        fieldLabel: 'SRV Target',
        startOffset: rdataOffset + 6,
        traced,
      });
      return fields;
    }

    if ((rrtype === RR_TYPES.DNSKEY || rrtype === RR_TYPES.CDNSKEY) && rdlength >= 4) {
      const flags = view.getUint16(rdataOffset, false);
      const proto = buf[rdataOffset + 2];
      const alg = buf[rdataOffset + 3];
      const keyTag = computeKeyTag(buf.subarray(rdataOffset, end));
      const isSep = (flags & 0x0001) !== 0;
      const isZone = (flags & 0x0100) !== 0;
      fields.push(
        {
          id: `${prefixId}-dnskey-flags`,
          label: 'DNSKEY Flags',
          startOffset: rdataOffset,
          endOffset: rdataOffset + 2,
          valueSummary: `${flags} (${isZone ? 'ZONE ' : ''}${isSep ? 'SEP/KSK' : 'ZSK'})`,
        },
        {
          id: `${prefixId}-dnskey-proto`,
          label: 'Protocol',
          startOffset: rdataOffset + 2,
          endOffset: rdataOffset + 3,
          valueSummary: String(proto),
        },
        {
          id: `${prefixId}-dnskey-alg`,
          label: 'Algorithm',
          startOffset: rdataOffset + 3,
          endOffset: rdataOffset + 4,
          valueSummary: `Alg ${alg} (Key Tag #${keyTag})`,
        }
      );
      if (rdlength > 4) {
        fields.push({
          id: `${prefixId}-dnskey-pub`,
          label: 'Public Key Material',
          startOffset: rdataOffset + 4,
          endOffset: end,
          valueSummary: `${rdlength - 4} bytes`,
        });
      }
      return fields;
    }

    if ((rrtype === RR_TYPES.DS || rrtype === RR_TYPES.CDS) && rdlength >= 4) {
      const keyTag = view.getUint16(rdataOffset, false);
      const alg = buf[rdataOffset + 2];
      const digestType = buf[rdataOffset + 3];
      fields.push(
        {
          id: `${prefixId}-ds-tag`,
          label: 'Key Tag',
          startOffset: rdataOffset,
          endOffset: rdataOffset + 2,
          valueSummary: `#${keyTag}`,
        },
        {
          id: `${prefixId}-ds-alg`,
          label: 'Algorithm',
          startOffset: rdataOffset + 2,
          endOffset: rdataOffset + 3,
          valueSummary: String(alg),
        },
        {
          id: `${prefixId}-ds-dt`,
          label: 'Digest Type',
          startOffset: rdataOffset + 3,
          endOffset: rdataOffset + 4,
          valueSummary: String(digestType),
        }
      );
      if (rdlength > 4) {
        fields.push({
          id: `${prefixId}-ds-dig`,
          label: 'Digest',
          startOffset: rdataOffset + 4,
          endOffset: end,
          valueSummary: `${bytesToHex(buf.subarray(rdataOffset + 4, end)).slice(0, 24)}… (${rdlength - 4}B)`,
        });
      }
      return fields;
    }

    if (rrtype === RR_TYPES.RRSIG && rdlength >= 19) {
      const typeCovered = view.getUint16(rdataOffset, false);
      const alg = buf[rdataOffset + 2];
      const labels = buf[rdataOffset + 3];
      const origTtl = view.getUint32(rdataOffset + 4, false);
      const sigExp = view.getUint32(rdataOffset + 8, false);
      const sigInc = view.getUint32(rdataOffset + 12, false);
      const keyTag = view.getUint16(rdataOffset + 16, false);
      fields.push(
        {
          id: `${prefixId}-rrsig-cov`,
          label: 'Type Covered',
          startOffset: rdataOffset,
          endOffset: rdataOffset + 2,
          valueSummary: `${rrTypeToString(typeCovered)} (${typeCovered})`,
        },
        {
          id: `${prefixId}-rrsig-alg`,
          label: 'Alg & Labels',
          startOffset: rdataOffset + 2,
          endOffset: rdataOffset + 4,
          valueSummary: `Alg ${alg}, ${labels} label(s)`,
        },
        {
          id: `${prefixId}-rrsig-ttl`,
          label: 'Original TTL',
          startOffset: rdataOffset + 4,
          endOffset: rdataOffset + 8,
          valueSummary: `${origTtl}s`,
        },
        {
          id: `${prefixId}-rrsig-exp`,
          label: 'Expiration',
          startOffset: rdataOffset + 8,
          endOffset: rdataOffset + 12,
          valueSummary: formatDnsTimestamp(sigExp),
        },
        {
          id: `${prefixId}-rrsig-inc`,
          label: 'Inception',
          startOffset: rdataOffset + 12,
          endOffset: rdataOffset + 16,
          valueSummary: formatDnsTimestamp(sigInc),
        },
        {
          id: `${prefixId}-rrsig-tag`,
          label: 'Key Tag',
          startOffset: rdataOffset + 16,
          endOffset: rdataOffset + 18,
          valueSummary: `#${keyTag}`,
        }
      );
      const signer = decodeWireNameWithTrace(buf, rdataOffset + 18);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-rrsig-signer`,
        section,
        fieldLabel: 'Signer Name',
        startOffset: rdataOffset + 18,
        traced: signer,
      });
      const sigStart = rdataOffset + 18 + signer.bytesRead;
      if (sigStart < end) {
        fields.push({
          id: `${prefixId}-rrsig-sig`,
          label: 'Cryptographic Signature',
          startOffset: sigStart,
          endOffset: end,
          valueSummary: `${end - sigStart} bytes`,
        });
      }
      return fields;
    }

    if ((rrtype === RR_TYPES.HTTPS || rrtype === RR_TYPES.SVCB) && rdlength >= 3) {
      const svcPrio = view.getUint16(rdataOffset, false);
      fields.push({
        id: `${prefixId}-svcb-prio`,
        label: 'SvcPriority',
        startOffset: rdataOffset,
        endOffset: rdataOffset + 2,
        valueSummary: svcPrio === 0 ? '0 (AliasMode)' : `${svcPrio} (ServiceMode)`,
      });
      const target = decodeWireNameWithTrace(buf, rdataOffset + 2);
      appendNameSubfields(fields, compressionJumps, {
        prefixId: `${prefixId}-svcb-target`,
        section,
        fieldLabel: 'TargetName',
        startOffset: rdataOffset + 2,
        traced: target,
      });
      let pOff = rdataOffset + 2 + target.bytesRead;
      let pIdx = 0;
      while (pOff + 4 <= end) {
        const key = view.getUint16(pOff, false);
        const vLen = view.getUint16(pOff + 2, false);
        const pEnd = Math.min(end, pOff + 4 + vLen);
        fields.push({
          id: `${prefixId}-svcb-param-${pIdx++}`,
          label: `SvcParam ${svcParamKeyToString(key)} (key ${key})`,
          startOffset: pOff,
          endOffset: pEnd,
          valueSummary: `4B header + ${vLen}B value`,
        });
        pOff = pEnd;
      }
      return fields;
    }

    if ((rrtype === RR_TYPES.TLSA || rrtype === RR_TYPES.SMIMEA) && rdlength >= 3) {
      const usage = buf[rdataOffset];
      const selector = buf[rdataOffset + 1];
      const matching = buf[rdataOffset + 2];
      fields.push(
        {
          id: `${prefixId}-dane-usage`,
          label: 'Certificate Usage',
          startOffset: rdataOffset,
          endOffset: rdataOffset + 1,
          valueSummary: String(usage),
        },
        {
          id: `${prefixId}-dane-sel`,
          label: 'Selector',
          startOffset: rdataOffset + 1,
          endOffset: rdataOffset + 2,
          valueSummary: String(selector),
        },
        {
          id: `${prefixId}-dane-match`,
          label: 'Matching Type',
          startOffset: rdataOffset + 2,
          endOffset: rdataOffset + 3,
          valueSummary: String(matching),
        }
      );
      if (rdlength > 3) {
        fields.push({
          id: `${prefixId}-dane-assoc`,
          label: 'Certificate Association Data',
          startOffset: rdataOffset + 3,
          endOffset: end,
          valueSummary: `${rdlength - 3} bytes`,
        });
      }
      return fields;
    }

    if (rrtype === RR_TYPES.OPENPGPKEY && rdlength >= 1) {
      fields.push({
        id: `${prefixId}-openpgpkey`,
        label: 'OpenPGP Transferable Public Key (RFC 7929)',
        startOffset: rdataOffset,
        endOffset: end,
        valueSummary: `${rdlength} bytes`,
      });
      return fields;
    }

    if (rrtype === RR_TYPES.TXT || rrtype === RR_TYPES.SPF) {
      let tOff = rdataOffset;
      let chunkIdx = 0;
      const dec = new TextDecoder();
      while (tOff < end) {
        const sLen = buf[tOff];
        const sEnd = Math.min(end, tOff + 1 + sLen);
        const strPreview = dec.decode(buf.subarray(tOff + 1, sEnd));
        const idx = chunkIdx++;
        fields.push({
          id: `${prefixId}-txt-${idx}`,
          label: `TXT String #${idx + 1} (len ${sLen})`,
          startOffset: tOff,
          endOffset: sEnd,
          valueSummary: strPreview.length > 48 ? `"${strPreview.slice(0, 48)}…"` : `"${strPreview}"`,
        });
        tOff = sEnd;
      }
      return fields;
    }
  } catch {
    // Fall back cleanly to raw RDATA span below if RDATA is malformed
  }

  fields.push({
    id: `${prefixId}-rdata`,
    label: `${rrTypeToString(rrtype)} RDATA`,
    startOffset: rdataOffset,
    endOffset: end,
    valueSummary: `${rdlength} byte(s)`,
  });
  return fields;
}

/**
 * Dissects a raw DNS wire packet (`Uint8Array`) into byte-accurate section spans,
 * 16-bit header flag bitfields, RDATA subfields, and RFC 1035 §4.1.4 `0xC0xx` compression pointer jumps.
 */
export function dissectDnsWirePacket(buf: Uint8Array): DissectedWirePacket {
  if (buf.length < 12) {
    throw new Error(`DNS wire packet must be at least 12 bytes (got ${buf.length} bytes)`);
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = view.getUint16(0, false);
  const flagWord = view.getUint16(2, false);
  const qdCount = view.getUint16(4, false);
  const anCount = view.getUint16(6, false);
  const nsCount = view.getUint16(8, false);
  const arCount = view.getUint16(10, false);

  const spans: WireSectionSpan[] = [];
  const compressionJumps: WireCompressionJump[] = [];
  let extendedRcode = 0;
  let parseWarning: string | undefined;

  const headerSpan: WireSectionSpan = {
    id: 'section-header',
    category: 'header',
    title: 'DNS Header (12 bytes)',
    subtitle: `ID 0x${id.toString(16).toUpperCase().padStart(4, '0')} · Flags 0x${flagWord.toString(16).toUpperCase().padStart(4, '0')} · QD=${qdCount} AN=${anCount} NS=${nsCount} AR=${arCount}`,
    startOffset: 0,
    endOffset: 12,
    fields: [
      {
        id: 'hdr-id',
        label: 'Transaction ID',
        startOffset: 0,
        endOffset: 2,
        valueSummary: `0x${id.toString(16).toUpperCase().padStart(4, '0')} (${id})`,
      },
      {
        id: 'hdr-flags',
        label: 'Flags & Codes (16 bits)',
        startOffset: 2,
        endOffset: 4,
        valueSummary: `0x${flagWord.toString(16).toUpperCase().padStart(4, '0')} (${flagWord.toString(2).padStart(16, '0')})`,
      },
      {
        id: 'hdr-qdcount',
        label: 'QDCOUNT (Questions)',
        startOffset: 4,
        endOffset: 6,
        valueSummary: String(qdCount),
      },
      {
        id: 'hdr-ancount',
        label: 'ANCOUNT (Answers)',
        startOffset: 6,
        endOffset: 8,
        valueSummary: String(anCount),
      },
      {
        id: 'hdr-nscount',
        label: 'NSCOUNT (Authority RRs)',
        startOffset: 8,
        endOffset: 10,
        valueSummary: String(nsCount),
      },
      {
        id: 'hdr-arcount',
        label: 'ARCOUNT (Additional RRs)',
        startOffset: 10,
        endOffset: 12,
        valueSummary: String(arCount),
      },
    ],
  };
  spans.push(headerSpan);

  let offset = 12;

  try {
    for (let qIdx = 0; qIdx < qdCount; qIdx++) {
      if (offset >= buf.length) break;
      const qStart = offset;
      const qFields: WireSubfieldSpan[] = [];
      const traced = decodeWireNameWithTrace(buf, offset);
      appendNameSubfields(qFields, compressionJumps, {
        prefixId: `q-${qIdx}`,
        section: 'question',
        fieldLabel: 'QNAME',
        startOffset: offset,
        traced,
      });
      offset += traced.bytesRead;
      if (offset + 4 > buf.length) {
        parseWarning = `Truncated Question #${qIdx + 1} at ${formatOffsetHex(offset)}`;
        break;
      }
      const qtype = view.getUint16(offset, false);
      const qclass = view.getUint16(offset + 2, false);
      qFields.push(
        {
          id: `q-${qIdx}-qtype`,
          label: 'QTYPE',
          startOffset: offset,
          endOffset: offset + 2,
          valueSummary: `${rrTypeToString(qtype)} (${qtype})`,
        },
        {
          id: `q-${qIdx}-qclass`,
          label: 'QCLASS',
          startOffset: offset + 2,
          endOffset: offset + 4,
          valueSummary: qclass === 1 ? 'IN (1)' : `CLASS${qclass} (${qclass})`,
        }
      );
      offset += 4;

      spans.push({
        id: `section-q-${qIdx}`,
        category: 'question',
        title: `Question #${qIdx + 1}: ${normalizeFqdn(traced.fullName)} ${rrTypeToString(qtype)}`,
        subtitle: `${offset - qStart}B (${formatOffsetHex(qStart)}..${formatOffsetHex(offset - 1)})`,
        startOffset: qStart,
        endOffset: offset,
        fields: qFields,
      });
    }

    const dissectRrSection = (count: number, category: 'answer' | 'authority' | 'additional') => {
      const sectionLabel =
        category === 'answer' ? 'Answer' : category === 'authority' ? 'Authority' : 'Additional';
      for (let rIdx = 0; rIdx < count; rIdx++) {
        if (offset >= buf.length) break;
        const rStart = offset;
        const rFields: WireSubfieldSpan[] = [];
        const traced = decodeWireNameWithTrace(buf, offset);
        const peekTypeOffset = offset + traced.bytesRead;
        if (peekTypeOffset + 10 > buf.length) {
          parseWarning = `Truncated ${sectionLabel} RR #${rIdx + 1} header at ${formatOffsetHex(offset)}`;
          break;
        }
        const rrtype = view.getUint16(peekTypeOffset, false);
        const rrclass = view.getUint16(peekTypeOffset + 2, false);
        const ttl = view.getUint32(peekTypeOffset + 4, false);
        const rdlength = view.getUint16(peekTypeOffset + 8, false);
        const rdataStart = peekTypeOffset + 10;
        const rdataEnd = rdataStart + rdlength;

        if (rdataEnd > buf.length) {
          parseWarning = `Truncated ${sectionLabel} RR #${rIdx + 1} RDATA at ${formatOffsetHex(rdataStart)} (expected ${rdlength}B)`;
          break;
        }

        const effectiveCat: WireSpanCategory = rrtype === RR_TYPES.OPT ? 'edns' : category;

        appendNameSubfields(rFields, compressionJumps, {
          prefixId: `${category}-${rIdx}`,
          section: effectiveCat,
          fieldLabel: rrtype === RR_TYPES.OPT ? 'OPT Root Domain' : 'Owner NAME',
          startOffset: offset,
          traced,
        });

        if (rrtype === RR_TYPES.OPT) {
          const extRcode = (ttl >>> 24) & 0xff;
          const ednsVer = (ttl >>> 16) & 0xff;
          const ednsFlags = ttl & 0xffff;
          const doBit = (ednsFlags & 0x8000) !== 0;
          if (extRcode > 0) extendedRcode = extRcode;

          rFields.push(
            {
              id: `${category}-${rIdx}-type`,
              label: 'TYPE',
              startOffset: peekTypeOffset,
              endOffset: peekTypeOffset + 2,
              valueSummary: 'OPT (41 — RFC 6891 EDNS0)',
            },
            {
              id: `${category}-${rIdx}-udpsize`,
              label: 'Requestor UDP Payload Size',
              startOffset: peekTypeOffset + 2,
              endOffset: peekTypeOffset + 4,
              valueSummary: `${rrclass} bytes`,
            },
            {
              id: `${category}-${rIdx}-extflags`,
              label: 'EXT-RCODE / Version / Flags',
              startOffset: peekTypeOffset + 4,
              endOffset: peekTypeOffset + 8,
              valueSummary: `ExtRCODE=${extRcode}, EDNS v${ednsVer}, DO=${doBit ? 1 : 0} (0x${ednsFlags.toString(16).toUpperCase().padStart(4, '0')})`,
            },
            {
              id: `${category}-${rIdx}-rdlen`,
              label: 'RDLENGTH',
              startOffset: peekTypeOffset + 8,
              endOffset: peekTypeOffset + 10,
              valueSummary: `${rdlength} bytes`,
            }
          );

          let optOff = rdataStart;
          let optIdx = 0;
          const dec = new TextDecoder();
          while (optOff + 4 <= rdataEnd) {
            const optCode = view.getUint16(optOff, false);
            const optLen = view.getUint16(optOff + 2, false);
            const optDataEnd = Math.min(rdataEnd, optOff + 4 + optLen);
            let optSummary = `${optLen}B payload`;
            if (optCode === 15 && optOff + 6 <= optDataEnd) {
              const infoCode = view.getUint16(optOff + 4, false);
              const extra =
                optDataEnd > optOff + 6
                  ? dec.decode(buf.subarray(optOff + 6, optDataEnd)).replace(/\0+$/, '')
                  : '';
              const meta = EDE_CODES[infoCode];
              optSummary = `EDE ${infoCode} (${meta?.name ?? 'Unknown'})${extra ? `: "${extra}"` : ''}`;
            } else if (optCode === 12) {
              optSummary = `${optLen} padding bytes (RFC 7830)`;
            }
            rFields.push({
              id: `${category}-${rIdx}-opt-${optIdx++}`,
              label: `EDNS Option ${optCode} (${EDNS_OPTION_NAMES[optCode] ?? 'Custom'})`,
              startOffset: optOff,
              endOffset: optDataEnd,
              valueSummary: optSummary,
            });
            optOff = optDataEnd;
          }

          spans.push({
            id: `section-${category}-${rIdx}`,
            category: 'edns',
            title: `EDNS0 OPT Pseudo-RR (UDP ${rrclass}B, DO=${doBit ? 1 : 0})`,
            subtitle: `${rdataEnd - rStart}B (${formatOffsetHex(rStart)}..${formatOffsetHex(rdataEnd - 1)})`,
            startOffset: rStart,
            endOffset: rdataEnd,
            fields: rFields,
          });
        } else {
          rFields.push(
            {
              id: `${category}-${rIdx}-type`,
              label: 'TYPE',
              startOffset: peekTypeOffset,
              endOffset: peekTypeOffset + 2,
              valueSummary: `${rrTypeToString(rrtype)} (${rrtype})`,
            },
            {
              id: `${category}-${rIdx}-class`,
              label: 'CLASS',
              startOffset: peekTypeOffset + 2,
              endOffset: peekTypeOffset + 4,
              valueSummary: rrclass === 1 ? 'IN (1)' : `CLASS${rrclass} (${rrclass})`,
            },
            {
              id: `${category}-${rIdx}-ttl`,
              label: 'TTL',
              startOffset: peekTypeOffset + 4,
              endOffset: peekTypeOffset + 8,
              valueSummary: `${ttl}s`,
            },
            {
              id: `${category}-${rIdx}-rdlen`,
              label: 'RDLENGTH',
              startOffset: peekTypeOffset + 8,
              endOffset: peekTypeOffset + 10,
              valueSummary: `${rdlength} bytes`,
            }
          );

          const rdataSubfields = dissectRdataSubfields(
            buf,
            rdataStart,
            rdlength,
            rrtype,
            `${category}-${rIdx}`,
            category,
            compressionJumps
          );
          rFields.push(...rdataSubfields);

          spans.push({
            id: `section-${category}-${rIdx}`,
            category,
            title: `${sectionLabel} #${rIdx + 1}: ${normalizeFqdn(traced.fullName)} ${rrTypeToString(rrtype)}`,
            subtitle: `TTL ${ttl}s · RDATA ${rdlength}B · Total ${rdataEnd - rStart}B (${formatOffsetHex(rStart)}..${formatOffsetHex(rdataEnd - 1)})`,
            startOffset: rStart,
            endOffset: rdataEnd,
            fields: rFields,
          });
        }

        offset = rdataEnd;
      }
    };

    dissectRrSection(anCount, 'answer');
    dissectRrSection(nsCount, 'authority');
    dissectRrSection(arCount, 'additional');
  } catch (err) {
    parseWarning = err instanceof Error ? err.message : String(err);
  }

  let parsedPacket: DnsPacket | undefined;
  try {
    parsedPacket = parseDnsPacket(buf);
  } catch (err) {
    if (!parseWarning) {
      parseWarning = err instanceof Error ? err.message : String(err);
    }
  }

  const totalSavedBytes = compressionJumps.reduce((acc, j) => acc + j.savedBytes, 0);
  const uncompressedEquivalentSize = buf.length + totalSavedBytes;
  const savingsPercent =
    uncompressedEquivalentSize > 0
      ? Math.round((totalSavedBytes / uncompressedEquivalentSize) * 1000) / 10
      : 0;

  return {
    bytes: buf,
    wireSize: buf.length,
    base64: bytesToBase64(buf),
    base64Url: bytesToBase64Url(buf),
    id,
    flagWord,
    flagWordHex: `0x${flagWord.toString(16).toUpperCase().padStart(4, '0')}`,
    flagWordBinary: flagWord.toString(2).padStart(16, '0'),
    headerBits: buildHeaderBitFields(flagWord, extendedRcode),
    counts: { qdCount, anCount, nsCount, arCount },
    spans,
    compressionJumps,
    compressionStats: {
      pointerCount: compressionJumps.length,
      compressedWireSize: buf.length,
      uncompressedEquivalentSize,
      totalSavedBytes,
      savingsPercent,
    },
    parsedPacket,
    parseWarning,
  };
}

/**
 * Flexible offline parser for user-pasted DNS wire payloads:
 * - Full DoH URL containing `?dns=<base64url>` (RFC 8484)
 * - Raw `dns=<base64url>` parameter
 * - Hex dumps from `xxd`, `hexdump -C`, `tcpdump -xx`, Wireshark, or DigDeep (`0000  12 34 ... |..|`)
 * - Plain continuous or whitespace/colon-delimited hexadecimal (`12348180...` or `12:34:81:80...`)
 * - Standard Base64 or URL-safe Base64url (`AAABAAAB...`)
 */
export function decodeUserWireInput(rawInput: string): {
  bytes: Uint8Array;
  detectedFormat: 'doh-url' | 'hex-dump' | 'hex' | 'base64url';
} {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('Paste a DoH ?dns= URL, Base64url string, or hexadecimal wire dump.');
  }

  // 1. Check for full DoH URL or `?dns=` / `dns=` query parameter
  const dnsParamMatch = /(?:[?&]|^)dns=([A-Za-z0-9+/=_-]+)/.exec(trimmed);
  if (dnsParamMatch) {
    const bytes = base64UrlToBytes(dnsParamMatch[1]);
    if (bytes.length < 12) {
      throw new Error(`Decoded ?dns= payload is only ${bytes.length} bytes (minimum 12-byte DNS header required).`);
    }
    return { bytes, detectedFormat: 'doh-url' };
  }

  // 2. Check for multi-line or offset-prefixed hex dump (`xxd`, `hexdump -C`, `tcpdump -xx`, DigDeep hex view)
  const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const looksLikeOffsetHexDump =
    lines.length >= 1 &&
    lines.every((l) => /^(?:0x)?[0-9a-fA-F]{4,8}:?\s+(?:[0-9a-fA-F]{2,4}\s+)+/.test(l));
  if (looksLikeOffsetHexDump) {
    const hexTokens: string[] = [];
    for (const line of lines) {
      // Strip leading offset (`0000:` or `0x0000`) and trailing ASCII column (`|...|` or after two+ spaces)
      const withoutAscii = line.replace(/\|.*\|$/, '');
      const afterOffset = withoutAscii.replace(/^(?:0x)?[0-9a-fA-F]{4,8}:?\s+/, '');
      // Stop before trailing 16-char ASCII column in `xxd` (separated by 2+ spaces after hex bytes)
      const hexPart = afterOffset.split(/\s{3,}/)[0] ?? afterOffset;
      const groups = hexPart.trim().split(/\s+/);
      for (const g of groups) {
        if (/^[0-9a-fA-F]{2}$/.test(g) || /^[0-9a-fA-F]{4}$/.test(g)) {
          hexTokens.push(g);
        } else {
          break;
        }
      }
    }
    const joinedHex = hexTokens.join('');
    if (joinedHex.length >= 24 && joinedHex.length % 2 === 0) {
      return { bytes: hexToBytes(joinedHex), detectedFormat: 'hex-dump' };
    }
  }

  // 3. Plain hexadecimal (continuous `12348180...`, space-separated `12 34`, colon-separated `12:34`, or `0x...`)
  const strippedHex = trimmed.replace(/^0x/i, '').replace(/[\s:-]+/g, '');
  const hasSeparators = /[\s:]/.test(trimmed);
  if (
    /^[0-9a-fA-F]+$/.test(strippedHex) &&
    strippedHex.length >= 24 &&
    strippedHex.length % 2 === 0 &&
    (hasSeparators || !/[G-Zg-z+/=_-]/.test(trimmed))
  ) {
    // Disambiguate pure `[0-9A-Fa-f]` strings that might actually be Base64 only when length isn't Base64-like:
    // Almost all Base64 DNS headers start with 'AA' or contain non-hex letters ('g'-'z', 'G'-'Z', '-', '_').
    // If it contains spaces/colons or starts with non-'AA' hex, treat as hex; if it starts with 'AA' and no spaces, check header sanity.
    const candidateHexBytes = hexToBytes(strippedHex);
    if (hasSeparators) {
      return { bytes: candidateHexBytes, detectedFormat: 'hex' };
    }
    try {
      const candidateB64Bytes = base64UrlToBytes(trimmed);
      // Prefer whichever parses cleanly as a valid DNS packet without truncation!
      let hexValid = false;
      let b64Valid = false;
      try {
        parseDnsPacket(candidateHexBytes);
        hexValid = true;
      } catch {
        hexValid = false;
      }
      try {
        if (candidateB64Bytes.length >= 12) {
          parseDnsPacket(candidateB64Bytes);
          b64Valid = true;
        }
      } catch {
        b64Valid = false;
      }
      if (b64Valid && !hexValid) {
        return { bytes: candidateB64Bytes, detectedFormat: 'base64url' };
      }
    } catch {
      // Ignore base64 fallback error; return hex bytes
    }
    return { bytes: candidateHexBytes, detectedFormat: 'hex' };
  }

  // 4. Base64url / standard Base64 (`?dns=` payload without prefix)
  try {
    const cleanB64 = trimmed.replace(/\s+/g, '');
    const bytes = cleanB64.includes('-') || cleanB64.includes('_')
      ? base64UrlToBytes(cleanB64)
      : base64UrlToBytes(cleanB64);
    if (bytes.length < 12) {
      throw new Error(`Decoded packet is only ${bytes.length} bytes (expected >= 12 bytes).`);
    }
    return { bytes, detectedFormat: 'base64url' };
  } catch (err) {
    throw new Error(
      err instanceof Error && err.message.includes('only')
        ? err.message
        : 'Unrecognized DNS wire input. Paste a DoH ?dns= URL, Base64url/Base64 payload, or hex dump.'
    );
  }
}

/**
 * Builds a synthetic `DohQueryLog` wrapper around a decoded offline `DissectedWirePacket`
 * so `formatPacketAsDig` can format pasted offline packets identically to live DoH responses.
 */
export function buildSyntheticLogFromDissected(dissected: DissectedWirePacket): DohQueryLog | null {
  if (!dissected.parsedPacket) return null;
  const firstQ = dissected.parsedPacket.questions[0];
  return {
    id: 'offline-custom-wire',
    qname: firstQ?.name ?? '.',
    qtype: firstQ?.type ?? RR_TYPES.A,
    qtypeName: firstQ?.typeName ?? 'A',
    cd: dissected.parsedPacket.flags.cd,
    doBit: Boolean(dissected.parsedPacket.edns?.doBit),
    purpose: 'Offline Wire Packet Dissector',
    startedAt: 0,
    latencyMs: 0,
    httpStatus: 200,
    endpoint: 'offline-input',
    requestWireBase64: '',
    wireBase64: dissected.base64,
    packet: dissected.parsedPacket,
  };
}
