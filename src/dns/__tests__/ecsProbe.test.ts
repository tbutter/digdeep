import { describe, expect, it } from 'vitest';
import { RR_TYPES } from '../constants';
import { formatPacketAsDig, generateCliReproducerCommands } from '../digFormat';
import { DohSession } from '../doh';
import {
  ECS_REGIONAL_PROBES,
  evaluateEcsGeoFromLogs,
  probeCustomEcsSubnet,
  runEcsGeoProbes,
  selectEcsDohEndpoint,
} from '../ecsProbe';
import { bytesToBase64, concatBytes } from '../encoding';
import type { DohQueryLog } from '../types';
import {
  buildDnsQuery,
  decodeEdnsClientSubnetOption,
  encodeDnsName,
  encodeEdnsClientSubnetOption,
  formatEcsQuerySubnet,
  parseDnsPacket,
  parseEcsSubnetInput,
} from '../wire';
import { dissectDnsWirePacket } from '../wireDissector';

/**
 * Helper to synthesize a raw DNS wire response packet with optional CNAME, A/AAAA answers, and EDNS0 Option 8 (`CLIENT-SUBNET`).
 */
function buildSyntheticEcsResponseWire(opts: {
  qname: string;
  qtype: number;
  rcode?: number;
  ad?: boolean;
  cnameTarget?: string;
  ipv4Answers?: string[];
  ipv6Answers?: number[][];
  ttl?: number;
  ecsPayload?: Uint8Array;
}): Uint8Array {
  const rcode = opts.rcode ?? 0;
  const ttl = opts.ttl ?? 60;
  const header = new Uint8Array(12);
  const hv = new DataView(header.buffer);
  hv.setUint16(0, 0x1234, false);
  // QR=1, RD=1, RA=1, AD=opts.ad, RCODE=low 4 bits
  const flags = 0x8180 | (opts.ad ? 0x0020 : 0) | (rcode & 0x0f);
  hv.setUint16(2, flags, false);
  hv.setUint16(4, 1, false); // QDCOUNT = 1

  const answerChunks: Uint8Array[] = [];
  let ownerForAddr = opts.qname;
  if (opts.cnameTarget) {
    const ownerWire = encodeDnsName(opts.qname, false);
    const targetWire = encodeDnsName(opts.cnameTarget, false);
    const meta = new Uint8Array(10);
    const mv = new DataView(meta.buffer);
    mv.setUint16(0, RR_TYPES.CNAME, false);
    mv.setUint16(2, 1, false);
    mv.setUint32(4, ttl, false);
    mv.setUint16(8, targetWire.length, false);
    answerChunks.push(concatBytes(ownerWire, meta, targetWire));
    ownerForAddr = opts.cnameTarget;
  }

  for (const ip of opts.ipv4Answers ?? []) {
    const ownerWire = encodeDnsName(ownerForAddr, false);
    const rdata = new Uint8Array(ip.split('.').map((n) => Number.parseInt(n, 10)));
    const meta = new Uint8Array(10);
    const mv = new DataView(meta.buffer);
    mv.setUint16(0, RR_TYPES.A, false);
    mv.setUint16(2, 1, false);
    mv.setUint32(4, ttl, false);
    mv.setUint16(8, 4, false);
    answerChunks.push(concatBytes(ownerWire, meta, rdata));
  }

  for (const bytes16 of opts.ipv6Answers ?? []) {
    const ownerWire = encodeDnsName(ownerForAddr, false);
    const rdata = new Uint8Array(bytes16);
    const meta = new Uint8Array(10);
    const mv = new DataView(meta.buffer);
    mv.setUint16(0, RR_TYPES.AAAA, false);
    mv.setUint16(2, 1, false);
    mv.setUint32(4, ttl, false);
    mv.setUint16(8, 16, false);
    answerChunks.push(concatBytes(ownerWire, meta, rdata));
  }

  hv.setUint16(6, answerChunks.length, false); // ANCOUNT
  hv.setUint16(8, 0, false); // NSCOUNT
  hv.setUint16(10, 1, false); // ARCOUNT = 1 (OPT)

  const qnameWire = encodeDnsName(opts.qname, false);
  const qTail = new Uint8Array(4);
  const qv = new DataView(qTail.buffer);
  qv.setUint16(0, opts.qtype, false);
  qv.setUint16(2, 1, false);

  let optRdata: Uint8Array = new Uint8Array(0);
  if (opts.ecsPayload) {
    const tlvHdr = new Uint8Array(4);
    const tv = new DataView(tlvHdr.buffer);
    tv.setUint16(0, 8, false); // OPTION-CODE = 8
    tv.setUint16(2, opts.ecsPayload.length, false);
    optRdata = concatBytes(tlvHdr, opts.ecsPayload);
  }

  const optRecord = new Uint8Array(11 + optRdata.length);
  optRecord[0] = 0; // root owner
  const ov = new DataView(optRecord.buffer);
  ov.setUint16(1, RR_TYPES.OPT, false);
  ov.setUint16(3, 1232, false);
  optRecord[5] = (rcode >>> 4) & 0xff;
  optRecord[6] = 0;
  ov.setUint16(7, 0x8000, false); // DO=1
  ov.setUint16(9, optRdata.length, false);
  optRecord.set(optRdata, 11);

  return concatBytes(header, qnameWire, qTail, ...answerChunks, optRecord);
}

function makeSyntheticEcsLog(params: {
  id: string;
  qname: string;
  qtype: 'A' | 'AAAA';
  ecsSubnet: string;
  endpoint?: string;
  rcode?: number;
  ad?: boolean;
  cnameTarget?: string;
  ipv4Answers?: string[];
  ipv6Answers?: number[][];
  ecsPayload?: Uint8Array;
}): DohQueryLog {
  const rrtype = params.qtype === 'A' ? RR_TYPES.A : RR_TYPES.AAAA;
  const wire = buildSyntheticEcsResponseWire({
    qname: params.qname,
    qtype: rrtype,
    rcode: params.rcode,
    ad: params.ad,
    cnameTarget: params.cnameTarget,
    ipv4Answers: params.ipv4Answers,
    ipv6Answers: params.ipv6Answers,
    ecsPayload: params.ecsPayload,
  });
  return {
    id: params.id,
    qname: params.qname,
    qtype: rrtype,
    qtypeName: params.qtype,
    purpose: `ECS Geo probe (${params.ecsSubnet} ${params.qtype})`,
    cd: false,
    doBit: true,
    ecsSubnet: params.ecsSubnet,
    endpoint: params.endpoint ?? 'https://8.8.8.8/dns-query',
    startedAt: 1700000000000,
    latencyMs: 18,
    httpStatus: 200,
    requestWireBase64: bytesToBase64(wire),
    wireBase64: bytesToBase64(wire),
    packet: parseDnsPacket(wire),
  };
}

describe('RFC 7871 EDNS Client Subnet (ECS — Option 8) Wire Codec & Geo-Steering Probe', () => {
  it('parses, bit-masks, wire-encodes, and decodes IPv4, IPv6, non-8-bit CIDR, and /0 opt-out subnets', () => {
    // 1. IPv4 /24 masks host bits and truncates wire address to 3 octets
    const v4 = parseEcsSubnetInput('71.252.0.99/24');
    expect(v4).toEqual({
      family: 1,
      address: '71.252.0.0',
      sourcePrefixLength: 24,
      scopePrefixLength: 0,
    });
    expect(formatEcsQuerySubnet(v4!)).toBe('71.252.0.0/24');
    const tlvV4 = encodeEdnsClientSubnetOption(v4!);
    // 4B TLV header + 4B ECS header + 3B address = 11 bytes
    expect(tlvV4.length).toBe(11);
    expect(Array.from(tlvV4)).toEqual([0, 8, 0, 7, 0, 1, 24, 0, 71, 252, 0]);

    const queryWire = buildDnsQuery('www.example.com.', RR_TYPES.A, {
      id: 0x4242,
      cd: false,
      doBit: true,
      ecs: v4!,
    });
    const parsedQuery = parseDnsPacket(queryWire);
    expect(parsedQuery.edns?.ecs).toBeDefined();
    expect(parsedQuery.edns?.ecs?.family).toBe(1);
    expect(parsedQuery.edns?.ecs?.address).toBe('71.252.0.0');
    expect(parsedQuery.edns?.ecs?.sourcePrefixLength).toBe(24);
    expect(parsedQuery.edns?.ecs?.scopePrefixLength).toBe(0);
    expect(parsedQuery.edns?.ecs?.addressByteLength).toBe(3);
    expect(parsedQuery.edns?.ecs?.hasNonZeroTailBits).toBeUndefined();
    expect(parsedQuery.edns?.ecs?.hasExcessAddressBytes).toBeUndefined();

    // 2. Non-byte-aligned IPv4 /19 masks low 5 bits of 3rd octet (100 = 0x64 -> 96 = 0x60)
    const v4Slash19 = parseEcsSubnetInput('198.51.100.255/19');
    expect(v4Slash19?.address).toBe('198.51.96.0');
    const tlv19 = encodeEdnsClientSubnetOption(v4Slash19!);
    expect(Array.from(tlv19.subarray(4))).toEqual([0, 1, 19, 0, 198, 51, 96]);
    const dec19 = decodeEdnsClientSubnetOption(tlv19.subarray(4));
    expect(dec19.presentation).toBe('198.51.96.0/19/0');
    expect(dec19.hasNonZeroTailBits).toBeUndefined();

    // 3. IPv6 /56 preserves byte 7 (0xab) and masks byte 8 (0xcd -> 0x00), truncating wire address to 7 octets
    const v6 = parseEcsSubnetInput('2601:140:4000:abcd::1/56');
    expect(v6).toEqual({
      family: 2,
      address: '2601:140:4000:ab00::',
      sourcePrefixLength: 56,
      scopePrefixLength: 0,
    });
    const tlvV6 = encodeEdnsClientSubnetOption(v6!);
    // 4B TLV + 4B ECS header + 7B address = 15 bytes
    expect(tlvV6.length).toBe(15);
    const decV6 = decodeEdnsClientSubnetOption(tlvV6.subarray(4));
    expect(decV6.familyName).toBe('IPv6');
    expect(decV6.address).toBe('2601:140:4000:ab00::');
    expect(decV6.addressByteLength).toBe(7);

    // 4. Privacy opt-out 0.0.0.0/0 and ::/0 encode 0 address octets (OPTION-LENGTH = 4)
    const optOutV4 = parseEcsSubnetInput('0.0.0.0/0')!;
    const optOutTlv = encodeEdnsClientSubnetOption(optOutV4);
    expect(Array.from(optOutTlv)).toEqual([0, 8, 0, 4, 0, 1, 0, 0]);
    const decOptOut = decodeEdnsClientSubnetOption(optOutTlv.subarray(4));
    expect(decOptOut.presentation).toBe('0.0.0.0/0/0');
    expect(decOptOut.addressByteLength).toBe(0);

    const optOutV6 = parseEcsSubnetInput('::/0')!;
    expect(Array.from(encodeEdnsClientSubnetOption(optOutV6))).toEqual([0, 8, 0, 4, 0, 2, 0, 0]);

    // 5. Rejects invalid inputs cleanly
    expect(parseEcsSubnetInput('')).toBeNull();
    expect(parseEcsSubnetInput('71.252.0.0/33')).toBeNull();
    expect(parseEcsSubnetInput('2601:140::/129')).toBeNull();
    expect(parseEcsSubnetInput('not-an-ip/24')).toBeNull();
  });

  it('flags RFC 7871 §6 wire anomalies (non-zero tail bits, excess bytes, invalid prefix lengths)', () => {
    // Non-zero tail bits in /19 (0x64 has bit 0x04 set past bit 19)
    const dirtyTail = decodeEdnsClientSubnetOption(new Uint8Array([0, 1, 19, 19, 198, 51, 0x64]));
    expect(dirtyTail.hasNonZeroTailBits).toBe(true);

    // Excess trailing zero octet on /24 (4 bytes sent instead of 3)
    const excessBytes = decodeEdnsClientSubnetOption(new Uint8Array([0, 1, 24, 24, 71, 252, 0, 0]));
    expect(excessBytes.hasExcessAddressBytes).toBe(true);
    expect(excessBytes.hasNonZeroTailBits).toBeUndefined();

    // Invalid prefix length (> 32 for IPv4)
    const badPrefix = decodeEdnsClientSubnetOption(new Uint8Array([0, 1, 40, 24, 71, 252, 0, 0]));
    expect(badPrefix.invalidPrefixLength).toBe(true);

    // Truncated payload (< 4 bytes)
    const shortOpt = decodeEdnsClientSubnetOption(new Uint8Array([0, 1]));
    expect(shortOpt.familyName).toBe('MALFORMED');
    expect(shortOpt.invalidPrefixLength).toBe(true);
  });

  it('renders ECS Option 8 in WireDissector, formatPacketAsDig, and CLI reproducers', () => {
    const respWire = buildSyntheticEcsResponseWire({
      qname: 'cdn.example.com.',
      qtype: RR_TYPES.A,
      ad: true,
      ipv4Answers: ['198.51.100.10'],
      ecsPayload: new Uint8Array([0, 1, 24, 20, 71, 252, 0]),
    });
    const pkt = parseDnsPacket(respWire);
    expect(pkt.edns?.ecs?.presentation).toBe('71.252.0.0/24/20');

    const synLog = makeSyntheticEcsLog({
      id: 'dig-test',
      qname: 'cdn.example.com.',
      qtype: 'A',
      ecsSubnet: '71.252.0.0/24',
      ad: true,
      ipv4Answers: ['198.51.100.10'],
      ecsPayload: new Uint8Array([0, 1, 24, 20, 71, 252, 0]),
    });
    const digOut = formatPacketAsDig(synLog);
    expect(digOut).toContain('; CLIENT-SUBNET: 71.252.0.0/24/20');

    const cli = generateCliReproducerCommands({
      qname: 'cdn.example.com.',
      qtypeName: 'A',
      dohEndpoint: 'https://8.8.8.8/dns-query',
      cd: false,
      ecsSubnet: '71.252.0.0/24',
    });
    expect(cli.dig).toContain('+subnet=71.252.0.0/24');
    expect(cli.kdig).toContain('+subnet=71.252.0.0/24');

    const dissected = dissectDnsWirePacket(respWire);
    const ednsSpan = dissected.spans.find((s) => s.category === 'edns');
    expect(ednsSpan).toBeDefined();
    const childLabels = (ednsSpan?.fields ?? []).map((c) => c.label);
    expect(childLabels.some((l) => l.includes('ECS FAMILY'))).toBe(true);
    expect(childLabels.some((l) => l.includes('ECS SOURCE / SCOPE PREFIX-LENGTH'))).toBe(true);
    expect(childLabels.some((l) => l.includes('ECS ADDRESS'))).toBe(true);
  });

  it('audits cache-busting /32 & /128 SCOPE, /0 opt-out violations, dangling regional CNAMEs, and regional SERVFAIL/AD skew without IPv4-only false positives', () => {
    const qname = 'geo.example.com.';
    const logs: DohQueryLog[] = [];

    for (const preset of ECS_REGIONAL_PROBES) {
      if (preset.id === 'us-east') {
        // Cache-busting /32 SCOPE on IPv4 + IPv4-only CNAME (AAAA returns NOERROR NODATA behind CNAME -> must NOT be flagged as dangling CNAME!)
        logs.push(
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v4`,
            qname,
            qtype: 'A',
            ecsSubnet: preset.ipv4Subnet,
            ad: true,
            cnameTarget: 'v4only-iad.example.net.',
            ipv4Answers: ['198.51.100.11'],
            ecsPayload: new Uint8Array([0, 1, 24, 32, 71, 252, 0]),
          }),
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v6`,
            qname,
            qtype: 'AAAA',
            ecsSubnet: preset.ipv6Subnet,
            ad: true,
            cnameTarget: 'v4only-iad.example.net.',
            ipv6Answers: [],
            ecsPayload: new Uint8Array([0, 2, 56, 56, 0x26, 0x01, 0x01, 0x40, 0x40, 0x00, 0x00]),
          })
        );
      } else if (preset.id === 'eu-central') {
        // Dangling regional CNAME -> NXDOMAIN (RCODE 3)
        logs.push(
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v4`,
            qname,
            qtype: 'A',
            ecsSubnet: preset.ipv4Subnet,
            rcode: 3,
            cnameTarget: 'dead-pop-fra.example.net.',
            ipv4Answers: [],
            ecsPayload: new Uint8Array([0, 1, 24, 24, 80, 150, 6]),
          }),
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v6`,
            qname,
            qtype: 'AAAA',
            ecsSubnet: preset.ipv6Subnet,
            rcode: 3,
            cnameTarget: 'dead-pop-fra.example.net.',
            ipv6Answers: [],
            ecsPayload: new Uint8Array([0, 2, 56, 56, 0x20, 0x03, 0x00, 0xc0, 0x40, 0x00, 0x00]),
          })
        );
      } else if (preset.id === 'ap-east') {
        // Regional SERVFAIL
        logs.push(
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v4`,
            qname,
            qtype: 'A',
            ecsSubnet: preset.ipv4Subnet,
            rcode: 2,
          }),
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v6`,
            qname,
            qtype: 'AAAA',
            ecsSubnet: preset.ipv6Subnet,
            rcode: 2,
          })
        );
      } else if (preset.id === 'opt-out') {
        // Privacy opt-out /0 violated with SCOPE = 24
        logs.push(
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v4`,
            qname,
            qtype: 'A',
            ecsSubnet: preset.ipv4Subnet,
            ad: false,
            ipv4Answers: ['198.51.100.99'],
            ecsPayload: new Uint8Array([0, 1, 0, 24]),
          }),
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v6`,
            qname,
            qtype: 'AAAA',
            ecsSubnet: preset.ipv6Subnet,
            ad: false,
            ecsPayload: new Uint8Array([0, 2, 0, 0]),
          })
        );
      } else {
        // Healthy regional answer with AD=0 (causing AD divergence vs us-east AD=1)
        logs.push(
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v4`,
            qname,
            qtype: 'A',
            ecsSubnet: preset.ipv4Subnet,
            ad: false,
            cnameTarget: `pop-${preset.id}.example.net.`,
            ipv4Answers: ['203.0.113.25'],
            ecsPayload: new Uint8Array([0, 1, 24, 24, 1, 120, 0]),
          }),
          makeSyntheticEcsLog({
            id: `log-${preset.id}-v6`,
            qname,
            qtype: 'AAAA',
            ecsSubnet: preset.ipv6Subnet,
            ad: false,
            cnameTarget: `pop-${preset.id}.example.net.`,
            ipv6Answers: [],
            ecsPayload: new Uint8Array([0, 2, 56, 48, 0x20, 0x01, 0x80, 0x03, 0x10, 0x00, 0x00]),
          })
        );
      }
    }

    const { ecsGeo, ecsFindings } = evaluateEcsGeoFromLogs({
      targetName: qname,
      primaryEndpoint: 'https://1.1.1.1/dns-query',
      queries: logs,
    });

    expect(ecsGeo).toBeDefined();
    expect(ecsGeo!.optOutHonored).toBe(false);
    expect(ecsGeo!.cacheBustingRegions).toContain('North America East');

    // Verify us-east IPv4-only CNAME is NOT marked dangling, while eu-central NXDOMAIN CNAME IS marked dangling
    const usEastRow = ecsGeo!.regions.find((r) => r.regionId === 'us-east')!;
    expect(usEastRow.ipv6.isDanglingCname).toBe(false);
    const euRow = ecsGeo!.regions.find((r) => r.regionId === 'eu-central')!;
    expect(euRow.ipv4.isDanglingCname).toBe(true);

    const codes = new Set(ecsFindings.map((f) => f.code));
    expect(codes.has('ECS_CACHE_BUSTING_SCOPE')).toBe(true);
    expect(codes.has('ECS_SCOPE_EXCEEDS_SOURCE')).toBe(true);
    expect(codes.has('ECS_REGIONAL_DANGLING_CNAME')).toBe(true);
    expect(codes.has('ECS_REGIONAL_SERVFAIL_OR_NXDOMAIN')).toBe(true);
    expect(codes.has('ECS_REGIONAL_AD_DIVERGENCE')).toBe(true);

    expect(selectEcsDohEndpoint('https://1.1.1.1/dns-query')).toBe('https://8.8.8.8/dns-query');
    expect(selectEcsDohEndpoint('https://dns.google/dns-query')).toBe(
      'https://dns.google/dns-query'
    );
    expect(selectEcsDohEndpoint('https://9.9.9.11/dns-query')).toBe('https://9.9.9.11/dns-query');
  });

  it(
    'executes live multi-region RFC 7871 ECS GeoDNS steering probes against 8.8.8.8 DoH',
    async () => {
      const bgpSession = new DohSession({ endpoint: 'https://1.1.1.1/dns-query' });
      const ecsLogs = await runEcsGeoProbes({
        targetName: 'www.wikipedia.org.',
        primaryEndpoint: 'https://1.1.1.1/dns-query',
        bgpSession,
      });
      expect(ecsLogs.length).toBeGreaterThanOrEqual(12);

      const { ecsGeo, ecsFindings } = evaluateEcsGeoFromLogs({
        targetName: 'www.wikipedia.org.',
        primaryEndpoint: 'https://1.1.1.1/dns-query',
        queries: [...bgpSession.getLogs(), ...ecsLogs],
      });

      expect(ecsGeo).toBeDefined();
      expect(ecsGeo!.ecsSupportedByResolver).toBe(true);
      expect(ecsGeo!.uniqueIpv4PoolCount).toBeGreaterThanOrEqual(2);
      expect(ecsGeo!.steeringModel).toBe('geodns-ip');
      expect(ecsGeo!.optOutHonored).toBe(true);
      expect(ecsGeo!.ipv4ScopeRange?.max).toBeGreaterThan(0);
      expect(ecsGeo!.regions.some((r) => r.asns.some((a) => a.asn === 14907))).toBe(true);
      expect(ecsFindings.some((f) => f.code === 'ECS_GEODNS_STEERING_DETECTED')).toBe(true);

      const custom = await probeCustomEcsSubnet({
        targetName: 'www.wikipedia.org',
        subnetInput: '81.2.69.0/24',
        qtype: 'A',
        dohEndpoint: 'https://8.8.8.8/dns-query',
      });
      expect(custom.canonicalSubnet).toBe('81.2.69.0/24');
      expect(custom.probe.rcode).toBe(0);
      expect(custom.probe.answers.length).toBeGreaterThan(0);
      expect(custom.probe.responseEcs?.sourcePrefixLength).toBe(24);
    },
    25000
  );
});
