import { describe, expect, it } from 'vitest';
import { evaluateSnapshotFromLogs, runDnsvizAnalysis } from '../analyzer';
import { RR_TYPES } from '../constants';
import { ipToCymruOriginQname } from '../ipUtils';
import { detectDns64Address, evaluateIpv6ReadinessAudit } from '../ipv6Readiness';
import type { DnsRecord, DohQueryLog, ZoneAnalysis } from '../types';
import { findAuditFindingWireQuery } from '../wireQueryFilter';

function makeDummyPacket(params: {
  qname: string;
  qtype: number;
  qtypeName: string;
  answers?: DnsRecord[];
  authorities?: DnsRecord[];
  rcode?: number;
}) {
  return {
    id: 1234,
    flags: {
      qr: true,
      opcode: 0,
      aa: false,
      tc: false,
      rd: true,
      ra: true,
      z: 0,
      ad: false,
      cd: true,
      rcode: params.rcode ?? 0,
    },
    questions: [
      {
        name: params.qname,
        type: params.qtype,
        typeName: params.qtypeName,
        qclass: 1,
      },
    ],
    answers: params.answers ?? [],
    authorities: params.authorities ?? [],
    additionals: [],
    wireSize: 64,
  };
}

function makeQueryLog(params: {
  id: string;
  qname: string;
  qtype: number;
  qtypeName: string;
  purpose: string;
  cd?: boolean;
  answers?: DnsRecord[];
  authorities?: DnsRecord[];
}): DohQueryLog {
  return {
    id: params.id,
    qname: params.qname,
    qtype: params.qtype,
    qtypeName: params.qtypeName,
    cd: params.cd ?? true,
    doBit: false,
    endpoint: 'https://1.1.1.1/dns-query',
    startedAt: 1700000000000,
    latencyMs: 12,
    httpStatus: 200,
    wireBase64: '',
    requestWireBase64: '',
    purpose: params.purpose,
    packet: makeDummyPacket({
      qname: params.qname,
      qtype: params.qtype,
      qtypeName: params.qtypeName,
      answers: params.answers,
      authorities: params.authorities,
    }),
  };
}

function makeAddrRecord(name: string, family: 4 | 6, ip: string): DnsRecord {
  return {
    name,
    type: family === 4 ? RR_TYPES.A : RR_TYPES.AAAA,
    typeName: family === 4 ? 'A' : 'AAAA',
    rrclass: 1,
    ttl: 300,
    rdataBase64: '',
    canonicalRdataBase64: '',
    rdataText: ip,
    parsed: { kind: 'GENERIC' },
    section: 'answer',
  };
}

function makeNsRecord(zoneName: string, nsTarget: string): DnsRecord {
  return {
    name: zoneName,
    type: RR_TYPES.NS,
    typeName: 'NS',
    rrclass: 1,
    ttl: 3600,
    rdataBase64: '',
    canonicalRdataBase64: '',
    rdataText: nsTarget,
    parsed: { kind: 'GENERIC', target: nsTarget },
    section: 'answer',
  };
}

function makeTxtRecord(name: string, text: string): DnsRecord {
  return {
    name,
    type: RR_TYPES.TXT,
    typeName: 'TXT',
    rrclass: 1,
    ttl: 3600,
    rdataBase64: '',
    canonicalRdataBase64: '',
    rdataText: `"${text}"`,
    parsed: { kind: 'TXT', strings: [text], joinedText: text },
    section: 'answer',
  };
}

describe('End-to-End IPv6-Only Authoritative Resolution & Delegation Glue Readiness (#58)', () => {
  it('detects RFC 6052 64:ff9b::/96 and RFC 8215 64:ff9b:1::/48 DNS64 synthesis and extracts embedded IPv4', () => {
    const wkpHex = detectDns64Address('64:ff9b::c000:0201');
    expect(wkpHex).toEqual({
      canonicalIp: '64:ff9b::c000:201',
      prefixKind: 'well-known-64:ff9b::/96',
      prefixCidr: '64:ff9b::/96',
      embeddedIpv4: '192.0.2.1',
    });

    const wkpDotted = detectDns64Address('64:ff9b::198.51.100.42');
    expect(wkpDotted?.prefixKind).toBe('well-known-64:ff9b::/96');
    expect(wkpDotted?.embeddedIpv4).toBe('198.51.100.42');

    const local96 = detectDns64Address('64:ff9b:1::cb00:7105');
    expect(local96).toEqual({
      canonicalIp: '64:ff9b:1::cb00:7105',
      prefixKind: 'local-use-64:ff9b:1::/48',
      prefixCidr: '64:ff9b:1::/48',
      embeddedIpv4: '203.0.113.5',
    });

    const local64 = detectDns64Address('64:ff9b:1:cafe:00c0:0002:0100:0000');
    expect(local64?.prefixKind).toBe('local-use-64:ff9b:1::/48');
    expect(local64?.embeddedIpv4).toBe('192.0.2.1');

    // Non-DNS64 IPv6 addresses must return null
    expect(detectDns64Address('2606:4700::6810:84e5')).toBeNull();
    expect(detectDns64Address('2001:4860:4860::8888')).toBeNull();
    expect(detectDns64Address('64:ff9c::1')).toBeNull();
    expect(detectDns64Address('64:ff9b:2::1')).toBeNull();
    expect(detectDns64Address('::1')).toBeNull();
    expect(detectDns64Address('192.0.2.1')).toBeNull();
  });

  it(
    'verifies live end-to-end IPv6 delegation readiness across Root, TLD, leaf, and out-of-bailiwick NS zones',
    async () => {
      const snap = await runDnsvizAnalysis('0dot1.net', {
        queryTypes: ['A', 'AAAA', 'HTTPS', 'MX'],
      });
      const ipv6 = snap.ipv6Readiness;
      expect(ipv6).toBeDefined();
      expect(ipv6?.overallStatus).toBe('ipv6-ready');
      expect(ipv6?.resolvableViaIpv6Only).toBe(true);

      // Every zone hop ('.', 'net.', '0dot1.net.') should be probed and Dual-Stack
      const hopNames = ipv6?.hops.map((h) => h.zoneName) ?? [];
      expect(hopNames).toEqual(['.', 'net.', '0dot1.net.']);
      for (const hop of ipv6?.hops ?? []) {
        expect(hop.probedNsCount).toBeGreaterThanOrEqual(2);
        expect(hop.ipv4NsCount).toBeGreaterThanOrEqual(2);
        expect(hop.ipv6NsCount).toBeGreaterThanOrEqual(2);
        expect(hop.status).toBe('dual-stack');
      }

      // 0dot1.net delegates to out-of-bailiwick *.ns.cloudflare.com -> cloudflare.com. probed as OOB NS zone!
      expect(ipv6?.oobNsZones.some((o) => o.zoneName === 'cloudflare.com.')).toBe(true);
      const cfOob = ipv6?.oobNsZones.find((o) => o.zoneName === 'cloudflare.com.');
      expect(cfOob?.referencedByZones).toContain('0dot1.net.');
      expect(cfOob?.ipv6NsCount).toBeGreaterThanOrEqual(2);
      expect(cfOob?.status).toBe('dual-stack');

      expect(snap.findings.some((f) => f.code === 'IPV6_NS_DELEGATION_GAP')).toBe(false);
      expect(snap.findings.some((f) => f.code === 'IPV6_SINGLE_NS_ONLY')).toBe(false);
      expect(snap.findings.some((f) => f.code === 'DNS64_SYNTHESIZED_AAAA')).toBe(false);

      // Simulate zero-AAAA bottleneck at leaf hop and single-AAAA bottleneck via evaluateSnapshotFromLogs
      const leafNsHosts =
        snap.zones.find((z) => z.zoneName === '0dot1.net.')?.nameservers.map((n) => n.hostname) ??
        [];
      const zeroLeafV6Queries = snap.queries.map((q) =>
        q.purpose.startsWith('Nameserver IP') &&
        q.qtype === RR_TYPES.AAAA &&
        leafNsHosts.includes(q.qname)
          ? { ...q, packet: { ...q.packet, answers: [] } }
          : q
      );
      const zeroV6Snap = await evaluateSnapshotFromLogs({
        id: 'test-ipv6-zero-leaf',
        targetName: snap.targetName,
        queryTypes: snap.queryTypes,
        dohEndpoint: snap.dohEndpoint,
        capturedAt: snap.capturedAt,
        validatedAt: snap.validatedAt,
        durationMs: snap.durationMs,
        queries: zeroLeafV6Queries,
        trustAnchors: snap.trustAnchorsUsed,
      });
      expect(zeroV6Snap.ipv6Readiness?.resolvableViaIpv6Only).toBe(false);
      expect(zeroV6Snap.ipv6Readiness?.overallStatus).toBe('broken-ipv6-path');
      expect(zeroV6Snap.ipv6Readiness?.bottleneckZones).toContain('0dot1.net.');
      const gapFinding = zeroV6Snap.findings.find((f) => f.code === 'IPV6_NS_DELEGATION_GAP');
      expect(gapFinding?.severity).toBe('warning');
      expect(gapFinding?.remediation).toContain('AAAA');
      expect(findAuditFindingWireQuery(gapFinding!, zeroV6Snap)?.qtypeName).toBe('AAAA');

      // Single IPv6 NS at leaf hop -> degraded-redundancy + IPV6_SINGLE_NS_ONLY
      const firstLeafNs = leafNsHosts[0];
      const singleLeafV6Queries = snap.queries.map((q) =>
        q.purpose.startsWith('Nameserver IP') &&
        q.qtype === RR_TYPES.AAAA &&
        leafNsHosts.includes(q.qname) &&
        q.qname !== firstLeafNs
          ? { ...q, packet: { ...q.packet, answers: [] } }
          : q
      );
      const singleV6Snap = await evaluateSnapshotFromLogs({
        id: 'test-ipv6-single-leaf',
        targetName: snap.targetName,
        queryTypes: snap.queryTypes,
        dohEndpoint: snap.dohEndpoint,
        capturedAt: snap.capturedAt,
        validatedAt: snap.validatedAt,
        durationMs: snap.durationMs,
        queries: singleLeafV6Queries,
        trustAnchors: snap.trustAnchorsUsed,
      });
      expect(singleV6Snap.ipv6Readiness?.resolvableViaIpv6Only).toBe(true);
      expect(singleV6Snap.ipv6Readiness?.overallStatus).toBe('degraded-redundancy');
      expect(singleV6Snap.ipv6Readiness?.singleIpv6NsZones).toContain('0dot1.net.');
      const singleFinding = singleV6Snap.findings.find((f) => f.code === 'IPV6_SINGLE_NS_ONLY');
      expect(singleFinding?.severity).toBe('warning');
      expect(singleFinding?.remediation).toContain('RFC 2182');
    },
    25000
  );

  it('catches out-of-bailiwick NS parent zone IPv4-only bottlenecks, single-ASN IPv6 concentration, DNS64 synthesis, and leaf Web/Mail parity gaps', () => {
    const zones: ZoneAnalysis[] = [
      {
        zoneName: '.',
        parentZone: null,
        depth: 0,
        status: 'secure',
        statusReason: 'Root trust anchor',
        nsecMode: 'NSEC',
        dnskeys: [],
        dsVerifications: [],
        trustAnchorMatches: [],
        rrsets: [],
        negativeNodes: [],
        nameservers: [
          {
            hostname: 'a.root-servers.net.',
            ipv4: ['198.41.0.4'],
            ipv6: ['2001:503:ba3e::2:30'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
          {
            hostname: 'b.root-servers.net.',
            ipv4: ['170.247.170.2'],
            ipv6: ['2801:1b8:10::b'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
        ],
      },
      {
        zoneName: 'com.',
        parentZone: '.',
        depth: 1,
        status: 'secure',
        statusReason: 'Signed TLD',
        nsecMode: 'NSEC3-OPTOUT',
        dnskeys: [],
        dsVerifications: [],
        trustAnchorMatches: [],
        rrsets: [],
        negativeNodes: [],
        nameservers: [
          {
            hostname: 'a.gtld-servers.net.',
            ipv4: ['192.5.6.30'],
            ipv6: ['2001:503:a83e::2:30'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
          {
            hostname: 'b.gtld-servers.net.',
            ipv4: ['192.33.14.30'],
            ipv6: ['2001:503:231d::2:30'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
        ],
      },
      {
        zoneName: 'example.com.',
        parentZone: 'com.',
        depth: 2,
        status: 'secure',
        statusReason: 'Signed leaf',
        nsecMode: 'NSEC',
        dnskeys: [],
        dsVerifications: [],
        trustAnchorMatches: [],
        rrsets: [],
        negativeNodes: [],
        nameservers: [
          // ns1 has IPv4 in AS13335 ONLY (no IPv6)
          {
            hostname: 'ns1.dnsvendor.org.',
            ipv4: ['1.1.1.53'],
            ipv6: [],
            status: 'ok',
            addressStack: 'ipv4-only',
          },
          // ns2 & ns3 have IPv4 + IPv6, BOTH IPv6 addresses inside AS16509!
          {
            hostname: 'ns2.dnsvendor.org.',
            ipv4: ['52.1.1.53'],
            ipv6: ['2600:1f18::53'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
          {
            hostname: 'ns3.dnsvendor.org.',
            ipv4: ['52.2.2.53'],
            ipv6: ['2600:1f18:1::53'],
            status: 'ok',
            addressStack: 'dual-stack',
          },
        ],
      },
    ];

    const v4Origin1 = ipToCymruOriginQname('1.1.1.53')!;
    const v4Origin2 = ipToCymruOriginQname('52.1.1.53')!;
    const v6Origin1 = ipToCymruOriginQname('2600:1f18::53')!;
    const v6Origin2 = ipToCymruOriginQname('2600:1f18:1::53')!;

    const queries: DohQueryLog[] = [
      // Out-of-bailiwick NS zone `dnsvendor.org.` whose OWN nameservers are IPv4-only!
      makeQueryLog({
        id: 'q-oob-ns',
        qname: 'dnsvendor.org.',
        qtype: RR_TYPES.NS,
        qtypeName: 'NS',
        purpose: 'OOB NS zone NS (dnsvendor.org.)',
        answers: [
          makeNsRecord('dnsvendor.org.', 'auth1.legacyroot.biz.'),
          makeNsRecord('dnsvendor.org.', 'auth2.legacyroot.biz.'),
        ],
      }),
      makeQueryLog({
        id: 'q-oob-a1',
        qname: 'auth1.legacyroot.biz.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        purpose: 'Nameserver IP (auth1.legacyroot.biz. A)',
        answers: [makeAddrRecord('auth1.legacyroot.biz.', 4, '198.51.100.10')],
      }),
      makeQueryLog({
        id: 'q-oob-aaaa1',
        qname: 'auth1.legacyroot.biz.',
        qtype: RR_TYPES.AAAA,
        qtypeName: 'AAAA',
        purpose: 'Nameserver IPv6 (auth1.legacyroot.biz. AAAA)',
        answers: [],
      }),
      makeQueryLog({
        id: 'q-oob-a2',
        qname: 'auth2.legacyroot.biz.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        purpose: 'Nameserver IP (auth2.legacyroot.biz. A)',
        answers: [makeAddrRecord('auth2.legacyroot.biz.', 4, '198.51.100.11')],
      }),
      makeQueryLog({
        id: 'q-oob-aaaa2',
        qname: 'auth2.legacyroot.biz.',
        qtype: RR_TYPES.AAAA,
        qtypeName: 'AAAA',
        purpose: 'Nameserver IPv6 (auth2.legacyroot.biz. AAAA)',
        answers: [],
      }),
      // Team Cymru BGP origin lookups demonstrating multi-ASN IPv4 (AS13335 + AS16509) vs single-ASN IPv6 (AS16509 only)
      makeQueryLog({
        id: 'q-cymru-v4-1',
        qname: v4Origin1,
        qtype: RR_TYPES.TXT,
        qtypeName: 'TXT',
        purpose: `BGP ASN lookup (${v4Origin1} TXT)`,
        answers: [makeTxtRecord(v4Origin1, '13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11')],
      }),
      makeQueryLog({
        id: 'q-cymru-v4-2',
        qname: v4Origin2,
        qtype: RR_TYPES.TXT,
        qtypeName: 'TXT',
        purpose: `BGP ASN lookup (${v4Origin2} TXT)`,
        answers: [makeTxtRecord(v4Origin2, '16509 | 52.1.0.0/16 | US | arin | 2014-01-01')],
      }),
      makeQueryLog({
        id: 'q-cymru-v6-1',
        qname: v6Origin1,
        qtype: RR_TYPES.TXT,
        qtypeName: 'TXT',
        purpose: `BGP ASN lookup (${v6Origin1} TXT)`,
        answers: [makeTxtRecord(v6Origin1, '16509 | 2600:1f18::/32 | US | arin | 2016-01-01')],
      }),
      makeQueryLog({
        id: 'q-cymru-v6-2',
        qname: v6Origin2,
        qtype: RR_TYPES.TXT,
        qtypeName: 'TXT',
        purpose: `BGP ASN lookup (${v6Origin2} TXT)`,
        answers: [makeTxtRecord(v6Origin2, '16509 | 2600:1f18::/32 | US | arin | 2016-01-01')],
      }),
      // Leaf A + DNS64 synthesized AAAA + HTTPS ipv4hint without native ipv6hint + IPv4-only MX
      makeQueryLog({
        id: 'q-leaf-a',
        qname: 'example.com.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        purpose: 'Target RRset (example.com. A)',
        answers: [makeAddrRecord('example.com.', 4, '93.184.215.14')],
      }),
      makeQueryLog({
        id: 'q-leaf-aaaa-dns64',
        qname: 'example.com.',
        qtype: RR_TYPES.AAAA,
        qtypeName: 'AAAA',
        purpose: 'Target RRset (example.com. AAAA)',
        answers: [makeAddrRecord('example.com.', 6, '64:ff9b::5db8:d70e')],
      }),
      makeQueryLog({
        id: 'q-leaf-https',
        qname: 'example.com.',
        qtype: RR_TYPES.HTTPS,
        qtypeName: 'HTTPS',
        purpose: 'Target RRset (example.com. HTTPS)',
        answers: [
          {
            name: 'example.com.',
            type: RR_TYPES.HTTPS,
            typeName: 'HTTPS',
            rrclass: 1,
            ttl: 300,
            rdataBase64: '',
            canonicalRdataBase64: '',
            rdataText: '1 . alpn="h3,h2" ipv4hint="93.184.215.14"',
            parsed: {
              kind: 'SVCB',
              rrtypeName: 'HTTPS',
              priority: 1,
              isAliasMode: false,
              target: '.',
              params: [
                {
                  key: 4,
                  keyName: 'ipv4hint',
                  rawHex: '5db8d70e',
                  valueText: '93.184.215.14',
                  ipv4Hints: ['93.184.215.14'],
                },
              ],
            },
            section: 'answer',
          },
        ],
      }),
      makeQueryLog({
        id: 'q-leaf-mx',
        qname: 'example.com.',
        qtype: RR_TYPES.MX,
        qtypeName: 'MX',
        purpose: 'Target RRset (example.com. MX)',
        answers: [
          {
            name: 'example.com.',
            type: RR_TYPES.MX,
            typeName: 'MX',
            rrclass: 1,
            ttl: 3600,
            rdataBase64: '',
            canonicalRdataBase64: '',
            rdataText: '10 mx1.example.com.',
            parsed: { kind: 'MX', preference: 10, exchange: 'mx1.example.com.' },
            section: 'answer',
          },
        ],
      }),
      makeQueryLog({
        id: 'q-mx-a',
        qname: 'mx1.example.com.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        purpose: 'Mail target (mx1.example.com. A)',
        answers: [makeAddrRecord('mx1.example.com.', 4, '93.184.215.25')],
      }),
      makeQueryLog({
        id: 'q-mx-aaaa',
        qname: 'mx1.example.com.',
        qtype: RR_TYPES.AAAA,
        qtypeName: 'AAAA',
        purpose: 'Mail target (mx1.example.com. AAAA)',
        answers: [],
      }),
    ];

    const { audit, findings } = evaluateIpv6ReadinessAudit({
      targetName: 'example.com.',
      zones,
      cnameEdges: [],
      queries,
    });

    // 1. OOB NS zone bottleneck caught even though leaf NS hostnames had AAAA!
    expect(audit.resolvableViaIpv6Only).toBe(false);
    expect(audit.overallStatus).toBe('broken-ipv6-path');
    expect(audit.bottleneckZones).toEqual(['dnsvendor.org.']);
    expect(audit.oobNsZones).toHaveLength(1);
    expect(audit.oobNsZones[0].status).toBe('ipv4-only-bottleneck');
    expect(audit.oobNsZones[0].referencedByZones).toEqual(['example.com.']);

    const oobGapFinding = findings.find((f) => f.code === 'IPV6_NS_DELEGATION_GAP');
    expect(oobGapFinding).toBeDefined();
    expect(oobGapFinding?.title).toContain('dnsvendor.org');
    expect(oobGapFinding?.remediation).toContain('dnsvendor.org');

    // 2. Hidden single-ASN IPv6 concentration caught on example.com. (2 overall ASNs, 1 IPv6 ASN)
    const leafHop = audit.hops.find((h) => h.zoneName === 'example.com.');
    expect(leafHop?.overallAsns.map((a) => a.asn).sort()).toEqual([13335, 16509]);
    expect(leafHop?.ipv6Asns.map((a) => a.asn)).toEqual([16509]);
    expect(leafHop?.singleIpv6Asn).toBe(true);
    expect(findings.some((f) => f.code === 'IPV6_SINGLE_ASN_CONCENTRATION')).toBe(true);

    // 3. DNS64 synthesized AAAA detected and not counted as native IPv6!
    expect(audit.leaf.nativeIpv6Addresses).toEqual([]);
    expect(audit.leaf.dns64TargetIps).toHaveLength(1);
    expect(audit.leaf.dns64TargetIps[0].embeddedIpv4).toBe('93.184.215.14');
    expect(audit.leaf.status).toBe('dns64-only');
    const dns64Finding = findings.find((f) => f.code === 'DNS64_SYNTHESIZED_AAAA');
    expect(dns64Finding?.detail).toContain('93.184.215.14');
    expect(dns64Finding?.remediation).toContain('2000::/3');

    // 4. HTTPS missing ipv6hint & MX missing AAAA parity findings
    expect(findings.some((f) => f.code === 'IPV6_HTTPS_MISSING_IPV6HINT')).toBe(true);
    expect(findings.some((f) => f.code === 'IPV6_MX_NO_AAAA')).toBe(true);
  });
});
