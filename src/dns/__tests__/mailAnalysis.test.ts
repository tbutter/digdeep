import { describe, expect, it } from 'vitest';
import { reverifySnapshot } from '../analyzer';
import { RR_TYPES } from '../constants';
import { concatBytes, hexToBytes } from '../encoding';
import {
  classifyIpAddress,
  evaluateMailFromSnapshotData,
  parseSpfTerms,
  runMailAnalysis,
} from '../mailAnalyzer';
import type { DohQueryLog, ZoneAnalysis } from '../types';
import { encodeDnsName, parseDnsPacket } from '../wire';

function buildSyntheticResponsePacket(params: {
  qname: string;
  qtype: number;
  rcode?: number;
  ad?: boolean;
  answers?: Array<{ name: string; type: number; ttl?: number; rdata: Uint8Array }>;
}) {
  const { qname, qtype, rcode = 0, ad = false, answers = [] } = params;
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  view.setUint16(0, 0x1234, false);
  const flags = 0x8180 | (ad ? 0x0020 : 0) | (rcode & 0x000f);
  view.setUint16(2, flags, false);
  view.setUint16(4, 1, false); // QDCOUNT
  view.setUint16(6, answers.length, false); // ANCOUNT

  const qWire = concatBytes(
    encodeDnsName(qname),
    new Uint8Array([(qtype >> 8) & 0xff, qtype & 0xff, 0, 1])
  );

  const ansChunks = answers.map((a) => {
    const ownerWire = encodeDnsName(a.name);
    const meta = new Uint8Array(10);
    const mv = new DataView(meta.buffer);
    mv.setUint16(0, a.type, false);
    mv.setUint16(2, 1, false); // IN
    mv.setUint32(4, a.ttl ?? 300, false);
    mv.setUint16(8, a.rdata.length, false);
    return concatBytes(ownerWire, meta, a.rdata);
  });

  return parseDnsPacket(concatBytes(header, qWire, ...ansChunks));
}

function encodeTxtRdata(chunks: string[]): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(
    ...chunks.map((c) => {
      const b = enc.encode(c);
      return concatBytes(new Uint8Array([b.length]), b);
    })
  );
}

function encodeMxRdata(preference: number, exchange: string): Uint8Array {
  const pref = new Uint8Array([(preference >> 8) & 0xff, preference & 0xff]);
  return concatBytes(pref, encodeDnsName(exchange));
}

function encodeTlsaRdata(
  usage: number,
  selector: number,
  matchingType: number,
  hex: string
): Uint8Array {
  return concatBytes(new Uint8Array([usage, selector, matchingType]), hexToBytes(hex));
}

function makeLog(
  qname: string,
  qtype: number,
  qtypeName: string,
  packet: ReturnType<typeof buildSyntheticResponsePacket>,
  cd = true
): DohQueryLog {
  return {
    id: `test-${qname}-${qtypeName}`,
    qname,
    qtype,
    qtypeName,
    cd,
    doBit: true,
    endpoint: 'https://1.1.1.1/dns-query',
    startedAt: Date.now(),
    latencyMs: 5,
    httpStatus: 200,
    wireBase64: '',
    requestWireBase64: '',
    packet,
    purpose: 'Test',
  };
}

describe('Wire Parser: Structured TLSA and Multi-Chunk TXT/SPF RDATA', () => {
  it('concatenates multi-string TXT chunks without spaces per RFC 7208 §3.3 and decodes TLSA fields', () => {
    const sha256Hex = 'A'.repeat(64);
    const txtPacket = buildSyntheticResponsePacket({
      qname: 'example.com.',
      qtype: RR_TYPES.TXT,
      answers: [
        {
          name: 'example.com.',
          type: RR_TYPES.TXT,
          rdata: encodeTxtRdata(['v=spf1 ip4:192.0.2.0/24 ', 'include:_spf.example.com -all']),
        },
      ],
    });
    const txtRec = txtPacket.answers[0];
    expect(txtRec.parsed.kind).toBe('TXT');
    if (txtRec.parsed.kind === 'TXT') {
      expect(txtRec.parsed.strings).toEqual([
        'v=spf1 ip4:192.0.2.0/24 ',
        'include:_spf.example.com -all',
      ]);
      expect(txtRec.parsed.joinedText).toBe('v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all');
    }

    const tlsaPacket = buildSyntheticResponsePacket({
      qname: '_25._tcp.mx.example.com.',
      qtype: RR_TYPES.TLSA,
      answers: [
        {
          name: '_25._tcp.mx.example.com.',
          type: RR_TYPES.TLSA,
          rdata: encodeTlsaRdata(3, 1, 1, sha256Hex),
        },
      ],
    });
    const tlsaRec = tlsaPacket.answers[0];
    expect(tlsaRec.parsed.kind).toBe('TLSA');
    if (tlsaRec.parsed.kind === 'TLSA') {
      expect(tlsaRec.parsed.usage).toBe(3);
      expect(tlsaRec.parsed.selector).toBe(1);
      expect(tlsaRec.parsed.matchingType).toBe(1);
      expect(tlsaRec.parsed.certAssociationHex).toBe(sha256Hex);
    }
  });
});

describe('SPF Parser & RFC 7208 Mechanism / Lookup Rules', () => {
  it('accurately counts DNS-querying mechanisms, dual CIDRs, macros, unreachable after all, and syntax errors', () => {
    const terms = parseSpfTerms(
      'v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 a:mail.example.com/24//64 mx//56 include:_spf.example.com exists:%{i}._spf.example.com exp=explain.example.com -all include:ignored.example.com'
    );

    const counting = terms.filter((t) => t.countsTowardLookupLimit);
    // a, mx, include:_spf.example.com, exists:%{i}... => 4 lookups (ip4, ip6, exp=, -all, and unreachable include after -all do NOT count!)
    expect(counting.map((t) => t.mechanism ?? t.modifier)).toEqual([
      'a',
      'mx',
      'include',
      'exists',
    ]);
    expect(terms.every((t) => t.syntaxValid)).toBe(true);

    const trailingInclude = terms[terms.length - 1];
    expect(trailingInclude.unreachableAfterAll).toBe(true);
    expect(trailingInclude.countsTowardLookupLimit).toBe(false);

    // redirect= is ignored when all is present in the same record (RFC 7208 §6.1)
    const redirWithAll = parseSpfTerms('v=spf1 redirect=_spf.example.com ~all');
    expect(redirWithAll.filter((t) => t.countsTowardLookupLimit)).toHaveLength(0);
    expect(redirWithAll[1].warning).toContain('Ignored per RFC 7208 §6.1');

    // Invalid CIDRs and unknown mechanisms produce syntax errors (permerror)
    const broken = parseSpfTerms('v=spf1 ip4:192.0.2.1/33 ip6:2001:db8::/129 bogusmech -all');
    expect(broken[1].syntaxValid).toBe(false);
    expect(broken[2].syntaxValid).toBe(false);
    expect(broken[3].syntaxValid).toBe(false);
  });

  it('classifies private, loopback, documentation, and public IPv4/IPv6 MX addresses', () => {
    expect(classifyIpAddress('127.0.0.1', 4).isPublic).toBe(false);
    expect(classifyIpAddress('10.1.2.3', 4).isPublic).toBe(false);
    expect(classifyIpAddress('192.168.1.1', 4).isPublic).toBe(false);
    expect(classifyIpAddress('93.184.216.34', 4).isPublic).toBe(true);
    expect(classifyIpAddress('::1', 6).isPublic).toBe(false);
    expect(classifyIpAddress('fe80::1', 6).isPublic).toBe(false);
    expect(classifyIpAddress('2606:2800:220:1::248', 6).isPublic).toBe(true);
  });
});

describe('RFC 7505, RFC 7672 (SMTP DANE), and RFC 7208 (SPF) Audit Scenarios', () => {
  it('flags unsigned TLSA records as ignored (DANE_TLSA_UNSIGNED) and detects >10 SPF lookups & +all', () => {
    const queries: DohQueryLog[] = [
      makeLog(
        'unsigned.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'unsigned.example.',
          qtype: RR_TYPES.MX,
          answers: [{ name: 'unsigned.example.', type: RR_TYPES.MX, rdata: encodeMxRdata(10, 'mx.unsigned.example.') }],
        })
      ),
      makeLog(
        'mx.unsigned.example.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: 'mx.unsigned.example.',
          qtype: RR_TYPES.A,
          answers: [{ name: 'mx.unsigned.example.', type: RR_TYPES.A, rdata: new Uint8Array([93, 184, 216, 34]) }],
        })
      ),
      makeLog(
        '_25._tcp.mx.unsigned.example.',
        RR_TYPES.TLSA,
        'TLSA',
        buildSyntheticResponsePacket({
          qname: '_25._tcp.mx.unsigned.example.',
          qtype: RR_TYPES.TLSA,
          answers: [
            {
              name: '_25._tcp.mx.unsigned.example.',
              type: RR_TYPES.TLSA,
              rdata: encodeTlsaRdata(3, 1, 1, 'b'.repeat(64)),
            },
          ],
        })
      ),
      makeLog(
        'unsigned.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'unsigned.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'unsigned.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([
                'v=spf1 a mx ptr exists:a1.example exists:a2.example exists:a3.example exists:a4.example exists:a5.example exists:a6.example exists:a7.example exists:a8.example +all',
              ]),
            },
          ],
        })
      ),
    ];

    const unsignedZone: ZoneAnalysis = {
      zoneName: 'unsigned.example.',
      parentZone: '.',
      depth: 2,
      status: 'insecure',
      statusReason: 'Unsigned zone',
      nsecMode: 'UNSIGNED',
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [],
      negativeNodes: [],
      nameservers: [],
    };

    const res = evaluateMailFromSnapshotData({
      targetName: 'unsigned.example.',
      queries,
      zones: [unsignedZone],
      cnameEdges: [],
      targetDomainStatus: 'insecure',
    });

    expect(res.mailAnalysis.daneStatus).toBe('unsigned-ignored');
    expect(res.mailFindings.some((f) => f.code === 'DANE_TLSA_UNSIGNED')).toBe(true);
    expect(res.mailAnalysis.spf.dnsLookupCount).toBe(11);
    expect(res.mailAnalysis.spf.verdict).toBe('permerror');
    expect(res.mailFindings.some((f) => f.code === 'SPF_DNS_LOOKUP_LIMIT_EXCEEDED')).toBe(true);
    expect(res.mailFindings.some((f) => f.code === 'SPF_DEPRECATED_PTR')).toBe(true);
    expect(res.overallStatus).toBe('bogus');
  });

  it('recognizes RFC 7505 Null MX (0 .) paired with strict SPF (-all) as SECURE on a signed zone', () => {
    const queries: DohQueryLog[] = [
      makeLog(
        'nomail.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'nomail.example.',
          qtype: RR_TYPES.MX,
          answers: [{ name: 'nomail.example.', type: RR_TYPES.MX, rdata: encodeMxRdata(0, '.') }],
        })
      ),
      makeLog(
        'nomail.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'nomail.example.',
          qtype: RR_TYPES.TXT,
          answers: [{ name: 'nomail.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 -all']) }],
        })
      ),
    ];

    const signedZone: ZoneAnalysis = {
      zoneName: 'nomail.example.',
      parentZone: '.',
      depth: 2,
      status: 'secure',
      statusReason: 'Signed',
      nsecMode: 'NSEC',
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [],
      negativeNodes: [],
      nameservers: [],
    };

    const res = evaluateMailFromSnapshotData({
      targetName: 'nomail.example.',
      queries,
      zones: [signedZone],
      cnameEdges: [],
      targetDomainStatus: 'secure',
    });

    expect(res.mailAnalysis.mxStatus).toBe('null-mx');
    expect(res.mailAnalysis.daneStatus).toBe('not-applicable');
    expect(res.mailAnalysis.spf.verdict).toBe('strict-fail');
    expect(res.mailAnalysis.spf.dnsLookupCount).toBe(0);
    expect(res.overallStatus).toBe('secure');
  });

  it('detects multiple v=spf1 TXT records and circular include: loops as RFC 7208 permerror', () => {
    const multiQueries: DohQueryLog[] = [
      makeLog(
        'dup.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'dup.example.',
          qtype: RR_TYPES.MX,
          answers: [{ name: 'dup.example.', type: RR_TYPES.MX, rdata: encodeMxRdata(0, '.') }],
        })
      ),
      makeLog(
        'dup.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'dup.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            { name: 'dup.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 include:a.example -all']) },
            { name: 'dup.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 ~all']) },
          ],
        })
      ),
    ];

    const dupRes = evaluateMailFromSnapshotData({
      targetName: 'dup.example.',
      queries: multiQueries,
      zones: [],
      cnameEdges: [],
      targetDomainStatus: 'insecure',
    });
    expect(dupRes.mailAnalysis.spf.verdict).toBe('permerror');
    expect(dupRes.mailFindings.some((f) => f.code === 'SPF_MULTIPLE_TXT_RECORDS')).toBe(true);

    // Circular include loop: loop1.example -> loop2.example -> loop1.example
    const loopQueries: DohQueryLog[] = [
      makeLog(
        'loop1.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'loop1.example.',
          qtype: RR_TYPES.MX,
          answers: [{ name: 'loop1.example.', type: RR_TYPES.MX, rdata: encodeMxRdata(0, '.') }],
        })
      ),
      makeLog(
        'loop1.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'loop1.example.',
          qtype: RR_TYPES.TXT,
          answers: [{ name: 'loop1.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 include:loop2.example -all']) }],
        })
      ),
      makeLog(
        'loop2.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'loop2.example.',
          qtype: RR_TYPES.TXT,
          answers: [{ name: 'loop2.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 include:loop1.example -all']) }],
        }),
        false
      ),
    ];

    const loopRes = evaluateMailFromSnapshotData({
      targetName: 'loop1.example.',
      queries: loopQueries,
      zones: [],
      cnameEdges: [],
      targetDomainStatus: 'insecure',
    });
    expect(loopRes.mailAnalysis.spf.verdict).toBe('permerror');
    expect(loopRes.mailFindings.some((f) => f.code === 'SPF_INCLUDE_REDIRECT_LOOP')).toBe(true);
  });
});

describe('Live DoH Mail + SMTP DANE + SPF End-to-End Verification', () => {
  it(
    'verifies ietf.org MX, DNSSEC-signed _25._tcp DANE TLSA, SPF policy, and offline clock-override re-verification',
    async () => {
      const snap = await runMailAnalysis('ietf.org');
      expect(snap.mode).toBe('mail');
      expect(snap.mailAnalysis).toBeDefined();
      const mail = snap.mailAnalysis!;

      // mx.ietf.org currently points to a Cloudflare Spectrum CNAME (RFC 2181 §10.3 warning) with valid A/AAAA targets
      expect(['valid', 'warning']).toContain(mail.mxStatus);
      expect(mail.mxDnssecStatus).toBe('secure');
      expect(mail.mxHosts.length).toBeGreaterThanOrEqual(1);
      expect(mail.mxHosts[0].addresses.length).toBeGreaterThan(0);

      // ietf.org deploys authenticated SMTP DANE (_25._tcp.<mx> TLSA)
      expect(mail.daneStatus === 'all-valid' || mail.daneStatus === 'partial').toBe(true);
      expect(mail.mxHosts[0].dane.records.length).toBeGreaterThan(0);
      expect(mail.mxHosts[0].dane.dnssecStatus).toBe('secure');

      // ietf.org publishes a valid v=spf1 policy within the 10-lookup budget
      expect(mail.spf.present).toBe(true);
      expect(mail.spf.dnsLookupCount).toBeLessThanOrEqual(10);

      // Offline time-travel re-verification into 2099 invalidates RRSIGs and turns DANE status to BOGUS!
      const futureSnap = await reverifySnapshot(snap, {
        validationTimeMs: Date.UTC(2099, 0, 1),
      });
      expect(futureSnap.overallStatus).toBe('bogus');
      expect(futureSnap.mailAnalysis?.daneStatus).toBe('bogus');
    },
    25000
  );
});
