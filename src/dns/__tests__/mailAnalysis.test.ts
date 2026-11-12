import { describe, expect, it } from 'vitest';
import { reverifySnapshot } from '../analyzer';
import { RR_TYPES } from '../constants';
import { bytesToBase64, concatBytes, hexToBytes } from '../encoding';
import {
  buildPslQueryName,
  classifyIpAddress,
  clearPublicSuffixCache,
  collectSpfMacroExpansions,
  decodeDkimPublicKey,
  estimateOrganizationalDomain,
  evaluateMailFromSnapshotData,
  evaluateSpfForSenderIp,
  expandSpfMacroString,
  extractSpfMacros,
  ipToReverseArpa,
  matchesMtaStsMxPattern,
  matchIpv4Cidr,
  matchIpv6Cidr,
  parseDkimSelectorInput,
  parseMtaStsPolicyFile,
  parseSpfTerms,
  runMailAnalysis,
  splitDomainByPublicSuffix,
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
  const wireParts: Uint8Array[] = [];
  for (const c of chunks) {
    const b = enc.encode(c);
    if (b.length === 0) {
      wireParts.push(new Uint8Array([0]));
    } else {
      for (let off = 0; off < b.length; off += 255) {
        const sub = b.subarray(off, Math.min(b.length, off + 255));
        wireParts.push(concatBytes(new Uint8Array([sub.length]), sub));
      }
    }
  }
  return concatBytes(...wireParts);
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
    expect(res.overallStatus).toBe('policy-error');
    expect(res.overallSummary).toContain('Mail policy/DNS check failed:');

    // When the target zone itself fails DNSSEC validation (`bogus`), overallStatus stays `'bogus'`
    const bogusZoneRes = evaluateMailFromSnapshotData({
      targetName: 'unsigned.example.',
      queries,
      zones: [{ ...unsignedZone, status: 'bogus' }],
      cnameEdges: [],
      targetDomainStatus: 'bogus',
    });
    expect(bogusZoneRes.overallStatus).toBe('bogus');
    expect(bogusZoneRes.overallSummary).toContain('DNSSEC validation failed (BOGUS):');
  });

  it('performs exact 32-bit IPv4 and 128-bit IPv6 CIDR bitmask matching for SPF mechanisms', () => {
    expect(matchIpv4Cidr('192.0.2.45', '192.0.2.0', 24)).toBe(true);
    expect(matchIpv4Cidr('192.0.3.1', '192.0.2.0', 24)).toBe(false);
    expect(matchIpv4Cidr('10.255.255.254', '10.0.0.0', 8)).toBe(true);
    expect(matchIpv4Cidr('198.51.100.1', '198.51.100.1', 32)).toBe(true);
    expect(matchIpv4Cidr('198.51.100.2', '198.51.100.1', 32)).toBe(false);
    expect(matchIpv4Cidr('203.0.113.99', '0.0.0.0', 0)).toBe(true);
    expect(matchIpv4Cidr('172.16.15.255', '172.16.0.0', 20)).toBe(true);
    expect(matchIpv4Cidr('172.16.16.0', '172.16.0.0', 20)).toBe(false);

    expect(matchIpv6Cidr('2001:db8:abcd:0012::1', '2001:db8:abcd::', 48)).toBe(true);
    expect(matchIpv6Cidr('2001:db8:abce::1', '2001:db8:abcd::', 48)).toBe(false);
    expect(matchIpv6Cidr('2a00:1450:4000::beef', '2a00:1450:4000::', 36)).toBe(true);
    expect(matchIpv6Cidr('2a00:1450:5000::beef', '2a00:1450:4000::', 36)).toBe(false);
    expect(matchIpv6Cidr('2001:db8::1', '2001:db8::1', 128)).toBe(true);
    expect(matchIpv6Cidr('2001:db8::2', '2001:db8::1', 128)).toBe(false);
  });

  it('detects and expands RFC 7208 §7 SPF macros (including transformers, delimiters & IPv6 nibbles)', () => {
    const terms = parseSpfTerms(
      'v=spf1 exists:%{ir}.%{v}._spf.%{d2} include:%{l-}.%{o}.spf.%{d} exp=explain._spf.%{d} -all'
    );
    expect(terms[1].macros).toEqual(['%{ir}', '%{v}', '%{d2}']);
    expect(terms[2].macros).toEqual(['%{l-}', '%{o}', '%{d}']);
    expect(terms[3].macros).toEqual(['%{d}']);

    expect(extractSpfMacros('%{ir}.%{v}._spf.%{d2}.%%.%_.%-')).toEqual([
      '%{ir}',
      '%{v}',
      '%{d2}',
      '%%',
      '%_',
      '%-',
    ]);

    // IPv4 reverse + domain right-hand parts + sender local-part delimiter split
    const v4Exp = expandSpfMacroString('%{ir}.%{v}.%{l-}.%{d2}.example.net', {
      ip: '192.0.2.25',
      sender: 'alice-bob@mail.sub.example.com',
      domain: 'mail.sub.example.com',
    });
    expect(v4Exp.expanded).toBe('25.2.0.192.in-addr.alice.bob.example.com.example.net');

    // IPv6 32-nibble dot-separated reverse format per RFC 7208 §7.3
    const v6Exp = expandSpfMacroString('%{ir}.%{v}._spf.%{d}', {
      ip: '2001:db8::1',
      sender: 'postmaster@example.org',
      domain: 'example.org',
    });
    expect(v6Exp.expanded).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.org'
    );

    // Uppercase URL-encoding macro letter %{S} and escape tokens %%, %_, %-
    const escExp = expandSpfMacroString('%{S}%%20%_test%-end', {
      ip: '192.0.2.1',
      sender: 'user+tag@example.org',
      domain: 'example.org',
    });
    expect(escExp.expanded).toBe('user%2Btag%40example.org%20 test%20end');
  });

  it('audits overly broad IPv4 (< /16) and IPv6 (< /32) SPF CIDR blocks and evaluates candidate sender IPs across recursive trees', () => {
    const terms = parseSpfTerms('v=spf1 ip4:192.0.0.0/8 ip6:2001::/16 -ip4:10.0.0.0/8 ip4:198.51.100.0/24 ~all');
    expect(terms[1].broadCidr).toBe(true);
    expect(terms[1].warning).toContain('/8');
    expect(terms[1].warning).toContain('16,777,216');
    expect(terms[2].broadCidr).toBe(true);
    expect(terms[2].warning).toContain('/16');
    // Negative qualifier (-ip4:10.0.0.0/8) does not authorize senders so should not trigger broadCidr
    expect(terms[3].broadCidr).toBeUndefined();
    // /24 is narrow and valid
    expect(terms[4].broadCidr).toBeUndefined();

    const queries: DohQueryLog[] = [
      makeLog(
        'spf-eval.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'spf-eval.example.',
          qtype: RR_TYPES.MX,
          answers: [
            {
              name: 'spf-eval.example.',
              type: RR_TYPES.MX,
              rdata: encodeMxRdata(10, 'mx1.spf-eval.example.'),
            },
          ],
        })
      ),
      makeLog(
        'mx1.spf-eval.example.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: 'mx1.spf-eval.example.',
          qtype: RR_TYPES.A,
          answers: [
            {
              name: 'mx1.spf-eval.example.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([198, 51, 100, 10]),
            },
          ],
        })
      ),
      makeLog(
        'spf-eval.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'spf-eval.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'spf-eval.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([
                'v=spf1 mx/28 ip4:203.0.0.0/8 -ip4:192.0.2.99 include:_spf.partner.example exists:%{ir}._spf.%{d} ~all',
              ]),
            },
          ],
        })
      ),
      makeLog(
        '_spf.partner.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_spf.partner.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_spf.partner.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8:abcd::/48 -all']),
            },
          ],
        })
      ),
    ];

    const zone: ZoneAnalysis = {
      zoneName: 'spf-eval.example.',
      parentZone: '.',
      depth: 2,
      status: 'insecure',
      statusReason: 'Unsigned',
      nsecMode: 'UNSIGNED',
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [],
      negativeNodes: [],
      nameservers: [],
    };

    const res = evaluateMailFromSnapshotData({
      targetName: 'spf-eval.example.',
      queries,
      zones: [zone],
      cnameEdges: [],
      targetDomainStatus: 'insecure',
    });

    // Broad CIDR audit finding emitted for ip4:203.0.0.0/8
    const broadFinding = res.mailFindings.find((f) => f.code === 'SPF_BROAD_CIDR');
    expect(broadFinding).toBeDefined();
    expect(broadFinding?.title).toContain('ip4:203.0.0.0/8');

    const rootNode = res.mailAnalysis.spf.rootNode;

    // 1. Candidate matching MX /28 netblock (198.51.100.10/28 covers 198.51.100.0..15)
    const mxMatch = evaluateSpfForSenderIp(rootNode, '198.51.100.14');
    expect(mxMatch.disposition).toBe('pass');
    expect(mxMatch.matchedMechanism).toBe('mx');
    expect(mxMatch.matchedTermRaw).toBe('mx/28');
    expect(mxMatch.matchedNetworkOrHost).toBe('198.51.100.10/28');

    // 2. Candidate explicitly rejected by -ip4:192.0.2.99 before reaching include:_spf.partner.example
    const explicitDeny = evaluateSpfForSenderIp(rootNode, '192.0.2.99');
    expect(explicitDeny.disposition).toBe('fail');
    expect(explicitDeny.qualifier).toBe('-');
    expect(explicitDeny.matchedTermRaw).toBe('-ip4:192.0.2.99');

    // 3. Candidate matching nested include:_spf.partner.example (IPv4 192.0.2.42)
    const incV4 = evaluateSpfForSenderIp(rootNode, '192.0.2.42', {
      sender: 'billing@spf-eval.example',
    });
    expect(incV4.disposition).toBe('pass');
    expect(incV4.matchedDomain).toBe('_spf.partner.example.');
    expect(incV4.matchedTermRaw).toBe('ip4:192.0.2.0/24');
    expect(incV4.tracePath).toEqual(['spf-eval.example', '_spf.partner.example']);
    expect(incV4.macroExpansions).toHaveLength(1);
    expect(incV4.macroExpansions[0].expandedSpec).toBe('42.2.0.192._spf.spf-eval.example');

    // 4. Candidate matching nested include:_spf.partner.example (IPv6 2001:db8:abcd:1::5)
    const incV6 = evaluateSpfForSenderIp(rootNode, '2001:db8:abcd:1::5');
    expect(incV6.disposition).toBe('pass');
    expect(incV6.matchedDomain).toBe('_spf.partner.example.');
    expect(incV6.matchedTermRaw).toBe('ip6:2001:db8:abcd::/48');

    // 5. Unauthorized IPv4 falling through to terminal ~all
    const softFail = evaluateSpfForSenderIp(rootNode, '198.51.100.200');
    expect(softFail.disposition).toBe('softfail');
    expect(softFail.qualifier).toBe('~');
    expect(softFail.matchedTermRaw).toBe('~all');

    // 6. Invalid IP input handled gracefully
    const badIp = evaluateSpfForSenderIp(rootNode, '999.999.999.999');
    expect(badIp.validIp).toBe(false);
    expect(badIp.error).toContain('Invalid IPv4 or IPv6');
    expect(collectSpfMacroExpansions(rootNode, { ip: '198.51.100.200' })[0].expandedSpec).toBe(
      '200.100.51.198._spf.spf-eval.example'
    );
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
      makeLog(
        '_dmarc.nomail.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_dmarc.nomail.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_dmarc.nomail.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=DMARC1; p=reject;']),
            },
          ],
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

  it('decodes DKIM RSA/Ed25519 keys, extracts selectors from DKIM-Signature headers, and validates DMARC policies', () => {
    const derLen = (len: number): Uint8Array => {
      if (len < 128) return new Uint8Array([len]);
      if (len < 256) return new Uint8Array([0x81, len]);
      return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
    };
    const derTlv = (tag: number, content: Uint8Array): Uint8Array =>
      concatBytes(new Uint8Array([tag]), derLen(content.length), content);

    const buildSyntheticRsaSpkiBase64 = (bits: number): string => {
      const modBytes = new Uint8Array(bits / 8 + 1);
      modBytes[0] = 0x00;
      modBytes[1] = 0x80; // MSB set -> exact `bits` bit length
      modBytes[modBytes.length - 1] = 0x01;
      const modInt = derTlv(0x02, modBytes);
      const expInt = new Uint8Array([0x02, 0x03, 0x01, 0x00, 0x01]); // e = 65537
      const rsaSeq = derTlv(0x30, concatBytes(modInt, expInt));
      const algId = new Uint8Array([
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
      ]);
      const bitStr = derTlv(0x03, concatBytes(new Uint8Array([0x00]), rsaSeq));
      return bytesToBase64(derTlv(0x30, concatBytes(algId, bitStr)));
    };

    // 1. Organizational domain estimation (including DOMAIN.psl.digdeep.fyi TXT lookup)
    clearPublicSuffixCache();
    expect(buildPslQueryName('supertux.github.io')).toBe('supertux.github.io.psl.digdeep.fyi.');
    expect(buildPslQueryName('1.1.1.1')).toBeNull();
    expect(estimateOrganizationalDomain('sub.mail.example.com.')).toBe('example.com.');

    const pslLogs: DohQueryLog[] = [
      makeLog(
        'a.b.example.co.uk.psl.digdeep.fyi.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'a.b.example.co.uk.psl.digdeep.fyi.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'a.b.example.co.uk.psl.digdeep.fyi.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['co.uk']),
            },
          ],
        })
      ),
      makeLog(
        'app.supertux.github.io.psl.digdeep.fyi.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'app.supertux.github.io.psl.digdeep.fyi.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'app.supertux.github.io.psl.digdeep.fyi.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['github.io']),
            },
          ],
        })
      ),
    ];
    expect(estimateOrganizationalDomain('a.b.example.co.uk.', pslLogs)).toBe('example.co.uk.');
    expect(estimateOrganizationalDomain('app.supertux.github.io.', pslLogs)).toBe(
      'supertux.github.io.'
    );
    expect(estimateOrganizationalDomain('supertux.github.io.')).toBe('supertux.github.io.');
    expect(splitDomainByPublicSuffix('app.supertux.github.io')).toEqual({
      leadingWhitespace: '',
      prefix: 'app.supertux.',
      publicSuffix: 'github.io',
      trailingDotAndWhitespace: '',
      isDnsVerified: true,
    });
    expect(splitDomainByPublicSuffix('1.1.1.1')).toBeNull();

    // 2. DKIM selector input & DKIM-Signature header extraction
    expect(
      parseDkimSelectorInput(
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=ietf.org; s=ietf1; bh=abc==; b=xyz=='
      )
    ).toEqual(['ietf1']);
    expect(
      parseDkimSelectorInput('s1._domainkey.cloudflare.com, google, selector2', 'cloudflare.com')
    ).toEqual(['s1', 'google', 'selector2']);

    // 3. ASN.1 DER RSA & Ed25519 key decoding
    const rsa2048B64 = buildSyntheticRsaSpkiBase64(2048);
    const rsa512B64 = buildSyntheticRsaSpkiBase64(512);
    const k2048 = decodeDkimPublicKey('rsa', rsa2048B64);
    expect(k2048.valid).toBe(true);
    expect(k2048.keyBits).toBe(2048);
    expect(k2048.rsaExponent).toBe(65537);

    const k512 = decodeDkimPublicKey('rsa', rsa512B64);
    expect(k512.valid).toBe(true);
    expect(k512.keyBits).toBe(512);

    const kRevoked = decodeDkimPublicKey('rsa', '');
    expect(kRevoked.revoked).toBe(true);
    expect(kRevoked.valid).toBe(true);

    const ed25519RawB64 = bytesToBase64(new Uint8Array(32).fill(0x42));
    const kEd = decodeDkimPublicKey('ed25519', ed25519RawB64);
    expect(kEd.valid).toBe(true);
    expect(kEd.keyBits).toBe(256);

    // 4. Synthetic DMARC organizational fallback, unauthorized external rua, RFC 9091 np=, weak DKIM RSA-512, sha1, & revoked key
    const queries: DohQueryLog[] = [
      makeLog(
        'sub.corp.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'sub.corp.example.',
          qtype: RR_TYPES.MX,
          answers: [{ name: 'sub.corp.example.', type: RR_TYPES.MX, rdata: encodeMxRdata(0, '.') }],
        })
      ),
      makeLog(
        'sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'sub.corp.example.',
          qtype: RR_TYPES.TXT,
          answers: [{ name: 'sub.corp.example.', type: RR_TYPES.TXT, rdata: encodeTxtRdata(['v=spf1 -all']) }],
        })
      ),
      // _dmarc.sub.corp.example has no record -> falls back to _dmarc.corp.example!
      makeLog(
        '_dmarc.sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_dmarc.sub.corp.example.',
          qtype: RR_TYPES.TXT,
          rcode: 3,
        })
      ),
      makeLog(
        '_dmarc.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_dmarc.corp.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_dmarc.corp.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([
                'v=DMARC1; p=reject; sp=quarantine; np=reject; adkim=s; aspf=s; pct=50; rua=mailto:dmarc@corp.example!10m,mailto:agg@thirdparty.test',
              ]),
            },
          ],
        })
      ),
      // External report target thirdparty.test lacks _report._dmarc TXT!
      makeLog(
        'corp.example._report._dmarc.thirdparty.test.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'corp.example._report._dmarc.thirdparty.test.',
          qtype: RR_TYPES.TXT,
          rcode: 3,
        }),
        false
      ),
      // DKIM selectors: strong2048, weak512, sha1only, revokedkey
      makeLog(
        'strong2048._domainkey.sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'strong2048._domainkey.sub.corp.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'strong2048._domainkey.sub.corp.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([`v=DKIM1; k=rsa; p=${rsa2048B64}`]),
            },
          ],
        })
      ),
      makeLog(
        'weak512._domainkey.sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'weak512._domainkey.sub.corp.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'weak512._domainkey.sub.corp.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([`v=DKIM1; k=rsa; h=sha1; p=${rsa512B64}`]),
            },
          ],
        })
      ),
      makeLog(
        'revoked._domainkey.sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'revoked._domainkey.sub.corp.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'revoked._domainkey.sub.corp.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=DKIM1; k=rsa; p=']),
            },
          ],
        })
      ),
      makeLog(
        'missingcustom._domainkey.sub.corp.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'missingcustom._domainkey.sub.corp.example.',
          qtype: RR_TYPES.TXT,
          rcode: 3,
        })
      ),
    ];

    const res = evaluateMailFromSnapshotData({
      targetName: 'sub.corp.example.',
      queries,
      zones: [],
      cnameEdges: [],
      targetDomainStatus: 'secure',
      customDkimSelectors: ['strong2048', 'weak512', 'revoked', 'missingcustom'],
    });

    const dmarc = res.mailAnalysis.dmarc;
    expect(dmarc.present).toBe(true);
    expect(dmarc.usedOrgFallback).toBe(true);
    expect(dmarc.queriedOwner).toBe('_dmarc.corp.example.');
    expect(dmarc.policy).toBe('reject');
    expect(dmarc.subdomainPolicy).toBe('quarantine');
    expect(dmarc.nonExistentSubdomainPolicy).toBe('reject');
    expect(dmarc.verdict).toBe('quarantine'); // sp=quarantine applies to subdomain!
    expect(dmarc.adkim).toBe('s');
    expect(dmarc.aspf).toBe('s');
    expect(dmarc.pct).toBe(50);
    expect(dmarc.rua[0].isExternalDomain).toBe(false);
    expect(dmarc.rua[0].maxSizeSpec).toBe('10m');
    expect(dmarc.rua[1].isExternalDomain).toBe(true);
    expect(dmarc.rua[1].externalAuthorized).toBe('unauthorized');

    const codes = res.mailFindings.map((f) => f.code);
    expect(codes).toContain('DMARC_EXTERNAL_REPORT_UNAUTHORIZED');
    expect(codes).toContain('DMARC_PARTIAL_PCT');
    expect(codes).toContain('DKIM_WEAK_RSA_KEY');
    expect(codes).toContain('DKIM_SHA1_ONLY');
    expect(codes).toContain('DKIM_KEY_REVOKED');
    expect(codes).toContain('DKIM_SELECTOR_NOT_FOUND');

    const dkimSels = res.mailAnalysis.dkim.selectors;
    expect(dkimSels.find((s) => s.selector === 'strong2048')?.status).toBe('valid');
    expect(dkimSels.find((s) => s.selector === 'weak512')?.keyBits).toBe(512);
    expect(dkimSels.find((s) => s.selector === 'revoked')?.status).toBe('revoked');
    expect(dkimSels.find((s) => s.selector === 'missingcustom')?.status).toBe('missing');
  });

  it('converts IPv4/IPv6 addresses to reverse .arpa names and validates MTA-STS (RFC 8461), TLS-RPT (RFC 8460), BIMI, and MX FCrDNS (PTR)', () => {
    // 1. Reverse .arpa conversion (IPv4, compressed IPv6, IPv4-mapped IPv6, invalid)
    expect(ipToReverseArpa('192.0.2.25')).toBe('25.2.0.192.in-addr.arpa.');
    expect(ipToReverseArpa('2001:db8::1')).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    );
    expect(ipToReverseArpa('::ffff:192.0.2.1')).toBe(
      '1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.'
    );
    expect(ipToReverseArpa('999.0.0.1')).toBeNull();

    // 2. RFC 8461 §4.1 MX pattern matching (exact vs single-label leftmost wildcard)
    expect(matchesMtaStsMxPattern('mx1.example.com.', 'mx1.example.com')).toBe(true);
    expect(matchesMtaStsMxPattern('mx1.example.com.', '*.example.com')).toBe(true);
    expect(matchesMtaStsMxPattern('sub.mx1.example.com.', '*.example.com')).toBe(false);
    expect(matchesMtaStsMxPattern('example.com.', '*.example.com')).toBe(false);

    // 3. RFC 8461 §3.2 policy file parser & MX cross-check
    const parsedPolicy = parseMtaStsPolicyFile(
      'version: STSv1\r\nmode: enforce\r\nmx: *.mail.example.com\r\nmx: backup.example.net\r\nmax_age: 604800\r\n',
      ['mx1.mail.example.com.', 'unlisted.example.org.']
    );
    expect(parsedPolicy.valid).toBe(true);
    expect(parsedPolicy.mode).toBe('enforce');
    expect(parsedPolicy.maxAge).toBe(604800);
    expect(parsedPolicy.matchedMxHosts).toEqual(['mx1.mail.example.com.']);
    expect(parsedPolicy.unmatchedMxHosts).toEqual(['unlisted.example.org.']);

    // 4. Synthetic end-to-end evaluation of MX FCrDNS (valid + mismatch + missing PTR), MTA-STS, TLS-RPT, and BIMI
    const queries: DohQueryLog[] = [
      makeLog(
        'transport.example.',
        RR_TYPES.MX,
        'MX',
        buildSyntheticResponsePacket({
          qname: 'transport.example.',
          qtype: RR_TYPES.MX,
          answers: [
            {
              name: 'transport.example.',
              type: RR_TYPES.MX,
              rdata: encodeMxRdata(10, 'mx1.transport.example.'),
            },
            {
              name: 'transport.example.',
              type: RR_TYPES.MX,
              rdata: encodeMxRdata(20, 'mx2.transport.example.'),
            },
          ],
        })
      ),
      // mx1 has two public IPs: 93.184.216.10 (valid FCrDNS) and 93.184.216.11 (PTR mismatch)
      makeLog(
        'mx1.transport.example.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: 'mx1.transport.example.',
          qtype: RR_TYPES.A,
          answers: [
            {
              name: 'mx1.transport.example.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([93, 184, 216, 10]),
            },
            {
              name: 'mx1.transport.example.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([93, 184, 216, 11]),
            },
          ],
        })
      ),
      // mx2 has one public IP: 93.184.216.20 (missing PTR -> NXDOMAIN)
      makeLog(
        'mx2.transport.example.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: 'mx2.transport.example.',
          qtype: RR_TYPES.A,
          answers: [
            {
              name: 'mx2.transport.example.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([93, 184, 216, 20]),
            },
          ],
        })
      ),
      // PTR for 93.184.216.10 -> mx1.transport.example. (which already resolves to 93.184.216.10 -> valid FCrDNS!)
      makeLog(
        '10.216.184.93.in-addr.arpa.',
        RR_TYPES.PTR,
        'PTR',
        buildSyntheticResponsePacket({
          qname: '10.216.184.93.in-addr.arpa.',
          qtype: RR_TYPES.PTR,
          answers: [
            {
              name: '10.216.184.93.in-addr.arpa.',
              type: RR_TYPES.PTR,
              rdata: encodeDnsName('mx1.transport.example.'),
            },
          ],
        }),
        false
      ),
      // PTR for 93.184.216.11 -> wrong-host.transport.example. whose A record is 93.184.216.99 (FCrDNS mismatch!)
      makeLog(
        '11.216.184.93.in-addr.arpa.',
        RR_TYPES.PTR,
        'PTR',
        buildSyntheticResponsePacket({
          qname: '11.216.184.93.in-addr.arpa.',
          qtype: RR_TYPES.PTR,
          answers: [
            {
              name: '11.216.184.93.in-addr.arpa.',
              type: RR_TYPES.PTR,
              rdata: encodeDnsName('wrong-host.transport.example.'),
            },
          ],
        }),
        false
      ),
      makeLog(
        'wrong-host.transport.example.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: 'wrong-host.transport.example.',
          qtype: RR_TYPES.A,
          answers: [
            {
              name: 'wrong-host.transport.example.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([93, 184, 216, 99]),
            },
          ],
        }),
        false
      ),
      // PTR for 93.184.216.20 -> NXDOMAIN (no PTR)
      makeLog(
        '20.216.184.93.in-addr.arpa.',
        RR_TYPES.PTR,
        'PTR',
        buildSyntheticResponsePacket({
          qname: '20.216.184.93.in-addr.arpa.',
          qtype: RR_TYPES.PTR,
          rcode: 3,
        }),
        false
      ),
      // SPF
      makeLog(
        'transport.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'transport.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'transport.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=spf1 mx -all']),
            },
          ],
        })
      ),
      // DMARC with p=quarantine; pct=50 (violates BIMI prerequisite which requires pct=100 for quarantine!)
      makeLog(
        '_dmarc.transport.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_dmarc.transport.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_dmarc.transport.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=DMARC1; p=quarantine; pct=50;']),
            },
          ],
        })
      ),
      // MTA-STS (_mta-sts.transport.example.)
      makeLog(
        '_mta-sts.transport.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_mta-sts.transport.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_mta-sts.transport.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['v=STSv1; id=2026110701;']),
            },
          ],
        })
      ),
      // TLS-RPT (_smtp._tls.transport.example.) with mailto:, https:, and invalid ftp: URI
      makeLog(
        '_smtp._tls.transport.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '_smtp._tls.transport.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '_smtp._tls.transport.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([
                'v=TLSRPTv1; rua=mailto:tlsrpt@transport.example,https://rpt.transport.example/v1/tlsrpt,ftp://bad.transport.example',
              ]),
            },
          ],
        })
      ),
      // BIMI (default._bimi.transport.example.)
      makeLog(
        'default._bimi.transport.example.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: 'default._bimi.transport.example.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: 'default._bimi.transport.example.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata([
                'v=BIMI1; l=https://transport.example/brand.svg; a=https://transport.example/vmc.pem;',
              ]),
            },
          ],
        })
      ),
      // DNSBL reputation: 93.184.216.10 is listed on bl.spamcop.net (127.0.0.2) with TXT explanation
      makeLog(
        '10.216.184.93.bl.spamcop.net.',
        RR_TYPES.A,
        'A',
        buildSyntheticResponsePacket({
          qname: '10.216.184.93.bl.spamcop.net.',
          qtype: RR_TYPES.A,
          answers: [
            {
              name: '10.216.184.93.bl.spamcop.net.',
              type: RR_TYPES.A,
              rdata: new Uint8Array([127, 0, 0, 2]),
            },
          ],
        }),
        false
      ),
      makeLog(
        '10.216.184.93.bl.spamcop.net.',
        RR_TYPES.TXT,
        'TXT',
        buildSyntheticResponsePacket({
          qname: '10.216.184.93.bl.spamcop.net.',
          qtype: RR_TYPES.TXT,
          answers: [
            {
              name: '10.216.184.93.bl.spamcop.net.',
              type: RR_TYPES.TXT,
              rdata: encodeTxtRdata(['Blocked - see https://www.spamcop.net/bl.shtml?93.184.216.10']),
            },
          ],
        }),
        false
      ),
      // SRV Service Discovery: _imaps._tcp.transport.example. active (priority=0, weight=1, port=993, target=imap.transport.example.)
      makeLog(
        '_imaps._tcp.transport.example.',
        RR_TYPES.SRV,
        'SRV',
        buildSyntheticResponsePacket({
          qname: '_imaps._tcp.transport.example.',
          qtype: RR_TYPES.SRV,
          answers: [
            {
              name: '_imaps._tcp.transport.example.',
              type: RR_TYPES.SRV,
              rdata: concatBytes(
                new Uint8Array([0, 0, 0, 1, 0x03, 0xe1]),
                encodeDnsName('imap.transport.example.')
              ),
            },
          ],
        })
      ),
      // SRV Service Discovery: _pop3s._tcp.transport.example. explicitly disabled via target "." (RFC 6186 / RFC 2782)
      makeLog(
        '_pop3s._tcp.transport.example.',
        RR_TYPES.SRV,
        'SRV',
        buildSyntheticResponsePacket({
          qname: '_pop3s._tcp.transport.example.',
          qtype: RR_TYPES.SRV,
          answers: [
            {
              name: '_pop3s._tcp.transport.example.',
              type: RR_TYPES.SRV,
              rdata: concatBytes(new Uint8Array([0, 0, 0, 0, 0, 0]), new Uint8Array([0])),
            },
          ],
        })
      ),
    ];

    const res = evaluateMailFromSnapshotData({
      targetName: 'transport.example.',
      queries,
      zones: [],
      cnameEdges: [],
      targetDomainStatus: 'secure',
      mtaStsPolicyFetch: {
        url: 'https://mta-sts.transport.example/.well-known/mta-sts.txt',
        fetchedAt: Date.now(),
        ok: true,
        httpStatus: 200,
        rawBody: 'version: STSv1\nmode: enforce\nmx: mx1.transport.example\nmax_age: 604800\n',
      },
    });

    const mail = res.mailAnalysis;
    // FCrDNS checks
    expect(mail.fcrdnsSummary.checkedIpCount).toBe(3);
    expect(mail.fcrdnsSummary.validCount).toBe(1);
    expect(mail.fcrdnsSummary.mismatchCount).toBe(1);
    expect(mail.fcrdnsSummary.noPtrCount).toBe(1);
    expect(mail.fcrdnsSummary.status).toBe('partial');
    expect(mail.mxHosts[0].addresses[0].fcrdnsStatus).toBe('valid');
    expect(mail.mxHosts[0].addresses[0].fcrdnsMatchedNames).toEqual(['mx1.transport.example.']);
    expect(mail.mxHosts[0].addresses[1].fcrdnsStatus).toBe('ptr-mismatch');
    expect(mail.mxHosts[1].addresses[0].fcrdnsStatus).toBe('no-ptr');

    // MTA-STS checks (mx2.transport.example is not covered by policy!)
    expect(mail.mtaSts.present).toBe(true);
    expect(mail.mtaSts.policyId).toBe('2026110701');
    expect(mail.mtaSts.policy?.mode).toBe('enforce');
    expect(mail.mtaSts.policy?.matchedMxHosts).toEqual(['mx1.transport.example.']);
    expect(mail.mtaSts.policy?.unmatchedMxHosts).toEqual(['mx2.transport.example.']);
    expect(mail.mtaSts.status).toBe('invalid');

    // TLS-RPT checks
    expect(mail.tlsRpt.present).toBe(true);
    expect(mail.tlsRpt.rua).toHaveLength(3);
    expect(mail.tlsRpt.rua[0].scheme).toBe('mailto');
    expect(mail.tlsRpt.rua[0].syntaxValid).toBe(true);
    expect(mail.tlsRpt.rua[1].scheme).toBe('https');
    expect(mail.tlsRpt.rua[1].syntaxValid).toBe(true);
    expect(mail.tlsRpt.rua[2].scheme).toBe('ftp');
    expect(mail.tlsRpt.rua[2].syntaxValid).toBe(false);
    expect(mail.tlsRpt.status).toBe('warning');

    // BIMI checks (DMARC p=quarantine; pct=50 fails BIMI prerequisite!)
    expect(mail.bimi.present).toBe(true);
    expect(mail.bimi.logoUrl).toBe('https://transport.example/brand.svg');
    expect(mail.bimi.authorityUrl).toBe('https://transport.example/vmc.pem');
    expect(mail.bimi.dmarcEligible).toBe(false);
    expect(mail.bimi.status).toBe('dmarc-ineligible');

    const codes = res.mailFindings.map((f) => f.code);
    expect(codes).toContain('MX_PTR_MISSING');
    expect(codes).toContain('MX_FCRDNS_MISMATCH');
    expect(codes).toContain('MX_DNSBL_LISTED');
    expect(codes).toContain('MTA_STS_MX_MISMATCH');
    expect(codes).toContain('TLSRPT_URI_WARNING');
    expect(codes).toContain('BIMI_DMARC_PREREQUISITE_NOT_MET');
    expect(codes).toContain('MAIL_SRV_DISCOVERED');

    // DNSBL check on 93.184.216.10
    expect(mail.mxHosts[0].addresses[0].dnsbl?.status).toBe('listed');
    expect(mail.mxHosts[0].addresses[0].dnsbl?.listedCount).toBe(1);
    expect(mail.mxHosts[0].addresses[0].dnsbl?.providers[0]?.zone).toBe('bl.spamcop.net');
    expect(mail.mxHosts[0].addresses[0].dnsbl?.providers[0]?.returnCodes).toEqual(['127.0.0.2']);
    expect(mail.mxHosts[0].addresses[0].dnsbl?.providers[0]?.reasons[0]).toContain('spamcop.net');

    // SRV Service Discovery check
    expect(mail.srvDiscovery).toBeDefined();
    expect(mail.srvDiscovery?.probedCount).toBe(2);
    expect(mail.srvDiscovery?.activeCount).toBe(1);
    expect(mail.srvDiscovery?.disabledCount).toBe(1);
    const imapsSrv = mail.srvDiscovery?.services.find((s) => s.prefix === '_imaps._tcp');
    expect(imapsSrv?.status).toBe('active');
    expect(imapsSrv?.records[0]?.port).toBe(993);
    expect(imapsSrv?.records[0]?.target).toBe('imap.transport.example.');
    const pop3sSrv = mail.srvDiscovery?.services.find((s) => s.prefix === '_pop3s._tcp');
    expect(pop3sSrv?.status).toBe('disabled-explicitly');
    expect(pop3sSrv?.records[0]?.isNullService).toBe(true);
  });
});

describe('Live DoH Mail + SMTP DANE + SPF + DKIM + DMARC End-to-End Verification', () => {
  it(
    'verifies ietf.org MX, DANE TLSA, SPF, DMARC (_report._dmarc), auto & custom DKIM selectors, and offline clock override',
    async () => {
      const snap = await runMailAnalysis('ietf.org', { dkimSelectors: ['ietf1'] });
      expect(snap.mode).toBe('mail');
      expect(snap.customDkimSelectors).toEqual(['ietf1']);
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

      // ietf.org publishes DNSSEC-signed _dmarc.ietf.org with authorized external rua (vali.email)
      expect(mail.dmarc.present).toBe(true);
      expect(mail.dmarc.dnssecStatus).toBe('secure');
      expect(mail.dmarc.rua.length).toBeGreaterThanOrEqual(1);
      const extRua = mail.dmarc.rua.find((u) => u.isExternalDomain);
      if (extRua) {
        expect(extRua.externalAuthorized).toBe('authorized');
      }

      // ietf.org publishes both auto-discovered "mail" and custom "ietf1" DKIM keys signed with DNSSEC
      const mailSel = mail.dkim.selectors.find((s) => s.selector === 'mail');
      const ietf1Sel = mail.dkim.selectors.find((s) => s.selector === 'ietf1');
      expect(mailSel?.present).toBe(true);
      expect(mailSel?.dnssecStatus).toBe('secure');
      expect(mailSel?.keyBits).toBeGreaterThanOrEqual(1024);
      expect(ietf1Sel?.present).toBe(true);
      expect(ietf1Sel?.source).toBe('custom');
      expect(ietf1Sel?.dnssecStatus).toBe('secure');
      expect(ietf1Sel?.keyBits).toBeGreaterThanOrEqual(1024);

      // MX FCrDNS (PTR), MTA-STS, TLS-RPT, and BIMI fields are populated
      expect(mail.fcrdnsSummary.checkedIpCount).toBeGreaterThanOrEqual(1);
      expect(mail.fcrdnsSummary.status).not.toBe('unchecked');
      expect(mail.mxHosts[0].addresses[0].ptrQname).toMatch(/\.(in-addr|ip6)\.arpa\.$/);
      expect(mail.mtaSts.qname).toBe('_mta-sts.ietf.org.');
      expect(mail.tlsRpt.qname).toBe('_smtp._tls.ietf.org.');
      expect(mail.bimi.qname).toBe('default._bimi.ietf.org.');
      expect(mail.srvDiscovery?.probedCount).toBe(10);
      const ipv4MxAddr = mail.mxHosts[0].addresses.find((a) => a.family === 4);
      if (ipv4MxAddr) {
        expect(ipv4MxAddr.dnsbl?.checkedCount).toBe(6);
      }

      // Offline time-travel re-verification into 2099 invalidates RRSIGs across DANE, DMARC & DKIM!
      const futureSnap = await reverifySnapshot(snap, {
        validationTimeMs: Date.UTC(2099, 0, 1),
      });
      expect(futureSnap.overallStatus).toBe('bogus');
      expect(futureSnap.mailAnalysis?.daneStatus).toBe('bogus');
      expect(futureSnap.mailAnalysis?.dmarc.dnssecStatus).toBe('bogus');
      expect(
        futureSnap.mailAnalysis?.dkim.selectors.find((s) => s.selector === 'ietf1')?.dnssecStatus
      ).toBe('bogus');
    },
    30000
  );

  it(
    'verifies cloudflare.com strict DMARC (p=reject + external _report._dmarc) and cross-zone CNAME DKIM keys',
    async () => {
      const cfSnap = await runMailAnalysis('cloudflare.com');
      const mail = cfSnap.mailAnalysis!;
      expect(mail.dmarc.present).toBe(true);
      expect(mail.dmarc.policy).toBe('reject');
      expect(mail.dmarc.verdict).toBe('reject');
      expect(mail.dmarc.dnssecStatus).toBe('secure');

      // Auto-discovers SendGrid/Mailchimp/Mandrill DKIM selectors (e.g. s1 CNAME -> 2048-bit RSA)
      expect(mail.dkim.selectors.length).toBeGreaterThanOrEqual(1);
      const s1 = mail.dkim.selectors.find((s) => s.selector === 's1');
      if (s1) {
        expect(s1.cnameChain.length).toBeGreaterThanOrEqual(1);
        expect(s1.keyBits).toBe(2048);
      }
    },
    30000
  );
});
