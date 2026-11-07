import { describe, expect, it } from 'vitest';
import { reverifySnapshot } from '../analyzer';
import { RR_TYPES } from '../constants';
import { bytesToBase64, concatBytes, hexToBytes } from '../encoding';
import {
  classifyIpAddress,
  decodeDkimPublicKey,
  estimateOrganizationalDomain,
  evaluateMailFromSnapshotData,
  parseDkimSelectorInput,
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

    // 1. Organizational domain estimation
    expect(estimateOrganizationalDomain('sub.mail.example.com.')).toBe('example.com.');
    expect(estimateOrganizationalDomain('a.b.example.co.uk.')).toBe('example.co.uk.');

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
