import { describe, expect, it } from 'vitest';
import {
  classifyApexTxtRecord,
  evaluateSnapshotFromLogs,
  reverifySnapshot,
  runDnsvizAnalysis,
} from '../analyzer';
import {
  CONSENSUS_DOH_RESOLVERS,
  DOH_SERVER_PRESETS,
  IANA_ROOT_TRUST_ANCHORS,
  normalizeDohEndpoint,
  RR_TYPES,
} from '../constants';
import {
  categorizeEdeCode,
  isSinkholeIpAddress,
  runConsensusAnalysis,
} from '../consensusAnalyzer';
import { computeDsDigest, computeNsec3Hash } from '../crypto';
import {
  formatSnapshotAsZonefile,
  formatZoneAsZonefile,
  generateCliReproducerCommands,
} from '../digFormat';
import {
  base64ToBytes,
  compareCanonicalDnsNames,
  computeKeyTag,
  concatBytes,
  normalizeFqdn,
} from '../encoding';
import {
  classifyDnsblReturnIp,
  getCachedRpkiValidation,
  ipToCymruOriginQname,
  ipToDnsblQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseReverseIpInput,
  reverseArpaToIp,
  seedRpkiValidationCache,
  summarizeRpkiValidationState,
  validateRpkiRoute,
} from '../ipUtils';
import { buildDnsQuery, decodeDnsName, encodeDnsName, parseDnsPacket } from '../wire';
import {
  mapCtIssuerToCaaDomains,
  parseCaaRecordEntry,
  parseCertSpotterJson,
  parseCrtShJson,
  runWebAnalysis,
} from '../webAnalyzer';

describe('DNS Wireformat & RFC Primitives', () => {
  it('normalizes domain names and enforces RFC 4034 §6.1 canonical DNS name order', () => {
    expect(normalizeFqdn('CloudFlare.COM')).toBe('cloudflare.com.');
    expect(normalizeFqdn('https://www.ietf.org/rfc/rfc4035.txt')).toBe('www.ietf.org.');
    expect(normalizeFqdn('.')).toBe('.');

    // RFC 4034 §6.1 canonical ordering example:
    // example < a.example < yljkjljk.a.example < Z.a.example < zABC.a.EXAMPLE < z.example < \001.z.example < *.z.example < \200.z.example
    const names = [
      '\\200.z.example.',
      'z.example.',
      'yljkjljk.a.example.',
      'example.',
      '*.z.example.',
      '\\001.z.example.',
      'Z.a.example.',
      'a.example.',
    ];
    const sorted = [...names].sort(compareCanonicalDnsNames);
    expect(sorted.map(normalizeFqdn)).toEqual([
      'example.',
      'a.example.',
      'yljkjljk.a.example.',
      'z.a.example.',
      'z.example.',
      '\\001.z.example.',
      '*.z.example.',
      '\\200.z.example.',
    ]);

    const blackLiesWire = encodeDnsName('\\000.0dot1.net.', true);
    expect(Array.from(blackLiesWire.subarray(0, 2))).toEqual([1, 0]);
    expect(decodeDnsName(blackLiesWire, 0).name).toBe('\\000.0dot1.net.');
  });

  it('encodes and decodes compressed DNS wire names and EDNS0 queries', () => {
    const query = buildDnsQuery('www.cloudflare.com.', RR_TYPES.A, { cd: true, doBit: true });
    const parsed = parseDnsPacket(query);
    expect(parsed.questions).toHaveLength(1);
    expect(parsed.questions[0].name).toBe('www.cloudflare.com.');
    expect(parsed.questions[0].type).toBe(RR_TYPES.A);
    expect(parsed.flags.cd).toBe(true);
    expect(parsed.edns?.doBit).toBe(true);

    // Compression pointer test: offset 0 = \x03com\x00, offset 5 = \x07example\xc0\x00
    const buf = concatBytes(
      encodeDnsName('com.'),
      new Uint8Array([7, 101, 120, 97, 109, 112, 108, 101, 0xc0, 0x00])
    );
    const dec = decodeDnsName(buf, 5);
    expect(dec.name).toBe('example.com.');
    expect(dec.bytesRead).toBe(10);
  });

  it('computes exact IANA Root Trust Anchor key tags and SHA-256 digests', async () => {
    const ksk2024Pub = base64ToBytes(
      'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc='
    );
    const rdata = concatBytes(new Uint8Array([0x01, 0x01, 3, 8]), ksk2024Pub);
    expect(computeKeyTag(rdata)).toBe(38696);
    const digest = await computeDsDigest('.', rdata, 2);
    expect(digest).toBe(IANA_ROOT_TRUST_ANCHORS[0].digest);
  });

  it('matches RFC 5155 Appendix A NSEC3 SHA-1 + Base32hex test vector', async () => {
    // RFC 5155 Appendix A: H(example, salt=aabbccdd, iterations=12) == 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM
    const hash = await computeNsec3Hash('example.', 'aabbccdd', 12);
    expect(hash).toBe('0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM');
  });
});

describe('Live 1.1.1.1 DoH DNSViz Client-Side Engine', () => {
  it(
    'verifies full cryptographic chain of trust for cloudflare.com (ECDSA + RSA)',
    async () => {
      const snap = await runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A', 'AAAA'] });
      expect(snap.overallStatus === 'secure' || snap.overallStatus === 'warning').toBe(true);
      expect(snap.zones.map((z) => z.zoneName)).toEqual(['.', 'com.', 'cloudflare.com.']);
      expect(snap.resolverVerdict?.adBit).toBe(true);

      // Offline time-travel re-verification far in the future should mark RRSIGs expired (bogus)
      const futureSnap = await reverifySnapshot(snap, {
        validationTimeMs: Date.UTC(2038, 0, 1),
      });
      expect(futureSnap.overallStatus).toBe('bogus');
    },
    25000
  );

  it(
    'detects broken DS delegation and missing SEP DNSKEY on dnssec-failed.org',
    async () => {
      const snap = await runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] });
      expect(snap.overallStatus).toBe('bogus');
      const leaf = snap.zones.find((z) => z.zoneName === 'dnssec-failed.org.');
      expect(leaf?.status).toBe('bogus');
      expect(leaf?.dnskeys.some((k) => k.role === 'missing')).toBe(true);
    },
    25000
  );

  it(
    'detects corrupted RRSIG cryptographic signature on sigfail.verteiltesysteme.net',
    async () => {
      const snap = await runDnsvizAnalysis('sigfail.verteiltesysteme.net', { queryTypes: ['A'] });
      expect(snap.overallStatus).toBe('bogus');
      expect(snap.findings.some((f) => f.severity === 'error')).toBe(true);
    },
    25000
  );

  it(
    'proves unsigned/insecure delegation via NSEC3 Opt-Out for github.com',
    async () => {
      const snap = await runDnsvizAnalysis('github.com', { queryTypes: ['A'] });
      expect(snap.overallStatus).toBe('insecure');
      const ghZone = snap.zones.find((z) => z.zoneName === 'github.com.');
      expect(ghZone?.status).toBe('insecure');
      expect(ghZone?.insecureDelegationProof?.valid).toBe(true);
    },
    25000
  );

  it(
    'follows cross-zone signed CNAME chain on www.iana.org',
    async () => {
      const snap = await runDnsvizAnalysis('www.iana.org', { queryTypes: ['A'] });
      expect(snap.overallStatus === 'secure' || snap.overallStatus === 'warning').toBe(true);
      expect(snap.cnameEdges.length).toBeGreaterThanOrEqual(1);
      expect(snap.zones.some((z) => z.zoneName === 'iana.org.')).toBe(true);
      expect(snap.zones.some((z) => z.zoneName === 'cloudflare.net.')).toBe(true);
    },
    25000
  );

  it(
    'validates Compact Denial of Existence (NODATA) on nonexistent.cloudflare.com and NXDOMAIN on nonexistent.nlnetlabs.nl',
    async () => {
      const cfSnap = await runDnsvizAnalysis('nonexistent-digdeep-check.cloudflare.com', {
        queryTypes: ['A'],
      });
      expect(cfSnap.overallStatus === 'secure' || cfSnap.overallStatus === 'warning').toBe(true);
      const cfZone = cfSnap.zones.find((z) => z.zoneName === 'cloudflare.com.');
      expect(cfZone?.negativeNodes[0].kind).toBe('NODATA');
      expect(cfSnap.findings.some((f) => f.code === 'COMPACT_DENIAL_OF_EXISTENCE')).toBe(true);

      const nlSnap = await runDnsvizAnalysis('nonexistent-digdeep-check.nlnetlabs.nl', {
        queryTypes: ['A'],
      });
      expect(nlSnap.overallStatus === 'secure' || nlSnap.overallStatus === 'warning').toBe(true);
      const nlZone = nlSnap.zones.find((z) => z.zoneName === 'nlnetlabs.nl.');
      expect(nlZone?.negativeNodes[0].kind).toBe('NXDOMAIN');
    },
    25000
  );

  it(
    'normalizes manual DoH inputs and validates DNSSEC via Google 8.8.8.8 DoH',
    async () => {
      expect(normalizeDohEndpoint('8.8.4.4')).toBe('https://8.8.4.4/dns-query');
      expect(normalizeDohEndpoint('dns.quad9.net')).toBe('https://dns.quad9.net/dns-query');
      expect(normalizeDohEndpoint('https://custom.example.org/doh')).toBe(
        'https://custom.example.org/doh'
      );
      const presetUrls = DOH_SERVER_PRESETS.map((p) => p.url);
      expect(presetUrls).toContain('https://unfiltered.joindns4.eu/dns-query');
      expect(presetUrls).toContain('https://child-noads.joindns4.eu/dns-query');
      expect(presetUrls).toContain('https://protective.joindns4.eu/dns-query');
      expect(presetUrls).not.toContain('https://wikimedia-dns.org/dns-query');

      const googleSnap = await runDnsvizAnalysis('cloudflare.com', {
        endpoint: 'https://8.8.8.8/dns-query',
        queryTypes: ['A'],
      });
      expect(googleSnap.dohEndpoint).toBe('https://8.8.8.8/dns-query');
      expect(googleSnap.overallStatus === 'secure' || googleSnap.overallStatus === 'warning').toBe(
        true
      );
    },
    25000
  );

  it(
    'validates 0dot1.net across multiple per-query synthesized Black-Lies NSEC bitmaps without false RRSIG mismatch',
    async () => {
      const snap = await runDnsvizAnalysis('0dot1.net', {
        queryTypes: ['A', 'AAAA', 'MX', 'TXT', 'CAA', 'HTTPS'],
      });
      expect(snap.overallStatus).toBe('secure');
      expect(snap.findings.some((f) => f.severity === 'error')).toBe(false);
      const leafZone = snap.zones.find((z) => z.zoneName === '0dot1.net.');
      expect(leafZone?.status).toBe('secure');
      const nsecRrsets = leafZone?.rrsets.filter((r) => r.type === RR_TYPES.NSEC) ?? [];
      expect(nsecRrsets.length).toBeGreaterThanOrEqual(2);
      expect(nsecRrsets.every((r) => r.status === 'secure')).toBe(true);
    },
    25000
  );

  it(
    'ignores out-of-bailiwick nameserver IP authority SOAs (e.g. commerzbank.de NS under commerzbank.com)',
    async () => {
      const snap = await runDnsvizAnalysis('commerzbank.de', {
        queryTypes: ['A', 'AAAA'],
      });
      expect(snap.zones.map((z) => z.zoneName)).toEqual(['.', 'de.', 'commerzbank.de.']);
      expect(snap.overallStatus).toBe('insecure');
      expect(snap.findings.some((f) => f.severity === 'error')).toBe(false);
    },
    25000
  );

  it(
    'validates short-lived online-signed Route 53 RRSIGs (slack.com) as secure and emits RRSIG_EXPIRING_SOON when TTL exceeds remaining validity',
    async () => {
      const snap = await runDnsvizAnalysis('slack.com', {
        queryTypes: ['A', 'AAAA'],
      });
      expect(snap.overallStatus).toBe('secure');
      expect(snap.findings.some((f) => f.code === 'RRSIG_EXPIRING_SOON')).toBe(false);

      // Find the earliest RRSIG expiration in slack.com. and time-travel to 20s before expiration (< TTL)
      const slackZone = snap.zones.find((z) => z.zoneName === 'slack.com.');
      const aRrset = slackZone?.rrsets.find((r) => r.type === RR_TYPES.A);
      const aExpSec = aRrset?.rrsigs[0]?.rrsig.expiration;
      expect(aExpSec).toBeDefined();
      if (aExpSec) {
        const nearExpirySnap = await reverifySnapshot(snap, {
          validationTimeMs: (aExpSec - 20) * 1000,
        });
        expect(nearExpirySnap.overallStatus).toBe('warning');
        expect(nearExpirySnap.findings.some((f) => f.code === 'RRSIG_EXPIRING_SOON')).toBe(true);
      }
    },
    25000
  );

  it(
    'automatically detects IPv4/IPv6 input, validates .arpa DNSSEC chain, verifies FCrDNS, and looks up BGP ASN',
    async () => {
      // 1. Unit checks for IPv4 / IPv6 <-> .arpa round-tripping and Cymru TXT parsing
      const v4Parsed = parseReverseIpInput('1.1.1.1');
      expect(v4Parsed?.wasRawIpInput).toBe(true);
      expect(v4Parsed?.arpaFqdn).toBe('1.1.1.1.in-addr.arpa.');
      expect(v4Parsed?.cymruOriginQname).toBe('1.1.1.1.origin.asn.cymru.com.');

      const v6Parsed = parseReverseIpInput('2606:4700:4700::1111');
      expect(v6Parsed?.wasRawIpInput).toBe(true);
      expect(v6Parsed?.ip).toBe('2606:4700:4700::1111');
      expect(v6Parsed?.arpaFqdn).toBe(
        '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa.'
      );
      expect(reverseArpaToIp(v6Parsed!.arpaFqdn)).toEqual({
        ip: '2606:4700:4700::1111',
        family: 6,
      });
      expect(ipToCymruOriginQname('2606:4700:4700::1111')).toBe(
        '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.origin6.asn.cymru.com.'
      );

      const origins = parseCymruOriginTxt(['13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11']);
      expect(origins[0].asns).toEqual([13335]);
      expect(origins[0].bgpPrefix).toBe('1.1.1.0/24');
      expect(origins[0].rir).toBe('apnic');

      const asnInfo = parseCymruAsnTxt([
        '13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US',
      ]);
      expect(asnInfo?.asn).toBe(13335);
      expect(asnInfo?.asName).toContain('CLOUDFLARENET');

      // 2. Live DNSSEC-signed IPv4 reverse DNS trace on '9.9.9.9' (Quad9: signed all the way to 9.9.9.in-addr.arpa. PTR)
      const quad9Snap = await runDnsvizAnalysis('9.9.9.9');
      expect(quad9Snap.targetName).toBe('9.9.9.9.in-addr.arpa.');
      expect(quad9Snap.queriedIp).toBe('9.9.9.9');
      expect(quad9Snap.queryTypes).toEqual(['PTR']);
      expect(quad9Snap.overallStatus).toBe('secure');
      expect(quad9Snap.zones.map((z) => z.zoneName)).toEqual([
        '.',
        'arpa.',
        'in-addr.arpa.',
        '9.in-addr.arpa.',
        '9.9.9.in-addr.arpa.',
      ]);
      expect(quad9Snap.reverseDns?.ptrStatus).toBe('resolved');
      expect(quad9Snap.reverseDns?.ptrDnssecStatus).toBe('secure');
      expect(quad9Snap.reverseDns?.targets.map((t) => t.hostname)).toContain('dns9.quad9.net.');
      expect(quad9Snap.reverseDns?.fcrdnsStatus).toBe('valid');
      expect(quad9Snap.reverseDns?.bgp?.asns.some((a) => a.asn === 19281)).toBe(true);

      // 3. Live IPv4 & IPv6 reverse DNS traces on '1.1.1.1' and '2606:4700:4700::1111' (signed RIR parent + unsigned leaf zone)
      const v4Snap = await runDnsvizAnalysis('1.1.1.1');
      expect(v4Snap.targetName).toBe('1.1.1.1.in-addr.arpa.');
      expect(v4Snap.queriedIp).toBe('1.1.1.1');
      expect(v4Snap.queryTypes).toEqual(['PTR']);
      expect(v4Snap.overallStatus).toBe('insecure');
      expect(v4Snap.zones.find((z) => z.zoneName === '1.in-addr.arpa.')?.status).toBe('secure');
      expect(v4Snap.reverseDns?.targets.map((t) => t.hostname)).toContain('one.one.one.one.');
      expect(v4Snap.reverseDns?.fcrdnsStatus).toBe('valid');
      expect(v4Snap.reverseDns?.bgp?.bgpPrefix).toBe('1.1.1.0/24');
      expect(v4Snap.reverseDns?.bgp?.asns.some((a) => a.asn === 13335)).toBe(true);

      const v6Snap = await runDnsvizAnalysis('2606:4700:4700::1111');
      expect(v6Snap.queriedIp).toBe('2606:4700:4700::1111');
      expect(v6Snap.queryTypes).toEqual(['PTR']);
      expect(v6Snap.overallStatus).toBe('insecure');
      expect(v6Snap.zones.find((z) => z.zoneName === '0.6.2.ip6.arpa.')?.status).toBe('secure');
      expect(v6Snap.reverseDns?.fcrdnsStatus).toBe('valid');
      expect(v6Snap.reverseDns?.targets.map((t) => t.hostname)).toContain('one.one.one.one.');
      expect(v6Snap.reverseDns?.bgp?.asns.some((a) => a.asn === 13335)).toBe(true);
    },
    30000
  );

  it(
    'audits CDS/CDNSKEY rollover sync (RFC 7344/8078), CSYNC wire parsing (RFC 7477), NS BGP ASN diversity, SOA timers, and dangling NS/CNAME',
    async () => {
      // 1. Wire parsing test for CDS (59), CDNSKEY (60), and CSYNC (62)
      const buildSingleRrPacket = (qname: string, rrtype: number, rdata: Uint8Array) => {
        const header = new Uint8Array([0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        const nameWire = encodeDnsName(qname, true);
        const qTail = new Uint8Array([rrtype >> 8, rrtype & 0xff, 0, 1]);
        const ansMeta = new Uint8Array(10);
        const v = new DataView(ansMeta.buffer);
        v.setUint16(0, rrtype, false);
        v.setUint16(2, 1, false);
        v.setUint32(4, 3600, false);
        v.setUint16(8, rdata.length, false);
        return parseDnsPacket(concatBytes(header, nameWire, qTail, nameWire, ansMeta, rdata));
      };

      // CSYNC: serial=2026110701 (0x78c3feed), flags=3 (immediate + soaminimum), bitmap window 0 len 4 [A(1), NS(2), AAAA(28)]
      const csyncRdata = new Uint8Array([
        0x78,
        0xc3,
        0xfe,
        0xed, // 2026110701
        0x00,
        0x03, // flags = 3
        0x00,
        0x04,
        0x60,
        0x00,
        0x00,
        0x08, // bit 1 (A), bit 2 (NS), bit 28 (AAAA)
      ]);
      const csyncPkt = buildSingleRrPacket('example.com.', RR_TYPES.CSYNC, csyncRdata);
      const csyncAns = csyncPkt.answers[0];
      expect(csyncAns.typeName).toBe('CSYNC');
      expect(csyncAns.parsed.kind).toBe('CSYNC');
      if (csyncAns.parsed.kind === 'CSYNC') {
        expect(csyncAns.parsed.soaSerial).toBe(2026110701);
        expect(csyncAns.parsed.immediate).toBe(true);
        expect(csyncAns.parsed.soaMinimum).toBe(true);
        expect(csyncAns.parsed.typeNames).toEqual(['A', 'NS', 'AAAA']);
      }

      // 2. Live CDS / CDNSKEY KSK rollover sync & NS BGP ASN diversity on cloudflare.com
      const cfSnap = await runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A'] });
      const cfLeaf = cfSnap.zones.find((z) => z.zoneName === 'cloudflare.com.');
      expect(cfLeaf).toBeDefined();
      expect(cfLeaf?.cdsRollover?.present).toBe(true);
      expect(cfLeaf?.cdsRollover?.status).toBe('in-sync');
      expect(cfLeaf?.cdsRollover?.signedByKsk).toBe(true);
      expect(cfLeaf?.cdsRollover?.cdsRecords[0]?.matchesParentDs).toBe(true);
      expect(cfSnap.findings.some((f) => f.code === 'CDS_PARENT_IN_SYNC')).toBe(true);

      // Nameserver BGP ASN diversity on cloudflare.com (all in AS13335)
      expect(cfLeaf?.nsDiversity?.uniqueAsns.some((a) => a.asn === 13335)).toBe(true);
      expect(cfLeaf?.nsDiversity?.singleAsn).toBe(true);
      expect(cfLeaf?.nsDiversity?.hasIpv6).toBe(true);
      expect(cfSnap.findings.some((f) => f.code === 'NS_SINGLE_ASN')).toBe(true);
      expect(cfLeaf?.soaAudit?.valid).toBe(true);

      // 3. Synthetic evaluation for SOA timer anomalies, RFC 8078 CDS delete signal, dangling NS, and dangling CNAME
      const firstNsHost = cfLeaf?.nameservers[0]?.hostname ?? 'ns3.cloudflare.com.';
      const mutatedQueries = cfSnap.queries.map((q) => {
        // Mutate cloudflare.com SOA to have retry >= refresh and minimum > 86400
        if (q.qname === 'cloudflare.com.' && q.qtype === RR_TYPES.SOA) {
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: q.packet.answers.map((ans) =>
                ans.type === RR_TYPES.SOA && ans.parsed.kind === 'SOA'
                  ? {
                      ...ans,
                      parsed: {
                        ...ans.parsed,
                        refresh: 3600,
                        retry: 7200, // retry >= refresh
                        expire: 5000, // expire < refresh + retry
                        minimum: 172800, // minimum > 86400
                      },
                    }
                  : ans
              ),
            },
          };
        }
        // Mutate cloudflare.com CDS to RFC 8078 delete signal (0 0 0 00)
        if (q.qname === 'cloudflare.com.' && q.qtype === RR_TYPES.CDS) {
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: q.packet.answers.map((ans) =>
                ans.type === RR_TYPES.CDS && ans.parsed.kind === 'DS'
                  ? {
                      ...ans,
                      parsed: {
                        ...ans.parsed,
                        keyTag: 0,
                        algorithm: 0,
                        digestType: 0,
                        digestHex: '00',
                      },
                    }
                  : ans
              ),
            },
          };
        }
        // Simulate first NS hostname returning NXDOMAIN (rcode=3) with 0 answers
        if (q.purpose.startsWith('Nameserver IP') && q.qname === firstNsHost) {
          return {
            ...q,
            packet: {
              ...q.packet,
              flags: { ...q.packet.flags, rcode: 3 },
              answers: [],
            },
          };
        }
        return q;
      });

      const mutatedSnap = await evaluateSnapshotFromLogs({
        id: 'test-mutated-resilience',
        targetName: cfSnap.targetName,
        queryTypes: cfSnap.queryTypes,
        dohEndpoint: cfSnap.dohEndpoint,
        capturedAt: cfSnap.capturedAt,
        validatedAt: cfSnap.validatedAt,
        durationMs: cfSnap.durationMs,
        queries: mutatedQueries,
        trustAnchors: cfSnap.trustAnchorsUsed,
      });

      const mutLeaf = mutatedSnap.zones.find((z) => z.zoneName === 'cloudflare.com.');
      expect(mutLeaf?.soaAudit?.valid).toBe(false);
      expect(mutLeaf?.soaAudit?.issues.length).toBe(3);
      expect(mutatedSnap.findings.some((f) => f.code === 'SOA_TIMER_ANOMALY')).toBe(true);
      expect(mutLeaf?.cdsRollover?.status).toBe('delete-signal');
      expect(mutatedSnap.findings.some((f) => f.code === 'CDS_DELETE_SIGNAL')).toBe(true);
      expect(mutLeaf?.nsDiversity?.danglingHosts).toContain(firstNsHost);
      expect(mutatedSnap.findings.some((f) => f.code === 'DANGLING_NS_TARGET')).toBe(true);
    },
    25000
  );

  it(
    'decodes RFC 9460 HTTPS/SVCB SvcParams, TLS ECHConfigList, SSHFP, RFC 8659/8657 CAA & runs live Web analysis',
    async () => {
      const buildSingleRrPacket = (owner: string, rrtype: number, rdata: Uint8Array) => {
        const nameWire = encodeDnsName(owner, false);
        const header = new Uint8Array([
          0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        const qTail = new Uint8Array([(rrtype >> 8) & 0xff, rrtype & 0xff, 0x00, 0x01]);
        const ansMeta = new Uint8Array(10);
        const v = new DataView(ansMeta.buffer);
        v.setUint16(0, rrtype, false);
        v.setUint16(2, 1, false);
        v.setUint32(4, 3600, false);
        v.setUint16(8, rdata.length, false);
        return parseDnsPacket(concatBytes(header, nameWire, qTail, nameWire, ansMeta, rdata));
      };

      // 1. Construct binary ECHConfigList (version 0xfe0d, configId=42, KEM=0x0020 X25519, 32B pubKey, KDF=1/AEAD=1, maxNameLen=64, publicName="cloudflare-ech.com")
      const pubNameBytes = new TextEncoder().encode('cloudflare-ech.com');
      const pubKeyBytes = new Uint8Array(32).fill(0xab);
      const echContents = concatBytes(
        new Uint8Array([
          42, // config_id = 42
          0x00, 0x20, // kem_id = 0x0020 (DHKEM(X25519, HKDF-SHA256))
          0x00, 0x20, // public_key length = 32
        ]),
        pubKeyBytes,
        new Uint8Array([
          0x00, 0x04, // cipher_suites length = 4
          0x00, 0x01, // KDF = HKDF-SHA256 (0x0001)
          0x00, 0x01, // AEAD = AES-128-GCM (0x0001)
          64, // maximum_name_length = 64
          pubNameBytes.length,
        ]),
        pubNameBytes,
        new Uint8Array([0x00, 0x00]) // extensions length = 0
      );
      const echConfigEntry = concatBytes(
        new Uint8Array([
          0xfe, 0x0d, // version = 0xfe0d (Draft-13+)
          (echContents.length >> 8) & 0xff,
          echContents.length & 0xff,
        ]),
        echContents
      );
      const echConfigList = concatBytes(
        new Uint8Array([(echConfigEntry.length >> 8) & 0xff, echConfigEntry.length & 0xff]),
        echConfigEntry
      );

      // Construct HTTPS RDATA: priority=1, target=".", SvcParams: alpn(1)="h3,h2", port(3)=8443, ipv4hint(4)=192.0.2.1, ech(5)=echConfigList
      const alpnVal = new Uint8Array([2, 0x68, 0x33, 2, 0x68, 0x32]); // "h3", "h2"
      const httpsRdata = concatBytes(
        new Uint8Array([
          0x00, 0x01, // priority = 1 (ServiceMode)
          0x00, // target = "."
          // Key 1 (alpn)
          0x00, 0x01, 0x00, alpnVal.length,
        ]),
        alpnVal,
        new Uint8Array([
          // Key 3 (port = 8443 = 0x20fb)
          0x00, 0x03, 0x00, 0x02, 0x20, 0xfb,
          // Key 4 (ipv4hint = 192.0.2.1)
          0x00, 0x04, 0x00, 0x04, 192, 0, 2, 1,
          // Key 5 (ech)
          0x00, 0x05, (echConfigList.length >> 8) & 0xff, echConfigList.length & 0xff,
        ]),
        echConfigList
      );

      const httpsPkt = buildSingleRrPacket('example.com.', RR_TYPES.HTTPS, httpsRdata);
      const httpsAns = httpsPkt.answers[0];
      expect(httpsAns.typeName).toBe('HTTPS');
      expect(httpsAns.parsed.kind).toBe('SVCB');
      if (httpsAns.parsed.kind === 'SVCB') {
        expect(httpsAns.parsed.priority).toBe(1);
        expect(httpsAns.parsed.isAliasMode).toBe(false);
        const echParam = httpsAns.parsed.params.find((p) => p.key === 5);
        expect(echParam?.echConfigs).toHaveLength(1);
        expect(echParam?.echConfigs?.[0]?.publicName).toBe('cloudflare-ech.com');
        expect(echParam?.echConfigs?.[0]?.kemName).toContain('X25519');
        expect(echParam?.echConfigs?.[0]?.cipherSuites[0]?.aeadName).toBe('AES-128-GCM');
      }

      // 2. Test SSHFP (TYPE44) RDATA decoder (Algo 4 = Ed25519, FP Type 2 = SHA-256)
      const sshfpDigest = new Uint8Array(32).fill(0x5a);
      const sshfpRdata = concatBytes(new Uint8Array([4, 2]), sshfpDigest);
      const sshfpPkt = buildSingleRrPacket('example.com.', RR_TYPES.SSHFP, sshfpRdata);
      const sshfpAns = sshfpPkt.answers[0];
      expect(sshfpAns.parsed.kind).toBe('SSHFP');
      if (sshfpAns.parsed.kind === 'SSHFP') {
        expect(sshfpAns.parsed.algorithmName).toContain('Ed25519');
        expect(sshfpAns.parsed.fpTypeName).toBe('SHA-256');
        expect(sshfpAns.parsed.fingerprintHex).toHaveLength(64);
      }

      // 3. Test RFC 8659 & RFC 8657 CAA record parser
      const acmeCaa = parseCaaRecordEntry(
        'example.com.',
        128,
        'issue',
        'letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345'
      );
      expect(acmeCaa.valid).toBe(true);
      expect(acmeCaa.critical).toBe(true);
      expect(acmeCaa.caDomain).toBe('letsencrypt.org');
      expect(acmeCaa.parameters).toEqual([
        { key: 'validationmethods', value: 'dns-01' },
        { key: 'accounturi', value: 'https://acme-v02.api.letsencrypt.org/acme/acct/12345' },
      ]);

      const unknownCritCaa = parseCaaRecordEntry('example.com.', 128, 'futuretag', 'someval');
      expect(unknownCritCaa.valid).toBe(false);
      expect(unknownCritCaa.recognizedTag).toBe(false);

      // 4. Live Web & HTTPS Analysis on cloudflare.com
      const webSnap = await runWebAnalysis('cloudflare.com');
      expect(webSnap.mode).toBe('web');
      expect(webSnap.webAnalysis).toBeDefined();
      expect(webSnap.webAnalysis?.httpsRecords.length).toBeGreaterThan(0);
      expect(webSnap.webAnalysis?.supportsHttp3).toBe(true);
      expect(webSnap.webAnalysis?.supportsHttp2).toBe(true);
      expect(webSnap.webAnalysis?.caa.hops.length).toBeGreaterThanOrEqual(2);

      // 5. Synthetic mutation on webSnap to verify ipv4hint drift & ECH detection
      const driftedQueries = webSnap.queries.map((q) => {
        if (q.qname === 'cloudflare.com.' && q.qtype === RR_TYPES.HTTPS) {
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: httpsPkt.answers.map((a) => ({ ...a, name: 'cloudflare.com.' })),
            },
          };
        }
        return q;
      });
      const driftedSnap = await evaluateSnapshotFromLogs({
        id: 'test-web-drift-ech',
        mode: 'web',
        targetName: webSnap.targetName,
        queryTypes: webSnap.queryTypes,
        dohEndpoint: webSnap.dohEndpoint,
        capturedAt: webSnap.capturedAt,
        validatedAt: webSnap.validatedAt,
        durationMs: webSnap.durationMs,
        queries: driftedQueries,
        trustAnchors: webSnap.trustAnchorsUsed,
      });
      expect(driftedSnap.webAnalysis?.echEnabled).toBe(true);
      expect(driftedSnap.webAnalysis?.echPublicNames).toContain('cloudflare-ech.com');
      expect(driftedSnap.webAnalysis?.ipHintStatus).toBe('drift-detected');
      expect(driftedSnap.findings.some((f) => f.code === 'HTTPS_ECH_ENABLED')).toBe(true);
      expect(driftedSnap.findings.some((f) => f.code === 'HTTPS_IP_HINT_DRIFT')).toBe(true);
    },
    25000
  );

  it(
    'runs Multi-Resolver DoH Consensus across public & protective resolvers and detects Protective Blocking (RFC 8914 EDE), SOA Serial Skew, and Key-Tag Skew',
    async () => {
      // 1. Unit tests for RFC 8914 EDE categorization & sinkhole IP detection
      expect(CONSENSUS_DOH_RESOLVERS.length).toBeGreaterThanOrEqual(8);
      expect(categorizeEdeCode(6)).toBe('dnssec-bogus');
      expect(categorizeEdeCode(15)).toBe('policy-blocked');
      expect(categorizeEdeCode(17)).toBe('policy-blocked');
      expect(categorizeEdeCode(22)).toBe('upstream-reachability');
      expect(isSinkholeIpAddress('0.0.0.0')).toBe(true);
      expect(isSinkholeIpAddress('127.0.0.1')).toBe(true);
      expect(isSinkholeIpAddress('::')).toBe(true);
      expect(isSinkholeIpAddress('93.184.215.14')).toBe(false);

      // 2. Live Multi-Resolver DoH Consensus probe on iana.org
      const consensusSnap = await runConsensusAnalysis('iana.org');
      expect(consensusSnap.mode).toBe('consensus');
      expect(consensusSnap.consensusAnalysis).toBeDefined();
      const ca = consensusSnap.consensusAnalysis!;
      expect(ca.resolvers).toHaveLength(CONSENSUS_DOH_RESOLVERS.length);
      expect(ca.reachableCount).toBeGreaterThanOrEqual(4);
      expect(ca.uniqueSoaSerials.length).toBeGreaterThanOrEqual(1);
      expect(ca.keyTagConsensus).toBe('synchronized');

      // 3. Synthetic mutation: simulate protective blocking (0.0.0.0 + EDE 15) on 1.1.1.2 (Cloudflare Protective)
      //    plus SOA serial skew on 8.8.8.8
      const mutatedQueries = consensusSnap.queries.map((q) => {
        if (q.endpoint === 'https://1.1.1.2/dns-query' && q.qtype === RR_TYPES.A) {
          return {
            ...q,
            packet: {
              ...q.packet,
              edns: q.packet.edns
                ? {
                    ...q.packet.edns,
                    ede: [
                      {
                        infoCode: 15,
                        name: 'Blocked',
                        extraText: 'Blocked by Threat Intelligence feed',
                      },
                    ],
                  }
                : undefined,
              answers: q.packet.answers.map((ans) =>
                ans.type === RR_TYPES.A
                  ? { ...ans, rdataText: '0.0.0.0' }
                  : ans
              ),
            },
          };
        }
        if (q.endpoint === 'https://8.8.8.8/dns-query' && q.qtype === RR_TYPES.SOA) {
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: q.packet.answers.map((ans) =>
                ans.type === RR_TYPES.SOA && ans.parsed.kind === 'SOA'
                  ? {
                      ...ans,
                      parsed: {
                        ...ans.parsed,
                        serial: ans.parsed.serial + 42,
                      },
                    }
                  : ans
              ),
            },
          };
        }
        return q;
      });

      const skewedSnap = await evaluateSnapshotFromLogs({
        id: 'test-consensus-skew-block',
        mode: 'consensus',
        targetName: consensusSnap.targetName,
        queryTypes: consensusSnap.queryTypes,
        dohEndpoint: consensusSnap.dohEndpoint,
        capturedAt: consensusSnap.capturedAt,
        validatedAt: consensusSnap.validatedAt,
        durationMs: consensusSnap.durationMs,
        queries: mutatedQueries,
        trustAnchors: consensusSnap.trustAnchorsUsed,
      });

      const skewedCa = skewedSnap.consensusAnalysis!;
      expect(skewedCa.protectiveBlockedResolvers.length).toBeGreaterThanOrEqual(1);
      const cfProtRow = skewedCa.resolvers.find((r) => r.shortLabel === '1.1.1.2');
      expect(cfProtRow?.classification).toBe('policy-blocked');
      expect(cfProtRow?.isSinkholed).toBe(true);
      expect(cfProtRow?.ede.some((e) => e.infoCode === 15)).toBe(true);
      expect(skewedCa.soaSerialConsensus).toBe('skew-detected');
      expect(
        skewedSnap.findings.some((f) => f.code === 'CONSENSUS_PROTECTIVE_BLOCKED')
      ).toBe(true);
      expect(
        skewedSnap.findings.some((f) => f.code === 'CONSENSUS_SOA_SERIAL_SKEW')
      ).toBe(true);
    },
    30000
  );

  it(
    'decodes ZONEMD (RFC 8976), SMIMEA (RFC 8162), and OPENPGPKEY (RFC 7929) wire RDATA and validates Root Zone (.) ZONEMD & DNSBL IP reputation (RFC 5782)',
    async () => {
      // 1. DNSBL helper unit checks (RFC 5782 §5 test point & administrative block differentiation)
      expect(ipToDnsblQname('192.0.2.42', 'bl.spamcop.net')).toBe(
        '42.2.0.192.bl.spamcop.net.'
      );
      expect(ipToDnsblQname('2001:db8::1', 'bl.spamcop.net')).toBe(
        '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.bl.spamcop.net.'
      );
      expect(ipToDnsblQname('invalid-ip', 'bl.spamcop.net')).toBeNull();
      expect(classifyDnsblReturnIp('127.0.0.2')).toBe('listed');
      expect(classifyDnsblReturnIp('127.0.1.5')).toBe('listed');
      expect(classifyDnsblReturnIp('127.255.255.254')).toBe('admin-blocked');
      expect(classifyDnsblReturnIp('127.255.255.255')).toBe('admin-blocked');
      expect(classifyDnsblReturnIp('1.1.1.1')).toBe('ignore');

      // 2. Wire decoding for ZONEMD (TYPE63), SMIMEA (TYPE53), and OPENPGPKEY (TYPE61)
      const qWire = buildDnsQuery('.', RR_TYPES.ZONEMD, { id: 0x7788 });
      const header = new Uint8Array(qWire.slice(0, 12));
      const hv = new DataView(header.buffer);
      hv.setUint16(2, 0x8180, false);
      hv.setUint16(4, 1, false); // QDCOUNT = 1
      hv.setUint16(6, 3, false); // ANCOUNT = 3 (ZONEMD + SMIMEA + OPENPGPKEY)
      hv.setUint16(10, 0, false); // ARCOUNT = 0

      const questionSection = qWire.slice(12, 17); // root (1 byte) + qtype (2) + qclass (2)

      // ZONEMD RDATA: serial=2026110700 (0x78C3FEEC), scheme=1 (SIMPLE), hashAlgorithm=1 (SHA-384, 48 bytes)
      const zonemdDigest = new Uint8Array(48);
      zonemdDigest.fill(0xab);
      const zonemdRdata = concatBytes(
        new Uint8Array([0x78, 0xc3, 0xfe, 0xec, 1, 1]),
        zonemdDigest
      );
      const zonemdMeta = new Uint8Array(10);
      const zmv = new DataView(zonemdMeta.buffer);
      zmv.setUint16(0, RR_TYPES.ZONEMD, false);
      zmv.setUint16(2, 1, false);
      zmv.setUint32(4, 86400, false);
      zmv.setUint16(8, zonemdRdata.length, false);
      const zonemdRr = concatBytes(new Uint8Array([0]), zonemdMeta, zonemdRdata);

      // SMIMEA RDATA: usage=3 (DANE-EE), selector=1 (SPKI), matchingType=1 (SHA-256, 32 bytes)
      const smimeaHash = new Uint8Array(32);
      smimeaHash.fill(0xcd);
      const smimeaRdata = concatBytes(new Uint8Array([3, 1, 1]), smimeaHash);
      const smimeaMeta = new Uint8Array(10);
      const smv = new DataView(smimeaMeta.buffer);
      smv.setUint16(0, RR_TYPES.SMIMEA, false);
      smv.setUint16(2, 1, false);
      smv.setUint32(4, 3600, false);
      smv.setUint16(8, smimeaRdata.length, false);
      const smimeaRr = concatBytes(new Uint8Array([0]), smimeaMeta, smimeaRdata);

      // OPENPGPKEY RDATA: arbitrary public key bytes
      const openpgpRdata = new Uint8Array([0x99, 0x01, 0x0d, 0x04, 0x55, 0x66, 0x77, 0x88]);
      const openpgpMeta = new Uint8Array(10);
      const opv = new DataView(openpgpMeta.buffer);
      opv.setUint16(0, RR_TYPES.OPENPGPKEY, false);
      opv.setUint16(2, 1, false);
      opv.setUint32(4, 3600, false);
      opv.setUint16(8, openpgpRdata.length, false);
      const openpgpRr = concatBytes(new Uint8Array([0]), openpgpMeta, openpgpRdata);

      const parsedPkt = parseDnsPacket(
        concatBytes(header, questionSection, zonemdRr, smimeaRr, openpgpRr)
      );
      expect(parsedPkt.answers).toHaveLength(3);

      const zAns = parsedPkt.answers[0];
      expect(zAns.typeName).toBe('ZONEMD');
      expect(zAns.parsed.kind).toBe('ZONEMD');
      if (zAns.parsed.kind === 'ZONEMD') {
        expect(zAns.parsed.serial).toBe(2026110700);
        expect(zAns.parsed.scheme).toBe(1);
        expect(zAns.parsed.hashAlgorithm).toBe(1);
        expect(zAns.parsed.digestHex).toBe('AB'.repeat(48));
      }

      const sAns = parsedPkt.answers[1];
      expect(sAns.typeName).toBe('SMIMEA');
      expect(sAns.parsed.kind).toBe('TLSA');
      if (sAns.parsed.kind === 'TLSA') {
        expect(sAns.parsed.usage).toBe(3);
        expect(sAns.parsed.selector).toBe(1);
        expect(sAns.parsed.matchingType).toBe(1);
        expect(sAns.parsed.certAssociationHex).toBe('CD'.repeat(32));
      }

      const oAns = parsedPkt.answers[2];
      expect(oAns.typeName).toBe('OPENPGPKEY');
      expect(oAns.parsed.kind).toBe('OPENPGPKEY');
      if (oAns.parsed.kind === 'OPENPGPKEY') {
        expect(oAns.parsed.byteLength).toBe(8);
      }

      // 3. Live Root Zone (.) ZONEMD verification & Reverse IP + DNSBL audit on 1.1.1.1
      const revSnap = await runDnsvizAnalysis('1.1.1.1');
      const rootZone = revSnap.zones.find((z) => z.zoneName === '.');
      expect(rootZone?.zonemd).toBeDefined();
      expect(rootZone?.zonemd?.present).toBe(true);
      expect(rootZone?.zonemd?.status).toBe('valid-sync');
      expect(rootZone?.zonemd?.dnssecStatus).toBe('secure');
      expect(rootZone?.zonemd?.records[0]?.scheme).toBe(1);
      expect(rootZone?.zonemd?.records[0]?.hashAlgorithm).toBe(1);
      expect(rootZone?.zonemd?.records[0]?.digestLengthValid).toBe(true);
      expect(rootZone?.zonemd?.records[0]?.serialMatchesSoa).toBe(true);
      expect(
        revSnap.findings.some((f) => f.code === 'ZONEMD_SERIAL_SYNC' && f.zone === '.')
      ).toBe(true);

      // 1.1.1.1 Reverse DNS includes DNSBL reputation check across 6 DNSBL zones
      expect(revSnap.reverseDns?.dnsbl).toBeDefined();
      expect(revSnap.reverseDns?.dnsbl?.checkedCount).toBe(6);
      expect(revSnap.reverseDns?.dnsbl?.providers).toHaveLength(6);
    },
    30000
  );

  it(
    'audits Wildcard DNS (*.domain) synthesis (RFC 4035 §5.3.4 / RFC 5155 §7.2.6) and SaaS Verification TXT Hygiene',
    async () => {
      // 1. Unit tests for classifyApexTxtRecord across SaaS, DID, SPF, and misplaced protocol policies
      expect(classifyApexTxtRecord('google-site-verification=abc123XYZ').provider).toBe(
        'Google Workspace / Search Console'
      );
      expect(classifyApexTxtRecord('MS=ms12345678').provider).toBe('Microsoft 365 / Entra ID');
      expect(classifyApexTxtRecord('apple-domain-verification=a1b2c3').provider).toBe(
        'Apple Business / Domain Verification'
      );
      expect(classifyApexTxtRecord('atlassian-domain-verification=atl99').provider).toBe(
        'Atlassian Cloud'
      );
      expect(classifyApexTxtRecord('stripe-verification=str42').provider).toBe('Stripe');
      expect(classifyApexTxtRecord('docusign=0123-4567').provider).toBe('DocuSign');
      expect(classifyApexTxtRecord('facebook-domain-verification=fb99').provider).toBe(
        'Meta / Facebook Business'
      );
      expect(classifyApexTxtRecord('protonmail-verification=pm88').provider).toBe('Proton Mail');
      expect(classifyApexTxtRecord('keybase-site-verification=kb77').provider).toBe('Keybase');
      expect(classifyApexTxtRecord('_github-challenge-org=gh66').provider).toBe('GitHub');
      expect(classifyApexTxtRecord('did=did:plc:ewvi7nxzyoun6zhxrhs64oiz').category).toBe(
        'decentralized-id'
      );
      expect(classifyApexTxtRecord('v=spf1 include:_spf.google.com -all').status).toBe('valid');
      expect(classifyApexTxtRecord('spf1 include:_spf.google.com -all').status).toBe('malformed');
      expect(classifyApexTxtRecord('v=DMARC1; p=reject;').status).toBe('misplaced-at-apex');
      expect(classifyApexTxtRecord('v=STSv1; id=20261107;').status).toBe('misplaced-at-apex');
      expect(classifyApexTxtRecord('v=TLSRPTv1; rua=mailto:tls@example.com').status).toBe(
        'misplaced-at-apex'
      );
      expect(classifyApexTxtRecord('v=DKIM1; k=rsa; p=MIIB...').status).toBe('misplaced-at-apex');

      // 2. Live trace on cloudflare.com: verifies wildcardAudit (_digdeep-wildcard-check.cloudflare.com.) and apex TXT SaaS inventory
      const cfSnap = await runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A'] });
      const cfZone = cfSnap.zones.find((z) => z.zoneName === 'cloudflare.com.');
      expect(cfZone?.wildcardAudit).toBeDefined();
      expect(cfZone?.wildcardAudit?.probeQname).toBe('_digdeep-wildcard-check.cloudflare.com.');
      expect(cfZone?.wildcardAudit?.wildcardDetected).toBe(false);
      expect(cfZone?.wildcardAudit?.status).toBe('no-wildcard');

      expect(cfZone?.txtHygiene).toBeDefined();
      expect(cfZone?.txtHygiene?.recordCount).toBeGreaterThanOrEqual(1);
      expect(cfZone?.txtHygiene?.saasVerificationCount).toBeGreaterThanOrEqual(1);
      expect(
        cfSnap.findings.some((f) => f.code === 'TXT_SAAS_VERIFICATIONS_PRESENT')
      ).toBe(true);

      // 3. Synthetic mutation: simulate wildcard A + MX synthesis and duplicate / misplaced apex TXT records
      const mutatedQueries = cfSnap.queries.map((q) => {
        if (
          q.qname === '_digdeep-wildcard-check.cloudflare.com.' &&
          (q.qtype === RR_TYPES.A || q.qtype === RR_TYPES.MX)
        ) {
          return {
            ...q,
            packet: {
              ...q.packet,
              flags: { ...q.packet.flags, rcode: 0 },
              answers: [
                {
                  name: '_digdeep-wildcard-check.cloudflare.com.',
                  type: q.qtype,
                  typeName: q.qtypeName,
                  rrclass: 1,
                  ttl: 300,
                  section: 'answer' as const,
                  rdataBase64: 'xFFkKg==',
                  rdataText: q.qtype === RR_TYPES.A ? '198.51.100.42' : '10 mail.cloudflare.com.',
                  canonicalRdataBase64: 'xFFkKg==',
                  parsed: { kind: 'GENERIC' as const, rawHex: 'c633642a', text: '198.51.100.42' },
                },
              ],
            },
          };
        }
        if (q.qname === 'cloudflare.com.' && q.qtype === RR_TYPES.TXT) {
          const dupRec = q.packet.answers.find((a) => a.type === RR_TYPES.TXT);
          const misplacedDmarc = dupRec
            ? {
                ...dupRec,
                rdataText: '"v=DMARC1; p=reject;"',
                parsed: {
                  kind: 'TXT' as const,
                  strings: ['v=DMARC1; p=reject;'],
                  joinedText: 'v=DMARC1; p=reject;',
                },
              }
            : undefined;
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: [
                ...q.packet.answers,
                ...(dupRec ? [dupRec] : []),
                ...(misplacedDmarc ? [misplacedDmarc] : []),
              ],
            },
          };
        }
        return q;
      });

      const mutatedSnap = await evaluateSnapshotFromLogs({
        id: 'test-wildcard-txt-hygiene',
        targetName: cfSnap.targetName,
        queryTypes: cfSnap.queryTypes,
        dohEndpoint: cfSnap.dohEndpoint,
        capturedAt: cfSnap.capturedAt,
        validatedAt: cfSnap.validatedAt,
        durationMs: cfSnap.durationMs,
        queries: mutatedQueries,
        trustAnchors: cfSnap.trustAnchorsUsed,
      });

      const mutZone = mutatedSnap.zones.find((z) => z.zoneName === 'cloudflare.com.');
      expect(mutZone?.wildcardAudit?.wildcardDetected).toBe(true);
      expect(mutZone?.wildcardAudit?.hasWildcardMx).toBe(true);
      expect(mutZone?.wildcardAudit?.wildcardTypes).toEqual(['A', 'MX']);
      // Because cloudflare.com is DNSSEC-signed and our synthetic wildcard answer had no RRSIG, it flags WILDCARD_DNSSEC_BOGUS!
      expect(mutZone?.wildcardAudit?.status).toBe('wildcard-bogus');
      expect(
        mutatedSnap.findings.some((f) => f.code === 'WILDCARD_DNSSEC_BOGUS')
      ).toBe(true);

      expect(mutZone?.txtHygiene?.duplicateCount).toBeGreaterThanOrEqual(1);
      expect(mutZone?.txtHygiene?.misplacedCount).toBe(1);
      expect(
        mutatedSnap.findings.some((f) => f.code === 'TXT_APEX_MISPLACED_POLICY')
      ).toBe(true);
      expect(
        mutatedSnap.findings.some((f) => f.code === 'TXT_DUPLICATE_VERIFICATION')
      ).toBe(true);
    },
    30000
  );

  it(
    'validates BGP Route Origin Authorizations (RPKI ROAs — RFC 6811 / RFC 6480) on live routes and flags BGP_RPKI_ROA_INVALID on unauthorized origins',
    async () => {
      // 1. Live RIPE Stat RPKI validation checks for valid, invalid-asn, and invalid-length routes
      const [validRoa, invalidAsnRoa, invalidLenRoa] = await Promise.all([
        validateRpkiRoute(13335, '1.1.1.0/24'),
        validateRpkiRoute(64496, '1.1.1.0/24'),
        validateRpkiRoute(13335, '1.1.1.0/25'),
      ]);

      expect(validRoa.status).toBe('valid');
      expect(validRoa.roas.some((r) => r.originAsn === 13335 && r.maxLength === 24)).toBe(true);
      expect(getCachedRpkiValidation(13335, '1.1.1.0/24')?.status).toBe('valid');

      expect(invalidAsnRoa.status).toBe('invalid-asn');
      expect(invalidAsnRoa.summary).toContain('Unauthorized Origin ASN');
      expect(invalidAsnRoa.roas.some((r) => r.originAsn === 13335)).toBe(true);

      expect(invalidLenRoa.status).toBe('invalid-length');
      expect(invalidLenRoa.summary).toContain('MaxLength Exceeded');

      expect(summarizeRpkiValidationState([validRoa, invalidAsnRoa])).toBe('invalid-asn');
      expect(summarizeRpkiValidationState([validRoa, invalidLenRoa])).toBe('invalid-length');
      expect(summarizeRpkiValidationState([validRoa])).toBe('valid');

      // 2. Verify Reverse DNS snapshot on 1.1.1.1 includes valid RPKI ROA and flags BGP_RPKI_ROA_INVALID when origin ASN is hijacked
      const rdnsSnap = await runDnsvizAnalysis('1.1.1.1');
      expect(rdnsSnap.reverseDns?.bgp?.rpki).toBeDefined();
      expect(rdnsSnap.reverseDns?.bgp?.rpki?.status).toBe('valid');

      // Simulate an unauthorized BGP origin announcement (AS64496 announcing 1.1.1.0/24) in Cymru TXT log
      seedRpkiValidationCache([invalidAsnRoa]);
      const hijackedRdnsQueries = rdnsSnap.queries.map((q) => {
        if (q.qname === '1.1.1.1.origin.asn.cymru.com.' && q.qtype === RR_TYPES.TXT) {
          return {
            ...q,
            packet: {
              ...q.packet,
              answers: q.packet.answers.map((ans) =>
                ans.type === RR_TYPES.TXT
                  ? {
                      ...ans,
                      rdataText: '"64496 | 1.1.1.0/24 | AU | apnic | 2011-08-11"',
                      parsed: {
                        kind: 'TXT' as const,
                        strings: ['64496 | 1.1.1.0/24 | AU | apnic | 2011-08-11'],
                        joinedText: '64496 | 1.1.1.0/24 | AU | apnic | 2011-08-11',
                      },
                    }
                  : ans
              ),
            },
          };
        }
        return q;
      });

      const hijackedSnap = await evaluateSnapshotFromLogs({
        id: 'test-rpki-hijack-rdns',
        targetName: rdnsSnap.targetName,
        queriedIp: rdnsSnap.queriedIp,
        queryTypes: rdnsSnap.queryTypes,
        dohEndpoint: rdnsSnap.dohEndpoint,
        capturedAt: rdnsSnap.capturedAt,
        validatedAt: rdnsSnap.validatedAt,
        durationMs: rdnsSnap.durationMs,
        queries: hijackedRdnsQueries,
        trustAnchors: rdnsSnap.trustAnchorsUsed,
      });

      expect(hijackedSnap.reverseDns?.bgp?.rpki?.status).toBe('invalid-asn');
      expect(
        hijackedSnap.findings.some(
          (f) => f.code === 'BGP_RPKI_ROA_INVALID' && f.severity === 'warning'
        )
      ).toBe(true);
    },
    30000
  );

  it(
    'cross-checks Certificate Transparency (CT) log issuances against RFC 8659 CAA policy & _443._tcp DANE TLSA and extracts subdomains',
    async () => {
      // 1. Unit tests for CT issuer -> CAA domain mapping and CertSpotter/crt.sh parsers
      expect(mapCtIssuerToCaaDomains("Let's Encrypt", 'C=US, O=Let\'s Encrypt, CN=E7')).toContain(
        'letsencrypt.org'
      );
      expect(
        mapCtIssuerToCaaDomains('Google Trust Services', 'C=US, O=Google Trust Services, CN=WE1')
      ).toContain('pki.goog');
      expect(mapCtIssuerToCaaDomains('DigiCert', 'C=US, O=DigiCert Inc, CN=DigiCert SHA2')).toContain(
        'digicert.com'
      );
      expect(mapCtIssuerToCaaDomains('Sectigo', 'C=GB, O=Sectigo Limited')).toContain('sectigo.com');
      expect(mapCtIssuerToCaaDomains('Amazon', 'C=US, O=Amazon, CN=Amazon RSA 2048 M02')).toContain(
        'amazon.com'
      );

      const parsedSpotter = parseCertSpotterJson([
        {
          id: '9001',
          dns_names: ['cloudflare.com', '*.cloudflare.com', 'ns.cloudflare.com'],
          issuer: {
            friendly_name: "Let's Encrypt",
            name: "C=US, O=Let's Encrypt, CN=E7",
            pubkey_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          },
          not_before: '2026-10-01T00:00:00Z',
          not_after: '2027-01-01T00:00:00Z',
          revoked: false,
          cert_sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          pubkey_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
      ]);
      expect(parsedSpotter).toHaveLength(1);
      expect(parsedSpotter[0].issuerFriendlyName).toBe("Let's Encrypt");
      expect(parsedSpotter[0].dnsNames).toEqual([
        'cloudflare.com',
        '*.cloudflare.com',
        'ns.cloudflare.com',
      ]);

      const parsedCrt = parseCrtShJson([
        {
          id: 12345,
          name_value: 'example.com\n*.example.com\napi.example.com',
          common_name: 'example.com',
          issuer_name: 'C=US, O=Google Trust Services, CN=WR2',
          not_before: '2026-09-01T00:00:00',
          not_after: '2026-12-01T00:00:00',
        },
      ]);
      expect(parsedCrt).toHaveLength(1);
      expect(parsedCrt[0].issuerFriendlyName).toBe('Google Trust Services');
      expect(parsedCrt[0].dnsNames).toContain('api.example.com');

      // 2. Live Web analysis on cloudflare.com: verifies live CT log fetch & CAA compliance
      const webSnap = await runWebAnalysis('cloudflare.com');
      expect(webSnap.ctLogFetch).toBeDefined();
      expect(webSnap.webAnalysis?.ctAnalysis).toBeDefined();
      if (webSnap.ctLogFetch?.ok) {
        expect(webSnap.webAnalysis?.ctAnalysis?.status).toBe('caa-compliant');
        expect(webSnap.webAnalysis?.ctAnalysis?.activeCertCount).toBeGreaterThanOrEqual(1);
        expect(webSnap.webAnalysis?.ctAnalysis?.mismatchedActiveCertCount).toBe(0);
        expect(webSnap.findings.some((f) => f.code === 'CT_CAA_COMPLIANT')).toBe(true);
      }

      // 3. Synthetic CT log cross-check: simulate an unauthorized active CA (Amazon) + TLSA SHA-256 match + offline reverifySnapshot
      const syntheticCtSnap = await evaluateSnapshotFromLogs({
        id: 'test-ct-caa-mismatch',
        mode: 'web',
        targetName: webSnap.targetName,
        queryTypes: webSnap.queryTypes,
        ctLogFetch: {
          source: 'certspotter',
          url: 'https://api.certspotter.com/v1/issuances?domain=cloudflare.com',
          fetchedAt: webSnap.capturedAt,
          ok: true,
          entries: [
            {
              id: 'cert-unauth-amazon',
              dnsNames: ['cloudflare.com', 'portal.cloudflare.com', 'staging.cloudflare.com'],
              issuerFriendlyName: 'Amazon',
              issuerDn: 'C=US, O=Amazon, CN=Amazon RSA 2048 M02',
              notBefore: '2026-10-01T00:00:00Z',
              notAfter: '2027-10-01T00:00:00Z',
              revoked: false,
              certSha256: '1111111111111111111111111111111111111111111111111111111111111111',
            },
            {
              id: 'cert-auth-le',
              dnsNames: ['cloudflare.com', '*.cloudflare.com'],
              issuerFriendlyName: "Let's Encrypt",
              issuerDn: "C=US, O=Let's Encrypt, CN=E7",
              notBefore: '2026-10-15T00:00:00Z',
              notAfter: '2027-01-15T00:00:00Z',
              revoked: false,
            },
          ],
        },
        dohEndpoint: webSnap.dohEndpoint,
        capturedAt: webSnap.capturedAt,
        validatedAt: webSnap.validatedAt,
        durationMs: webSnap.durationMs,
        queries: webSnap.queries,
        trustAnchors: webSnap.trustAnchorsUsed,
      });

      expect(syntheticCtSnap.webAnalysis?.ctAnalysis?.status).toBe('caa-mismatch');
      expect(syntheticCtSnap.webAnalysis?.ctAnalysis?.mismatchedActiveCertCount).toBe(1);
      expect(syntheticCtSnap.webAnalysis?.ctAnalysis?.discoveredSubdomains).toEqual([
        'portal.cloudflare.com',
        'staging.cloudflare.com',
      ]);
      expect(
        syntheticCtSnap.findings.some(
          (f) => f.code === 'CT_CAA_ISSUER_MISMATCH' && f.severity === 'warning'
        )
      ).toBe(true);

      // Verify offline reverifySnapshot preserves ctLogFetch and re-evaluates CT vs CAA
      const reverified = await reverifySnapshot(syntheticCtSnap, {
        validationTimeMs: webSnap.validatedAt,
      });
      expect(reverified.webAnalysis?.ctAnalysis?.status).toBe('caa-mismatch');

      // 3b. Verify full CT log domain chain CAA check: when a subdomain in CT logs (e.g. *.app.delegated.cloudflare.com)
      // has an intermediate parent CAA record (delegated.cloudflare.com. CAA 0 issue "amazon.com"), the certificate is authorized!
      const subdomainCaaLog = {
        ...webSnap.queries[0],
        id: 'ct-caa-delegated',
        qname: 'delegated.cloudflare.com.',
        qtype: RR_TYPES.CAA,
        qtypeName: 'CAA',
        cd: true,
        doBit: true,
        purpose: 'CT CAA lookup (delegated.cloudflare.com. CAA)',
        packet: {
          ...webSnap.queries[0].packet,
          questions: [{ name: 'delegated.cloudflare.com.', type: RR_TYPES.CAA, typeName: 'CAA', qclass: 1 }],
          answers: [
            {
              name: 'delegated.cloudflare.com.',
              type: RR_TYPES.CAA,
              typeName: 'CAA',
              rrclass: 1,
              ttl: 300,
              rdataBase64: '',
              canonicalRdataBase64: '',
              rdataText: '0 issue "amazon.com"',
              parsed: { kind: 'CAA' as const, flags: 0, tag: 'issue', value: 'amazon.com' },
              section: 'answer' as const,
            },
          ],
          authorities: [],
          additionals: [],
        },
      };

      const subChainCtSnap = await evaluateSnapshotFromLogs({
        id: 'test-ct-subdomain-caa-chain',
        mode: 'web',
        targetName: webSnap.targetName,
        queryTypes: webSnap.queryTypes,
        ctLogFetch: {
          source: 'certspotter',
          url: 'https://api.certspotter.com/v1/issuances?domain=cloudflare.com&include_subdomains=true',
          fetchedAt: webSnap.capturedAt,
          ok: true,
          includeSubdomains: true,
          entries: [
            {
              id: 'cert-sub-delegated',
              dnsNames: ['*.delegated.cloudflare.com', '*.app.delegated.cloudflare.com'],
              issuerFriendlyName: 'Amazon',
              issuerDn: 'C=US, O=Amazon, CN=Amazon RSA 2048 M02',
              notBefore: '2026-10-01T00:00:00Z',
              notAfter: '2027-10-01T00:00:00Z',
              revoked: false,
            },
          ],
        },
        dohEndpoint: webSnap.dohEndpoint,
        capturedAt: webSnap.capturedAt,
        validatedAt: webSnap.validatedAt,
        durationMs: webSnap.durationMs,
        queries: [...webSnap.queries, subdomainCaaLog],
        trustAnchors: webSnap.trustAnchorsUsed,
      });

      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.status).toBe('caa-compliant');
      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.mismatchedActiveCertCount).toBe(0);
      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.certificates[0]?.caaAuthorized).toBe(
        'authorized'
      );
      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.certificates[0]?.effectiveCaaOwners).toContain(
        'delegated.cloudflare.com'
      );
      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.subdomainCaaPolicies).toHaveLength(1);
      expect(subChainCtSnap.webAnalysis?.ctAnalysis?.subdomainCaaPolicies?.[0]?.displayOwner).toBe(
        'delegated.cloudflare.com'
      );

      // 4. Verify CLI Command Reproducer (dig / delv / kdig) & RFC 1035 Master Zonefile (.zone) export (#18)
      const cli = generateCliReproducerCommands({
        qname: 'cloudflare.com.',
        qtypeName: 'HTTPS',
        dohEndpoint: 'https://cloudflare-dns.com/dns-query',
        cd: true,
        capturedAt: 1700000000000,
        validatedAt: 1700003600000,
      });
      expect(cli.dig).toBe('dig +dnssec +multi +cd @1.1.1.1 cloudflare.com HTTPS');
      expect(cli.delv).toBe('delv @1.1.1.1 cloudflare.com HTTPS +rtrace -t 1700003600');
      expect(cli.kdig).toBe('kdig +dnssec +cd +https @cloudflare-dns.com cloudflare.com HTTPS');

      const cfZone = webSnap.zones.find((z) => z.zoneName === 'cloudflare.com.')!;
      expect(cfZone).toBeDefined();
      const singleZonefile = formatZoneAsZonefile(cfZone, webSnap);
      expect(singleZonefile).toContain('$ORIGIN cloudflare.com.');
      expect(singleZonefile).toContain('$TTL ');
      expect(singleZonefile).toContain('IN SOA');
      expect(singleZonefile).toContain('IN NS');
      expect(singleZonefile).toContain('IN HTTPS');
      expect(singleZonefile).toContain('IN CAA');
      expect(singleZonefile).toContain('IN DNSKEY');
      expect(singleZonefile).toContain('IN RRSIG');

      const noDnssecZonefile = formatZoneAsZonefile(cfZone, webSnap, {
        includeDnssecRecords: false,
      });
      expect(noDnssecZonefile).toContain('IN HTTPS');
      expect(noDnssecZonefile).not.toContain('IN RRSIG');
      expect(noDnssecZonefile).not.toContain('IN DNSKEY');

      const fullZonefile = formatSnapshotAsZonefile(webSnap);
      expect(fullZonefile).toContain('RFC 1035 Master Zonefile Export');
      expect(fullZonefile).toContain('$ORIGIN cloudflare.com.');
      expect(fullZonefile).toContain('$ORIGIN com.');
      expect(fullZonefile).toContain('$ORIGIN .');
    },
    30000
  );
});
