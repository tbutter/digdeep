import { describe, expect, it } from 'vitest';
import { evaluateSnapshotFromLogs, reverifySnapshot, runDnsvizAnalysis } from '../analyzer';
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
  base64ToBytes,
  compareCanonicalDnsNames,
  computeKeyTag,
  concatBytes,
  normalizeFqdn,
} from '../encoding';
import {
  classifyDnsblReturnIp,
  ipToCymruOriginQname,
  ipToDnsblQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseReverseIpInput,
  reverseArpaToIp,
} from '../ipUtils';
import { buildDnsQuery, decodeDnsName, encodeDnsName, parseDnsPacket } from '../wire';
import { parseCaaRecordEntry, runWebAnalysis } from '../webAnalyzer';

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
});
