import { describe, expect, it } from 'vitest';
import { reverifySnapshot, runDnsvizAnalysis } from '../analyzer';
import { IANA_ROOT_TRUST_ANCHORS, normalizeDohEndpoint, RR_TYPES } from '../constants';
import { computeDsDigest, computeNsec3Hash } from '../crypto';
import {
  base64ToBytes,
  compareCanonicalDnsNames,
  computeKeyTag,
  concatBytes,
  normalizeFqdn,
} from '../encoding';
import { buildDnsQuery, decodeDnsName, encodeDnsName, parseDnsPacket } from '../wire';

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
});
