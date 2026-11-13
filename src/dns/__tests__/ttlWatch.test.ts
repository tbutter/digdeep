import { describe, expect, it, vi } from 'vitest';
import { diffSnapshots } from '../../storage/historyStore';
import { CONSENSUS_DOH_RESOLVERS, RR_TYPES } from '../constants';
import {
  MIN_EXPIRY_POLL_COOLDOWN_MS,
  buildWatchTickSample,
  classifyResolverTtlBehavior,
  computeLiveTtlCountdown,
  computeNextWatchDelayMs,
  createTtlWatchController,
  detectWatchTransitions,
  extractResolverWatchObservation,
  runWatchPulseTick,
  seedWatchSampleFromSnapshot,
  type WatchPulseResult,
  type WatchTickSample,
} from '../ttlWatch';
import type { AnalysisSnapshot, DnsRecord, DohQueryLog, EdeEntry } from '../types';
import { computeWireQueryCategoryCounts } from '../wireQueryFilter';

const CF_PRESET = CONSENSUS_DOH_RESOLVERS.find((r) => r.url === 'https://1.1.1.1/dns-query')!;
const GOOGLE_PRESET = CONSENSUS_DOH_RESOLVERS.find((r) => r.url === 'https://8.8.8.8/dns-query')!;
const QUAD9_PRESET = CONSENSUS_DOH_RESOLVERS.find((r) => r.url === 'https://9.9.9.9/dns-query')!;

function makeARecord(name: string, ip: string, ttl: number): DnsRecord {
  return {
    name,
    type: RR_TYPES.A,
    typeName: 'A',
    rrclass: 1,
    ttl,
    rdataBase64: 'AAECAw==',
    canonicalRdataBase64: 'AAECAw==',
    rdataText: ip,
    parsed: { kind: 'GENERIC' },
    section: 'answer',
  };
}

function makeRrsigRecord(params: {
  name: string;
  typeCovered: number;
  typeCoveredName: string;
  ttl: number;
  originalTtl: number;
  keyTag: number;
  signerName: string;
  inception: number;
  expiration: number;
  section?: 'answer' | 'authority';
}): DnsRecord {
  return {
    name: params.name,
    type: RR_TYPES.RRSIG,
    typeName: 'RRSIG',
    rrclass: 1,
    ttl: params.ttl,
    rdataBase64: 'AA==',
    canonicalRdataBase64: 'AA==',
    rdataText: `${params.typeCoveredName} 13 2 ${params.originalTtl} ${params.expiration} ${params.inception} ${params.keyTag} ${params.signerName} sig==`,
    parsed: {
      kind: 'RRSIG',
      typeCovered: params.typeCovered,
      typeCoveredName: params.typeCoveredName,
      algorithm: 13,
      labels: 2,
      originalTtl: params.originalTtl,
      expiration: params.expiration,
      inception: params.inception,
      keyTag: params.keyTag,
      signerName: params.signerName,
      signatureBase64: 'c2ln',
      signedHeaderBase64: 'aGRy',
    },
    section: params.section ?? 'answer',
  };
}

function makeSoaRecord(
  zone: string,
  serial: number,
  ttl: number,
  minimum: number,
  section: 'answer' | 'authority' = 'answer'
): DnsRecord {
  return {
    name: zone,
    type: RR_TYPES.SOA,
    typeName: 'SOA',
    rrclass: 1,
    ttl,
    rdataBase64: 'AA==',
    canonicalRdataBase64: 'AA==',
    rdataText: `ns1.${zone} hostmaster.${zone} ${serial} 3600 600 604800 ${minimum}`,
    parsed: {
      kind: 'SOA',
      mname: `ns1.${zone}`,
      rname: `hostmaster.${zone}`,
      serial,
      refresh: 3600,
      retry: 600,
      expire: 604800,
      minimum,
    },
    section,
  };
}

function makeDnskeyRecord(zone: string, keyTag: number, flags = 257): DnsRecord {
  return {
    name: zone,
    type: RR_TYPES.DNSKEY,
    typeName: 'DNSKEY',
    rrclass: 1,
    ttl: 3600,
    rdataBase64: 'AA==',
    canonicalRdataBase64: 'AA==',
    rdataText: `${flags} 3 13 key==`,
    parsed: {
      kind: 'DNSKEY',
      flags,
      protocol: 3,
      algorithm: 13,
      publicKeyBase64: 'a2V5',
      publicKeyHex: '6b6579',
      keyTag,
      isZoneKey: true,
      isSep: flags === 257,
      isRevoked: false,
      keySizeInfo: '256-bit ECDSA',
    },
    section: 'answer',
  };
}

function makeWatchLog(params: {
  id: string;
  endpoint: string;
  qname: string;
  qtype: number;
  qtypeName: string;
  startedAt: number;
  rcode?: number;
  ad?: boolean;
  cd?: boolean;
  answers?: DnsRecord[];
  authorities?: DnsRecord[];
  ede?: EdeEntry[];
  purpose?: string;
}): DohQueryLog {
  const rcode = params.rcode ?? 0;
  return {
    id: params.id,
    qname: params.qname,
    qtype: params.qtype,
    qtypeName: params.qtypeName,
    cd: params.cd ?? false,
    doBit: true,
    endpoint: params.endpoint,
    startedAt: params.startedAt,
    latencyMs: 18,
    httpStatus: 200,
    wireBase64: 'AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=',
    requestWireBase64: 'AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=',
    purpose: params.purpose ?? `Watch probe (${params.qtypeName})`,
    packet: {
      id: 1,
      flags: {
        qr: true,
        opcode: 0,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        z: 0,
        ad: params.ad ?? true,
        cd: params.cd ?? false,
        rcode,
      },
      questions: [{ name: params.qname, type: params.qtype, typeName: params.qtypeName, qclass: 1 }],
      answers: params.answers ?? [],
      authorities: params.authorities ?? [],
      additionals: [],
      edns: {
        udpPayloadSize: 1232,
        extendedRcode: 0,
        version: 0,
        doBit: true,
        flags: 0x8000,
        ede: params.ede ?? [],
      },
      wireSize: 96,
    },
  };
}

function buildSyntheticResolverLogs(params: {
  tick: number;
  endpoint: string;
  shortLabel: string;
  capturedAtMs: number;
  ips?: string[];
  ttl?: number;
  originalTtl?: number;
  soaSerial?: number;
  dnskeyTags?: number[];
  rrsigInception?: number;
  rrsigExpiration?: number;
  rcode?: number;
  ede?: EdeEntry[];
}): DohQueryLog[] {
  const target = 'example.com.';
  const ips = params.ips ?? ['198.51.100.10'];
  const ttl = params.ttl ?? 120;
  const origTtl = params.originalTtl ?? 300;
  const serial = params.soaSerial ?? 2026111301;
  const keyTags = params.dnskeyTags ?? [34505];
  const inc = params.rrsigInception ?? 1_780_000_000;
  const exp = params.rrsigExpiration ?? 1_810_000_000;

  const answers: DnsRecord[] =
    (params.rcode ?? 0) === 0
      ? [
          ...ips.map((ip) => makeARecord(target, ip, ttl)),
          makeRrsigRecord({
            name: target,
            typeCovered: RR_TYPES.A,
            typeCoveredName: 'A',
            ttl,
            originalTtl: origTtl,
            keyTag: keyTags[0]!,
            signerName: target,
            inception: inc,
            expiration: exp,
          }),
        ]
      : [];

  return [
    makeWatchLog({
      id: `q-${params.shortLabel}-${params.tick}-A`,
      endpoint: params.endpoint,
      qname: target,
      qtype: RR_TYPES.A,
      qtypeName: 'A',
      startedAt: params.capturedAtMs,
      rcode: params.rcode ?? 0,
      answers,
      ede: params.ede,
      purpose: `Watch probe (${params.shortLabel} A)`,
    }),
    makeWatchLog({
      id: `q-${params.shortLabel}-${params.tick}-SOA`,
      endpoint: params.endpoint,
      qname: target,
      qtype: RR_TYPES.SOA,
      qtypeName: 'SOA',
      startedAt: params.capturedAtMs,
      cd: true,
      answers: [makeSoaRecord(target, serial, 3600, 300)],
      purpose: `Watch probe (${params.shortLabel} SOA)`,
    }),
    makeWatchLog({
      id: `q-${params.shortLabel}-${params.tick}-DNSKEY`,
      endpoint: params.endpoint,
      qname: target,
      qtype: RR_TYPES.DNSKEY,
      qtypeName: 'DNSKEY',
      startedAt: params.capturedAtMs,
      cd: true,
      answers: keyTags.map((kt) => makeDnskeyRecord(target, kt)),
      purpose: `Watch probe (${params.shortLabel} DNSKEY)`,
    }),
  ];
}

describe('Live TTL Countdown, Cache-Decay & RFC 8767 Serve-Stale Watch (#32)', () => {
  it('computes real-time live TTL countdowns and seeds zero-network samples from existing snapshots', () => {
    const t0 = 1_790_000_000_000;
    const logs = buildSyntheticResolverLogs({
      tick: 0,
      endpoint: CF_PRESET.url,
      shortLabel: CF_PRESET.shortLabel,
      capturedAtMs: t0,
      ttl: 180,
      originalTtl: 300,
    });

    const mockSnapshot: AnalysisSnapshot = {
      id: 'snap-seed-1',
      version: 3,
      mode: 'dnssec',
      targetName: 'example.com.',
      displayDomain: 'example.com',
      queryTypes: ['A'],
      dohEndpoint: CF_PRESET.url,
      capturedAt: t0,
      validatedAt: t0,
      durationMs: 95,
      overallStatus: 'secure',
      overallSummary: 'Secure',
      zones: [
        {
          zoneName: 'example.com.',
          parentZone: 'com.',
          depth: 2,
          status: 'secure',
          statusReason: 'OK',
          nsecMode: 'NSEC',
          dnskeys: [],
          dsVerifications: [],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [],
        },
      ],
      cnameEdges: [],
      findings: [],
      queries: logs,
      trustAnchorsUsed: [],
    };

    const seeded = seedWatchSampleFromSnapshot(mockSnapshot, 'A');
    expect(seeded).not.toBeNull();
    expect(seeded!.tickNumber).toBe(0);
    expect(seeded!.resolvers).toHaveLength(1);
    const obs = seeded!.resolvers[0]!;
    expect(obs.observedTtl).toBe(180);
    expect(obs.authoritativeOriginalTtl).toBe(300);
    expect(obs.estimatedCacheAgeSec).toBe(120);
    expect(obs.ttlBehavior).toBe('normal');

    // 60s later -> 120s remaining out of 300s ceiling (40%)
    const cd60 = computeLiveTtlCountdown(obs, t0 + 60_000);
    expect(cd60.remainingSec).toBe(120);
    expect(cd60.elapsedSec).toBe(60);
    expect(cd60.percentRemaining).toBeCloseTo(40, 1);
    expect(cd60.isExpiringSoon).toBe(false);
    expect(cd60.isExpiredLocally).toBe(false);

    // 175s later -> 5s remaining (isExpiringSoon = true)
    const cd175 = computeLiveTtlCountdown(obs, t0 + 175_000);
    expect(cd175.remainingSec).toBe(5);
    expect(cd175.isExpiringSoon).toBe(true);
    expect(cd175.isExpiredLocally).toBe(false);

    // 185s later -> locally expired at 0s
    const cd185 = computeLiveTtlCountdown(obs, t0 + 185_000);
    expect(cd185.remainingSec).toBe(0);
    expect(cd185.percentRemaining).toBe(0);
    expect(cd185.isExpiredLocally).toBe(true);
  });

  it('accurately classifies RFC 8767 Serve-Stale, intentional TTL=0 GSLB, min-TTL floor clamping, and max-TTL ceiling clamping', () => {
    const t0 = 1_790_000_000_000;

    // 1. RFC 8914 EDE 3 (Stale Answer) -> serve-stale-ede
    const edeStaleLogs = buildSyntheticResolverLogs({
      tick: 1,
      endpoint: CF_PRESET.url,
      shortLabel: CF_PRESET.shortLabel,
      capturedAtMs: t0,
      ttl: 30,
      originalTtl: 300,
      ede: [{ infoCode: 3, name: 'Stale Answer', extraText: 'Upstream authoritative timeout' }],
    });
    const rawEdeStale = extractResolverWatchObservation({
      preset: CF_PRESET,
      targetName: 'example.com.',
      qtype: RR_TYPES.A,
      soaZone: 'example.com.',
      logs: edeStaleLogs,
      capturedAtMs: t0,
    });
    const classifiedEdeStale = classifyResolverTtlBehavior({
      rawObs: rawEdeStale,
      peerAuthoritativeTtl: 300,
      peerMaxObservedTtl: 290,
    });
    expect(classifiedEdeStale.ttlBehavior).toBe('serve-stale-ede');
    expect(classifiedEdeStale.ttlBehaviorDetail).toContain('EDE 3');

    // 2. RFC 8914 EDE 19 (Stale NXDOMAIN Answer) -> serve-stale-ede
    const ede19Logs = [
      makeWatchLog({
        id: 'q-ede19',
        endpoint: QUAD9_PRESET.url,
        qname: 'gone.example.com.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        startedAt: t0,
        rcode: 3,
        authorities: [makeSoaRecord('example.com.', 2026111301, 0, 300, 'authority')],
        ede: [{ infoCode: 19, name: 'Stale NXDOMAIN Answer', extraText: '' }],
      }),
    ];
    const rawEde19 = extractResolverWatchObservation({
      preset: QUAD9_PRESET,
      targetName: 'gone.example.com.',
      qtype: RR_TYPES.A,
      soaZone: 'example.com.',
      logs: ede19Logs,
      capturedAtMs: t0,
    });
    const classifiedEde19 = classifyResolverTtlBehavior({
      rawObs: rawEde19,
      peerAuthoritativeTtl: 300,
      peerMaxObservedTtl: 300,
    });
    expect(classifiedEde19.ttlBehavior).toBe('serve-stale-ede');
    expect(classifiedEde19.ttlBehaviorDetail).toContain('EDE 19');

    // 3. TTL=0 when authoritative RRSIG originalTTL > 0 -> serve-stale-zero-ttl
    const zeroStaleLogs = buildSyntheticResolverLogs({
      tick: 1,
      endpoint: GOOGLE_PRESET.url,
      shortLabel: GOOGLE_PRESET.shortLabel,
      capturedAtMs: t0,
      ttl: 0,
      originalTtl: 300,
    });
    const classifiedZeroStale = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: GOOGLE_PRESET,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: zeroStaleLogs,
        capturedAtMs: t0,
      }),
      peerAuthoritativeTtl: 300,
      peerMaxObservedTtl: 240,
    });
    expect(classifiedZeroStale.ttlBehavior).toBe('serve-stale-zero-ttl');

    // 4. Intentional authoritative originalTTL=0 -> zero-ttl-uncacheable (NOT misflagged as stale!)
    const intentionalZeroLogs = buildSyntheticResolverLogs({
      tick: 1,
      endpoint: CF_PRESET.url,
      shortLabel: CF_PRESET.shortLabel,
      capturedAtMs: t0,
      ttl: 0,
      originalTtl: 0,
    });
    const classifiedIntentionalZero = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: CF_PRESET,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: intentionalZeroLogs,
        capturedAtMs: t0,
      }),
      peerAuthoritativeTtl: 0,
      peerMaxObservedTtl: 0,
    });
    expect(classifiedIntentionalZero.ttlBehavior).toBe('zero-ttl-uncacheable');

    // 5. Min-TTL Floor Clamping: observed TTL (60s) > RRSIG originalTTL (20s)
    const minClampLogs = buildSyntheticResolverLogs({
      tick: 1,
      endpoint: QUAD9_PRESET.url,
      shortLabel: QUAD9_PRESET.shortLabel,
      capturedAtMs: t0,
      ttl: 60,
      originalTtl: 20,
    });
    const classifiedMinClamp = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: QUAD9_PRESET,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: minClampLogs,
        capturedAtMs: t0,
      }),
      peerAuthoritativeTtl: 20,
      peerMaxObservedTtl: 20,
    });
    expect(classifiedMinClamp.ttlBehavior).toBe('min-ttl-clamped');
    expect(classifiedMinClamp.ttlBehaviorDetail).toContain('60s > RRSIG originalTTL (20s)');

    // 6. Negative SOA Min-TTL Clamping per RFC 2308 §5: SOA TTL (600s) > SOA.minimum (120s)
    const negClampLogs = [
      makeWatchLog({
        id: 'q-neg-clamp',
        endpoint: QUAD9_PRESET.url,
        qname: 'nx.example.com.',
        qtype: RR_TYPES.A,
        qtypeName: 'A',
        startedAt: t0,
        rcode: 3,
        authorities: [
          makeSoaRecord('example.com.', 2026111301, 600, 120, 'authority'),
          makeRrsigRecord({
            name: 'example.com.',
            typeCovered: RR_TYPES.SOA,
            typeCoveredName: 'SOA',
            ttl: 600,
            originalTtl: 3600,
            keyTag: 34505,
            signerName: 'example.com.',
            inception: 1_780_000_000,
            expiration: 1_810_000_000,
            section: 'authority',
          }),
        ],
      }),
    ];
    const classifiedNegClamp = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: QUAD9_PRESET,
        targetName: 'nx.example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: negClampLogs,
        capturedAtMs: t0,
      }),
      peerAuthoritativeTtl: 120,
      peerMaxObservedTtl: 120,
    });
    expect(classifiedNegClamp.ttlBehavior).toBe('min-ttl-clamped');
    expect(classifiedNegClamp.ttlBehaviorDetail).toContain('RFC 2308 negative SOA ceiling (120s)');

    // 7. Max-TTL Ceiling Clamping: mid-decay Tick #1 is NOT falsely flagged, but fresh reload resetting to 3600s < 86400s IS flagged!
    const tick1MidDecay = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: GOOGLE_PRESET,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: buildSyntheticResolverLogs({
          tick: 1,
          endpoint: GOOGLE_PRESET.url,
          shortLabel: GOOGLE_PRESET.shortLabel,
          capturedAtMs: t0,
          ttl: 4,
          originalTtl: 86400,
        }),
        capturedAtMs: t0,
      }),
      peerAuthoritativeTtl: 86400,
      peerMaxObservedTtl: 86350,
    });
    expect(tick1MidDecay.ttlBehavior).toBe('normal');

    const t1 = t0 + 5_000;
    const tick2FreshClamped = classifyResolverTtlBehavior({
      rawObs: extractResolverWatchObservation({
        preset: GOOGLE_PRESET,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        logs: buildSyntheticResolverLogs({
          tick: 2,
          endpoint: GOOGLE_PRESET.url,
          shortLabel: GOOGLE_PRESET.shortLabel,
          capturedAtMs: t1,
          ttl: 3600,
          originalTtl: 86400,
        }),
        capturedAtMs: t1,
      }),
      previousObs: tick1MidDecay,
      peerAuthoritativeTtl: 86400,
      peerMaxObservedTtl: 86345,
    });
    expect(tick2FreshClamped.didRefreshCache).toBe(true);
    expect(tick2FreshClamped.ttlBehavior).toBe('max-ttl-clamped');
    expect(tick2FreshClamped.clampedMaxTtl).toBe(3600);
  });

  it('suppresses pure TTL decay ticks and records GSLB IP rotation, SOA serial bumps, DNSKEY rollovers, RRSIG re-signing, and RCODE/EDE transitions', () => {
    const presets = [CF_PRESET, GOOGLE_PRESET];
    const t0 = 1_790_000_000_000;

    const makeSample = (
      tick: number,
      atMs: number,
      prev: WatchTickSample | null,
      cfOpts: Partial<Parameters<typeof buildSyntheticResolverLogs>[0]>,
      ggOpts: Partial<Parameters<typeof buildSyntheticResolverLogs>[0]>
    ) => {
      const queries = [
        ...buildSyntheticResolverLogs({
          tick,
          endpoint: CF_PRESET.url,
          shortLabel: CF_PRESET.shortLabel,
          capturedAtMs: atMs,
          ...cfOpts,
        }),
        ...buildSyntheticResolverLogs({
          tick,
          endpoint: GOOGLE_PRESET.url,
          shortLabel: GOOGLE_PRESET.shortLabel,
          capturedAtMs: atMs,
          ...ggOpts,
        }),
      ];
      return buildWatchTickSample({
        tickNumber: tick,
        capturedAtMs: atMs,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        presets,
        queries,
        previousSample: prev,
      });
    };

    const s1 = makeSample(1, t0, null, { ttl: 120 }, { ttl: 250 });
    // Tick #2: pure TTL decay (105s / 235s) + cache refresh back to 300s with identical answers/SOA/RRSIG -> NO transition!
    const s2 = makeSample(2, t0 + 15_000, s1, { ttl: 300 }, { ttl: 235 });
    expect(detectWatchTransitions(s1, s2)).toBeNull();

    // Tick #3: Weighted GSLB IP rotation on 1.1.1.1 (same SOA serial)
    const s3 = makeSample(
      3,
      t0 + 30_000,
      s2,
      { ips: ['198.51.100.99'], ttl: 60 },
      { ttl: 220 }
    );
    const trGslb = detectWatchTransitions(s2, s3);
    expect(trGslb).not.toBeNull();
    expect(trGslb!.categories).toEqual(['answer-ip-change']);
    expect(trGslb!.diffs[0]!.subKind).toBe('gslb-rotation');
    expect(trGslb!.headline).toContain('GSLB IP pool rotated');

    // Tick #4: Zone update (SOA serial increment + new IP on 8.8.8.8)
    const s4 = makeSample(
      4,
      t0 + 45_000,
      s3,
      { ips: ['198.51.100.99'], ttl: 45 },
      { ips: ['203.0.113.50'], soaSerial: 2026111302, ttl: 300 }
    );
    const trZone = detectWatchTransitions(s3, s4);
    expect(trZone).not.toBeNull();
    expect(trZone!.categories).toContain('soa-serial-change');
    expect(trZone!.categories).toContain('answer-ip-change');
    expect(
      trZone!.diffs.find((d) => d.category === 'answer-ip-change')?.subKind
    ).toBe('zone-update');

    // Tick #5: DNSKEY rollover (#34505 -> #34505, #61234) + online RRSIG re-sign
    const s5 = makeSample(
      5,
      t0 + 60_000,
      s4,
      {
        ips: ['198.51.100.99'],
        ttl: 300,
        dnskeyTags: [34505, 61234],
        rrsigInception: 1_790_000_000,
        rrsigExpiration: 1_820_000_000,
      },
      { ips: ['203.0.113.50'], soaSerial: 2026111302, ttl: 285 }
    );
    const trCrypto = detectWatchTransitions(s4, s5);
    expect(trCrypto).not.toBeNull();
    expect(trCrypto!.categories).toContain('dnskey-keytag-change');
    expect(trCrypto!.categories).toContain('rrsig-resign');

    // Tick #6: Upstream outage -> EDE 3 Stale Answer on 1.1.1.1
    const s6 = makeSample(
      6,
      t0 + 75_000,
      s5,
      {
        ips: ['198.51.100.99'],
        ttl: 0,
        dnskeyTags: [34505, 61234],
        rrsigInception: 1_790_000_000,
        rrsigExpiration: 1_820_000_000,
        ede: [{ infoCode: 3, name: 'Stale Answer', extraText: 'Auth unreachable' }],
      },
      { ips: ['203.0.113.50'], soaSerial: 2026111302, ttl: 270 }
    );
    const trStale = detectWatchTransitions(s5, s6);
    expect(trStale).not.toBeNull();
    expect(trStale!.categories).toContain('rcode-ede-change');
    expect(trStale!.headline).toContain('Serve-Stale');
  });

  it('drives expiry-once single re-query at TTL=0, enforces cooldown floor, auto-pauses on hidden tab, and halts at maxIterations cap', async () => {
    vi.useFakeTimers();
    try {
      let fakeNow = 1_790_000_000_000;
      vi.setSystemTime(fakeNow);

      let probeCount = 0;
      const stubProbe = async (opts: {
        tickNumber?: number;
        previousSample?: WatchTickSample | null;
      }): Promise<WatchPulseResult> => {
        probeCount++;
        const tick = opts.tickNumber ?? probeCount;
        const now = Date.now();
        // Tick 1 has shortest TTL = 12s; Tick 2 rotates IP and refreshes TTL to 300s
        const ip = tick >= 2 ? '198.51.100.42' : '198.51.100.10';
        const ttl = tick === 1 ? 12 : 300;
        const queries = buildSyntheticResolverLogs({
          tick,
          endpoint: CF_PRESET.url,
          shortLabel: CF_PRESET.shortLabel,
          capturedAtMs: now,
          ips: [ip],
          ttl,
        });
        const sample = buildWatchTickSample({
          tickNumber: tick,
          capturedAtMs: now,
          targetName: 'example.com.',
          qtype: RR_TYPES.A,
          soaZone: 'example.com.',
          presets: [CF_PRESET],
          queries,
          previousSample: opts.previousSample,
        });
        const snap: AnalysisSnapshot = {
          id: `watch-snap-${tick}`,
          version: 3,
          mode: 'consensus',
          targetName: 'example.com.',
          displayDomain: 'example.com',
          queryTypes: ['A', 'SOA', 'DNSKEY'],
          dohEndpoint: CF_PRESET.url,
          capturedAt: now,
          validatedAt: now,
          durationMs: 20,
          overallStatus: 'secure',
          overallSummary: 'Secure',
          zones: [
            {
              zoneName: 'example.com.',
              parentZone: 'com.',
              depth: 2,
              status: 'secure',
              statusReason: 'OK',
              nsecMode: 'NSEC',
              dnskeys: [],
              dsVerifications: [],
              trustAnchorMatches: [],
              rrsets: [
                {
                  id: 'rrset-example.com.-A',
                  zone: 'example.com.',
                  name: 'example.com.',
                  type: RR_TYPES.A,
                  typeName: 'A',
                  ttl,
                  section: 'answer',
                  records: [makeARecord('example.com.', ip, ttl)],
                  rrsigs: [],
                  isQueryTarget: true,
                  status: 'secure',
                  statusReason: 'OK',
                },
              ],
              negativeNodes: [],
              nameservers: [],
            },
          ],
          cnameEdges: [],
          findings: [],
          queries,
          trustAnchorsUsed: [],
        };
        return {
          sample,
          chainState: { soaZone: 'example.com.', isSignedZone: true, chainLogs: [] },
          buildSnapshot: async () => snap,
        };
      };

      // Verify wireQueryFilter classifies Watch probe queries under 'consensus'
      const sampleCounts = computeWireQueryCategoryCounts(
        buildSyntheticResolverLogs({
          tick: 1,
          endpoint: CF_PRESET.url,
          shortLabel: CF_PRESET.shortLabel,
          capturedAtMs: fakeNow,
        })
      );
      expect(sampleCounts.consensus).toBe(3);

      // Verify expiry-continuous enforces >= 8000ms cooldown floor on TTL=0 uncacheable records
      const zeroTtlSample = buildWatchTickSample({
        tickNumber: 1,
        capturedAtMs: fakeNow,
        targetName: 'example.com.',
        qtype: RR_TYPES.A,
        soaZone: 'example.com.',
        presets: [CF_PRESET],
        queries: buildSyntheticResolverLogs({
          tick: 1,
          endpoint: CF_PRESET.url,
          shortLabel: CF_PRESET.shortLabel,
          capturedAtMs: fakeNow,
          ttl: 0,
          originalTtl: 0,
        }),
      });
      expect(computeNextWatchDelayMs('expiry-continuous', zeroTtlSample, fakeNow)).toBe(
        MIN_EXPIRY_POLL_COOLDOWN_MS
      );

      // 1. Test 'expiry-once': runs Tick #1 immediately, waits 12.75s for TTL=0, runs Tick #2, then stops cleanly!
      const ctrl = createTtlWatchController({
        targetName: 'example.com',
        pollMode: 'expiry-once',
        maxIterations: 3,
        enabledResolverUrls: [CF_PRESET.url],
        nowFn: () => Date.now(),
        probeTickFn: stubProbe,
      });

      await ctrl.start('expiry-once');
      expect(probeCount).toBe(1);
      expect(ctrl.getState().status).toBe('running');
      expect(ctrl.getState().nextPollAtMs).toBe(fakeNow + 12_350);

      // Advance 13s -> automatic TTL=0 re-query fires ONCE and stops!
      fakeNow += 13_000;
      await vi.advanceTimersByTimeAsync(13_000);
      expect(probeCount).toBe(2);
      expect(ctrl.getState().status).toBe('idle');
      expect(ctrl.getState().nextPollAtMs).toBeNull();
      expect(ctrl.getState().transitions).toHaveLength(1);

      // Verify transition snapshot pair diffs cleanly in diffSnapshots
      const tr = ctrl.getState().transitions[0]!;
      const snapDiff = diffSnapshots(tr.previousSnapshot, tr.currentSnapshot);
      expect(snapDiff.recordChanges).toHaveLength(1);
      expect(snapDiff.recordChanges[0]!.addedRecords).toContain('198.51.100.42');
      expect(snapDiff.recordChanges[0]!.removedRecords).toContain('198.51.100.10');

      // Advance another 60s -> no further polls because expiry-once completed!
      await vi.advanceTimersByTimeAsync(60_000);
      expect(probeCount).toBe(2);

      // 2. Test interval-15s + hidden-tab auto-pause + resume + maxIterations cap (3)
      ctrl.updateConfig({ pollMode: 'interval-15s', maxIterations: 3 });
      await ctrl.start('interval-15s');
      expect(ctrl.getState().status).toBe('running');

      // Simulate browser tab becoming hidden -> auto-pauses immediately!
      ctrl.handleVisibilityChange(true);
      expect(ctrl.getState().status).toBe('paused-hidden');
      expect(ctrl.getState().nextPollAtMs).toBeNull();

      await vi.advanceTimersByTimeAsync(30_000);
      expect(probeCount).toBe(2); // No background traffic while hidden!

      // Resume watch -> next 15s tick reaches maxIterations (3/3) and halts with 'completed-cap'
      ctrl.resume();
      expect(ctrl.getState().status).toBe('running');
      await vi.advanceTimersByTimeAsync(15_000);
      expect(probeCount).toBe(3);
      expect(ctrl.getState().completedTicks).toBe(3);
      expect(ctrl.getState().status).toBe('completed-cap');

      // Extend beyond cap -> resumes scheduling cleanly
      ctrl.continueBeyondCap(5);
      expect(ctrl.getState().maxIterations).toBe(8);
      expect(ctrl.getState().status).toBe('running');
      ctrl.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it(
    'executes a live multi-resolver Watch pulse tick against public DoH resolvers for cloudflare.com',
    async () => {
      const res = await runWatchPulseTick({
        targetName: 'cloudflare.com',
        qtypeName: 'A',
        resolverUrls: [
          'https://1.1.1.1/dns-query',
          'https://8.8.8.8/dns-query',
          'https://9.9.9.9/dns-query',
        ],
        tickNumber: 1,
      });

      expect(res.sample.targetName).toBe('cloudflare.com.');
      expect(res.sample.soaZone).toBe('cloudflare.com.');
      const reachable = res.sample.resolvers.filter((r) => r.reachable);
      expect(reachable.length).toBeGreaterThanOrEqual(2);

      for (const r of reachable) {
        expect(r.rcode).toBe(0);
        expect(r.answerValues.length).toBeGreaterThan(0);
        expect(r.observedTtl).not.toBeNull();
        expect(r.authoritativeOriginalTtl).toBe(300);
        expect(r.soaSerial).toBeGreaterThan(2_000_000_000);
      }

      const synthesized = await res.buildSnapshot();
      expect(synthesized.mode).toBe('consensus');
      expect(synthesized.consensusAnalysis).toBeDefined();
      expect(synthesized.consensusAnalysis!.reachableCount).toBeGreaterThanOrEqual(2);
    },
    25000
  );
});
