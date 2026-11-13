import {
  CONSENSUS_DOH_RESOLVERS,
  DEFAULT_DOH_ENDPOINT,
  DOH_SERVER_PRESETS,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  formatDohShortLabel,
  rcodeToString,
  rrTypeToString,
  stringToRrType,
  type DohResolverRole,
  type DohServerPreset,
  type TrustAnchor,
} from './constants';
import {
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
} from './analyzer';
import { evaluateConsensusFromSnapshotData } from './consensusAnalyzer';
import { DohSession } from './doh';
import { displayFqdn, isSubdomainOrEqual, normalizeFqdn } from './encoding';
import { formatCanonicalIpv6, parseIpv6Groups } from './ipUtils';
import type {
  AnalysisSnapshot,
  DnsRecord,
  DohQueryLog,
  EdeEntry,
  ValidationStatus,
} from './types';

export const WATCHABLE_RR_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'HTTPS',
  'CAA',
  'NS',
  'SOA',
  'DNSKEY',
  'DS',
] as const;

export type WatchableRrType = (typeof WATCHABLE_RR_TYPES)[number];

export const DEFAULT_WATCH_RESOLVER_URLS: readonly string[] = [
  'https://1.1.1.1/dns-query',
  'https://8.8.8.8/dns-query',
  'https://9.9.9.9/dns-query',
  'https://doh.dns.sb/dns-query',
  'https://unfiltered.joindns4.eu/dns-query',
];

export const DEFAULT_WATCH_MAX_ITERATIONS = 20;
export const MIN_EXPIRY_POLL_COOLDOWN_MS = 8000;

export type WatchPollMode =
  | 'manual'
  | 'expiry-once'
  | 'expiry-continuous'
  | 'interval-15s'
  | 'interval-30s'
  | 'interval-60s';

export type WatchControllerStatus =
  | 'idle'
  | 'running'
  | 'pulsing'
  | 'paused'
  | 'paused-hidden'
  | 'completed-cap';

export type TtlClampAndStaleStatus =
  | 'normal'
  | 'serve-stale-ede'
  | 'serve-stale-zero-ttl'
  | 'zero-ttl-uncacheable'
  | 'min-ttl-clamped'
  | 'max-ttl-clamped';

export interface WatchRrsigMeta {
  keyTag: number;
  algorithm: number;
  signerName: string;
  inception: number;
  expiration: number;
  originalTtl: number;
  isExpiredAtCapture: boolean;
}

export interface WatchResolverObservation {
  endpoint: string;
  shortLabel: string;
  provider: string;
  role: DohResolverRole;
  reachable: boolean;
  error?: string;
  capturedAtMs: number;
  latencyMs: number;
  qname: string;
  qtype: number;
  qtypeName: string;
  rcode: number;
  rcodeName: string;
  adBit: boolean;
  answerValues: string[];
  cnameChain: string[];
  observedTtl: number | null;
  ttlSource: 'answer' | 'negative-soa' | 'none';
  authoritativeOriginalTtl?: number;
  ceilingTtl: number | null;
  estimatedCacheAgeSec?: number;
  soaZone?: string;
  soaSerial?: number;
  soaMinimumTtl?: number;
  dnskeyKeyTags: number[];
  rrsigMeta?: WatchRrsigMeta;
  ede: EdeEntry[];
  ttlBehavior: TtlClampAndStaleStatus;
  ttlBehaviorDetail: string;
  didRefreshCache: boolean;
  cacheRefreshCount: number;
  clampedMaxTtl?: number;
  wireQueryId?: string;
}

export interface LiveTtlCountdown {
  remainingSec: number | null;
  elapsedSec: number;
  ceilingTtl: number | null;
  percentRemaining: number;
  isExpiredLocally: boolean;
  isExpiringSoon: boolean;
}

export interface WatchTickSample {
  tickNumber: number;
  capturedAtMs: number;
  targetName: string;
  displayDomain: string;
  qtype: number;
  qtypeName: string;
  soaZone: string;
  resolvers: WatchResolverObservation[];
  queries: DohQueryLog[];
  shortestPositiveTtlSec: number | null;
  serveStaleResolvers: string[];
  minClampedResolvers: string[];
  maxClampedResolvers: string[];
  uniqueSoaSerials: { serial: number; resolvers: string[] }[];
  uniqueAnswerPools: { fingerprint: string; values: string[]; resolvers: string[] }[];
}

export type WatchTransitionCategory =
  | 'answer-ip-change'
  | 'soa-serial-change'
  | 'dnskey-keytag-change'
  | 'rrsig-resign'
  | 'rcode-ede-change';

export interface WatchResolverFieldDiff {
  endpoint: string;
  shortLabel: string;
  category: WatchTransitionCategory;
  subKind?: 'gslb-rotation' | 'zone-update' | 'serve-stale';
  before: string;
  after: string;
  addedValues?: string[];
  removedValues?: string[];
}

export interface WatchTransitionEvent {
  id: string;
  tickNumber: number;
  detectedAtMs: number;
  categories: WatchTransitionCategory[];
  headline: string;
  diffs: WatchResolverFieldDiff[];
  previousSample: WatchTickSample;
  currentSample: WatchTickSample;
  previousSnapshot: AnalysisSnapshot;
  currentSnapshot: AnalysisSnapshot;
}

export interface TtlWatchState {
  targetName: string;
  displayDomain: string;
  qtypeName: WatchableRrType;
  pollMode: WatchPollMode;
  maxIterations: number;
  enabledResolverUrls: string[];
  status: WatchControllerStatus;
  completedTicks: number;
  nextPollAtMs: number | null;
  lastError?: string;
  currentSample: WatchTickSample | null;
  latestSnapshot: AnalysisSnapshot | null;
  transitions: WatchTransitionEvent[];
}

/**
 * Returns the full catalog of selectable DoH resolvers for Live Watch, including any custom primary DoH endpoint.
 */
export function getAvailableWatchResolvers(primaryEndpoint?: string): DohServerPreset[] {
  const list: DohServerPreset[] = [...CONSENSUS_DOH_RESOLVERS];
  if (primaryEndpoint && !list.some((r) => r.url === primaryEndpoint)) {
    const known = DOH_SERVER_PRESETS.find((r) => r.url === primaryEndpoint);
    if (known) {
      list.unshift({ ...known, isAlias: false });
    } else {
      list.unshift({
        url: primaryEndpoint,
        shortLabel: formatDohShortLabel(primaryEndpoint),
        provider: 'Custom DoH',
        description: `Custom DoH Resolver (${primaryEndpoint})`,
        role: 'unfiltered',
      });
    }
  }
  return list;
}

export function getDefaultWatchResolverUrls(primaryEndpoint?: string): string[] {
  const urls = [...DEFAULT_WATCH_RESOLVER_URLS];
  if (primaryEndpoint && !urls.includes(primaryEndpoint)) {
    const aliasMatch = DOH_SERVER_PRESETS.find((p) => p.url === primaryEndpoint);
    if (!aliasMatch?.isAlias) {
      urls.unshift(primaryEndpoint);
    }
  }
  return urls;
}

function formatRecordCanonicalValue(rec: DnsRecord): string {
  switch (rec.type) {
    case RR_TYPES.A:
      return rec.rdataText.trim();
    case RR_TYPES.AAAA: {
      const grps = parseIpv6Groups(rec.rdataText);
      return grps ? formatCanonicalIpv6(grps) : rec.rdataText.trim().toLowerCase();
    }
    case RR_TYPES.CNAME:
    case RR_TYPES.NS:
    case RR_TYPES.PTR:
      return rec.parsed.kind === 'GENERIC' && rec.parsed.target
        ? displayFqdn(rec.parsed.target)
        : displayFqdn(rec.rdataText);
    case RR_TYPES.MX:
      return rec.parsed.kind === 'MX'
        ? `${rec.parsed.preference} ${displayFqdn(rec.parsed.exchange)}`
        : rec.rdataText.trim();
    case RR_TYPES.TXT:
      return rec.parsed.kind === 'TXT' ? rec.parsed.joinedText : rec.rdataText.trim();
    case RR_TYPES.SOA:
      return rec.parsed.kind === 'SOA'
        ? `serial=${rec.parsed.serial} min=${rec.parsed.minimum}`
        : rec.rdataText.trim();
    case RR_TYPES.DNSKEY:
      return rec.parsed.kind === 'DNSKEY'
        ? `#${rec.parsed.keyTag} alg=${rec.parsed.algorithm} flags=${rec.parsed.flags}`
        : rec.rdataText.trim();
    case RR_TYPES.DS:
      return rec.parsed.kind === 'DS'
        ? `#${rec.parsed.keyTag} alg=${rec.parsed.algorithm} dt=${rec.parsed.digestType}`
        : rec.rdataText.trim();
    case RR_TYPES.CAA:
      return rec.parsed.kind === 'CAA'
        ? `${rec.parsed.flags} ${rec.parsed.tag} "${rec.parsed.value}"`
        : rec.rdataText.trim();
    case RR_TYPES.HTTPS:
    case RR_TYPES.SVCB:
      return rec.parsed.kind === 'SVCB'
        ? `${rec.parsed.priority} ${displayFqdn(rec.parsed.target)} ${rec.parsed.params.map((p) => `${p.keyName}=${p.valueText}`).join(' ')}`.trim()
        : rec.rdataText.trim();
    default:
      return rec.rdataText.trim();
  }
}

/**
 * Extracts raw TTL, RRSIG originalTTL, SOA serial, DNSKEY key tags, and RFC 8914 EDE observations
 * for a single DoH resolver prior to cross-resolver clamping classification.
 */
export function extractResolverWatchObservation(params: {
  preset: DohServerPreset;
  targetName: string;
  qtype: number;
  soaZone: string;
  logs: readonly DohQueryLog[];
  capturedAtMs: number;
}): Omit<
  WatchResolverObservation,
  | 'ceilingTtl'
  | 'ttlBehavior'
  | 'ttlBehaviorDetail'
  | 'didRefreshCache'
  | 'cacheRefreshCount'
  | 'clampedMaxTtl'
> {
  const { preset, targetName, qtype, soaZone, logs, capturedAtMs } = params;
  const qtypeName = rrTypeToString(qtype);

  const epLogs = logs.filter(
    (q) => !q.ecsSubnet && !q.purpose.startsWith('ECS ') && q.endpoint === preset.url
  );

  if (epLogs.length === 0) {
    return {
      endpoint: preset.url,
      shortLabel: preset.shortLabel,
      provider: preset.provider,
      role: preset.role,
      reachable: false,
      error: 'Resolver timeout or CORS / network unreachable',
      capturedAtMs,
      latencyMs: 0,
      qname: targetName,
      qtype,
      qtypeName,
      rcode: -1,
      rcodeName: 'UNREACHABLE',
      adBit: false,
      answerValues: [],
      cnameChain: [],
      observedTtl: null,
      ttlSource: 'none',
      dnskeyKeyTags: [],
      ede: [],
    };
  }

  const targetLog =
    epLogs.find((q) => q.qname === targetName && q.qtype === qtype && !q.cd) ??
    epLogs.find((q) => q.qname === targetName && q.qtype === qtype) ??
    epLogs.find((q) => q.qname === targetName && !q.cd) ??
    epLogs[0]!;

  const soaLog =
    epLogs.find((q) => q.qtype === RR_TYPES.SOA && q.qname === soaZone) ??
    epLogs.find((q) => q.qtype === RR_TYPES.SOA);

  const dnskeyLog = epLogs.find((q) => q.qtype === RR_TYPES.DNSKEY && q.qname === soaZone);

  const rcode = targetLog.packet.flags.rcode;
  const rcodeName = rcodeToString(rcode);
  const adBit = Boolean(targetLog.packet.flags.rcode === 0 && targetLog.packet.flags.ad);
  const avgLatency = Math.max(
    1,
    Math.round(epLogs.reduce((acc, l) => acc + l.latencyMs, 0) / epLogs.length)
  );

  // Follow any in-packet CNAME hops unless watching CNAME directly
  let terminalOwner = targetName;
  const cnameChain: string[] = [];
  if (qtype !== RR_TYPES.CNAME) {
    const visited = new Set<string>([targetName]);
    for (let hop = 0; hop < 8; hop++) {
      const cRec = targetLog.packet.answers.find(
        (r) => normalizeFqdn(r.name) === terminalOwner && r.type === RR_TYPES.CNAME
      );
      if (!cRec || cRec.parsed.kind !== 'GENERIC' || !cRec.parsed.target) break;
      const next = normalizeFqdn(cRec.parsed.target);
      if (visited.has(next)) break;
      visited.add(next);
      cnameChain.push(next);
      terminalOwner = next;
    }
  }

  const matchingAnswers = targetLog.packet.answers.filter(
    (r) =>
      r.type === qtype &&
      (normalizeFqdn(r.name) === terminalOwner || normalizeFqdn(r.name) === targetName)
  );

  const answerSet = new Set<string>();
  for (const ans of matchingAnswers) {
    const v = formatRecordCanonicalValue(ans);
    if (v) answerSet.add(v);
  }
  const answerValues = Array.from(answerSet).sort();

  // Extract SOA serial & minimum negative TTL
  let soaSerial: number | undefined;
  let soaMinimumTtl: number | undefined;
  let resolvedSoaZone: string | undefined;
  for (const l of [soaLog, targetLog]) {
    if (!l) continue;
    for (const rec of [...l.packet.answers, ...l.packet.authorities]) {
      if (rec.type === RR_TYPES.SOA && rec.parsed.kind === 'SOA') {
        soaSerial = rec.parsed.serial;
        soaMinimumTtl = rec.parsed.minimum;
        resolvedSoaZone = normalizeFqdn(rec.name);
        break;
      }
    }
    if (soaSerial !== undefined) break;
  }

  // Extract DNSKEY key tags
  const dnskeyKeyTags: number[] = [];
  for (const l of [dnskeyLog, qtype === RR_TYPES.DNSKEY ? targetLog : undefined]) {
    if (!l) continue;
    for (const ans of l.packet.answers) {
      if (ans.type === RR_TYPES.DNSKEY && ans.parsed.kind === 'DNSKEY') {
        if (!dnskeyKeyTags.includes(ans.parsed.keyTag)) {
          dnskeyKeyTags.push(ans.parsed.keyTag);
        }
      }
    }
  }
  dnskeyKeyTags.sort((a, b) => a - b);

  // Determine observed wire TTL & authoritative originalTTL (from RRSIG or RFC 2308 negative SOA)
  let observedTtl: number | null = null;
  let ttlSource: WatchResolverObservation['ttlSource'] = 'none';
  let authoritativeOriginalTtl: number | undefined;
  let rrsigMeta: WatchRrsigMeta | undefined;
  const captureEpochSec = Math.floor(capturedAtMs / 1000);

  if (matchingAnswers.length > 0) {
    observedTtl = Math.min(...matchingAnswers.map((r) => r.ttl));
    ttlSource = 'answer';

    const coveringRrsig =
      targetLog.packet.answers.find(
        (r) =>
          r.type === RR_TYPES.RRSIG &&
          r.parsed.kind === 'RRSIG' &&
          r.parsed.typeCovered === qtype &&
          normalizeFqdn(r.name) === terminalOwner
      ) ??
      targetLog.packet.answers.find(
        (r) =>
          r.type === RR_TYPES.RRSIG &&
          r.parsed.kind === 'RRSIG' &&
          r.parsed.typeCovered === qtype
      );

    if (coveringRrsig && coveringRrsig.parsed.kind === 'RRSIG') {
      const sig = coveringRrsig.parsed;
      authoritativeOriginalTtl = sig.originalTtl;
      rrsigMeta = {
        keyTag: sig.keyTag,
        algorithm: sig.algorithm,
        signerName: normalizeFqdn(sig.signerName),
        inception: sig.inception,
        expiration: sig.expiration,
        originalTtl: sig.originalTtl,
        isExpiredAtCapture: sig.expiration < captureEpochSec,
      };
    }
  } else {
    const negSoaRec = targetLog.packet.authorities.find((r) => r.type === RR_TYPES.SOA);
    if (negSoaRec) {
      observedTtl = negSoaRec.ttl;
      ttlSource = 'negative-soa';
      const negMin = negSoaRec.parsed.kind === 'SOA' ? negSoaRec.parsed.minimum : undefined;
      const soaSig = targetLog.packet.authorities.find(
        (r) =>
          r.type === RR_TYPES.RRSIG &&
          r.parsed.kind === 'RRSIG' &&
          r.parsed.typeCovered === RR_TYPES.SOA
      );
      if (soaSig && soaSig.parsed.kind === 'RRSIG') {
        const sig = soaSig.parsed;
        authoritativeOriginalTtl =
          negMin !== undefined ? Math.min(sig.originalTtl, negMin) : sig.originalTtl;
        rrsigMeta = {
          keyTag: sig.keyTag,
          algorithm: sig.algorithm,
          signerName: normalizeFqdn(sig.signerName),
          inception: sig.inception,
          expiration: sig.expiration,
          originalTtl: sig.originalTtl,
          isExpiredAtCapture: sig.expiration < captureEpochSec,
        };
      } else if (negMin !== undefined) {
        authoritativeOriginalTtl = negMin;
      }
    } else if (cnameChain.length > 0) {
      const cnameRecs = targetLog.packet.answers.filter((r) => r.type === RR_TYPES.CNAME);
      if (cnameRecs.length > 0) {
        observedTtl = Math.min(...cnameRecs.map((r) => r.ttl));
        ttlSource = 'answer';
      }
    }
  }

  const estimatedCacheAgeSec =
    authoritativeOriginalTtl !== undefined &&
    observedTtl !== null &&
    authoritativeOriginalTtl >= observedTtl
      ? authoritativeOriginalTtl - observedTtl
      : undefined;

  // Deduplicate RFC 8914 EDE entries
  const ede: EdeEntry[] = [];
  for (const l of epLogs) {
    for (const e of l.packet.edns?.ede ?? []) {
      if (!ede.some((x) => x.infoCode === e.infoCode && x.extraText === e.extraText)) {
        ede.push(e);
      }
    }
  }

  return {
    endpoint: preset.url,
    shortLabel: preset.shortLabel,
    provider: preset.provider,
    role: preset.role,
    reachable: true,
    capturedAtMs,
    latencyMs: avgLatency,
    qname: targetName,
    qtype,
    qtypeName,
    rcode,
    rcodeName,
    adBit,
    answerValues,
    cnameChain,
    observedTtl,
    ttlSource,
    authoritativeOriginalTtl,
    estimatedCacheAgeSec,
    soaZone: resolvedSoaZone ?? soaZone,
    soaSerial,
    soaMinimumTtl,
    dnskeyKeyTags,
    rrsigMeta,
    ede,
    wireQueryId: targetLog.id,
  };
}

/**
 * Classifies resolver cache behavior (RFC 8767 Serve-Stale, Min-TTL Floor Clamping, Max-TTL Ceiling Clamping,
 * Zero-TTL GSLB, or Normal Cache Decay) by comparing observed wire TTLs against authoritative RRSIG/SOA ceilings,
 * peer resolver ceilings, and cache-reload jumps across ticks.
 */
export function classifyResolverTtlBehavior(params: {
  rawObs: Omit<
    WatchResolverObservation,
    | 'ceilingTtl'
    | 'ttlBehavior'
    | 'ttlBehaviorDetail'
    | 'didRefreshCache'
    | 'cacheRefreshCount'
    | 'clampedMaxTtl'
  >;
  previousObs?: WatchResolverObservation;
  peerAuthoritativeTtl: number | null;
  peerMaxObservedTtl: number | null;
}): WatchResolverObservation {
  const { rawObs, previousObs, peerAuthoritativeTtl, peerMaxObservedTtl } = params;

  if (!rawObs.reachable) {
    return {
      ...rawObs,
      ceilingTtl: null,
      ttlBehavior: 'normal',
      ttlBehaviorDetail: rawObs.error ?? 'Resolver unreachable',
      didRefreshCache: false,
      cacheRefreshCount: previousObs?.cacheRefreshCount ?? 0,
    };
  }

  const authoritativeCeiling = rawObs.authoritativeOriginalTtl ?? peerAuthoritativeTtl ?? undefined;
  const referenceCeiling =
    authoritativeCeiling ??
    (peerMaxObservedTtl !== null && rawObs.observedTtl !== null
      ? Math.max(peerMaxObservedTtl, rawObs.observedTtl)
      : (rawObs.observedTtl ?? null));

  // Detect whether this resolver refreshed its cache entry since previousObs
  let didRefreshCache = false;
  let elapsedSincePrevSec = 0;
  if (
    previousObs &&
    previousObs.reachable &&
    previousObs.observedTtl !== null &&
    rawObs.observedTtl !== null
  ) {
    elapsedSincePrevSec = Math.max(0, (rawObs.capturedAtMs - previousObs.capturedAtMs) / 1000);
    const expectedPrevRemaining = Math.max(0, previousObs.observedTtl - elapsedSincePrevSec);
    if (
      (previousObs.observedTtl > 0 && expectedPrevRemaining <= 1.5 && rawObs.observedTtl > 1) ||
      rawObs.observedTtl > expectedPrevRemaining + 3
    ) {
      didRefreshCache = true;
    }
  }
  const cacheRefreshCount = (previousObs?.cacheRefreshCount ?? 0) + (didRefreshCache ? 1 : 0);

  const staleEde = rawObs.ede.find((e) => e.infoCode === 3 || e.infoCode === 19);
  if (staleEde) {
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: referenceCeiling,
      ttlBehavior: 'serve-stale-ede',
      ttlBehaviorDetail: `RFC 8767 Serve-Stale confirmed via RFC 8914 EDE ${staleEde.infoCode} (${staleEde.name})${staleEde.extraText ? `: "${staleEde.extraText}"` : ''}`,
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  if (
    rawObs.observedTtl === 0 &&
    ((authoritativeCeiling !== undefined && authoritativeCeiling > 0) ||
      (authoritativeCeiling === undefined &&
        peerMaxObservedTtl !== null &&
        peerMaxObservedTtl >= 30))
  ) {
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: referenceCeiling,
      ttlBehavior: 'serve-stale-zero-ttl',
      ttlBehaviorDetail: `RFC 8767 Serve-Stale / expired cache entry: served TTL=0s while authoritative TTL is ${authoritativeCeiling ?? peerMaxObservedTtl}s`,
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  if (rawObs.rcode === 0 && rawObs.rrsigMeta?.isExpiredAtCapture) {
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: referenceCeiling,
      ttlBehavior: 'serve-stale-zero-ttl',
      ttlBehaviorDetail: `Stale cached RRSIG (#${rawObs.rrsigMeta.keyTag}) served past cryptographic expiration`,
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  if (rawObs.observedTtl === 0) {
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: 0,
      ttlBehavior: 'zero-ttl-uncacheable',
      ttlBehaviorDetail: 'Authoritative TTL=0s (uncacheable / live GSLB record)',
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  // Min-TTL Floor Clamping (resolver inflates wire TTL above signed originalTTL / RFC 2308 negative SOA minimum)
  if (
    rawObs.observedTtl !== null &&
    authoritativeCeiling !== undefined &&
    rawObs.observedTtl > authoritativeCeiling
  ) {
    const sourceDesc =
      rawObs.ttlSource === 'negative-soa'
        ? `RFC 2308 negative SOA ceiling (${authoritativeCeiling}s)`
        : `RRSIG originalTTL (${authoritativeCeiling}s)`;
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: rawObs.observedTtl,
      ttlBehavior: 'min-ttl-clamped',
      ttlBehaviorDetail: `Min-TTL floor clamped: serving ${rawObs.observedTtl}s > ${sourceDesc}`,
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  if (
    rawObs.observedTtl !== null &&
    authoritativeCeiling === undefined &&
    peerMaxObservedTtl !== null &&
    peerMaxObservedTtl > 0 &&
    peerMaxObservedTtl <= 30 &&
    rawObs.observedTtl >= Math.max(peerMaxObservedTtl * 2, peerMaxObservedTtl + 15)
  ) {
    return {
      ...rawObs,
      ceilingTtl: rawObs.observedTtl,
      ttlBehavior: 'min-ttl-clamped',
      ttlBehaviorDetail: `Min-TTL floor clamped: serving ${rawObs.observedTtl}s while peer ceiling is ≤${peerMaxObservedTtl}s`,
      didRefreshCache,
      cacheRefreshCount,
    };
  }

  // Max-TTL Ceiling Clamping (confirmed on fresh cache reload when fresh peak is strictly below authoritative/peer ceiling)
  let clampedMaxTtl = previousObs?.clampedMaxTtl;
  if (
    didRefreshCache &&
    rawObs.observedTtl !== null &&
    previousObs?.observedTtl !== null &&
    previousObs?.observedTtl !== undefined &&
    referenceCeiling !== null &&
    referenceCeiling >= 60
  ) {
    const maxPossibleRefreshAgeSec = Math.max(0, elapsedSincePrevSec - previousObs.observedTtl);
    const upperBoundFreshPeak = Math.ceil(rawObs.observedTtl + maxPossibleRefreshAgeSec);
    if (
      upperBoundFreshPeak <= referenceCeiling * 0.85 &&
      referenceCeiling - upperBoundFreshPeak >= 60
    ) {
      clampedMaxTtl = rawObs.observedTtl;
    } else if (rawObs.observedTtl > referenceCeiling * 0.85) {
      clampedMaxTtl = undefined;
    }
  }

  if (
    clampedMaxTtl !== undefined &&
    referenceCeiling !== null &&
    rawObs.observedTtl !== null &&
    rawObs.observedTtl <= clampedMaxTtl + 5
  ) {
    return {
      ...rawObs,
      authoritativeOriginalTtl: authoritativeCeiling,
      ceilingTtl: referenceCeiling,
      estimatedCacheAgeSec:
        authoritativeCeiling !== undefined && authoritativeCeiling >= rawObs.observedTtl
          ? authoritativeCeiling - rawObs.observedTtl
          : rawObs.estimatedCacheAgeSec,
      ttlBehavior: 'max-ttl-clamped',
      ttlBehaviorDetail: `Max-TTL ceiling clamped on refresh: reset to ~${clampedMaxTtl}s < ${authoritativeCeiling !== undefined ? `RRSIG originalTTL ${authoritativeCeiling}s` : `peer ceiling ${referenceCeiling}s`}`,
      didRefreshCache,
      cacheRefreshCount,
      clampedMaxTtl,
    };
  }

  const ageSec =
    authoritativeCeiling !== undefined &&
    rawObs.observedTtl !== null &&
    authoritativeCeiling >= rawObs.observedTtl
      ? authoritativeCeiling - rawObs.observedTtl
      : rawObs.estimatedCacheAgeSec;

  return {
    ...rawObs,
    authoritativeOriginalTtl: authoritativeCeiling,
    ceilingTtl: referenceCeiling,
    estimatedCacheAgeSec: ageSec,
    ttlBehavior: 'normal',
    ttlBehaviorDetail:
      rawObs.observedTtl !== null
        ? ageSec !== undefined && authoritativeCeiling !== undefined
          ? `Normal cache decay (${rawObs.observedTtl}s / ${authoritativeCeiling}s, cached ~${ageSec}s ago)`
          : `Active cache entry (${rawObs.observedTtl}s remaining)`
        : `No cacheable RRset (${rawObs.rcodeName})`,
    didRefreshCache,
    cacheRefreshCount,
  };
}

/**
 * Synthesizes a complete `WatchTickSample` from raw per-resolver observations, correlating
 * authoritative `originalTtl` and peer TTL ceilings across the resolver fleet.
 */
export function buildWatchTickSample(params: {
  tickNumber: number;
  capturedAtMs: number;
  targetName: string;
  qtype: number;
  soaZone: string;
  presets: readonly DohServerPreset[];
  queries: DohQueryLog[];
  previousSample?: WatchTickSample | null;
}): WatchTickSample {
  const {
    tickNumber,
    capturedAtMs,
    targetName,
    qtype,
    soaZone,
    presets,
    queries,
    previousSample,
  } = params;

  const rawList = presets.map((preset) =>
    extractResolverWatchObservation({
      preset,
      targetName,
      qtype,
      soaZone,
      logs: queries,
      capturedAtMs,
    })
  );

  // Determine authoritative reference TTL (prefer RRSIG originalTTL from any reachable unfiltered resolver)
  let peerAuthoritativeTtl: number | null = null;
  for (const r of rawList) {
    if (r.reachable && r.authoritativeOriginalTtl !== undefined) {
      if (peerAuthoritativeTtl === null || r.authoritativeOriginalTtl > peerAuthoritativeTtl) {
        peerAuthoritativeTtl = r.authoritativeOriginalTtl;
      }
    }
  }

  const resolvers: WatchResolverObservation[] = rawList.map((rawObs) => {
    const prevObs = previousSample?.resolvers.find((p) => p.endpoint === rawObs.endpoint);
    const otherUnfilteredTtls = rawList
      .filter(
        (o) =>
          o.endpoint !== rawObs.endpoint &&
          o.reachable &&
          o.role === 'unfiltered' &&
          o.observedTtl !== null
      )
      .map((o) => o.observedTtl!);
    const peerMaxFromOthers =
      otherUnfilteredTtls.length > 0 ? Math.max(...otherUnfilteredTtls) : null;
    const prevSessionMax = previousSample
      ? Math.max(
          0,
          ...previousSample.resolvers
            .filter(
              (p) =>
                p.endpoint !== rawObs.endpoint &&
                p.reachable &&
                p.role === 'unfiltered' &&
                p.observedTtl !== null
            )
            .map((p) => p.observedTtl!)
        )
      : 0;
    const peerMaxObservedTtl =
      peerMaxFromOthers !== null || prevSessionMax > 0
        ? Math.max(peerMaxFromOthers ?? 0, prevSessionMax)
        : null;

    return classifyResolverTtlBehavior({
      rawObs,
      previousObs: prevObs,
      peerAuthoritativeTtl,
      peerMaxObservedTtl,
    });
  });

  let shortestPositiveTtlSec: number | null = null;
  for (const r of resolvers) {
    if (r.reachable && r.observedTtl !== null && r.observedTtl > 0) {
      if (shortestPositiveTtlSec === null || r.observedTtl < shortestPositiveTtlSec) {
        shortestPositiveTtlSec = r.observedTtl;
      }
    }
  }

  const serveStaleResolvers = resolvers
    .filter(
      (r) => r.ttlBehavior === 'serve-stale-ede' || r.ttlBehavior === 'serve-stale-zero-ttl'
    )
    .map((r) => r.shortLabel);
  const minClampedResolvers = resolvers
    .filter((r) => r.ttlBehavior === 'min-ttl-clamped')
    .map((r) => r.shortLabel);
  const maxClampedResolvers = resolvers
    .filter((r) => r.ttlBehavior === 'max-ttl-clamped')
    .map((r) => r.shortLabel);

  const serialMap = new Map<number, string[]>();
  for (const r of resolvers) {
    if (r.reachable && r.soaSerial !== undefined) {
      const arr = serialMap.get(r.soaSerial) ?? [];
      arr.push(r.shortLabel);
      serialMap.set(r.soaSerial, arr);
    }
  }
  const uniqueSoaSerials = Array.from(serialMap.entries())
    .map(([serial, res]) => ({ serial, resolvers: res }))
    .sort((a, b) => b.serial - a.serial);

  const poolMap = new Map<string, { values: string[]; resolvers: string[] }>();
  for (const r of resolvers) {
    if (r.reachable && r.answerValues.length > 0) {
      const fp = r.answerValues.join(', ');
      const existing = poolMap.get(fp) ?? { values: r.answerValues, resolvers: [] };
      existing.resolvers.push(r.shortLabel);
      poolMap.set(fp, existing);
    }
  }
  const uniqueAnswerPools = Array.from(poolMap.entries()).map(([fingerprint, item]) => ({
    fingerprint,
    values: item.values,
    resolvers: item.resolvers,
  }));

  return {
    tickNumber,
    capturedAtMs,
    targetName,
    displayDomain: displayFqdn(targetName),
    qtype,
    qtypeName: rrTypeToString(qtype),
    soaZone,
    resolvers,
    queries,
    shortestPositiveTtlSec,
    serveStaleResolvers,
    minClampedResolvers,
    maxClampedResolvers,
    uniqueSoaSerials,
    uniqueAnswerPools,
  };
}

/**
 * Computes real-time ticking countdown state for a resolver row at wall-clock `nowMs`.
 */
export function computeLiveTtlCountdown(
  obs: WatchResolverObservation,
  nowMs: number
): LiveTtlCountdown {
  if (!obs.reachable || obs.observedTtl === null) {
    return {
      remainingSec: null,
      elapsedSec: 0,
      ceilingTtl: null,
      percentRemaining: 0,
      isExpiredLocally: false,
      isExpiringSoon: false,
    };
  }

  const elapsedMs = Math.max(0, nowMs - obs.capturedAtMs);
  const elapsedSec = Math.floor(elapsedMs / 1000);

  if (obs.observedTtl <= 0) {
    return {
      remainingSec: 0,
      elapsedSec,
      ceilingTtl: obs.ceilingTtl ?? 0,
      percentRemaining: 0,
      isExpiredLocally: true,
      isExpiringSoon: false,
    };
  }

  const rawRemaining = obs.observedTtl - elapsedMs / 1000;
  const remainingSec = Math.max(0, Math.ceil(rawRemaining));
  const ceiling = Math.max(obs.ceilingTtl ?? obs.observedTtl, obs.observedTtl, 1);
  const percentRemaining =
    rawRemaining <= 0 ? 0 : Math.min(100, Math.max(0, (rawRemaining / ceiling) * 100));

  return {
    remainingSec,
    elapsedSec,
    ceilingTtl: ceiling,
    percentRemaining,
    isExpiredLocally: rawRemaining <= 0,
    isExpiringSoon: rawRemaining > 0 && rawRemaining <= 5,
  };
}

/**
 * Computes the next automatic poll delay in milliseconds for interval or smart `TTL=0` expiry modes.
 */
export function computeNextWatchDelayMs(
  pollMode: WatchPollMode,
  sample: WatchTickSample | null,
  nowMs: number
): number | null {
  switch (pollMode) {
    case 'manual':
      return null;
    case 'interval-15s':
      return 15_000;
    case 'interval-30s':
      return 30_000;
    case 'interval-60s':
      return 60_000;
    case 'expiry-once':
    case 'expiry-continuous': {
      if (!sample) return MIN_EXPIRY_POLL_COOLDOWN_MS;
      let earliestExpiryMs: number | null = null;
      for (const r of sample.resolvers) {
        if (!r.reachable || r.observedTtl === null || r.observedTtl <= 0) continue;
        // Fire 350ms after TTL hits 0 so resolver cache expiry has cleanly elapsed
        const targetAt = r.capturedAtMs + r.observedTtl * 1000 + 350;
        if (earliestExpiryMs === null || targetAt < earliestExpiryMs) {
          earliestExpiryMs = targetAt;
        }
      }
      if (earliestExpiryMs === null) {
        // All resolvers returned TTL=0 or NODATA without positive TTL: enforce safe floor cooldown
        return pollMode === 'expiry-once' ? 5_000 : MIN_EXPIRY_POLL_COOLDOWN_MS;
      }
      const rawDelay = earliestExpiryMs - nowMs;
      const floorMs = pollMode === 'expiry-once' ? 1_000 : MIN_EXPIRY_POLL_COOLDOWN_MS;
      return Math.max(floorMs, Math.min(rawDelay, 3_600_000));
    }
  }
}

/**
 * Detects Change-Only state transitions between two consecutive `WatchTickSample` observations,
 * ignoring pure TTL countdown decay and identical cache reloads.
 */
export function detectWatchTransitions(
  prevSample: WatchTickSample,
  nextSample: WatchTickSample
): {
  categories: WatchTransitionCategory[];
  headline: string;
  diffs: WatchResolverFieldDiff[];
} | null {
  if (
    prevSample.targetName !== nextSample.targetName ||
    prevSample.qtype !== nextSample.qtype
  ) {
    return null;
  }

  const diffs: WatchResolverFieldDiff[] = [];
  const prevByEndpoint = new Map(prevSample.resolvers.map((r) => [r.endpoint, r]));

  const anySoaChangedAcrossFleet = nextSample.resolvers.some((curr) => {
    const prev = prevByEndpoint.get(curr.endpoint);
    return (
      prev?.reachable &&
      curr.reachable &&
      prev.soaSerial !== undefined &&
      curr.soaSerial !== undefined &&
      prev.soaSerial !== curr.soaSerial
    );
  });

  for (const curr of nextSample.resolvers) {
    const prev = prevByEndpoint.get(curr.endpoint);
    if (!prev) continue;

    // 1. RCODE / AD / EDE / Serve-Stale / Reachability transition
    const prevEdeKey = prev.ede.map((e) => `${e.infoCode}:${e.extraText}`).join('|');
    const currEdeKey = curr.ede.map((e) => `${e.infoCode}:${e.extraText}`).join('|');
    const prevIsStale =
      prev.ttlBehavior === 'serve-stale-ede' || prev.ttlBehavior === 'serve-stale-zero-ttl';
    const currIsStale =
      curr.ttlBehavior === 'serve-stale-ede' || curr.ttlBehavior === 'serve-stale-zero-ttl';

    if (
      prev.reachable !== curr.reachable ||
      (prev.reachable &&
        curr.reachable &&
        (prev.rcode !== curr.rcode ||
          prev.adBit !== curr.adBit ||
          prevEdeKey !== currEdeKey ||
          prevIsStale !== currIsStale))
    ) {
      const fmtStatus = (o: WatchResolverObservation) => {
        if (!o.reachable) return 'UNREACHABLE';
        const parts = [`${o.rcodeName} (AD=${o.adBit ? '1' : '0'})`];
        if (o.ede.length > 0) {
          parts.push(`EDE ${o.ede.map((e) => `${e.infoCode} ${e.name}`).join(', ')}`);
        } else if (
          o.ttlBehavior === 'serve-stale-ede' ||
          o.ttlBehavior === 'serve-stale-zero-ttl'
        ) {
          parts.push('SERVE-STALE');
        }
        return parts.join(' · ');
      };
      diffs.push({
        endpoint: curr.endpoint,
        shortLabel: curr.shortLabel,
        category: 'rcode-ede-change',
        subKind: currIsStale ? 'serve-stale' : undefined,
        before: fmtStatus(prev),
        after: fmtStatus(curr),
      });
    }

    if (!prev.reachable || !curr.reachable) continue;

    // 2. SOA Serial propagation change
    if (
      prev.soaSerial !== undefined &&
      curr.soaSerial !== undefined &&
      prev.soaSerial !== curr.soaSerial
    ) {
      diffs.push({
        endpoint: curr.endpoint,
        shortLabel: curr.shortLabel,
        category: 'soa-serial-change',
        before: String(prev.soaSerial),
        after: String(curr.soaSerial),
      });
    }

    // 3. Answer IP / RDATA pool rotation or update
    if (prev.rcode === 0 && curr.rcode === 0) {
      const prevAnsKey = prev.answerValues.join('\n');
      const currAnsKey = curr.answerValues.join('\n');
      if (prevAnsKey !== currAnsKey) {
        const prevSet = new Set(prev.answerValues);
        const currSet = new Set(curr.answerValues);
        const addedValues = curr.answerValues.filter((v) => !prevSet.has(v));
        const removedValues = prev.answerValues.filter((v) => !currSet.has(v));
        diffs.push({
          endpoint: curr.endpoint,
          shortLabel: curr.shortLabel,
          category: 'answer-ip-change',
          subKind: anySoaChangedAcrossFleet ? 'zone-update' : 'gslb-rotation',
          before: prev.answerValues.join(', ') || '(empty)',
          after: curr.answerValues.join(', ') || '(empty)',
          addedValues,
          removedValues,
        });
      }
    }

    // 4. DNSKEY Key-Tag set or Signer Key-Tag rollover
    const prevKeyTags =
      prev.dnskeyKeyTags.length > 0
        ? prev.dnskeyKeyTags.map((k) => `#${k}`).join(', ')
        : prev.rrsigMeta
          ? `signer #${prev.rrsigMeta.keyTag}`
          : '';
    const currKeyTags =
      curr.dnskeyKeyTags.length > 0
        ? curr.dnskeyKeyTags.map((k) => `#${k}`).join(', ')
        : curr.rrsigMeta
          ? `signer #${curr.rrsigMeta.keyTag}`
          : '';
    if (prevKeyTags && currKeyTags && prevKeyTags !== currKeyTags) {
      diffs.push({
        endpoint: curr.endpoint,
        shortLabel: curr.shortLabel,
        category: 'dnskey-keytag-change',
        before: prevKeyTags,
        after: currKeyTags,
      });
    }

    // 5. Online / Scheduled RRSIG Re-signing (inception / expiration window shift)
    if (
      prev.rrsigMeta &&
      curr.rrsigMeta &&
      (prev.rrsigMeta.inception !== curr.rrsigMeta.inception ||
        prev.rrsigMeta.expiration !== curr.rrsigMeta.expiration)
    ) {
      const fmtEpoch = (sec: number) =>
        new Date(sec * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
      diffs.push({
        endpoint: curr.endpoint,
        shortLabel: curr.shortLabel,
        category: 'rrsig-resign',
        before: `#${prev.rrsigMeta.keyTag} [${fmtEpoch(prev.rrsigMeta.inception)} → ${fmtEpoch(prev.rrsigMeta.expiration)}]`,
        after: `#${curr.rrsigMeta.keyTag} [${fmtEpoch(curr.rrsigMeta.inception)} → ${fmtEpoch(curr.rrsigMeta.expiration)}]`,
      });
    }
  }

  if (diffs.length === 0) return null;

  const categories = Array.from(new Set(diffs.map((d) => d.category)));
  const summaryParts: string[] = [];
  if (categories.includes('soa-serial-change')) {
    const soaDiffs = diffs.filter((d) => d.category === 'soa-serial-change');
    summaryParts.push(
      `SOA serial ${soaDiffs[0]!.before} → ${soaDiffs[0]!.after} (${soaDiffs.map((d) => d.shortLabel).join(', ')})`
    );
  }
  if (categories.includes('answer-ip-change')) {
    const ansDiffs = diffs.filter((d) => d.category === 'answer-ip-change');
    const isGslb = ansDiffs.every((d) => d.subKind === 'gslb-rotation');
    summaryParts.push(
      `${isGslb ? 'GSLB IP pool rotated' : 'Answer pool changed'} on ${ansDiffs.map((d) => d.shortLabel).join(', ')}`
    );
  }
  if (categories.includes('dnskey-keytag-change')) {
    const keyDiffs = diffs.filter((d) => d.category === 'dnskey-keytag-change');
    summaryParts.push(`DNSKEY key-tag change (${keyDiffs.map((d) => d.shortLabel).join(', ')})`);
  }
  if (categories.includes('rrsig-resign')) {
    const sigDiffs = diffs.filter((d) => d.category === 'rrsig-resign');
    summaryParts.push(`RRSIG re-signed on ${sigDiffs.map((d) => d.shortLabel).join(', ')}`);
  }
  if (categories.includes('rcode-ede-change')) {
    const rDiffs = diffs.filter((d) => d.category === 'rcode-ede-change');
    const staleHit = rDiffs.some((d) => d.subKind === 'serve-stale');
    summaryParts.push(
      `${staleHit ? 'RFC 8767 Serve-Stale / EDE' : 'RCODE / EDE'} shift on ${rDiffs.map((d) => d.shortLabel).join(', ')}`
    );
  }

  return {
    categories,
    headline: summaryParts.join(' · '),
    diffs,
  };
}

/**
 * Seeds an immediate zero-network `WatchTickSample` from an already-captured `AnalysisSnapshot`
 * so live TTL bars start ticking as soon as the user opens the Watch tab.
 */
export function seedWatchSampleFromSnapshot(
  snapshot: AnalysisSnapshot,
  preferredQtypeName?: string
): WatchTickSample {
  const targetName = normalizeFqdn(snapshot.targetName);
  const candidateTypeStr = (
    preferredQtypeName ??
    snapshot.queryTypes.find((t) =>
      (WATCHABLE_RR_TYPES as readonly string[]).includes(t.toUpperCase())
    ) ??
    'A'
  ).toUpperCase();
  const qtype = stringToRrType(candidateTypeStr);

  const leafZone =
    [...snapshot.zones]
      .filter((z) => isSubdomainOrEqual(targetName, z.zoneName))
      .sort((a, b) => b.depth - a.depth)[0]?.zoneName ?? targetName;

  // Determine which resolvers actually have packets in snapshot.queries
  const allPresets = getAvailableWatchResolvers(snapshot.dohEndpoint);
  const presentEndpoints = new Set(
    snapshot.queries
      .filter((q) => !q.ecsSubnet && !q.purpose.startsWith('ECS '))
      .map((q) => q.endpoint)
  );
  const activePresets = allPresets.filter((p) => presentEndpoints.has(p.url));
  const presetsToUse =
    activePresets.length > 0
      ? activePresets
      : [
          allPresets.find((p) => p.url === snapshot.dohEndpoint) ?? {
            url: snapshot.dohEndpoint,
            shortLabel: formatDohShortLabel(snapshot.dohEndpoint),
            provider: 'Primary DoH',
            description: snapshot.dohEndpoint,
            role: 'unfiltered' as const,
          },
        ];

  return buildWatchTickSample({
    tickNumber: 0,
    capturedAtMs: snapshot.capturedAt,
    targetName,
    qtype,
    soaZone: leafZone,
    presets: presetsToUse,
    queries: snapshot.queries,
  });
}

/**
 * Synthesizes a full `AnalysisSnapshot` from a `WatchTickSample` plus cached parent DNSSEC chain logs
 * so any transition event supports 1-click cryptographic & multi-resolver snapshot comparison.
 */
export async function synthesizeWatchTickSnapshot(params: {
  sample: WatchTickSample;
  primaryEndpoint: string;
  chainLogs: readonly DohQueryLog[];
  trustAnchors?: TrustAnchor[];
}): Promise<AnalysisSnapshot> {
  const { sample, primaryEndpoint, chainLogs, trustAnchors = IANA_ROOT_TRUST_ANCHORS } = params;

  // Combine cached parent chain logs with this tick's fresh multi-resolver logs,
  // promoting the primary (or first reachable unfiltered) resolver's target query to CD=1 Target RRset if needed
  const primaryResolverUrl =
    sample.resolvers.find((r) => r.endpoint === primaryEndpoint && r.reachable)?.endpoint ??
    sample.resolvers.find((r) => r.reachable && r.role === 'unfiltered')?.endpoint ??
    primaryEndpoint;

  const promotedTargetLogs: DohQueryLog[] = [];
  for (const q of sample.queries) {
    if (
      q.endpoint === primaryResolverUrl &&
      q.qname === sample.targetName &&
      q.qtype === sample.qtype &&
      !q.cd &&
      q.packet.flags.rcode !== 2
    ) {
      promotedTargetLogs.push({
        ...q,
        id: `${q.id}-target-cd`,
        cd: true,
        purpose: `Target RRset (${sample.targetName} ${sample.qtypeName})`,
      });
    }
  }

  // Filter out stale leaf SOA/DNSKEY from chainLogs when fresh ones exist in sample.queries
  const freshLeafKeys = new Set(
    sample.queries
      .filter((q) => q.cd && (q.qtype === RR_TYPES.SOA || q.qtype === RR_TYPES.DNSKEY))
      .map((q) => `${q.qname}|${q.qtype}`)
  );
  const filteredChainLogs = chainLogs.filter((q) => !freshLeafKeys.has(`${q.qname}|${q.qtype}`));
  const mergedQueries = [...filteredChainLogs, ...promotedTargetLogs, ...sample.queries];

  const baseSnap = await evaluateSnapshotFromLogs({
    id: `watch-snap-${sample.capturedAtMs}-t${sample.tickNumber}`,
    mode: 'consensus',
    targetName: sample.targetName,
    queryTypes: [sample.qtypeName],
    dohEndpoint: primaryResolverUrl,
    capturedAt: sample.capturedAtMs,
    validatedAt: sample.capturedAtMs,
    durationMs: Math.max(
      1,
      ...sample.resolvers.filter((r) => r.reachable).map((r) => r.latencyMs)
    ),
    queries: mergedQueries,
    trustAnchors,
  });

  const targetStatus: ValidationStatus =
    baseSnap.overallStatus === 'policy-error' ? 'secure' : baseSnap.overallStatus;
  const consensusEval = evaluateConsensusFromSnapshotData({
    targetName: baseSnap.targetName,
    primaryEndpoint: primaryResolverUrl,
    queries: baseSnap.queries,
    zones: baseSnap.zones,
    targetDomainStatus: targetStatus,
  });

  return {
    ...baseSnap,
    overallStatus: consensusEval.overallStatus,
    overallSummary: `[Watch Tick #${sample.tickNumber}] ${consensusEval.overallSummary}`,
    findings: [...consensusEval.consensusFindings, ...baseSnap.findings],
    consensusAnalysis: consensusEval.consensusAnalysis,
    note: `Live Watch Tick #${sample.tickNumber} (${sample.qtypeName})`,
  };
}

export interface WatchPulseRunnerOptions {
  targetName: string;
  qtypeName: WatchableRrType;
  primaryEndpoint?: string;
  resolverUrls?: readonly string[];
  trustAnchors?: TrustAnchor[];
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  tickNumber?: number;
  previousSample?: WatchTickSample | null;
  cachedChainState?: {
    soaZone: string;
    isSignedZone: boolean;
    chainLogs: DohQueryLog[];
  } | null;
}

export interface WatchPulseResult {
  sample: WatchTickSample;
  chainState: {
    soaZone: string;
    isSignedZone: boolean;
    chainLogs: DohQueryLog[];
  };
  buildSnapshot: () => Promise<AnalysisSnapshot>;
}

/**
 * Executes a single parallel multi-resolver TTL & cache-decay pulse across all selected DoH endpoints.
 */
export async function runWatchPulseTick(
  options: WatchPulseRunnerOptions
): Promise<WatchPulseResult> {
  const targetName = normalizeFqdn(options.targetName);
  const qtype = stringToRrType(options.qtypeName);
  const qtypeName = rrTypeToString(qtype);
  const primaryEndpoint = options.primaryEndpoint ?? DEFAULT_DOH_ENDPOINT;
  const allPresets = getAvailableWatchResolvers(primaryEndpoint);
  const requestedUrls =
    options.resolverUrls && options.resolverUrls.length > 0
      ? options.resolverUrls
      : getDefaultWatchResolverUrls(primaryEndpoint);

  const selectedPresets: DohServerPreset[] = requestedUrls.map(
    (url) =>
      allPresets.find((p) => p.url === url) ?? {
        url,
        shortLabel: formatDohShortLabel(url),
        provider: 'Custom DoH',
        description: url,
        role: 'unfiltered' as const,
      }
  );

  // Step 1: Discover zone cuts & parent DNSKEY/DS chain once per domain (cached across ticks)
  let chainState = options.cachedChainState ?? null;
  if (!chainState) {
    const chainSession = new DohSession({
      endpoint: primaryEndpoint,
      timeoutMs: options.timeoutMs ?? 5000,
      fetchImpl: options.fetchImpl,
      signal: options.signal,
    });
    const discoveredZones = new Set<string>(['.']);
    const checkedCandidates = new Set<string>(['.']);

    await Promise.all([
      discoverZoneCutsForName(chainSession, targetName, discoveredZones, checkedCandidates),
      chainSession
        .query(targetName, qtype, {
          cd: true,
          doBit: true,
          purpose: `Target RRset (${targetName} ${qtypeName})`,
        })
        .catch(() => undefined),
    ]);

    for (const log of chainSession.getLogs()) {
      if (!log.cd) continue;
      for (const auth of log.packet.authorities) {
        if (auth.type === RR_TYPES.SOA) {
          discoveredZones.add(normalizeFqdn(auth.name));
        }
      }
    }

    const zoneList = Array.from(discoveredZones);
    await Promise.all(
      zoneList.flatMap((z) => {
        const tasks = [
          chainSession
            .query(z, RR_TYPES.DNSKEY, { cd: true, doBit: true, purpose: `Zone DNSKEY (${z})` })
            .catch(() => undefined),
          chainSession
            .query(z, RR_TYPES.SOA, { cd: true, doBit: true, purpose: `Zone SOA (${z})` })
            .catch(() => undefined),
          chainSession
            .query(z, RR_TYPES.NS, { cd: true, doBit: true, purpose: `Zone NS (${z})` })
            .catch(() => undefined),
        ];
        if (z !== '.') {
          tasks.push(
            chainSession
              .query(z, RR_TYPES.DS, { cd: true, doBit: true, purpose: `Delegation DS (${z})` })
              .catch(() => undefined)
          );
        }
        return tasks;
      })
    );

    const soaZone =
      zoneList
        .filter((z) => isSubdomainOrEqual(targetName, z))
        .sort((a, b) => b.length - a.length)[0] ?? targetName;
    const leafDnskeyLog = chainSession
      .getLogs()
      .find((l) => l.qname === soaZone && l.qtype === RR_TYPES.DNSKEY);
    const isSignedZone = Boolean(
      leafDnskeyLog?.packet.answers.some((r) => r.type === RR_TYPES.DNSKEY)
    );

    chainState = {
      soaZone,
      isSignedZone,
      chainLogs: chainSession.getLogs(),
    };
  }

  // Step 2: Parallel multi-resolver Watch probes (Target QTYPE + Leaf SOA + Leaf DNSKEY when signed)
  const tickQueries: DohQueryLog[] = [];
  await Promise.all(
    selectedPresets.map(async (preset) => {
      const rSession = new DohSession({
        endpoint: preset.url,
        timeoutMs: Math.min(options.timeoutMs ?? 4500, 4500),
        fetchImpl: options.fetchImpl,
        signal: options.signal,
      });

      const tasks: Promise<unknown>[] = [
        rSession
          .query(targetName, qtype, {
            cd: false,
            doBit: true,
            purpose: `Watch probe (${preset.shortLabel} ${qtypeName})`,
          })
          .catch(() => undefined),
      ];

      if (qtype !== RR_TYPES.SOA) {
        tasks.push(
          rSession
            .query(chainState!.soaZone, RR_TYPES.SOA, {
              cd: true,
              doBit: true,
              purpose: `Watch probe (${preset.shortLabel} SOA)`,
            })
            .catch(() => undefined)
        );
      }

      if (chainState!.isSignedZone && qtype !== RR_TYPES.DNSKEY) {
        tasks.push(
          rSession
            .query(chainState!.soaZone, RR_TYPES.DNSKEY, {
              cd: true,
              doBit: true,
              purpose: `Watch probe (${preset.shortLabel} DNSKEY)`,
            })
            .catch(() => undefined)
        );
      }

      await Promise.all(tasks);
      tickQueries.push(...rSession.getLogs());
    })
  );

  const capturedAtMs = Date.now();
  const sample = buildWatchTickSample({
    tickNumber: options.tickNumber ?? 1,
    capturedAtMs,
    targetName,
    qtype,
    soaZone: chainState.soaZone,
    presets: selectedPresets,
    queries: tickQueries,
    previousSample: options.previousSample,
  });

  let memoizedSnapshot: Promise<AnalysisSnapshot> | null = null;
  const buildSnapshot = () => {
    if (!memoizedSnapshot) {
      memoizedSnapshot = synthesizeWatchTickSnapshot({
        sample,
        primaryEndpoint,
        chainLogs: chainState!.chainLogs,
        trustAnchors: options.trustAnchors,
      });
    }
    return memoizedSnapshot;
  };

  return {
    sample,
    chainState,
    buildSnapshot,
  };
}

export interface CreateTtlWatchControllerOptions {
  targetName: string;
  qtypeName?: WatchableRrType;
  pollMode?: WatchPollMode;
  maxIterations?: number;
  enabledResolverUrls?: string[];
  primaryEndpoint?: string;
  trustAnchors?: TrustAnchor[];
  initialSnapshot?: AnalysisSnapshot | null;
  fetchImpl?: typeof fetch;
  nowFn?: () => number;
  probeTickFn?: (opts: WatchPulseRunnerOptions) => Promise<WatchPulseResult>;
  onUpdate?: (state: TtlWatchState) => void;
}

export interface TtlWatchController {
  getState: () => TtlWatchState;
  pulseOnce: () => Promise<TtlWatchState>;
  start: (overrideMode?: WatchPollMode) => Promise<void>;
  pause: () => void;
  resume: () => void;
  stop: () => void;
  continueBeyondCap: (extraIterations?: number) => void;
  updateConfig: (patch: {
    qtypeName?: WatchableRrType;
    pollMode?: WatchPollMode;
    maxIterations?: number;
    enabledResolverUrls?: string[];
  }) => void;
  handleVisibilityChange: (isHidden: boolean) => void;
}

/**
 * Creates a bounded, visibility-aware client-side Live TTL Watch controller supporting:
 * - Immediate single pulses (`pulseOnce`)
 * - Fixed interval polling (`15s`, `30s`, `60s`)
 * - Smart `TTL=0` expiry polling (`expiry-once` single re-query at `TTL=0` & `expiry-continuous`)
 * - Automatic background-tab pause (`handleVisibilityChange(true)` -> `'paused-hidden'`)
 * - Bounded `maxIterations` cap (`'completed-cap'`)
 * - Change-Only Transition Timeline with synthesized `AnalysisSnapshot` pairs
 */
export function createTtlWatchController(
  options: CreateTtlWatchControllerOptions
): TtlWatchController {
  const nowFn = options.nowFn ?? (() => Date.now());
  const probeFn = options.probeTickFn ?? runWatchPulseTick;
  const primaryEndpoint = options.primaryEndpoint ?? DEFAULT_DOH_ENDPOINT;
  const targetName = normalizeFqdn(options.targetName);
  const displayDomain = displayFqdn(targetName);

  const initialQtype: WatchableRrType =
    options.qtypeName ??
    ((options.initialSnapshot?.queryTypes.find((t) =>
      (WATCHABLE_RR_TYPES as readonly string[]).includes(t.toUpperCase())
    )?.toUpperCase() as WatchableRrType | undefined) ?? 'A');

  const seededSample =
    options.initialSnapshot && normalizeFqdn(options.initialSnapshot.targetName) === targetName
      ? seedWatchSampleFromSnapshot(options.initialSnapshot, initialQtype)
      : null;

  let state: TtlWatchState = {
    targetName,
    displayDomain,
    qtypeName: initialQtype,
    pollMode: options.pollMode ?? 'expiry-once',
    maxIterations: Math.max(1, Math.min(60, options.maxIterations ?? DEFAULT_WATCH_MAX_ITERATIONS)),
    enabledResolverUrls:
      options.enabledResolverUrls && options.enabledResolverUrls.length > 0
        ? [...options.enabledResolverUrls]
        : getDefaultWatchResolverUrls(primaryEndpoint),
    status: 'idle',
    completedTicks: 0,
    nextPollAtMs: null,
    currentSample: seededSample,
    latestSnapshot: options.initialSnapshot ?? null,
    transitions: [],
  };

  let timerId: ReturnType<typeof setTimeout> | null = null;
  let activeAbort: AbortController | null = null;
  let inFlightTick = false;
  let cachedChainState: WatchPulseResult['chainState'] | null = null;
  let prevTickBuildSnapshot: (() => Promise<AnalysisSnapshot>) | null = options.initialSnapshot
    ? async () => options.initialSnapshot!
    : null;
  let activeWatchLoop = false;

  const clearScheduledTimer = () => {
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
    state = { ...state, nextPollAtMs: null };
  };

  const emit = () => {
    options.onUpdate?.({
      ...state,
      enabledResolverUrls: [...state.enabledResolverUrls],
      transitions: [...state.transitions],
    });
  };

  const scheduleNextTick = () => {
    clearScheduledTimer();
    if (!activeWatchLoop) return;
    if (state.pollMode === 'manual') {
      activeWatchLoop = false;
      state = { ...state, status: 'idle', nextPollAtMs: null };
      emit();
      return;
    }
    if (state.completedTicks >= state.maxIterations) {
      activeWatchLoop = false;
      state = { ...state, status: 'completed-cap', nextPollAtMs: null };
      emit();
      return;
    }

    const now = nowFn();
    const delayMs = computeNextWatchDelayMs(state.pollMode, state.currentSample, now);
    if (delayMs === null) {
      activeWatchLoop = false;
      state = { ...state, status: 'idle', nextPollAtMs: null };
      emit();
      return;
    }

    const nextAt = now + delayMs;
    state = { ...state, status: 'running', nextPollAtMs: nextAt };
    emit();

    timerId = setTimeout(() => {
      timerId = null;
      void executeTick({ fromScheduledTimer: true });
    }, delayMs);
  };

  const executeTick = async (meta: { fromScheduledTimer: boolean }): Promise<TtlWatchState> => {
    if (inFlightTick) return state;
    inFlightTick = true;
    clearScheduledTimer();

    const abortController = new AbortController();
    activeAbort = abortController;
    const prevSample = state.currentSample;
    const prevBuilder = prevTickBuildSnapshot;
    const nextTickNum = state.completedTicks + 1;

    state = {
      ...state,
      status: 'pulsing',
      lastError: undefined,
    };
    emit();

    try {
      const res = await probeFn({
        targetName: state.targetName,
        qtypeName: state.qtypeName,
        primaryEndpoint,
        resolverUrls: state.enabledResolverUrls,
        trustAnchors: options.trustAnchors,
        fetchImpl: options.fetchImpl,
        signal: abortController.signal,
        tickNumber: nextTickNum,
        previousSample: prevSample,
        cachedChainState,
      });

      if (abortController.signal.aborted) {
        return state;
      }

      cachedChainState = res.chainState;

      let nextTransitions = state.transitions;
      let nextLatestSnapshot = state.latestSnapshot;

      if (prevSample && prevSample.tickNumber >= 1) {
        const detected = detectWatchTransitions(prevSample, res.sample);
        if (detected) {
          const [prevSnap, currSnap] = await Promise.all([
            prevBuilder ? prevBuilder() : res.buildSnapshot(),
            res.buildSnapshot(),
          ]);
          const transitionEvent: WatchTransitionEvent = {
            id: `watch-tr-${res.sample.capturedAtMs}-${nextTickNum}`,
            tickNumber: nextTickNum,
            detectedAtMs: res.sample.capturedAtMs,
            categories: detected.categories,
            headline: detected.headline,
            diffs: detected.diffs,
            previousSample: prevSample,
            currentSample: res.sample,
            previousSnapshot: prevSnap,
            currentSnapshot: currSnap,
          };
          nextTransitions = [transitionEvent, ...state.transitions].slice(0, 50);
          nextLatestSnapshot = currSnap;
        }
      } else {
        // Synthesize baseline snapshot on Tick #1
        nextLatestSnapshot = await res.buildSnapshot();
      }

      prevTickBuildSnapshot = res.buildSnapshot;

      state = {
        ...state,
        completedTicks: nextTickNum,
        currentSample: res.sample,
        latestSnapshot: nextLatestSnapshot,
        transitions: nextTransitions,
      };

      // If pollMode is 'expiry-once' and this tick WAS the automatic TTL=0 re-query, stop cleanly!
      if (activeWatchLoop && state.pollMode === 'expiry-once' && meta.fromScheduledTimer) {
        activeWatchLoop = false;
        state = { ...state, status: 'idle', nextPollAtMs: null };
        emit();
      } else if (activeWatchLoop) {
        scheduleNextTick();
      } else {
        state = { ...state, status: 'idle', nextPollAtMs: null };
        emit();
      }
    } catch (err) {
      if (!abortController.signal.aborted) {
        state = {
          ...state,
          status: activeWatchLoop ? 'paused' : 'idle',
          nextPollAtMs: null,
          lastError: err instanceof Error ? err.message : 'Live Watch DoH query failed',
        };
        activeWatchLoop = false;
        emit();
      }
    } finally {
      if (activeAbort === abortController) {
        activeAbort = null;
      }
      inFlightTick = false;
    }

    return state;
  };

  return {
    getState: () => ({
      ...state,
      enabledResolverUrls: [...state.enabledResolverUrls],
      transitions: [...state.transitions],
    }),

    pulseOnce: async () => {
      return await executeTick({ fromScheduledTimer: false });
    },

    start: async (overrideMode?: WatchPollMode) => {
      if (overrideMode) {
        state = {
          ...state,
          pollMode: overrideMode,
        };
      }
      if (state.pollMode === 'manual') {
        state = { ...state, pollMode: 'expiry-once' };
      }
      if (state.completedTicks >= state.maxIterations) {
        state = { ...state, maxIterations: state.completedTicks + DEFAULT_WATCH_MAX_ITERATIONS };
      }
      activeWatchLoop = true;

      // If we don't have a live multi-resolver tick yet (tickNumber === 0 seeded or null), run baseline Tick #1 immediately
      if (!state.currentSample || state.currentSample.tickNumber === 0) {
        await executeTick({ fromScheduledTimer: false });
      } else {
        scheduleNextTick();
      }
    },

    pause: () => {
      activeWatchLoop = false;
      activeAbort?.abort();
      clearScheduledTimer();
      state = { ...state, status: 'paused', nextPollAtMs: null };
      emit();
    },

    resume: () => {
      if (state.pollMode === 'manual') {
        state = { ...state, pollMode: 'expiry-once' };
      }
      if (state.completedTicks >= state.maxIterations) {
        state = { ...state, maxIterations: state.completedTicks + DEFAULT_WATCH_MAX_ITERATIONS };
      }
      activeWatchLoop = true;
      scheduleNextTick();
    },

    stop: () => {
      activeWatchLoop = false;
      activeAbort?.abort();
      clearScheduledTimer();
      state = { ...state, status: 'idle', nextPollAtMs: null };
      emit();
    },

    continueBeyondCap: (extraIterations = DEFAULT_WATCH_MAX_ITERATIONS) => {
      state = {
        ...state,
        maxIterations: state.completedTicks + Math.max(1, extraIterations),
      };
      activeWatchLoop = true;
      scheduleNextTick();
    },

    updateConfig: (patch) => {
      const qtypeChanged = patch.qtypeName && patch.qtypeName !== state.qtypeName;
      const resolversChanged =
        patch.enabledResolverUrls &&
        patch.enabledResolverUrls.join('|') !== state.enabledResolverUrls.join('|');

      state = {
        ...state,
        ...(patch.qtypeName ? { qtypeName: patch.qtypeName } : {}),
        ...(patch.pollMode ? { pollMode: patch.pollMode } : {}),
        ...(patch.maxIterations !== undefined
          ? { maxIterations: Math.max(1, Math.min(100, patch.maxIterations)) }
          : {}),
        ...(patch.enabledResolverUrls && patch.enabledResolverUrls.length > 0
          ? { enabledResolverUrls: [...patch.enabledResolverUrls] }
          : {}),
      };

      if (qtypeChanged) {
        // Reset tick baseline when switching watched RR type so we don't diff A against MX
        activeWatchLoop = false;
        activeAbort?.abort();
        clearScheduledTimer();
        state = {
          ...state,
          status: 'idle',
          completedTicks: 0,
          currentSample:
            options.initialSnapshot &&
            normalizeFqdn(options.initialSnapshot.targetName) === targetName
              ? seedWatchSampleFromSnapshot(options.initialSnapshot, state.qtypeName)
              : null,
          transitions: [],
        };
      } else if (activeWatchLoop && (patch.pollMode || resolversChanged || patch.maxIterations)) {
        scheduleNextTick();
        return;
      }
      emit();
    },

    handleVisibilityChange: (isHidden: boolean) => {
      if (isHidden && (activeWatchLoop || state.status === 'running' || state.status === 'pulsing')) {
        activeWatchLoop = false;
        activeAbort?.abort();
        clearScheduledTimer();
        state = { ...state, status: 'paused-hidden', nextPollAtMs: null };
        emit();
      }
    },
  };
}
