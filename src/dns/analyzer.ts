import {
  DEFAULT_DOH_ENDPOINT,
  DNSSEC_ALGORITHMS,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  formatAlgorithm,
  formatDigestType,
  rcodeToString,
  rrTypeToString,
  stringToRrType,
  type TrustAnchor,
} from './constants';
import {
  computeDsDigest,
  verifyDsAgainstZoneKeys,
  verifyNegativeProof,
  verifyRrsigForRrset,
} from './crypto';
import { DohSession, type DohClientOptions } from './doh';
import {
  base64ToBytes,
  displayFqdn,
  getDomainHierarchy,
  isSubdomainOrEqual,
  normalizeFqdn,
} from './encoding';
import { evaluateMailFromSnapshotData } from './mailAnalyzer';
import type {
  AnalysisMode,
  AnalysisProgress,
  AnalysisSnapshot,
  AnalyzedDnskey,
  AnalyzedRrset,
  AuditFinding,
  CnameEdge,
  DnsRecord,
  DnskeyRdata,
  DohQueryLog,
  DsVerification,
  NameserverEntry,
  ResolverVerdict,
  RrsigVerification,
  SoaRdata,
  ValidationStatus,
  ZoneAnalysis,
} from './types';

export const SNAPSHOT_ENGINE_VERSION = 5;

export interface AnalyzeOptions extends DohClientOptions {
  queryTypes?: string[];
  dkimSelectors?: string[];
  trustAnchors?: TrustAnchor[];
  validationTimeMs?: number;
  onProgress?: (progress: AnalysisProgress) => void;
}

export function findLog(
  logs: DohQueryLog[],
  qname: string,
  qtype: number,
  cd = true
): DohQueryLog | undefined {
  const norm = normalizeFqdn(qname);
  return logs.find((l) => l.qname === norm && l.qtype === qtype && l.cd === cd);
}

/**
 * Determines whether `candidate` is an actual zone cut (delegated zone apex) based on SOA + DS responses.
 */
function isCandidateZoneApex(
  candidate: string,
  soaLog?: DohQueryLog,
  dsLog?: DohQueryLog
): boolean {
  const cand = normalizeFqdn(candidate);
  if (cand === '.') return true;

  // If candidate itself has a CNAME in SOA or DS answer, it's an alias, NOT a zone apex!
  const hasCnameAtCand = [
    ...(soaLog?.packet.answers ?? []),
    ...(dsLog?.packet.answers ?? []),
  ].some((r) => r.name === cand && r.type === RR_TYPES.CNAME);
  if (hasCnameAtCand) return false;

  // 1. Direct SOA record at candidate owner name
  const hasDirectSoa = [
    ...(soaLog?.packet.answers ?? []),
    ...(soaLog?.packet.authorities ?? []),
  ].some((r) => r.name === cand && r.type === RR_TYPES.SOA);
  if (hasDirectSoa) return true;

  // 2. DS record exists for candidate in parent zone
  const hasDirectDs = (dsLog?.packet.answers ?? []).some(
    (r) => r.name === cand && r.type === RR_TYPES.DS
  );
  if (hasDirectDs) return true;

  // 3. Unsigned delegation where child SOA query SERVFAILed, but parent DS query returned NSEC at cand with NS bit set
  const hasDelegationNsec = (dsLog?.packet.authorities ?? []).some(
    (r) =>
      r.name === cand &&
      r.parsed.kind === 'NSEC' &&
      !r.parsed.nextDomainName.startsWith('\\000.') &&
      r.parsed.typeNames.includes('NS') &&
      !r.parsed.typeNames.includes('SOA')
  );
  if (hasDelegationNsec) return true;

  // 4. If SOA query returned SERVFAIL/REFUSED with CD=1 AND DS query did NOT return NXDOMAIN and parent SOA is strictly above cand
  if (
    soaLog &&
    (soaLog.packet.flags.rcode === 2 || soaLog.packet.flags.rcode === 5) &&
    dsLog &&
    dsLog.packet.flags.rcode === 0
  ) {
    const authNsec3OptOut = dsLog.packet.authorities.some(
      (r) => r.parsed.kind === 'NSEC3' && r.parsed.optOut
    );
    if (authNsec3OptOut) return true;
  }

  return false;
}

/**
 * Discovers all zone cuts along `fqdn` using parallel SOA + DS queries.
 */
export async function discoverZoneCutsForName(
  session: DohSession,
  fqdn: string,
  discoveredZones: Set<string>,
  checkedCandidates: Set<string>
): Promise<void> {
  discoveredZones.add('.');
  const hierarchy = getDomainHierarchy(fqdn);
  const candidates = hierarchy.slice(1).filter((c) => !checkedCandidates.has(c));
  if (candidates.length === 0) return;

  for (const c of candidates) checkedCandidates.add(c);

  await Promise.all(
    candidates.flatMap((cand) => [
      session.query(cand, RR_TYPES.SOA, { cd: true, doBit: true, purpose: `Zone-cut probe (${cand} SOA)` }),
      session.query(cand, RR_TYPES.DS, { cd: true, doBit: true, purpose: `Delegation probe (${cand} DS)` }),
    ])
  );

  const logs = session.getLogs();
  for (const cand of candidates) {
    const soaLog = findLog(logs, cand, RR_TYPES.SOA, true);
    const dsLog = findLog(logs, cand, RR_TYPES.DS, true);
    if (isCandidateZoneApex(cand, soaLog, dsLog)) {
      discoveredZones.add(cand);
    }
  }
}

/**
 * Runs a full live client-side DNSViz trace & cryptographic analysis via 1.1.1.1 DoH.
 */
export async function runDnsvizAnalysis(
  rawDomain: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisSnapshot> {
  const startedAt = Date.now();
  const targetName = normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const queryTypes =
    options.queryTypes && options.queryTypes.length > 0
      ? Array.from(new Set(options.queryTypes.map((t) => t.toUpperCase())))
      : ['A', 'AAAA'];
  const trustAnchors = options.trustAnchors ?? IANA_ROOT_TRUST_ANCHORS;
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;

  const session = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs,
    fetchImpl: options.fetchImpl,
  });

  let currentPhase: AnalysisProgress['phase'] = 'zone-cuts';
  session.onQueryCompleted = (count, lastLog) => {
    options.onProgress?.({
      phase: currentPhase,
      message: `Resolved ${lastLog.qname} ${lastLog.qtypeName} (${lastLog.latencyMs}ms)`,
      completedQueries: count,
    });
  };

  options.onProgress?.({
    phase: 'zone-cuts',
    message: `Discovering zone cuts from root (.) to ${displayDomain}…`,
    completedQueries: 0,
  });

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);

  // Phase 1 & 2: Discover initial zone cuts AND query target RRsets in parallel
  const primaryTypeNum = stringToRrType(queryTypes[0]);
  await Promise.all([
    discoverZoneCutsForName(session, targetName, discoveredZones, checkedCandidates),
    ...queryTypes.map((t) =>
      session.query(targetName, stringToRrType(t), {
        cd: true,
        doBit: true,
        purpose: `Target RRset (${targetName} ${t})`,
      })
    ),
    // Also perform one validating query (CD=0, DO=1) so we capture 1.1.1.1's own AD bit & RCODE
    session.query(targetName, primaryTypeNum, {
      cd: false,
      doBit: true,
      purpose: `1.1.1.1 validating check (${targetName} ${queryTypes[0]}, CD=0)`,
    }),
  ]);

  // Phase 2b: Follow any CNAME chains (including cross-zone CNAME targets!)
  currentPhase = 'targets';
  const visitedTargets = new Set<string>([targetName]);
  let frontier = [targetName];
  for (let hop = 0; hop < 6 && frontier.length > 0; hop++) {
    const nextFrontier: string[] = [];
    const logsSnapshot = session.getLogs();

    for (const name of frontier) {
      for (const qt of queryTypes) {
        const qtypeNum = stringToRrType(qt);
        const log = findLog(logsSnapshot, name, qtypeNum, true);
        if (!log) continue;

        let curOwner = name;
        for (let step = 0; step < 8; step++) {
          const cnameRec = log.packet.answers.find(
            (r) => r.name === curOwner && r.type === RR_TYPES.CNAME
          );
          if (!cnameRec || cnameRec.parsed.kind !== 'GENERIC' || !cnameRec.parsed.target) {
            break;
          }
          const target = normalizeFqdn(cnameRec.parsed.target);
          if (!visitedTargets.has(target)) {
            visitedTargets.add(target);
            nextFrontier.push(target);
          }
          curOwner = target;
        }
      }
    }

    if (nextFrontier.length > 0) {
      await Promise.all([
        ...nextFrontier.map((cnameTarget) =>
          discoverZoneCutsForName(session, cnameTarget, discoveredZones, checkedCandidates)
        ),
        ...nextFrontier.flatMap((cnameTarget) =>
          queryTypes
            .filter((qt) => qt !== 'CNAME')
            .map((qt) =>
              session.query(cnameTarget, stringToRrType(qt), {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cnameTarget} ${qt})`,
              })
            )
        ),
      ]);
    }
    frontier = nextFrontier;
  }

  // Also ensure any SOA authority owner names returned in responses are included in discoveredZones
  for (const log of session.getLogs()) {
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Phase 3: Fetch DNSKEY, DS (except root), SOA, and NS for every discovered zone
  currentPhase = 'security-records';
  options.onProgress?.({
    phase: 'security-records',
    message: `Fetching DNSKEY, DS, SOA & NS records across ${discoveredZones.size} zones…`,
    completedQueries: session.getLogs().length,
  });

  const zoneList = Array.from(discoveredZones);
  await Promise.all(
    zoneList.flatMap((z) => {
      const tasks = [
        session.query(z, RR_TYPES.DNSKEY, { cd: true, doBit: true, purpose: `Zone DNSKEY (${z})` }),
        session.query(z, RR_TYPES.SOA, { cd: true, doBit: true, purpose: `Zone SOA (${z})` }),
        session.query(z, RR_TYPES.NS, { cd: true, doBit: true, purpose: `Zone NS (${z})` }),
      ];
      if (z !== '.') {
        tasks.push(
          session.query(z, RR_TYPES.DS, { cd: true, doBit: true, purpose: `Delegation DS (${z})` })
        );
      }
      return tasks;
    })
  );

  // Phase 4: Resolve IPv4 / IPv6 for the leaf zone(s) authoritative nameservers (up to 6 hosts)
  currentPhase = 'nameservers';
  const leafZones = zoneList
    .sort((a, b) => getDomainHierarchy(b).length - getDomainHierarchy(a).length)
    .slice(0, 2);
  const nsHosts = new Set<string>();
  const currentLogs = session.getLogs();
  for (const lz of leafZones) {
    const nsLog = findLog(currentLogs, lz, RR_TYPES.NS, true);
    for (const rec of nsLog?.packet.answers ?? []) {
      if (rec.type === RR_TYPES.NS && rec.parsed.kind === 'GENERIC' && rec.parsed.target) {
        nsHosts.add(normalizeFqdn(rec.parsed.target));
        if (nsHosts.size >= 6) break;
      }
    }
  }

  if (nsHosts.size > 0) {
    await Promise.all(
      Array.from(nsHosts).flatMap((host) => [
        session
          .query(host, RR_TYPES.A, { cd: true, doBit: false, purpose: `Nameserver IP (${host} A)` })
          .catch(() => undefined),
        session
          .query(host, RR_TYPES.AAAA, {
            cd: true,
            doBit: false,
            purpose: `Nameserver IPv6 (${host} AAAA)`,
          })
          .catch(() => undefined),
      ])
    );
  }

  // Phase 5: Cryptographic validation & graph synthesis
  currentPhase = 'validating';
  options.onProgress?.({
    phase: 'validating',
    message: 'Verifying DNSSEC cryptographic chain of trust via WebCrypto…',
    completedQueries: session.getLogs().length,
  });

  const capturedAt = Date.now();
  const validatedAt = options.validationTimeMs ?? capturedAt;
  const durationMs = Math.max(1, capturedAt - startedAt);

  return evaluateSnapshotFromLogs({
    id: `snap-${capturedAt}-${Math.random().toString(36).slice(2, 8)}`,
    targetName,
    queryTypes,
    dohEndpoint: endpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries: session.getLogs(),
    trustAnchors,
  });
}

/**
 * Re-runs 100% client-side DNSSEC validation on an existing `AnalysisSnapshot`
 * (e.g. from `localStorage` with a custom validation timestamp or modified trust anchors)
 * with ZERO network requests.
 */
export async function reverifySnapshot(
  snapshot: AnalysisSnapshot,
  options: { validationTimeMs?: number; trustAnchors?: TrustAnchor[] } = {}
): Promise<AnalysisSnapshot> {
  const updated = await evaluateSnapshotFromLogs({
    id: snapshot.id,
    mode: snapshot.mode,
    targetName: snapshot.targetName,
    queryTypes: snapshot.queryTypes,
    customDkimSelectors: snapshot.customDkimSelectors,
    dohEndpoint: snapshot.dohEndpoint,
    capturedAt: snapshot.capturedAt,
    validatedAt: options.validationTimeMs ?? snapshot.validatedAt,
    durationMs: snapshot.durationMs,
    queries: snapshot.queries,
    trustAnchors: options.trustAnchors ?? snapshot.trustAnchorsUsed,
  });
  return {
    ...updated,
    pinned: snapshot.pinned,
    note: snapshot.note,
  };
}

interface EvaluateInput {
  id: string;
  mode?: AnalysisMode;
  targetName: string;
  queryTypes: string[];
  customDkimSelectors?: string[];
  dohEndpoint: string;
  capturedAt: number;
  validatedAt: number;
  durationMs: number;
  queries: DohQueryLog[];
  trustAnchors: TrustAnchor[];
}

function findDeepestParentZone(zoneName: string, allZones: Set<string>): string | null {
  if (zoneName === '.') return null;
  const hier = getDomainHierarchy(zoneName);
  // Walk backwards excluding zoneName itself
  for (let i = hier.length - 2; i >= 0; i--) {
    if (allZones.has(hier[i])) return hier[i];
  }
  return '.';
}

function findAuthoritativeZoneForOwner(
  owner: string,
  rrtype: number,
  signerName: string | undefined,
  allZones: Set<string>,
  section: 'answer' | 'authority' = 'answer'
): string {
  if (signerName && allZones.has(normalizeFqdn(signerName))) {
    return normalizeFqdn(signerName);
  }
  const norm = normalizeFqdn(owner);
  const hier = getDomainHierarchy(norm);
  // DS records and unsigned referral NS records in the authority section belong to the parent zone
  if (
    (rrtype === RR_TYPES.DS ||
      (rrtype === RR_TYPES.NS && !signerName && section === 'authority' && allZones.has(norm))) &&
    norm !== '.'
  ) {
    for (let i = hier.length - 2; i >= 0; i--) {
      if (allZones.has(hier[i])) return hier[i];
    }
    return '.';
  }
  for (let i = hier.length - 1; i >= 0; i--) {
    if (allZones.has(hier[i])) return hier[i];
  }
  return '.';
}

export async function evaluateSnapshotFromLogs(input: EvaluateInput): Promise<AnalysisSnapshot> {
  const {
    id,
    mode = 'dnssec',
    targetName,
    queryTypes,
    customDkimSelectors,
    dohEndpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries,
    trustAnchors,
  } = input;

  const validationEpochSec = Math.floor(validatedAt / 1000);
  const enabledAnchors = trustAnchors.filter((ta) => ta.enabled);
  // Exclude auxiliary out-of-bailiwick nameserver IP, recursive SPF, DMARC report, and speculative DKIM helper lookups from DNSSEC zone reconstruction
  const cdLogs = queries.filter(
    (q) =>
      q.cd &&
      !q.purpose.startsWith('Nameserver IP') &&
      !q.purpose.startsWith('SPF lookup') &&
      !q.purpose.startsWith('DMARC lookup') &&
      !q.purpose.startsWith('DKIM probe')
  );

  // Reconstruct set of discovered zones from DNSKEY queries + SOA records
  const allZones = new Set<string>(['.']);
  for (const log of cdLogs) {
    if (log.qtype === RR_TYPES.DNSKEY) {
      allZones.add(normalizeFqdn(log.qname));
    }
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        allZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Ensure targetName's zone cuts are only genuine zones (filter out CNAMEs if someone queried DNSKEY directly on a CNAME!)
  for (const z of Array.from(allZones)) {
    if (z === '.') continue;
    const dnskeyLog = findLog(cdLogs, z, RR_TYPES.DNSKEY, true);
    const soaLog = findLog(cdLogs, z, RR_TYPES.SOA, true);
    const dsLog = findLog(cdLogs, z, RR_TYPES.DS, true);
    const isCname = (dnskeyLog?.packet.answers ?? []).some(
      (r) => r.name === z && r.type === RR_TYPES.CNAME
    );
    if (isCname) {
      allZones.delete(z);
    } else if (
      targetName === z &&
      queryTypes.includes('DNSKEY') &&
      !isCandidateZoneApex(z, soaLog, dsLog) &&
      !(dnskeyLog?.packet.answers ?? []).some((r) => r.name === z && r.type === RR_TYPES.DNSKEY)
    ) {
      allZones.delete(z);
    }
  }

  const sortedZoneNames = Array.from(allZones).sort((a, b) => {
    const da = a === '.' ? 0 : a.slice(0, -1).split('.').length;
    const db = b === '.' ? 0 : b.slice(0, -1).split('.').length;
    if (da !== db) return da - db;
    return a.localeCompare(b);
  });

  // Collect DNSKEY records per zone
  const rawZoneDnskeys = new Map<string, DnsRecord[]>();
  for (const z of sortedZoneNames) {
    const kLog = findLog(cdLogs, z, RR_TYPES.DNSKEY, true);
    const keys = (kLog?.packet.answers ?? []).filter(
      (r) => r.name === z && r.type === RR_TYPES.DNSKEY
    );
    rawZoneDnskeys.set(z, keys);
  }

  // Collect all relevant RRsets across cdLogs (preserving atomic per-packet RRset integrity!)
  // IMPORTANT: Never merge distinct canonical RRset fingerprints across separate DNS responses
  // into a synthetic RRset — e.g. Cloudflare RFC 4470 "Black Lies" synthesizes a different NSEC
  // type bitmap per queried QTYPE at the same owner name (`0dot1.net. NSEC`), and each RRSIG
  // signs ONLY the exact RRset returned in that response packet.
  interface CollectedGroup {
    id: string;
    zone: string;
    name: string;
    type: number;
    fingerprint: string;
    section: 'answer' | 'authority';
    records: DnsRecord[];
    rrsigRecords: DnsRecord[];
    isQueryTarget: boolean;
  }

  const groupMap = new Map<string, CollectedGroup>();
  const variantCountByBaseKey = new Map<string, number>();

  const addSectionRecords = (
    records: DnsRecord[],
    section: 'answer' | 'authority',
    isTargetQuery: boolean
  ) => {
    const nonSigs = records.filter((r) => r.type !== RR_TYPES.RRSIG);
    const sigs = records.filter((r) => r.type === RR_TYPES.RRSIG && r.parsed.kind === 'RRSIG');

    // Group non-RRSIG records within THIS single packet section by (name, type)
    const byOwnerType = new Map<string, DnsRecord[]>();
    for (const r of nonSigs) {
      const k = `${r.name}|${r.type}`;
      const list = byOwnerType.get(k) ?? [];
      if (!list.some((ex) => ex.canonicalRdataBase64 === r.canonicalRdataBase64)) {
        list.push(r);
      }
      byOwnerType.set(k, list);
    }

    for (const [, recs] of byOwnerType.entries()) {
      const sample = recs[0];
      const matchingSigs = sigs.filter(
        (s) =>
          s.name === sample.name &&
          s.parsed.kind === 'RRSIG' &&
          s.parsed.typeCovered === sample.type
      );
      const signer =
        matchingSigs[0]?.parsed.kind === 'RRSIG' ? matchingSigs[0].parsed.signerName : undefined;
      const zone = findAuthoritativeZoneForOwner(
        sample.name,
        sample.type,
        signer,
        allZones,
        section
      );
      const fingerprint = recs
        .map((r) => r.canonicalRdataBase64)
        .sort()
        .join(',');
      const baseKey = `${zone}|${sample.name}|${sample.type}`;
      const isProofType = sample.type === RR_TYPES.NSEC || sample.type === RR_TYPES.NSEC3;
      const groupKey = isProofType ? `${baseKey}|${fingerprint}` : baseKey;

      const existing = groupMap.get(groupKey);
      if (!existing) {
        const count = (variantCountByBaseKey.get(baseKey) ?? 0) + 1;
        variantCountByBaseKey.set(baseKey, count);
        const typeStr = rrTypeToString(sample.type);
        const rrsetId =
          count === 1
            ? `rrset-${zone}-${sample.name}-${typeStr}`
            : `rrset-${zone}-${sample.name}-${typeStr}-${count}`;
        groupMap.set(groupKey, {
          id: rrsetId,
          zone,
          name: sample.name,
          type: sample.type,
          fingerprint,
          section,
          records: [...recs],
          rrsigRecords: [...matchingSigs],
          isQueryTarget: isTargetQuery && section === 'answer',
        });
      } else if (existing.fingerprint === fingerprint) {
        // Exact same canonical RRset across packets: safe to merge any additional RRSIGs
        if (section === 'answer') existing.section = 'answer';
        if (isTargetQuery && section === 'answer') existing.isQueryTarget = true;
        for (const s of matchingSigs) {
          if (
            !existing.rrsigRecords.some((ex) => ex.canonicalRdataBase64 === s.canonicalRdataBase64)
          ) {
            existing.rrsigRecords.push(s);
          }
        }
      } else {
        // Non-NSEC RRset whose RDATA changed across packets (e.g. SOA serial tick across PoPs):
        // never mix records from two different RRset versions; prefer signed Answer / Target RRsets atomically.
        const incomingPriority =
          (isTargetQuery && section === 'answer' ? 4 : 0) +
          (section === 'answer' ? 2 : 0) +
          (matchingSigs.length > 0 ? 1 : 0);
        const existingPriority =
          (existing.isQueryTarget ? 4 : 0) +
          (existing.section === 'answer' ? 2 : 0) +
          (existing.rrsigRecords.length > 0 ? 1 : 0);
        if (incomingPriority > existingPriority) {
          existing.fingerprint = fingerprint;
          existing.section = section;
          existing.records = [...recs];
          existing.rrsigRecords = [...matchingSigs];
          existing.isQueryTarget = existing.isQueryTarget || (isTargetQuery && section === 'answer');
        }
      }
    }
  };

  for (const log of cdLogs) {
    if (log.purpose.startsWith('Nameserver IP')) continue;
    // Skip speculative zone-cut / DS discovery probes for non-zone hostnames (unless user explicitly queried that type)
    if (
      (log.purpose.startsWith('Zone-cut probe') || log.purpose.startsWith('Delegation probe')) &&
      !allZones.has(log.qname) &&
      !(log.qname === targetName && queryTypes.includes(log.qtypeName))
    ) {
      continue;
    }
    const isTarget =
      log.purpose.startsWith('Target RRset') ||
      log.purpose.startsWith('CNAME target') ||
      log.purpose.startsWith('Mail target');
    addSectionRecords(log.packet.answers, 'answer', isTarget);
    addSectionRecords(log.packet.authorities, 'authority', false);
  }

  const findings: AuditFinding[] = [];
  const zonesByName = new Map<string, ZoneAnalysis>();
  const authenticatedKeyTagsByZone = new Map<string, Set<number>>();

  // Resolve NS IP map from helper logs
  const nsIpMap = new Map<string, { ipv4: string[]; ipv6: string[] }>();
  for (const log of queries) {
    if (!log.purpose.startsWith('Nameserver IP')) continue;
    const entry = nsIpMap.get(log.qname) ?? { ipv4: [], ipv6: [] };
    for (const ans of log.packet.answers) {
      if (ans.name === log.qname && ans.type === RR_TYPES.A && !entry.ipv4.includes(ans.rdataText)) {
        entry.ipv4.push(ans.rdataText);
      }
      if (
        ans.name === log.qname &&
        ans.type === RR_TYPES.AAAA &&
        !entry.ipv6.includes(ans.rdataText)
      ) {
        entry.ipv6.push(ans.rdataText);
      }
    }
    nsIpMap.set(log.qname, entry);
  }

  // Evaluate zones top-down (root -> TLD -> SLD -> subzones)
  for (const zoneName of sortedZoneNames) {
    const parentZone = findDeepestParentZone(zoneName, allZones);
    const parentAnalysis = parentZone ? zonesByName.get(parentZone) : undefined;
    const depth = zoneName === '.' ? 0 : zoneName.slice(0, -1).split('.').length;

    const zKeyRecords = rawZoneDnskeys.get(zoneName) ?? [];
    const zoneGroups = Array.from(groupMap.values()).filter((g) => g.zone === zoneName);

    // 1. Check direct Trust Anchors for this zone (e.g., '.' IANA KSK-2024 #38696 & KSK-2017 #20326)
    const zoneAnchors = enabledAnchors.filter((ta) => normalizeFqdn(ta.zone) === zoneName);
    const trustAnchorMatches: ZoneAnalysis['trustAnchorMatches'] = [];
    const anchorTrustedKeyTags = new Set<number>();

    for (const ta of zoneAnchors) {
      const matchingKeyRecs = zKeyRecords.filter(
        (r) =>
          r.parsed.kind === 'DNSKEY' &&
          r.parsed.keyTag === ta.keyTag &&
          r.parsed.algorithm === ta.algorithm
      );
      let matched = false;
      let computedHex: string | undefined;
      for (const kr of matchingKeyRecs) {
        const comp = await computeDsDigest(
          zoneName,
          base64ToBytes(kr.canonicalRdataBase64),
          ta.digestType
        );
        if (comp) {
          computedHex = comp;
          if (comp.toUpperCase() === ta.digest.toUpperCase()) {
            matched = true;
            anchorTrustedKeyTags.add(ta.keyTag);
          }
        }
      }
      trustAnchorMatches.push({
        anchorId: ta.id,
        label: ta.label,
        keyTag: ta.keyTag,
        matched,
        computedDigestHex: computedHex,
        expectedDigestHex: ta.digest.toUpperCase(),
      });
    }

    // 2. Check Parent DS Delegation (if non-root)
    const dsVerifications: DsVerification[] = [];
    let parentDsRrsetId: string | undefined;
    let insecureDelegationProof: ZoneAnalysis['insecureDelegationProof'];
    const dsMatchedKeyTags = new Set<number>();

    const dsLog = zoneName !== '.' ? findLog(cdLogs, zoneName, RR_TYPES.DS, true) : undefined;
    const parentDsGroup =
      parentZone !== null ? groupMap.get(`${parentZone}|${zoneName}|${RR_TYPES.DS}`) : undefined;

    if (parentDsGroup) {
      parentDsRrsetId = `rrset-${parentZone}-${zoneName}-DS`;
      for (const dsRec of parentDsGroup.records) {
        if (dsRec.parsed.kind !== 'DS') continue;
        const v = await verifyDsAgainstZoneKeys(zoneName, dsRec, zKeyRecords);
        dsVerifications.push(v);
        if (v.digestValid && v.matchedKeyTag !== undefined) {
          dsMatchedKeyTags.add(v.matchedKeyTag);
        }
      }
    } else if (zoneName !== '.' && parentZone && dsLog) {
      // No DS record in parent: evaluate NSEC / NSEC3 insecure delegation proof
      const authNsec = dsLog.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC);
      const authNsec3 = dsLog.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC3);
      if (authNsec.length > 0 || authNsec3.length > 0) {
        insecureDelegationProof = await verifyNegativeProof({
          kind: 'INSECURE_DELEGATION',
          zoneApex: parentZone,
          qname: zoneName,
          qtype: 'DS',
          nsecRecords: authNsec,
          nsec3Records: authNsec3,
        });
      }
    }

    // 3. Verify all RRsets in this zone (starting with DNSKEY RRset)
    const analyzedRrsets: AnalyzedRrset[] = [];
    const signingKeyTypesMap = new Map<number, Set<string>>();
    const referencedMissingKeys = new Map<number, number>(); // keyTag -> algorithm

    // Verify DNSKEY RRset first so we know which keys in zoneName are authenticated
    const dnskeyGroup = groupMap.get(`${zoneName}|${zoneName}|${RR_TYPES.DNSKEY}`);
    let dnskeyRrsigs: RrsigVerification[] = [];
    if (dnskeyGroup && zKeyRecords.length > 0) {
      dnskeyRrsigs = await Promise.all(
        dnskeyGroup.rrsigRecords.map((sigRec) =>
          verifyRrsigForRrset(dnskeyGroup.records, sigRec, zKeyRecords, validationEpochSec)
        )
      );
      for (const rv of dnskeyRrsigs) {
        if (rv.cryptoValid && rv.timeValid) {
          const set = signingKeyTypesMap.get(rv.signerKeyTag) ?? new Set<string>();
          set.add('DNSKEY');
          signingKeyTypesMap.set(rv.signerKeyTag, set);
        } else if (!rv.signerFound) {
          referencedMissingKeys.set(rv.signerKeyTag, rv.rrsig.algorithm);
        }
      }
    }

    // Also record missing keys referenced by parent DS records (e.g. dnssec-failed.org!)
    for (const dsv of dsVerifications) {
      if (!dsv.targetKeyFound) {
        referencedMissingKeys.set(dsv.ds.keyTag, dsv.ds.algorithm);
      }
    }

    // Determine Zone Chain-of-Trust Status!
    let zoneStatus: ValidationStatus = 'indeterminate';
    let zoneReason = '';

    if (zoneAnchors.length > 0) {
      // Directly anchored zone (typically root '.')
      if (anchorTrustedKeyTags.size === 0) {
        zoneStatus = 'bogus';
        zoneReason = `No DNSKEY in ${zoneName} matched configured Trust Anchor(s)`;
        findings.push({
          id: `err-ta-miss-${zoneName}`,
          severity: 'error',
          code: 'TRUST_ANCHOR_MISMATCH',
          title: `Trust anchor mismatch at ${zoneName}`,
          detail: `None of the DNSKEY records in ${zoneName} matched the configured trust anchor digest(s).`,
          rfc: 'RFC 4035 §5.2',
          zone: zoneName,
        });
      } else {
        const signedByAnchor = dnskeyRrsigs.some(
          (rv) =>
            anchorTrustedKeyTags.has(rv.signerKeyTag) && rv.cryptoValid && rv.timeValid
        );
        if (signedByAnchor) {
          const hasWarn = dnskeyRrsigs.some((rv) => rv.status === 'warning');
          zoneStatus = hasWarn ? 'warning' : 'secure';
          zoneReason = `Authenticated via Trust Anchor (${Array.from(anchorTrustedKeyTags)
            .map((t) => `#${t}`)
            .join(', ')})`;
        } else {
          zoneStatus = 'bogus';
          zoneReason = `DNSKEY RRset in ${zoneName} was not validly signed by a matched Trust Anchor`;
          findings.push({
            id: `err-ta-sig-${zoneName}`,
            severity: 'error',
            code: 'DNSKEY_RRSIG_BOGUS',
            title: `Broken DNSKEY self-signature at ${zoneName}`,
            detail: `Trust anchor matched key(s), but RRSIG(DNSKEY) failed cryptographic or timestamp validation.`,
            rfc: 'RFC 4035 §5.2',
            zone: zoneName,
          });
        }
      }
    } else if (!parentAnalysis) {
      zoneStatus = 'indeterminate';
      zoneReason = 'No trust anchor configured for root zone';
    } else if (parentAnalysis.status === 'bogus') {
      zoneStatus = 'bogus';
      zoneReason = `Chain of trust broken in ancestor zone ${parentZone}`;
    } else if (
      parentAnalysis.status === 'insecure' ||
      parentAnalysis.status === 'indeterminate'
    ) {
      zoneStatus = parentAnalysis.status;
      zoneReason =
        zKeyRecords.length > 0
          ? `Unanchored island of security (ancestor ${parentZone} is ${parentAnalysis.status})`
          : `Unsigned zone beneath ${parentAnalysis.status} ${parentZone}`;
    } else {
      // Parent zone is SECURE (or WARNING)
      const parentDsAnalysed = parentAnalysis.rrsets.find(
        (r) => r.name === zoneName && r.type === RR_TYPES.DS
      );

      if (dsVerifications.length > 0) {
        if (parentDsAnalysed && parentDsAnalysed.status === 'bogus') {
          zoneStatus = 'bogus';
          zoneReason = `Parent DS RRset for ${zoneName} in ${parentZone} failed RRSIG validation`;
        } else if (dsMatchedKeyTags.size === 0) {
          zoneStatus = 'bogus';
          const missingTags = dsVerifications.map((d) => `#${d.ds.keyTag}`).join(', ');
          zoneReason = `No SEP DNSKEY in ${zoneName} matched parent DS (${missingTags})`;
          findings.push({
            id: `err-ds-nosep-${zoneName}`,
            severity: 'error',
            code: 'DS_NO_MATCHING_DNSKEY',
            title: `Broken delegation from ${parentZone} to ${zoneName}`,
            detail: `Parent zone ${parentZone} publishes DS for key tag ${missingTags}, but no matching DNSKEY exists in ${zoneName}.`,
            rfc: 'RFC 4035 §5.2 / RFC 8914 EDE(9)',
            zone: zoneName,
            targetId: `zone-${zoneName}`,
          });
        } else {
          const validSelfSig = dnskeyRrsigs.some(
            (rv) => dsMatchedKeyTags.has(rv.signerKeyTag) && rv.cryptoValid && rv.timeValid
          );
          if (validSelfSig) {
            const hasWarn =
              dsVerifications.some((d) => d.status === 'warning') ||
              dnskeyRrsigs.some((r) => r.status === 'warning');
            zoneStatus = hasWarn ? 'warning' : 'secure';
            zoneReason = `Delegation verified from ${parentZone} via DS (${Array.from(dsMatchedKeyTags)
              .map((t) => `#${t}`)
              .join(', ')})`;
          } else {
            zoneStatus = 'bogus';
            zoneReason = `DS matched DNSKEY in ${zoneName}, but DNSKEY RRset lacks a valid RRSIG from that SEP key`;
            findings.push({
              id: `err-dnskey-sig-${zoneName}`,
              severity: 'error',
              code: 'DNSKEY_RRSIG_INVALID',
              title: `DNSKEY RRset signature failure in ${zoneName}`,
              detail: `Parent DS matched key tag ${Array.from(dsMatchedKeyTags).join(', ')}, but no valid RRSIG(DNSKEY) from that key was found.`,
              rfc: 'RFC 4035 §5.2',
              zone: zoneName,
            });
          }
        }
      } else {
        // No DS record in signed parent -> check authenticated denial of existence!
        const dsAuthNegCanon = new Set(
          (dsLog?.packet.authorities ?? [])
            .filter((r) => r.type === RR_TYPES.NSEC || r.type === RR_TYPES.NSEC3)
            .map((r) => `${r.name}|${r.canonicalRdataBase64}`)
        );
        const matchingParentNegRrsets = parentAnalysis.rrsets.filter(
          (r) =>
            (r.type === RR_TYPES.NSEC || r.type === RR_TYPES.NSEC3) &&
            r.records.some((rec) => dsAuthNegCanon.has(`${rec.name}|${rec.canonicalRdataBase64}`))
        );
        const parentNsecSigned =
          matchingParentNegRrsets.length > 0 &&
          matchingParentNegRrsets.every((r) => r.status === 'secure' || r.status === 'warning');

        if (insecureDelegationProof?.valid && parentNsecSigned) {
          zoneStatus = 'insecure';
          zoneReason = insecureDelegationProof.summary;
          findings.push({
            id: `info-unsigned-${zoneName}`,
            severity: 'info',
            code: 'UNSIGNED_DELEGATION',
            title: `Provably insecure delegation to ${zoneName}`,
            detail: insecureDelegationProof.summary,
            rfc: insecureDelegationProof.protocol === 'NSEC3' ? 'RFC 5155 §7.2.7' : 'RFC 4035 §5.2',
            zone: zoneName,
          });
        } else if (dsLog && dsLog.packet.flags.rcode === 3) {
          // NXDOMAIN on candidate zone
          zoneStatus = 'secure';
          zoneReason = `Authenticated non-existence from ${parentZone}`;
        } else {
          zoneStatus = 'bogus';
          zoneReason = `Missing DS and missing valid NSEC/NSEC3 proof of non-existence in signed parent ${parentZone}`;
          findings.push({
            id: `err-missing-nsec-ds-${zoneName}`,
            severity: 'error',
            code: 'MISSING_DS_NSEC_PROOF',
            title: `Unauthenticated unsigned delegation to ${zoneName}`,
            detail: `Signed parent ${parentZone} returned no DS record for ${zoneName} without a valid NSEC/NSEC3 proof.`,
            rfc: 'RFC 4035 §5.2',
            zone: zoneName,
          });
        }
      }
    }

    const trustedKeysInZone = new Set<number>();
    if (zoneStatus === 'secure' || zoneStatus === 'warning') {
      for (const kr of zKeyRecords) {
        if (kr.parsed.kind === 'DNSKEY' && kr.parsed.isZoneKey && !kr.parsed.isRevoked) {
          trustedKeysInZone.add(kr.parsed.keyTag);
        }
      }
    }
    authenticatedKeyTagsByZone.set(zoneName, trustedKeysInZone);

    // 4. Verify all RRsets in zoneName
    for (const grp of zoneGroups) {
      const rrsetId = grp.id;
      const rrsigs =
        grp.type === RR_TYPES.DNSKEY && grp.name === zoneName
          ? dnskeyRrsigs
          : await Promise.all(
              grp.rrsigRecords.map((sigRec) =>
                verifyRrsigForRrset(grp.records, sigRec, zKeyRecords, validationEpochSec)
              )
            );

      for (const rv of rrsigs) {
        if (rv.cryptoValid && rv.timeValid) {
          const s = signingKeyTypesMap.get(rv.signerKeyTag) ?? new Set<string>();
          s.add(rrTypeToString(grp.type));
          signingKeyTypesMap.set(rv.signerKeyTag, s);
        } else if (!rv.signerFound) {
          referencedMissingKeys.set(rv.signerKeyTag, rv.rrsig.algorithm);
        }

        if (rv.algorithmWarning) {
          findings.push({
            id: `warn-alg-${rrsetId}-${rv.signerKeyTag}`,
            severity: 'warning',
            code: 'WEAK_CRYPTO_ALGORITHM',
            title: `Deprecated cryptographic algorithm on ${grp.name} ${rrTypeToString(grp.type)}`,
            detail: rv.algorithmWarning,
            rfc: 'RFC 8624 §3.1',
            zone: zoneName,
            targetId: rrsetId,
          });
        }
        if (rv.expirationWarning) {
          findings.push({
            id: `warn-exp-${rrsetId}-${rv.signerKeyTag}`,
            severity: 'warning',
            code: 'RRSIG_EXPIRING_SOON',
            title: `RRSIG approaching expiration on ${grp.name} ${rrTypeToString(grp.type)}`,
            detail: rv.expirationWarning,
            rfc: 'RFC 4035 §5.3.1 / §5.3.3',
            zone: zoneName,
            targetId: rrsetId,
          });
        }
        if (rv.ttlMismatch) {
          findings.push({
            id: `warn-ttl-${rrsetId}-${rv.signerKeyTag}`,
            severity: 'warning',
            code: 'ORIGINAL_TTL_EXCEEDED',
            title: `RRset TTL exceeds RRSIG original TTL on ${grp.name} ${rrTypeToString(grp.type)}`,
            detail: `One or more records in ${grp.name} ${rrTypeToString(grp.type)} carry a TTL larger than RRSIG(#${rv.signerKeyTag}) original_ttl (${rv.rrsig.originalTtl}s).`,
            rfc: 'RFC 4035 §2.2',
            zone: zoneName,
            targetId: rrsetId,
          });
        }
        if (rv.wildcardSynthesized) {
          findings.push({
            id: `info-wc-${rrsetId}`,
            severity: 'info',
            code: 'WILDCARD_SYNTHESIS',
            title: `Wildcard synthesis detected for ${grp.name} ${rrTypeToString(grp.type)}`,
            detail: `RRSIG labels=${rv.rrsig.labels} (< ${grp.name} label count), synthesized from *.${rv.wildcardClosestEncloser ?? zoneName}`,
            rfc: 'RFC 4035 §5.3.4',
            zone: zoneName,
            targetId: rrsetId,
          });
        }
      }

      let rrStatus: ValidationStatus = zoneStatus;
      let rrReason = '';

      if (zoneStatus === 'insecure' || zoneStatus === 'indeterminate') {
        rrStatus = zoneStatus;
        rrReason =
          rrsigs.length > 0
            ? `Signed RRset inside ${zoneStatus} zone (no chain of trust from root)`
            : `Unsigned RRset (${zoneStatus} zone)`;
      } else if (grp.type === RR_TYPES.NS && grp.section === 'authority' && grp.name !== zoneName) {
        // Delegation NS in parent authority is never signed per RFC 4035
        rrStatus = 'insecure';
        rrReason = 'Delegation NS glue in parent authority (unsigned by design)';
      } else if (rrsigs.length === 0) {
        rrStatus = 'bogus';
        rrReason = `Missing RRSIG for ${grp.name} ${rrTypeToString(grp.type)} in signed zone ${zoneName}`;
        findings.push({
          id: `err-nosig-${rrsetId}`,
          severity: 'error',
          code: 'RRSIG_MISSING',
          title: `Missing RRSIG for ${grp.name} ${rrTypeToString(grp.type)}`,
          detail: `Zone ${zoneName} is signed, but no RRSIG was returned covering ${grp.name} ${rrTypeToString(grp.type)}.`,
          rfc: 'RFC 4035 §5.3 / EDE(10)',
          zone: zoneName,
          targetId: rrsetId,
        });
      } else {
        const validSig = rrsigs.find(
          (rv) =>
            rv.cryptoValid &&
            rv.timeValid &&
            (zoneStatus === 'bogus' || trustedKeysInZone.has(rv.signerKeyTag))
        );
        if (validSig && (zoneStatus === 'secure' || zoneStatus === 'warning')) {
          rrStatus =
            validSig.status === 'warning' || zoneStatus === 'warning' ? 'warning' : 'secure';
          rrReason = validSig.reason;
        } else if (validSig && zoneStatus === 'bogus') {
          rrStatus = 'bogus';
          rrReason = `Signature mathematically valid (#${validSig.signerKeyTag}), but zone ${zoneName} chain of trust is bogus`;
        } else {
          rrStatus = 'bogus';
          rrReason = rrsigs[0].reason;
          findings.push({
            id: `err-badsig-${rrsetId}`,
            severity: 'error',
            code: 'RRSIG_BOGUS',
            title: `Invalid RRSIG on ${grp.name} ${rrTypeToString(grp.type)}`,
            detail: rrsigs.map((r) => `#${r.signerKeyTag}: ${r.reason}`).join('; '),
            rfc: 'RFC 4035 §5.3',
            zone: zoneName,
            targetId: rrsetId,
          });
        }
      }

      analyzedRrsets.push({
        id: rrsetId,
        zone: zoneName,
        name: grp.name,
        type: grp.type,
        typeName: rrTypeToString(grp.type),
        ttl: grp.records[0]?.ttl ?? 0,
        section: grp.section,
        records: grp.records,
        rrsigs,
        isQueryTarget: grp.isQueryTarget,
        status: rrStatus,
        statusReason: rrReason,
      });
    }

    // 5. Build AnalyzedDnskey list (including phantom MISSING keys!)
    const analyzedDnskeys: AnalyzedDnskey[] = [];
    for (const kr of zKeyRecords) {
      if (kr.parsed.kind !== 'DNSKEY') continue;
      const pk = kr.parsed as DnskeyRdata;
      const rawRdata = base64ToBytes(kr.canonicalRdataBase64);
      const [sha256, sha384] = await Promise.all([
        computeDsDigest(zoneName, rawRdata, 2),
        computeDsDigest(zoneName, rawRdata, 4),
      ]);
      const signs = Array.from(signingKeyTypesMap.get(pk.keyTag) ?? []);
      const isTrustAnchor = anchorTrustedKeyTags.has(pk.keyTag);
      const matchedByParentDs = dsMatchedKeyTags.has(pk.keyTag);
      const signsDnskey = signs.includes('DNSKEY');
      const signsOther = signs.some((t) => t !== 'DNSKEY');

      let role: AnalyzedDnskey['role'] = 'zsk';
      if (pk.isRevoked) {
        role = 'revoked';
      } else if (isTrustAnchor) {
        role = 'trust-anchor';
      } else if (signsDnskey && signsOther) {
        role = 'csk';
      } else if (pk.isSep || signsDnskey || matchedByParentDs) {
        role = signs.length === 0 && !matchedByParentDs ? 'standby' : 'ksk';
      } else if (signs.length === 0) {
        role = 'standby';
      }

      const algInfo = DNSSEC_ALGORITHMS[pk.algorithm];
      const weakRsa =
        [5, 7, 8, 10].includes(pk.algorithm) && pk.keySizeInfo.startsWith('1024-bit');
      if (weakRsa) {
        findings.push({
          id: `warn-1024rsa-${zoneName}-${pk.keyTag}`,
          severity: 'warning',
          code: 'SHORT_RSA_KEY',
          title: `1024-bit RSA DNSKEY (#${pk.keyTag}) in ${zoneName}`,
          detail: `DNSKEY #${pk.keyTag} uses a 1024-bit RSA modulus; >= 2048-bit RSA or ECDSA/Ed25519 is recommended.`,
          rfc: 'RFC 8624',
          zone: zoneName,
          targetId: `dnskey-${zoneName}-${pk.keyTag}`,
        });
      }

      let keyStatus: ValidationStatus = zoneStatus;
      let keyReason = '';
      if (zoneStatus === 'secure' || zoneStatus === 'warning') {
        keyStatus = algInfo?.deprecated || weakRsa ? 'warning' : 'secure';
        keyReason = isTrustAnchor
          ? `Verified against Trust Anchor`
          : matchedByParentDs
            ? `Authenticated by parent DS & DNSKEY RRSIG`
            : role === 'standby'
              ? `Published standby key (authenticated in DNSKEY RRset)`
              : `Authenticated in ${zoneName} DNSKEY RRset`;
      } else if (zoneStatus === 'bogus') {
        keyStatus = 'bogus';
        keyReason = zoneReason;
      } else {
        keyStatus = zoneStatus;
        keyReason = `Unauthenticated key in ${zoneStatus} zone`;
      }

      const matchedTa = zoneAnchors.find((ta) => ta.keyTag === pk.keyTag);

      analyzedDnskeys.push({
        id: `dnskey-${zoneName}-${pk.keyTag}`,
        zone: zoneName,
        keyTag: pk.keyTag,
        flags: pk.flags,
        algorithm: pk.algorithm,
        protocol: pk.protocol,
        keySizeInfo: pk.keySizeInfo,
        publicKeyBase64: pk.publicKeyBase64,
        isSep: pk.isSep,
        isZoneKey: pk.isZoneKey,
        isRevoked: pk.isRevoked,
        role,
        trustAnchorLabel: matchedTa?.label,
        computedSha256: sha256 ?? undefined,
        computedSha384: sha384 ?? undefined,
        signsTypes: signs,
        matchedByParentDs,
        status: keyStatus,
        statusReason: keyReason,
      });
    }

    // Add phantom MISSING DNSKEY nodes (iconic DNSViz feature!)
    for (const [missingTag, alg] of referencedMissingKeys.entries()) {
      if (analyzedDnskeys.some((k) => k.keyTag === missingTag)) continue;
      analyzedDnskeys.push({
        id: `dnskey-${zoneName}-${missingTag}-missing`,
        zone: zoneName,
        keyTag: missingTag,
        flags: 257,
        algorithm: alg,
        protocol: 3,
        keySizeInfo: 'Missing Key',
        publicKeyBase64: '',
        isSep: true,
        isZoneKey: true,
        isRevoked: false,
        role: 'missing',
        signsTypes: [],
        matchedByParentDs: dsVerifications.some((d) => d.ds.keyTag === missingTag),
        status: 'bogus',
        statusReason: `Referenced DNSKEY #${missingTag} (${formatAlgorithm(alg)}) is missing from ${zoneName}`,
      });
    }

    // Check DS digest warnings (e.g. SHA-1 DS)
    for (const dsv of dsVerifications) {
      if (dsv.digestWarning && parentZone) {
        findings.push({
          id: `warn-ds-digest-${zoneName}-${dsv.ds.keyTag}-${dsv.ds.digestType}`,
          severity: 'warning',
          code: 'WEAK_DS_DIGEST',
          title: `Deprecated DS digest type (${formatDigestType(dsv.ds.digestType)}) for ${zoneName}`,
          detail: dsv.digestWarning,
          rfc: 'RFC 8624 §3.3',
          zone: parentZone,
          targetId: parentDsRrsetId,
        });
      }
    }

    // Check NSEC3 iteration count best practices (RFC 9276: iterations > 0 discouraged, > 100 warning)
    const nsec3Rrsets = analyzedRrsets.filter((r) => r.type === RR_TYPES.NSEC3);
    const nsecRrsets = analyzedRrsets.filter((r) => r.type === RR_TYPES.NSEC);
    let nsecMode: ZoneAnalysis['nsecMode'] =
      zKeyRecords.length === 0
        ? 'UNSIGNED'
        : nsec3Rrsets.length > 0
          ? nsec3Rrsets.some((r) =>
              r.records.some((rec) => rec.parsed.kind === 'NSEC3' && rec.parsed.optOut)
            )
            ? 'NSEC3-OPTOUT'
            : 'NSEC3'
          : 'NSEC';

    const sampleNsec3 = nsec3Rrsets[0]?.records[0];
    if (sampleNsec3?.parsed.kind === 'NSEC3' && sampleNsec3.parsed.iterations > 10) {
      findings.push({
        id: `warn-nsec3-iter-${zoneName}`,
        severity: 'warning',
        code: 'HIGH_NSEC3_ITERATIONS',
        title: `Elevated NSEC3 iteration count (${sampleNsec3.parsed.iterations}) in ${zoneName}`,
        detail: `RFC 9276 §3.1 recommends NSEC3 iterations = 0 (with empty salt) to avoid CPU burden on validating resolvers.`,
        rfc: 'RFC 9276 §3.1',
        zone: zoneName,
      });
    }
    void nsecRrsets;

    // Extract SOA & Nameservers for zone
    const soaLog = findLog(cdLogs, zoneName, RR_TYPES.SOA, true);
    const soaRec = [...(soaLog?.packet.answers ?? []), ...(soaLog?.packet.authorities ?? [])].find(
      (r) => r.name === zoneName && r.type === RR_TYPES.SOA && r.parsed.kind === 'SOA'
    );
    const soa = soaRec?.parsed.kind === 'SOA' ? (soaRec.parsed as SoaRdata) : undefined;

    const nsLog = findLog(cdLogs, zoneName, RR_TYPES.NS, true);
    const nameservers: NameserverEntry[] = [];
    for (const r of nsLog?.packet.answers ?? []) {
      if (r.name === zoneName && r.type === RR_TYPES.NS && r.parsed.kind === 'GENERIC' && r.parsed.target) {
        const host = normalizeFqdn(r.parsed.target);
        if (!nameservers.some((n) => n.hostname === host)) {
          const ips = nsIpMap.get(host);
          nameservers.push({
            hostname: host,
            ipv4: ips?.ipv4 ?? [],
            ipv6: ips?.ipv6 ?? [],
          });
        }
      }
    }

    zonesByName.set(zoneName, {
      zoneName,
      parentZone,
      depth,
      status: zoneStatus,
      statusReason: zoneReason,
      nsecMode,
      dnskeys: analyzedDnskeys,
      parentDsRrsetId,
      dsVerifications,
      trustAnchorMatches,
      insecureDelegationProof,
      rrsets: analyzedRrsets,
      negativeNodes: [],
      nameservers,
      soa,
    });
  }

  // 6. Build CNAME Edges & Target Negative Response Nodes (NXDOMAIN / NODATA)
  const cnameEdges: CnameEdge[] = [];
  const targetProbes: Array<{ owner: string; qt: string }> = queryTypes.map((qt) => ({
    owner: targetName,
    qt,
  }));
  for (const log of cdLogs) {
    if (log.purpose.startsWith('Mail target')) {
      if (!targetProbes.some((p) => p.owner === log.qname && p.qt === log.qtypeName)) {
        targetProbes.push({ owner: log.qname, qt: log.qtypeName });
      }
    }
  }

  for (const { owner: probeOwner, qt } of targetProbes) {
    const qtypeNum = stringToRrType(qt);
    const initialLog = findLog(cdLogs, probeOwner, qtypeNum, true);
    if (!initialLog) continue;

    // Follow CNAME hops starting at probeOwner
    let curName = probeOwner;
    const seenCnames = new Set<string>([curName]);
    let lastCnameRrsetId: string | undefined;
    let lastCnameFrom: string | undefined;

    for (let step = 0; step < 8; step++) {
      // Find CNAME RRset for curName across analyzed zones
      let cnameRrset: AnalyzedRrset | undefined;
      for (const z of zonesByName.values()) {
        cnameRrset = z.rrsets.find((r) => r.name === curName && r.type === RR_TYPES.CNAME);
        if (cnameRrset) break;
      }
      if (!cnameRrset || qt === 'CNAME') break;

      const targetField =
        cnameRrset.records[0]?.parsed.kind === 'GENERIC'
          ? cnameRrset.records[0].parsed.target
          : undefined;
      if (!targetField) break;
      const nextName = normalizeFqdn(targetField);

      if (lastCnameRrsetId && lastCnameFrom) {
        const edgeId = `cname-${lastCnameFrom}-${curName}-${qt}`;
        if (!cnameEdges.some((e) => e.id === edgeId)) {
          cnameEdges.push({
            id: edgeId,
            fromRrsetId: lastCnameRrsetId,
            fromName: lastCnameFrom,
            toName: curName,
            toRrsetId: cnameRrset.id,
            qtypeName: qt,
          });
        }
      }

      lastCnameRrsetId = cnameRrset.id;
      lastCnameFrom = curName;
      if (seenCnames.has(nextName)) break;
      seenCnames.add(nextName);
      curName = nextName;
    }

    // Check final target (`curName`) for requested `qtypeNum`
    let targetRrset: AnalyzedRrset | undefined;
    for (const z of zonesByName.values()) {
      targetRrset = z.rrsets.find((r) => r.name === curName && r.type === qtypeNum);
      if (targetRrset) {
        targetRrset.isQueryTarget = true;
        break;
      }
    }

    if (lastCnameRrsetId && lastCnameFrom && targetRrset) {
      const edgeId = `cname-${lastCnameFrom}-${curName}-${qt}`;
      if (!cnameEdges.some((e) => e.id === edgeId)) {
        cnameEdges.push({
          id: edgeId,
          fromRrsetId: lastCnameRrsetId,
          fromName: lastCnameFrom,
          toName: curName,
          toRrsetId: targetRrset.id,
          qtypeName: qt,
        });
      }
    }

    // If no targetRrset exists (and not satisfied by CNAME when querying CNAME), create NegativeNode (NXDOMAIN / NODATA)!
    if (!targetRrset) {
      const targetLog = findLog(cdLogs, curName, qtypeNum, true) ?? initialLog;
      const rcode = targetLog.packet.flags.rcode;
      if (rcode === 0 || rcode === 3) {
        const negKind: 'NXDOMAIN' | 'NODATA' = rcode === 3 ? 'NXDOMAIN' : 'NODATA';
        const authZoneName = findAuthoritativeZoneForOwner(curName, qtypeNum, undefined, allZones);
        const authZone = zonesByName.get(authZoneName);

        if (authZone) {
          const authNsec = targetLog.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC);
          const authNsec3 = targetLog.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC3);

          let proof = await verifyNegativeProof({
            kind: negKind,
            zoneApex: authZoneName,
            qname: curName,
            qtype: qt,
            nsecRecords: authNsec,
            nsec3Records: authNsec3,
          });

          const authNegCanonSet = new Set(
            [...authNsec, ...authNsec3].map((ar) => `${ar.name}|${ar.canonicalRdataBase64}`)
          );
          const coveringRrsetIds = authZone.rrsets
            .filter(
              (r) =>
                (r.type === RR_TYPES.NSEC || r.type === RR_TYPES.NSEC3) &&
                r.records.some((rec) =>
                  authNegCanonSet.has(`${rec.name}|${rec.canonicalRdataBase64}`)
                )
            )
            .map((r) => r.id);

          let negStatus: ValidationStatus = authZone.status;
          if (authZone.status === 'insecure' || authZone.status === 'indeterminate') {
            negStatus = authZone.status;
            proof = {
              ...proof,
              status: authZone.status,
              summary: `Unsigned ${negKind} response in ${authZone.status} zone ${authZoneName}`,
            };
          } else if (authZone.status === 'secure' || authZone.status === 'warning') {
            const coveringAllSigned =
              coveringRrsetIds.length > 0 &&
              coveringRrsetIds.every((cid) => {
                const found = authZone.rrsets.find((r) => r.id === cid);
                return found && (found.status === 'secure' || found.status === 'warning');
              });
            if (proof.valid && coveringAllSigned) {
              negStatus = authZone.status;
            } else {
              negStatus = 'bogus';
              findings.push({
                id: `err-negproof-${curName}-${qt}`,
                severity: 'error',
                code: 'BOGUS_NEGATIVE_PROOF',
                title: `Invalid ${negKind} denial-of-existence proof for ${curName} (${qt})`,
                detail: proof.valid
                  ? `Covering ${proof.protocol} record(s) for ${curName} failed RRSIG signature verification.`
                  : proof.summary,
                rfc: proof.protocol === 'NSEC3' ? 'RFC 5155' : 'RFC 4035 §5.4',
                zone: authZoneName,
              });
            }
          }

          const negId = `neg-${authZoneName}-${curName}-${qt}-${negKind}`;
          if (!authZone.negativeNodes.some((n) => n.id === negId)) {
            authZone.negativeNodes.push({
              id: negId,
              zone: authZoneName,
              qname: curName,
              qtypeName: qt,
              kind: negKind,
              proof,
              coveringRrsetIds,
              status: negStatus,
            });
          }

          // Detect RFC 4470 / RFC 9824 Compact Denial of Existence ("Black Lies": \000.<qname>)
          if (
            negKind === 'NODATA' &&
            authNsec.some(
              (r) => r.parsed.kind === 'NSEC' && r.parsed.nextDomainName.startsWith('\\000.')
            )
          ) {
            const compactFindingId = `info-compact-doe-${curName}`;
            const existingCompact = findings.find((f) => f.id === compactFindingId);
            if (!existingCompact) {
              findings.push({
                id: compactFindingId,
                severity: 'info',
                code: 'COMPACT_DENIAL_OF_EXISTENCE',
                title: `Compact Denial of Existence ("Black Lies") for ${curName}`,
                detail: `${authZoneName} uses online NSEC synthesis (next domain \\000.${curName}), returning per-query NOERROR/NODATA NSEC bitmaps [${qt}] instead of NXDOMAIN to prevent zone enumeration.`,
                rfc: 'RFC 4470 / RFC 9824',
                zone: authZoneName,
                targetId: negId,
              });
            } else if (
              !existingCompact.detail.includes(`[${qt}]`) &&
              !existingCompact.detail.includes(`[${qt},`) &&
              !existingCompact.detail.includes(`, ${qt}]`) &&
              !existingCompact.detail.includes(`, ${qt},`)
            ) {
              existingCompact.detail = existingCompact.detail.replace(
                /bitmaps \[([^\]]+)\]/,
                `bitmaps [$1, ${qt}]`
              );
            }
          }

          if (lastCnameRrsetId && lastCnameFrom) {
            const edgeId = `cname-${lastCnameFrom}-${curName}-${qt}`;
            if (!cnameEdges.some((e) => e.id === edgeId)) {
              cnameEdges.push({
                id: edgeId,
                fromRrsetId: lastCnameRrsetId,
                fromName: lastCnameFrom,
                toName: curName,
                toNegativeNodeId: negId,
                qtypeName: qt,
              });
            }
          }
        }
      }
    }
  }

  // 7. Packet Size / UDP Fragmentation & Extended DNS Error (RFC 8914) Audit Checks
  for (const log of queries) {
    if (log.purpose.startsWith('Nameserver IP')) continue;
    if (log.packet.wireSize > 1232) {
      findings.push({
        id: `warn-size-${log.id}`,
        severity: 'warning',
        code: 'LARGE_DNS_RESPONSE',
        title: `Large DNS response (${log.packet.wireSize} bytes) on ${log.qname} ${log.qtypeName}`,
        detail: `Wire response exceeds the 1232-byte DNS Flag Day 2020 threshold, which can cause IPv6/UDP fragmentation issues over legacy UDP transport.`,
        rfc: 'RFC 8900 / DNS Flag Day 2020',
      });
    }
    for (const ede of log.packet.edns?.ede ?? []) {
      const sev: AuditFinding['severity'] =
        [6, 7, 8, 9, 10, 11, 12].includes(ede.infoCode) ? 'error' : 'info';
      const fId = `ede-${log.qname}-${log.qtypeName}-${ede.infoCode}`;
      if (!findings.some((f) => f.id === fId)) {
        findings.push({
          id: fId,
          severity: sev,
          code: `EDE_${ede.infoCode}`,
          title: `1.1.1.1 Extended DNS Error ${ede.infoCode}: ${ede.name}`,
          detail: ede.extraText
            ? `${ede.extraText} (reported on ${log.qname} ${log.qtypeName})`
            : `Reported by 1.1.1.1 on ${log.qname} ${log.qtypeName}`,
          rfc: 'RFC 8914',
        });
      }
    }
  }

  // 8. Extract 1.1.1.1 CD=0 Resolver Verdict
  const valQuery =
    queries.find((q) => !q.cd && q.purpose.includes('validating check')) ??
    queries.find((q) => !q.cd && !q.purpose.startsWith('SPF lookup'));
  const resolverVerdict: ResolverVerdict | undefined = valQuery
    ? {
        qname: valQuery.qname,
        qtypeName: valQuery.qtypeName,
        rcode: valQuery.packet.flags.rcode,
        rcodeName: rcodeToString(valQuery.packet.flags.rcode),
        adBit: valQuery.packet.flags.ad,
        ede: valQuery.packet.edns?.ede ?? [],
        latencyMs: valQuery.latencyMs,
      }
    : undefined;

  // 9. Compute Overall Chain Status & Human-Readable Summary
  const zones = sortedZoneNames
    .map((zn) => zonesByName.get(zn))
    .filter((z): z is ZoneAnalysis => Boolean(z));

  const targetLeafZones = zones.filter((z) => {
    const isTargetAnc = isSubdomainOrEqual(targetName, z.zoneName);
    const isCnameTargetAnc =
      mode !== 'mail' && cnameEdges.some((ce) => isSubdomainOrEqual(ce.toName, z.zoneName));
    return isTargetAnc || isCnameTargetAnc;
  });

  // Check target RRset / negativeNode statuses specifically
  const targetElementStatuses: ValidationStatus[] = [];
  for (const z of zones) {
    if (mode === 'mail' && !isSubdomainOrEqual(targetName, z.zoneName)) {
      continue;
    }
    for (const r of z.rrsets) {
      if (r.isQueryTarget && (mode !== 'mail' || r.name === targetName)) {
        targetElementStatuses.push(r.status);
      }
    }
    for (const n of z.negativeNodes) {
      if (mode !== 'mail' || n.qname === targetName) {
        targetElementStatuses.push(n.status);
      }
    }
  }

  let overallStatus: ValidationStatus = 'secure';
  const allRelevantStatuses = [
    ...targetLeafZones.map((z) => z.status),
    ...targetElementStatuses,
  ];

  if (allRelevantStatuses.includes('bogus')) {
    overallStatus = 'bogus';
  } else if (
    targetElementStatuses.length > 0 &&
    targetElementStatuses.every((s) => s === 'insecure')
  ) {
    overallStatus = 'insecure';
  } else if (targetLeafZones[targetLeafZones.length - 1]?.status === 'insecure') {
    overallStatus = 'insecure';
  } else if (allRelevantStatuses.includes('indeterminate')) {
    overallStatus = 'indeterminate';
  } else if (allRelevantStatuses.includes('warning')) {
    overallStatus = 'warning';
  } else {
    overallStatus = 'secure';
  }

  const deepestTargetZone =
    zones
      .filter((z) => isSubdomainOrEqual(targetName, z.zoneName))
      .sort((a, b) => b.depth - a.depth)[0] ?? zones[zones.length - 1];

  let overallSummary = '';
  if (overallStatus === 'secure') {
    overallSummary = `Full cryptographic chain of trust verified from root (.) down to ${displayFqdn(targetName)} across ${zones.length} zone${zones.length === 1 ? '' : 's'}.`;
  } else if (overallStatus === 'warning') {
    overallSummary = `Chain of trust is cryptographically valid down to ${displayFqdn(targetName)}, with RFC best-practice warnings.`;
  } else if (overallStatus === 'insecure') {
    overallSummary = `${displayFqdn(targetName)} is provably unsigned (insecure delegation at ${deepestTargetZone.zoneName}).`;
  } else if (overallStatus === 'bogus') {
    const firstErr = findings.find((f) => f.severity === 'error');
    overallSummary = firstErr
      ? `DNSSEC validation failed (BOGUS): ${firstErr.title}.`
      : `DNSSEC chain of trust failed cryptographic validation for ${displayFqdn(targetName)}.`;
  } else {
    overallSummary = `Validation state is indeterminate for ${displayFqdn(targetName)}.`;
  }

  let mailAnalysis: AnalysisSnapshot['mailAnalysis'];
  if (mode === 'mail') {
    const mailResult = evaluateMailFromSnapshotData({
      targetName,
      queries,
      zones,
      cnameEdges,
      targetDomainStatus: overallStatus,
      customDkimSelectors,
    });
    mailAnalysis = mailResult.mailAnalysis;
    findings.push(...mailResult.mailFindings);
    overallStatus = mailResult.overallStatus;
    overallSummary = mailResult.overallSummary;
  }

  // Deduplicate findings & sort errors -> warnings -> info
  const severityOrder: Record<AuditFinding['severity'], number> = {
    error: 0,
    warning: 1,
    info: 2,
  };
  const uniqueFindingsMap = new Map<string, AuditFinding>();
  for (const f of findings) {
    if (!uniqueFindingsMap.has(f.id)) uniqueFindingsMap.set(f.id, f);
  }
  const sortedFindings = Array.from(uniqueFindingsMap.values()).sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  return {
    id,
    version: SNAPSHOT_ENGINE_VERSION,
    ...(mode !== 'dnssec' ? { mode } : {}),
    targetName,
    displayDomain: displayFqdn(targetName),
    queryTypes,
    ...(customDkimSelectors && customDkimSelectors.length > 0 ? { customDkimSelectors } : {}),
    dohEndpoint,
    capturedAt,
    validatedAt,
    durationMs,
    overallStatus,
    overallSummary,
    resolverVerdict,
    zones,
    cnameEdges,
    findings: sortedFindings,
    queries,
    trustAnchorsUsed: trustAnchors,
    ...(mailAnalysis ? { mailAnalysis } : {}),
  };
}
