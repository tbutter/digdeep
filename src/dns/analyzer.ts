import {
  DEFAULT_DOH_ENDPOINT,
  DNSSEC_ALGORITHMS,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  WILDCARD_PROBE_LABEL,
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
  countDnsLabels,
  displayFqdn,
  getDomainHierarchy,
  isSubdomainOrEqual,
  normalizeFqdn,
} from './encoding';
import {
  evaluateDnsblAuditForIp,
  formatCanonicalIpv6,
  getCachedRpkiValidation,
  ipToCymruOriginQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseIpv4Octets,
  parseIpv6Groups,
  parseReverseIpInput,
  queryDnsblForIp,
  seedRpkiValidationCache,
  summarizeRpkiValidationState,
  validateRpkiRoute,
  type ParsedReverseIpTarget,
} from './ipUtils';
import { evaluateConsensusFromSnapshotData } from './consensusAnalyzer';
import { evaluateMailFromSnapshotData } from './mailAnalyzer';
import { evaluateWebFromSnapshotData } from './webAnalyzer';
import type {
  AnalysisMode,
  AnalysisProgress,
  AnalysisSnapshot,
  AnalyzedDnskey,
  AnalyzedRrset,
  AuditFinding,
  BgpAsnOrganization,
  CdnskeyRecordDetail,
  CdsRecordDetail,
  CdsRolloverAnalysis,
  CnameEdge,
  CtLogFetchResult,
  DnsRecord,
  DnskeyRdata,
  DohQueryLog,
  DsVerification,
  MtaStsPolicyFetchResult,
  NameserverEntry,
  NsDiversityAnalysis,
  ResolverVerdict,
  ReverseDnsAnalysis,
  ReverseIpBgpInfo,
  ReversePtrTargetEntry,
  RpkiRouteValidation,
  RrsigVerification,
  SoaAuditSummary,
  SoaRdata,
  SoaTimerIssue,
  TxtHygieneAudit,
  TxtRecordCategory,
  TxtVerificationEntry,
  ValidationStatus,
  WildcardAuditSummary,
  WildcardProbeTypeResult,
  ZoneAnalysis,
  ZonemdAuditSummary,
  ZonemdRecordDetail,
} from './types';

export const SNAPSHOT_ENGINE_VERSION = 13;

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

  // Optimization for 32-nibble .ip6.arpa. reverse names (which have 35 hierarchy levels):
  // Probe the leaf SOA first so the Authority SOA owner reveals the deepest delegated prefix zone,
  // avoiding redundant SOA/DS queries for every single host nibble below the delegated zone apex.
  let filteredHierarchy = hierarchy.slice(1);
  if (fqdn.endsWith('.ip6.arpa.') && hierarchy.length > 14) {
    checkedCandidates.add(fqdn);
    const leafSoaLog = await session
      .query(fqdn, RR_TYPES.SOA, {
        cd: true,
        doBit: true,
        purpose: `Zone-cut probe (${fqdn} SOA)`,
      })
      .catch(() => undefined);
    const leafAuthSoa = [
      ...(leafSoaLog?.packet.answers ?? []),
      ...(leafSoaLog?.packet.authorities ?? []),
    ].find((r) => r.type === RR_TYPES.SOA);
    if (leafAuthSoa) {
      const leafZone = normalizeFqdn(leafAuthSoa.name);
      discoveredZones.add(leafZone);
      const leafIdx = hierarchy.indexOf(leafZone);
      if (leafIdx > 0) {
        filteredHierarchy = hierarchy.slice(1, leafIdx + 1);
      }
    }
  }

  const candidates = filteredHierarchy.filter((c) => !checkedCandidates.has(c));
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
 * Automatically detects raw IPv4 / IPv6 address inputs and converts them to `.in-addr.arpa.` / `.ip6.arpa.`
 * `PTR` traces with Forward-Confirmed Reverse DNS (FCrDNS) and BGP ASN lookup.
 */
export async function runDnsvizAnalysis(
  rawDomain: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisSnapshot> {
  const startedAt = Date.now();
  const reverseIpTarget = parseReverseIpInput(rawDomain);
  const targetName = reverseIpTarget ? reverseIpTarget.arpaFqdn : normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const requestedTypes =
    options.queryTypes && options.queryTypes.length > 0
      ? Array.from(new Set(options.queryTypes.map((t) => t.toUpperCase())))
      : ['A', 'AAAA'];
  const queryTypes =
    reverseIpTarget &&
    (!options.queryTypes ||
      options.queryTypes.length === 0 ||
      (reverseIpTarget.wasRawIpInput &&
        requestedTypes.every((t) => t === 'A' || t === 'AAAA')))
      ? ['PTR']
      : requestedTypes;
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
  // and probe CDS / CDNSKEY (RFC 7344 / RFC 8078) on leaf zone(s)
  currentPhase = 'nameservers';
  const leafZones = zoneList
    .sort((a, b) => getDomainHierarchy(b).length - getDomainHierarchy(a).length)
    .slice(0, 2);
  const nonRootLeafZones = leafZones.filter((lz) => lz !== '.');
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

  await Promise.all([
    ...zoneList
      .filter((z) => z === '.' || !z.endsWith('.arpa.'))
      .map((z) =>
        session
          .query(z, RR_TYPES.ZONEMD, {
            cd: true,
            doBit: true,
            purpose: `Zone ZONEMD (${z})`,
          })
          .catch(() => undefined)
      ),
    ...nonRootLeafZones.flatMap((lz) => {
      const tasks: Promise<unknown>[] = [
        session
          .query(lz, RR_TYPES.CDS, {
            cd: true,
            doBit: true,
            purpose: `Zone CDS (${lz})`,
          })
          .catch(() => undefined),
        session
          .query(lz, RR_TYPES.CDNSKEY, {
            cd: true,
            doBit: true,
            purpose: `Zone CDNSKEY (${lz})`,
          })
          .catch(() => undefined),
      ];
      // For leaf domain zones (depth >= 2, excluding .arpa reverse zones), probe wildcard synthesis and apex TXT hygiene
      if (!lz.endsWith('.arpa.') && getDomainHierarchy(lz).length >= 3) {
        const wildcardQname = `${WILDCARD_PROBE_LABEL}.${lz}`;
        tasks.push(
          session
            .query(wildcardQname, RR_TYPES.A, {
              cd: true,
              doBit: true,
              purpose: `Wildcard probe (${lz} A)`,
            })
            .catch(() => undefined),
          session
            .query(wildcardQname, RR_TYPES.AAAA, {
              cd: true,
              doBit: true,
              purpose: `Wildcard probe (${lz} AAAA)`,
            })
            .catch(() => undefined),
          session
            .query(wildcardQname, RR_TYPES.MX, {
              cd: true,
              doBit: true,
              purpose: `Wildcard probe (${lz} MX)`,
            })
            .catch(() => undefined)
        );
        if (!findLog(currentLogs, lz, RR_TYPES.TXT, true)) {
          tasks.push(
            session
              .query(lz, RR_TYPES.TXT, {
                cd: true,
                doBit: true,
                purpose: `Zone TXT (${lz})`,
              })
              .catch(() => undefined)
          );
        }
      }
      return tasks;
    }),
    ...Array.from(nsHosts).flatMap((host) => [
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
    ]),
  ]);

  // Phase 4a: BGP ASN & Prefix Lookup for resolved authoritative nameserver IPs (via Team Cymru DNS)
  const nsOriginQnames = new Set<string>();
  for (const log of session.getLogs()) {
    if (!log.purpose.startsWith('Nameserver IP')) continue;
    for (const ans of log.packet.answers) {
      if (ans.type === RR_TYPES.A || ans.type === RR_TYPES.AAAA) {
        const originQ = ipToCymruOriginQname(ans.rdataText);
        if (originQ) {
          nsOriginQnames.add(originQ);
          if (nsOriginQnames.size >= 12) break;
        }
      }
    }
    if (nsOriginQnames.size >= 12) break;
  }

  if (nsOriginQnames.size > 0) {
    const originLogs = await Promise.all(
      Array.from(nsOriginQnames).map((originQ) =>
        session
          .query(originQ, RR_TYPES.TXT, {
            cd: false,
            doBit: false,
            purpose: `BGP ASN lookup (${originQ} TXT)`,
          })
          .catch(() => undefined)
      )
    );
    const nsUniqueAsns = new Set<number>();
    const nsRpkiPairs = new Map<string, { asn: number; prefix: string }>();
    for (const oLog of originLogs) {
      if (!oLog) continue;
      const txts: string[] = [];
      for (const ans of oLog.packet.answers) {
        if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
          txts.push(ans.parsed.joinedText);
        }
      }
      for (const parsed of parseCymruOriginTxt(txts)) {
        for (const asn of parsed.asns) {
          nsUniqueAsns.add(asn);
          if (parsed.bgpPrefix && nsRpkiPairs.size < 12) {
            nsRpkiPairs.set(`${asn}|${parsed.bgpPrefix}`, {
              asn,
              prefix: parsed.bgpPrefix,
            });
          }
        }
      }
    }
    if (nsUniqueAsns.size > 0 || nsRpkiPairs.size > 0) {
      await Promise.all([
        ...Array.from(nsUniqueAsns)
          .slice(0, 8)
          .map((asn) => {
            const asnQname = `as${asn}.asn.cymru.com.`;
            return session
              .query(asnQname, RR_TYPES.TXT, {
                cd: false,
                doBit: false,
                purpose: `BGP ASN lookup (${asnQname} TXT)`,
              })
              .catch(() => undefined);
          }),
        ...Array.from(nsRpkiPairs.values()).map((pair) =>
          validateRpkiRoute(pair.asn, pair.prefix).catch(() => undefined)
        ),
      ]);
    }
  }

  // Phase 4b: Reverse DNS Forward-Confirmed rDNS (FCrDNS) & Team Cymru BGP ASN Lookup
  if (reverseIpTarget) {
    const ptrTargets = new Set<string>();
    const logsNow = session.getLogs();
    for (const log of logsNow) {
      if (log.qtype === RR_TYPES.PTR) {
        for (const ans of log.packet.answers) {
          if (ans.type === RR_TYPES.PTR && ans.parsed.kind === 'GENERIC' && ans.parsed.target) {
            ptrTargets.add(normalizeFqdn(ans.parsed.target));
          }
        }
      }
    }

    const rdnsTasks: Promise<unknown>[] = [];
    for (const ptrHost of Array.from(ptrTargets).slice(0, 8)) {
      rdnsTasks.push(
        session
          .query(ptrHost, RR_TYPES.A, {
            cd: false,
            doBit: true,
            purpose: `Reverse FCrDNS lookup (${ptrHost} A)`,
          })
          .catch(() => undefined),
        session
          .query(ptrHost, RR_TYPES.AAAA, {
            cd: false,
            doBit: true,
            purpose: `Reverse FCrDNS lookup (${ptrHost} AAAA)`,
          })
          .catch(() => undefined)
      );
    }

    if (reverseIpTarget.isPublic && reverseIpTarget.cymruOriginQname) {
      const originQname = reverseIpTarget.cymruOriginQname;
      rdnsTasks.push(
        session
          .query(originQname, RR_TYPES.TXT, {
            cd: false,
            doBit: true,
            purpose: `BGP ASN lookup (${originQname} TXT)`,
          })
          .then(async (originLog) => {
            const txtStrings: string[] = [];
            for (const ans of originLog.packet.answers) {
              if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
                txtStrings.push(ans.parsed.joinedText);
              }
            }
            const parsedOrigins = parseCymruOriginTxt(txtStrings);
            const uniqueAsns = Array.from(
              new Set(parsedOrigins.flatMap((o) => o.asns))
            ).slice(0, 4);
            const rdnsRpkiPairs = new Map<string, { asn: number; prefix: string }>();
            for (const o of parsedOrigins) {
              if (!o.bgpPrefix) continue;
              for (const asn of o.asns) {
                rdnsRpkiPairs.set(`${asn}|${o.bgpPrefix}`, { asn, prefix: o.bgpPrefix });
              }
            }
            if (uniqueAsns.length > 0 || rdnsRpkiPairs.size > 0) {
              await Promise.all([
                ...uniqueAsns.map((asn) => {
                  const asnQname = `as${asn}.asn.cymru.com.`;
                  return session
                    .query(asnQname, RR_TYPES.TXT, {
                      cd: false,
                      doBit: true,
                      purpose: `BGP ASN lookup (${asnQname} TXT)`,
                    })
                    .catch(() => undefined);
                }),
                ...Array.from(rdnsRpkiPairs.values()).map((pair) =>
                  validateRpkiRoute(pair.asn, pair.prefix).catch(() => undefined)
                ),
              ]);
            }
          })
          .catch(() => undefined)
      );
    }

    if (
      reverseIpTarget.family === 4 &&
      (reverseIpTarget.isPublic || reverseIpTarget.ip === '127.0.0.2')
    ) {
      rdnsTasks.push(queryDnsblForIp(session, reverseIpTarget.ip));
    }

    if (rdnsTasks.length > 0) {
      await Promise.all(rdnsTasks);
    }
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
    queriedIp: reverseIpTarget?.ip,
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
  const existingRpki: RpkiRouteValidation[] = [];
  for (const z of snapshot.zones) {
    for (const ns of z.nameservers) {
      for (const v of ns.rpkiValidations ?? []) {
        existingRpki.push(v);
      }
    }
  }
  if (snapshot.reverseDns?.bgp?.rpkiValidations) {
    existingRpki.push(...snapshot.reverseDns.bgp.rpkiValidations);
  } else if (snapshot.reverseDns?.bgp?.rpki) {
    existingRpki.push(snapshot.reverseDns.bgp.rpki);
  }
  if (existingRpki.length > 0) {
    seedRpkiValidationCache(existingRpki);
  }

  const updated = await evaluateSnapshotFromLogs({
    id: snapshot.id,
    mode: snapshot.mode,
    targetName: snapshot.targetName,
    queriedIp: snapshot.queriedIp,
    queryTypes: snapshot.queryTypes,
    customDkimSelectors: snapshot.customDkimSelectors,
    mtaStsPolicyFetch: snapshot.mtaStsPolicyFetch,
    ctLogFetch: snapshot.ctLogFetch,
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
  queriedIp?: string;
  queryTypes: string[];
  customDkimSelectors?: string[];
  mtaStsPolicyFetch?: MtaStsPolicyFetchResult;
  ctLogFetch?: CtLogFetchResult;
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
    queriedIp,
    queryTypes,
    customDkimSelectors,
    mtaStsPolicyFetch,
    ctLogFetch,
    dohEndpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries,
    trustAnchors,
  } = input;

  const validationEpochSec = Math.floor(validatedAt / 1000);
  const enabledAnchors = trustAnchors.filter((ta) => ta.enabled);
  // Exclude auxiliary out-of-bailiwick nameserver IP, recursive SPF, DMARC report, MX rDNS, Reverse FCrDNS, BGP ASN, DNSBL, and speculative DKIM/Mail helper lookups from DNSSEC zone reconstruction
  const cdLogs = queries.filter(
    (q) =>
      q.cd &&
      !q.purpose.startsWith('Nameserver IP') &&
      !q.purpose.startsWith('SPF lookup') &&
      !q.purpose.startsWith('DMARC lookup') &&
      !q.purpose.startsWith('DKIM probe') &&
      !q.purpose.startsWith('Mail probe') &&
      !(
        q.purpose.startsWith('Mail SRV probe') &&
        !q.packet.answers.some((r) => r.type === RR_TYPES.SRV)
      ) &&
      !(
        q.purpose.startsWith('Zone ZONEMD') &&
        !q.packet.answers.some((r) => r.type === RR_TYPES.ZONEMD)
      ) &&
      !q.purpose.startsWith('MX rDNS lookup') &&
      !q.purpose.startsWith('Reverse FCrDNS lookup') &&
      !q.purpose.startsWith('BGP ASN lookup') &&
      !q.purpose.startsWith('DNSBL reputation lookup') &&
      !q.purpose.startsWith('PSL lookup') &&
      !q.purpose.startsWith('Wildcard probe') &&
      !q.purpose.startsWith('Zone TXT') &&
      !q.purpose.startsWith('Consensus probe') &&
      !q.purpose.startsWith('CT CAA lookup')
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
      log.purpose.startsWith('Mail target') ||
      log.purpose.startsWith('Web target');
    addSectionRecords(log.packet.answers, 'answer', isTarget);
    if (
      (!log.purpose.startsWith('Zone ZONEMD') && !log.purpose.startsWith('Mail SRV probe')) ||
      (log.qname === targetName && queryTypes.includes(log.qtypeName))
    ) {
      addSectionRecords(log.packet.authorities, 'authority', false);
    }
  }

  const findings: AuditFinding[] = [];
  const zonesByName = new Map<string, ZoneAnalysis>();
  const authenticatedKeyTagsByZone = new Map<string, Set<number>>();

  // Build ASN organization lookup table from all Team Cymru AS<n>.asn.cymru.com TXT logs
  const cymruAsnOrgMap = new Map<number, BgpAsnOrganization>();
  for (const log of queries) {
    if (log.qtype === RR_TYPES.TXT && /^as\d+\.asn\.cymru\.com\.$/i.test(log.qname)) {
      const txts: string[] = [];
      for (const ans of log.packet.answers) {
        if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
          txts.push(ans.parsed.joinedText);
        }
      }
      const parsedAsn = parseCymruAsnTxt(txts);
      if (parsedAsn) {
        cymruAsnOrgMap.set(parsedAsn.asn, {
          asn: parsedAsn.asn,
          asName: parsedAsn.asName,
          country: parsedAsn.country,
          rir: parsedAsn.rir,
          allocatedDate: parsedAsn.allocatedDate,
        });
      }
    }
  }

  const lookupIpBgpMeta = (ip: string) => {
    const originQname = ipToCymruOriginQname(ip);
    if (!originQname) return undefined;
    const originLog = queries.find((q) => q.qname === originQname && q.qtype === RR_TYPES.TXT);
    if (!originLog) return undefined;
    const txts: string[] = [];
    for (const ans of originLog.packet.answers) {
      if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
        txts.push(ans.parsed.joinedText);
      }
    }
    const origins = parseCymruOriginTxt(txts);
    if (origins.length === 0) return undefined;
    const primary = origins[0];
    const uniqueAsnNums = Array.from(new Set(origins.flatMap((o) => o.asns)));
    const asns: BgpAsnOrganization[] = uniqueAsnNums.map((asn) => {
      const org = cymruAsnOrgMap.get(asn);
      return {
        asn,
        asName: org?.asName,
        country: org?.country ?? primary.country,
        rir: org?.rir ?? primary.rir,
        allocatedDate: org?.allocatedDate ?? primary.allocatedDate,
      };
    });
    const bgpPrefixes = Array.from(
      new Set(origins.map((o) => o.bgpPrefix).filter((p): p is string => Boolean(p)))
    );
    const rpkiValidations: RpkiRouteValidation[] = [];
    for (const o of origins) {
      if (!o.bgpPrefix) continue;
      for (const asn of o.asns) {
        const v = getCachedRpkiValidation(asn, o.bgpPrefix);
        if (v && !rpkiValidations.some((ex) => ex.asn === v.asn && ex.prefix === v.prefix)) {
          rpkiValidations.push(v);
        }
      }
    }
    return {
      asns,
      bgpPrefixes,
      country: primary.country,
      rir: primary.rir,
      rpkiValidations,
    };
  };

  // Resolve NS IP map & resolution status from helper logs
  const nsIpMap = new Map<
    string,
    {
      ipv4: string[];
      ipv6: string[];
      probedA: boolean;
      probedAAAA: boolean;
      rcodeA?: number;
      rcodeAAAA?: number;
    }
  >();
  for (const log of queries) {
    if (!log.purpose.startsWith('Nameserver IP')) continue;
    const entry = nsIpMap.get(log.qname) ?? {
      ipv4: [],
      ipv6: [],
      probedA: false,
      probedAAAA: false,
    };
    if (log.qtype === RR_TYPES.A) {
      entry.probedA = true;
      entry.rcodeA = log.packet.flags.rcode;
    } else if (log.qtype === RR_TYPES.AAAA) {
      entry.probedAAAA = true;
      entry.rcodeAAAA = log.packet.flags.rcode;
    }

    // Follow CNAME hops inside packet if NS hostname aliases to another name
    let owner = log.qname;
    const visited = new Set<string>([owner]);
    for (let hop = 0; hop < 6; hop++) {
      const cnameAns = log.packet.answers.find(
        (r) => r.name === owner && r.type === RR_TYPES.CNAME
      );
      if (!cnameAns || cnameAns.parsed.kind !== 'GENERIC' || !cnameAns.parsed.target) break;
      const next = normalizeFqdn(cnameAns.parsed.target);
      if (visited.has(next)) break;
      visited.add(next);
      owner = next;
    }

    for (const ans of log.packet.answers) {
      if (ans.name === owner && ans.type === RR_TYPES.A && !entry.ipv4.includes(ans.rdataText)) {
        entry.ipv4.push(ans.rdataText);
      }
      if (
        ans.name === owner &&
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
    const isLeafDelegatedZone =
      depth >= 2 &&
      !sortedZoneNames.some((other) => other !== zoneName && isSubdomainOrEqual(other, zoneName));

    // Evaluate SOA timers (RFC 1912 §2.2 / RIPE-203 / RFC 2308)
    let soaAudit: SoaAuditSummary | undefined;
    if (soa) {
      const soaIssues: SoaTimerIssue[] = [];
      if (soa.retry >= soa.refresh && soa.refresh > 0) {
        soaIssues.push({
          parameter: 'retry',
          value: soa.retry,
          severity: 'warning',
          message: `SOA retry (${soa.retry}s) >= refresh (${soa.refresh}s); RFC 1912 §2.2 requires retry to be strictly smaller than refresh.`,
          rfc: 'RFC 1912 §2.2',
        });
      }
      if (soa.expire < soa.refresh + soa.retry) {
        soaIssues.push({
          parameter: 'expire',
          value: soa.expire,
          severity: 'warning',
          message: `SOA expire (${soa.expire}s) < refresh + retry (${soa.refresh + soa.retry}s); secondary nameservers may expire the zone before completing a retry cycle.`,
          rfc: 'RFC 1912 §2.2',
        });
      } else if (soa.expire < 604800) {
        soaIssues.push({
          parameter: 'expire',
          value: soa.expire,
          severity: 'info',
          message: `SOA expire (${soa.expire}s / ${(soa.expire / 86400).toFixed(1)}d) is shorter than the 7-day (604800s) minimum recommended by RIPE-203 / RFC 1912 §2.2.`,
          rfc: 'RFC 1912 §2.2 / RIPE-203',
        });
      }
      if (soa.minimum > 86400) {
        soaIssues.push({
          parameter: 'minimum',
          value: soa.minimum,
          severity: 'warning',
          message: `SOA minimum / negative caching TTL (${soa.minimum}s) exceeds RFC 2308 §5 / §4 maximum recommendation of 86400s (24h).`,
          rfc: 'RFC 2308 §4',
        });
      }
      soaAudit = {
        valid: soaIssues.length === 0,
        issues: soaIssues,
        summary:
          soaIssues.length === 0
            ? `SOA timers conform to RFC 1912 / RFC 2308 (${soa.refresh}s refresh, ${soa.retry}s retry, ${Math.round(soa.expire / 86400)}d expire, ${soa.minimum}s min TTL).`
            : soaIssues.map((i) => i.message).join(' '),
      };
      if (isLeafDelegatedZone) {
        for (const issue of soaIssues) {
          findings.push({
            id: `${issue.severity}-soa-${issue.parameter}-${zoneName}`,
            severity: issue.severity,
            code: 'SOA_TIMER_ANOMALY',
            title: `SOA ${issue.parameter} timer anomaly (${issue.value}s) in ${zoneName}`,
            detail: issue.message,
            rfc: issue.rfc,
            zone: zoneName,
          });
        }
      }
    }

    const nsLog = findLog(cdLogs, zoneName, RR_TYPES.NS, true);
    const nameservers: NameserverEntry[] = [];
    for (const r of nsLog?.packet.answers ?? []) {
      if (r.name === zoneName && r.type === RR_TYPES.NS && r.parsed.kind === 'GENERIC' && r.parsed.target) {
        const host = normalizeFqdn(r.parsed.target);
        if (!nameservers.some((n) => n.hostname === host)) {
          const ips = nsIpMap.get(host);
          const ipv4 = ips?.ipv4 ?? [];
          const ipv6 = ips?.ipv6 ?? [];
          let nsStatus: NameserverEntry['status'];
          if (ipv4.length > 0 || ipv6.length > 0) {
            nsStatus = 'ok';
          } else if (ips && (ips.probedA || ips.probedAAAA)) {
            const aFailed =
              ips.probedA && (ips.rcodeA === 3 || ips.rcodeA === 2 || ips.rcodeA === 5);
            const aaaaFailed =
              !ips.probedAAAA ||
              ips.rcodeAAAA === 3 ||
              ips.rcodeAAAA === 2 ||
              ips.rcodeAAAA === 5 ||
              ips.rcodeAAAA === 0;
            nsStatus = aFailed && aaaaFailed ? 'dangling' : 'nodata';
          }

          // Aggregate BGP ASN & routed prefixes across all resolved IPs for this nameserver
          const hostAsnsMap = new Map<number, BgpAsnOrganization>();
          const hostPrefixes = new Set<string>();
          const hostRpkiMap = new Map<string, RpkiRouteValidation>();
          let hostCountry: string | undefined;
          let hostRir: string | undefined;
          for (const ip of [...ipv4, ...ipv6]) {
            const bgpMeta = lookupIpBgpMeta(ip);
            if (!bgpMeta) continue;
            if (!hostCountry && bgpMeta.country) hostCountry = bgpMeta.country;
            if (!hostRir && bgpMeta.rir) hostRir = bgpMeta.rir;
            for (const pfx of bgpMeta.bgpPrefixes) hostPrefixes.add(pfx);
            for (const a of bgpMeta.asns) {
              if (!hostAsnsMap.has(a.asn)) hostAsnsMap.set(a.asn, a);
            }
            for (const rv of bgpMeta.rpkiValidations) {
              const rk = `${rv.asn}|${rv.prefix}`;
              if (!hostRpkiMap.has(rk)) hostRpkiMap.set(rk, rv);
            }
          }
          const hostRpkiValidations = Array.from(hostRpkiMap.values());
          const hostRpkiStatus = summarizeRpkiValidationState(hostRpkiValidations);

          nameservers.push({
            hostname: host,
            ipv4,
            ipv6,
            ...(nsStatus ? { status: nsStatus } : {}),
            ...(hostAsnsMap.size > 0 ? { asns: Array.from(hostAsnsMap.values()) } : {}),
            ...(hostPrefixes.size > 0 ? { bgpPrefixes: Array.from(hostPrefixes) } : {}),
            ...(hostCountry ? { country: hostCountry } : {}),
            ...(hostRir ? { rir: hostRir } : {}),
            ...(hostRpkiStatus ? { rpkiStatus: hostRpkiStatus } : {}),
            ...(hostRpkiValidations.length > 0 ? { rpkiValidations: hostRpkiValidations } : {}),
          });
        }
      }
    }

    // Evaluate Nameserver Infrastructure & BGP ASN Diversity
    let nsDiversity: NsDiversityAnalysis | undefined;
    if (nameservers.length > 0) {
      const zoneAsnsMap = new Map<number, BgpAsnOrganization>();
      const zonePrefixes = new Set<string>();
      const danglingHosts: string[] = [];
      let hasIpv4 = false;
      let hasIpv6 = false;
      let anyNsProbed = false;

      for (const ns of nameservers) {
        if (ns.ipv4.length > 0) hasIpv4 = true;
        if (ns.ipv6.length > 0) hasIpv6 = true;
        if (ns.status !== undefined) anyNsProbed = true;
        if (ns.status === 'dangling') danglingHosts.push(ns.hostname);
        for (const a of ns.asns ?? []) {
          if (!zoneAsnsMap.has(a.asn)) zoneAsnsMap.set(a.asn, a);
        }
        for (const pfx of ns.bgpPrefixes ?? []) {
          zonePrefixes.add(pfx);
        }
      }

      const uniqueAsns = Array.from(zoneAsnsMap.values());
      const uniquePrefixes = Array.from(zonePrefixes);
      const singleAsn = nameservers.length >= 2 && uniqueAsns.length === 1;
      const singlePrefix = nameservers.length >= 2 && uniquePrefixes.length === 1;

      let divStatus: NsDiversityAnalysis['status'] = 'diverse';
      if (danglingHosts.length > 0) {
        divStatus = 'dangling';
      } else if (nameservers.length < 2) {
        divStatus = 'insufficient';
      } else if (singlePrefix) {
        divStatus = 'single-prefix';
      } else if (singleAsn) {
        divStatus = 'single-asn';
      }

      let divSummary = `${nameservers.length} authoritative nameserver${nameservers.length === 1 ? '' : 's'}`;
      if (uniqueAsns.length > 0) {
        const asnLabels = uniqueAsns
          .map((a) => `AS${a.asn}${a.asName ? ` (${a.asName})` : ''}`)
          .join(', ');
        divSummary += ` across ${uniqueAsns.length} BGP ASN${uniqueAsns.length === 1 ? '' : 's'} [${asnLabels}]`;
      }
      if (uniquePrefixes.length > 0) {
        divSummary += ` and ${uniquePrefixes.length} routed prefix${uniquePrefixes.length === 1 ? '' : 'es'}`;
      }
      divSummary += '.';

      if (anyNsProbed || uniqueAsns.length > 0) {
        nsDiversity = {
          nameserverCount: nameservers.length,
          uniqueAsns,
          uniquePrefixes,
          hasIpv4,
          hasIpv6,
          danglingHosts,
          singleAsn,
          singlePrefix,
          status: divStatus,
          summary: divSummary,
        };
      }

      if (isLeafDelegatedZone && anyNsProbed) {
        for (const dHost of danglingHosts) {
          const dMeta = nsIpMap.get(dHost);
          const rcodeName =
            dMeta?.rcodeA !== undefined ? rcodeToString(dMeta.rcodeA) : 'NXDOMAIN/SERVFAIL';
          findings.push({
            id: `warn-dangling-ns-${zoneName}-${dHost}`,
            severity: 'warning',
            code: 'DANGLING_NS_TARGET',
            title: `Dangling or unresolvable authoritative NS ${displayFqdn(dHost)} in ${zoneName}`,
            detail: `Authoritative nameserver ${displayFqdn(dHost)} for ${zoneName} failed to resolve to any IPv4/IPv6 address (${rcodeName}), creating lame delegation or subdomain takeover risk.`,
            rfc: 'RFC 1912 §2.8 / RFC 2182',
            zone: zoneName,
          });
        }
        if (singleAsn && uniqueAsns[0]) {
          const onlyAsn = uniqueAsns[0];
          findings.push({
            id: `info-ns-single-asn-${zoneName}`,
            severity: 'info',
            code: 'NS_SINGLE_ASN',
            title: `All ${nameservers.length} authoritative nameservers for ${zoneName} share a single BGP ASN (AS${onlyAsn.asn})`,
            detail: `All authoritative nameservers (${nameservers.map((n) => displayFqdn(n.hostname)).join(', ')}) route through AS${onlyAsn.asn}${onlyAsn.asName ? ` (${onlyAsn.asName})` : ''}${singlePrefix && uniquePrefixes[0] ? ` in a single BGP prefix (${uniquePrefixes[0]})` : ''}. RFC 2182 §3.1 recommends topological and ASN diversity to avoid a single routing point of failure.`,
            rfc: 'RFC 2182 §3.1',
            zone: zoneName,
          });
        }
        if (singlePrefix && uniquePrefixes[0]) {
          findings.push({
            id: `info-ns-single-prefix-${zoneName}`,
            severity: 'info',
            code: 'NS_SINGLE_PREFIX',
            title: `All authoritative nameservers for ${zoneName} reside in a single routed BGP prefix (${uniquePrefixes[0]})`,
            detail: `Every resolved nameserver IP for ${zoneName} is announced within ${uniquePrefixes[0]}. A single BGP route withdrawal or prefix hijack would affect all authoritative nameservers simultaneously.`,
            rfc: 'RFC 2182 §3.1',
            zone: zoneName,
          });
        }
        if (hasIpv4 && !hasIpv6) {
          findings.push({
            id: `info-ns-no-ipv6-${zoneName}`,
            severity: 'info',
            code: 'NS_NO_IPV6',
            title: `IPv4-only authoritative nameservers for ${zoneName} (no AAAA records)`,
            detail: `None of the probed authoritative nameservers for ${zoneName} (${nameservers.map((n) => displayFqdn(n.hostname)).join(', ')}) publish IPv6 AAAA glue/addresses.`,
            rfc: 'RFC 3901',
            zone: zoneName,
          });
        }
        for (const ns of nameservers) {
          for (const rv of ns.rpkiValidations ?? []) {
            if (rv.status === 'invalid-asn' || rv.status === 'invalid-length') {
              const rpkiFindingId = `warn-ns-rpki-invalid-${zoneName}-${ns.hostname}-${rv.asn}-${rv.prefix}`;
              if (!findings.some((f) => f.id === rpkiFindingId)) {
                findings.push({
                  id: rpkiFindingId,
                  severity: 'warning',
                  code: 'BGP_RPKI_ROA_INVALID',
                  title: `Authoritative NS ${displayFqdn(ns.hostname)} (${zoneName}) routed via RPKI-invalid BGP announcement (AS${rv.asn} / ${rv.prefix})`,
                  detail: `${displayFqdn(ns.hostname)} resolves to an IP announced by AS${rv.asn} in ${rv.prefix}: ${rv.summary}`,
                  rfc: 'RFC 6811 / RFC 6480',
                  zone: zoneName,
                });
              }
            }
          }
        }
      }
    }

    // Evaluate Automated DNSSEC Rollover Sync (CDS / CDNSKEY — RFC 7344 & RFC 8078)
    let cdsRollover: CdsRolloverAnalysis | undefined;
    const cdsRrset = analyzedRrsets.find((r) => r.name === zoneName && r.type === RR_TYPES.CDS);
    const cdnskeyRrset = analyzedRrsets.find(
      (r) => r.name === zoneName && r.type === RR_TYPES.CDNSKEY
    );
    const cdsLog = findLog(cdLogs, zoneName, RR_TYPES.CDS, true);
    const cdnskeyLog = findLog(cdLogs, zoneName, RR_TYPES.CDNSKEY, true);

    if (cdsRrset || cdnskeyRrset || cdsLog || cdnskeyLog) {
      const parentDsTagSet = new Set(dsVerifications.map((d) => d.ds.keyTag));
      const childDnskeyTagSet = new Set(
        analyzedDnskeys.filter((k) => k.role !== 'missing').map((k) => k.keyTag)
      );
      const sepKeyTagSet = new Set(
        analyzedDnskeys
          .filter((k) => k.role !== 'missing' && (k.isSep || k.matchedByParentDs))
          .map((k) => k.keyTag)
      );

      const cdsRecords: CdsRecordDetail[] = [];
      for (const rec of cdsRrset?.records ?? []) {
        if (rec.parsed.kind !== 'DS') continue;
        const parsedCds = rec.parsed;
        const isDeleteSignal =
          parsedCds.keyTag === 0 &&
          parsedCds.algorithm === 0 &&
          parsedCds.digestType === 0 &&
          /^0+$/.test(parsedCds.digestHex);
        const matchesParentDs = dsVerifications.some(
          (d) =>
            d.ds.keyTag === parsedCds.keyTag &&
            d.ds.algorithm === parsedCds.algorithm &&
            d.ds.digestType === parsedCds.digestType &&
            d.ds.digestHex.toUpperCase() === parsedCds.digestHex.toUpperCase()
        );
        const matchesChildDnskey = childDnskeyTagSet.has(parsedCds.keyTag);
        cdsRecords.push({
          keyTag: parsedCds.keyTag,
          algorithm: parsedCds.algorithm,
          digestType: parsedCds.digestType,
          digestHex: parsedCds.digestHex,
          isDeleteSignal,
          matchesParentDs,
          matchesChildDnskey,
        });
      }

      const cdnskeyRecords: CdnskeyRecordDetail[] = [];
      for (const rec of cdnskeyRrset?.records ?? []) {
        if (rec.parsed.kind !== 'DNSKEY') continue;
        const isDeleteSignal =
          rec.parsed.flags === 0 && rec.parsed.protocol === 3 && rec.parsed.algorithm === 0;
        const matchesChildDnskey = childDnskeyTagSet.has(rec.parsed.keyTag);
        cdnskeyRecords.push({
          keyTag: rec.parsed.keyTag,
          flags: rec.parsed.flags,
          protocol: rec.parsed.protocol,
          algorithm: rec.parsed.algorithm,
          publicKeyBase64: rec.parsed.publicKeyBase64,
          isDeleteSignal,
          matchesChildDnskey,
        });
      }

      const present = cdsRecords.length > 0 || cdnskeyRecords.length > 0;
      const signedByKsk =
        (cdsRrset?.rrsigs.some(
          (rv) => rv.cryptoValid && rv.timeValid && sepKeyTagSet.has(rv.signerKeyTag)
        ) ??
          false) ||
        (cdnskeyRrset?.rrsigs.some(
          (rv) => rv.cryptoValid && rv.timeValid && sepKeyTagSet.has(rv.signerKeyTag)
        ) ??
          false);

      const parentDsKeyTags = Array.from(parentDsTagSet);
      const childCdsKeyTags = Array.from(
        new Set([
          ...cdsRecords.filter((c) => !c.isDeleteSignal).map((c) => c.keyTag),
          ...cdnskeyRecords.filter((c) => !c.isDeleteSignal).map((c) => c.keyTag),
        ])
      );

      let rolloverStatus: CdsRolloverAnalysis['status'] = 'not-published';
      let rolloverSummary = `No CDS or CDNSKEY records published at ${zoneName}.`;

      if (present) {
        const hasDeleteSignal =
          cdsRecords.some((c) => c.isDeleteSignal) ||
          cdnskeyRecords.some((c) => c.isDeleteSignal);
        const isBogusOrUnsigned =
          cdsRrset?.status === 'bogus' ||
          cdnskeyRrset?.status === 'bogus' ||
          !signedByKsk;

        if (hasDeleteSignal) {
          rolloverStatus = 'delete-signal';
          rolloverSummary = `${zoneName} publishes an RFC 8078 §4 CDS/CDNSKEY delete signal (algorithm 0), requesting parent ${parentZone ?? '.'} to remove its DS RRset and transition to unsigned.`;
          findings.push({
            id: `warn-cds-delete-${zoneName}`,
            severity: 'warning',
            code: 'CDS_DELETE_SIGNAL',
            title: `RFC 8078 CDS/CDNSKEY DS deletion signal published at ${zoneName}`,
            detail: rolloverSummary,
            rfc: 'RFC 8078 §4',
            zone: zoneName,
            targetId: cdsRrset?.id ?? cdnskeyRrset?.id,
          });
        } else if (isBogusOrUnsigned) {
          rolloverStatus = 'unsigned-invalid';
          rolloverSummary = `CDS/CDNSKEY RRset at ${zoneName} is not validly signed by an active SEP KSK (RFC 7344 §4.1 requires KSK signature).`;
          findings.push({
            id: `warn-cds-invalid-${zoneName}`,
            severity: 'warning',
            code: 'CDS_WITHOUT_KSK_RRSIG',
            title: `CDS/CDNSKEY at ${zoneName} lacks valid KSK signature`,
            detail: rolloverSummary,
            rfc: 'RFC 7344 §4.1',
            zone: zoneName,
            targetId: cdsRrset?.id ?? cdnskeyRrset?.id,
          });
        } else {
          const allChildTagsInParent =
            childCdsKeyTags.length > 0 &&
            childCdsKeyTags.every((t) => parentDsTagSet.has(t)) &&
            parentDsKeyTags.every((t) => childCdsKeyTags.includes(t));

          if (allChildTagsInParent) {
            rolloverStatus = 'in-sync';
            rolloverSummary = `Child CDS/CDNSKEY (${childCdsKeyTags.map((t) => `#${t}`).join(', ')}) is synchronized with parent ${parentZone ?? '.'} DS RRset and signed by KSK.`;
            findings.push({
              id: `info-cds-sync-${zoneName}`,
              severity: 'info',
              code: 'CDS_PARENT_IN_SYNC',
              title: `CDS/CDNSKEY synchronized with parent DS at ${zoneName} (${childCdsKeyTags.map((t) => `#${t}`).join(', ')})`,
              detail: rolloverSummary,
              rfc: 'RFC 7344 / RFC 8078',
              zone: zoneName,
              targetId: cdsRrset?.id ?? cdnskeyRrset?.id,
            });
          } else {
            rolloverStatus = 'rollover-pending';
            const parentStr =
              parentDsKeyTags.length > 0
                ? parentDsKeyTags.map((t) => `#${t}`).join(', ')
                : 'none (unsigned delegation)';
            const childStr = childCdsKeyTags.map((t) => `#${t}`).join(', ');
            rolloverSummary = `Child ${zoneName} publishes CDS/CDNSKEY for key ${childStr}, while parent ${parentZone ?? '.'} currently publishes DS for ${parentStr} — automated KSK rollover or initial DS bootstrap in progress.`;
            findings.push({
              id: `warn-cds-mismatch-${zoneName}`,
              severity: 'warning',
              code: 'CDS_PARENT_MISMATCH',
              title: `CDS/CDNSKEY rollover mismatch between ${zoneName} (${childStr}) and parent ${parentZone ?? '.'} DS (${parentStr})`,
              detail: rolloverSummary,
              rfc: 'RFC 7344 / RFC 8078',
              zone: zoneName,
              targetId: cdsRrset?.id ?? cdnskeyRrset?.id,
            });
          }
        }
      }

      cdsRollover = {
        present,
        status: rolloverStatus,
        cdsRecords,
        cdnskeyRecords,
        cdsDnssecStatus: cdsRrset?.status,
        cdnskeyDnssecStatus: cdnskeyRrset?.status,
        signedByKsk,
        parentDsKeyTags,
        childCdsKeyTags,
        summary: rolloverSummary,
      };
    }

    // Evaluate Zone Digest (ZONEMD — RFC 8976)
    let zonemd: ZonemdAuditSummary | undefined;
    const zonemdRrset = analyzedRrsets.find(
      (r) => r.name === zoneName && r.type === RR_TYPES.ZONEMD
    );
    const zonemdLog = findLog(cdLogs, zoneName, RR_TYPES.ZONEMD, true);
    if (zonemdRrset || zonemdLog) {
      const zonemdRecords: ZonemdRecordDetail[] = [];
      for (const rec of zonemdRrset?.records ?? []) {
        if (rec.parsed.kind !== 'ZONEMD') continue;
        zonemdRecords.push({
          serial: rec.parsed.serial,
          scheme: rec.parsed.scheme,
          schemeName: rec.parsed.schemeName,
          hashAlgorithm: rec.parsed.hashAlgorithm,
          hashAlgorithmName: rec.parsed.hashAlgorithmName,
          digestHex: rec.parsed.digestHex,
          digestByteLength: rec.parsed.digestByteLength,
          digestLengthValid: rec.parsed.digestLengthValid,
          serialMatchesSoa: soa !== undefined ? rec.parsed.serial === soa.serial : true,
        });
      }

      if (zonemdRecords.length > 0) {
        const anyInvalidDigest = zonemdRecords.some(
          (z) => !z.digestLengthValid || (z.scheme !== 1 && (z.scheme < 240 || z.scheme > 254))
        );
        const anySerialMatch = zonemdRecords.some((z) => z.serialMatchesSoa);
        const isSignedValid =
          zonemdRrset?.status === 'secure' || zonemdRrset?.status === 'warning';

        let zmdStatus: ZonemdAuditSummary['status'] = 'valid-sync';
        let zmdSummary = '';

        if (anyInvalidDigest) {
          zmdStatus = 'invalid-digest';
          zmdSummary = `ZONEMD record in ${zoneName} has an invalid digest length or unrecognized scheme/algorithm per RFC 8976 §2.2.`;
          findings.push({
            id: `err-zonemd-digest-${zoneName}`,
            severity: 'error',
            code: 'ZONEMD_INVALID_DIGEST',
            title: `Invalid ZONEMD digest parameters in ${zoneName}`,
            detail: zmdSummary,
            rfc: 'RFC 8976 §2.2',
            zone: zoneName,
            targetId: zonemdRrset?.id,
          });
        } else if (soa && !anySerialMatch) {
          zmdStatus = 'serial-mismatch';
          const zmdSerials = zonemdRecords.map((z) => z.serial).join(', ');
          zmdSummary = `ZONEMD serial (${zmdSerials}) at ${zoneName} does not match authoritative SOA serial (${soa.serial}) — zone digest is out of sync with the served SOA.`;
          findings.push({
            id: `warn-zonemd-serial-${zoneName}`,
            severity: 'warning',
            code: 'ZONEMD_SERIAL_MISMATCH',
            title: `ZONEMD serial (${zmdSerials}) out of sync with SOA serial (${soa.serial}) in ${zoneName}`,
            detail: zmdSummary,
            rfc: 'RFC 8976 §4.2',
            zone: zoneName,
            targetId: zonemdRrset?.id,
          });
        } else if (!isSignedValid) {
          zmdStatus = 'unsigned-warning';
          zmdSummary = `ZONEMD record published at ${zoneName}, but RFC 8976 §4 requires a valid DNSSEC signature to authenticate the zone digest.`;
          findings.push({
            id: `warn-zonemd-unsigned-${zoneName}`,
            severity: 'warning',
            code: 'ZONEMD_UNSIGNED',
            title: `ZONEMD published without valid DNSSEC signature in ${zoneName}`,
            detail: zmdSummary,
            rfc: 'RFC 8976 §4',
            zone: zoneName,
            targetId: zonemdRrset?.id,
          });
        } else {
          zmdStatus = 'valid-sync';
          const schemes = Array.from(
            new Set(zonemdRecords.map((z) => `${z.schemeName}/${z.hashAlgorithmName}`))
          ).join(', ');
          zmdSummary = `RFC 8976 ZONEMD (${schemes}) is DNSSEC-authenticated and synchronized with ${zoneName} SOA serial ${soa?.serial ?? zonemdRecords[0].serial}.`;
          findings.push({
            id: `info-zonemd-sync-${zoneName}`,
            severity: 'info',
            code: 'ZONEMD_SERIAL_SYNC',
            title: `RFC 8976 ZONEMD zone digest verified in sync at ${zoneName} (serial ${soa?.serial ?? zonemdRecords[0].serial})`,
            detail: zmdSummary,
            rfc: 'RFC 8976',
            zone: zoneName,
            targetId: zonemdRrset?.id,
          });
        }

        zonemd = {
          present: true,
          status: zmdStatus,
          dnssecStatus: zonemdRrset?.status,
          soaSerial: soa?.serial,
          records: zonemdRecords,
          summary: zmdSummary,
        };
      } else if (isLeafDelegatedZone) {
        zonemd = {
          present: false,
          status: 'not-published',
          soaSerial: soa?.serial,
          records: [],
          summary: `No ZONEMD zone digest record published at ${zoneName} (RFC 8976).`,
        };
      }
    }

    // Evaluate Wildcard DNS (*.zone) Synthesis & RFC 4035 §5.3.4 / RFC 5155 §7.2.6 Proofs
    let wildcardAudit: WildcardAuditSummary | undefined;
    if (isLeafDelegatedZone && !zoneName.endsWith('.arpa.')) {
      wildcardAudit = await evaluateWildcardAuditForZone({
        zoneName,
        queries,
        zoneDnskeys: rawZoneDnskeys.get(zoneName) ?? [],
        zoneStatus,
        validationEpochSec,
        findings,
      });
    }

    // Evaluate Apex TXT Inventory & SaaS Verification Hygiene
    let txtHygiene: TxtHygieneAudit | undefined;
    if (isLeafDelegatedZone && !zoneName.endsWith('.arpa.')) {
      txtHygiene = evaluateTxtHygieneForZone({
        zoneName,
        queries,
        findings,
      });
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
      ...(soaAudit ? { soaAudit } : {}),
      ...(cdsRollover ? { cdsRollover } : {}),
      ...(nsDiversity ? { nsDiversity } : {}),
      ...(zonemd ? { zonemd } : {}),
      ...(wildcardAudit ? { wildcardAudit } : {}),
      ...(txtHygiene ? { txtHygiene } : {}),
    });
  }

  // 6. Build CNAME Edges & Target Negative Response Nodes (NXDOMAIN / NODATA)
  const cnameEdges: CnameEdge[] = [];
  const targetProbes: Array<{ owner: string; qt: string }> = queryTypes.map((qt) => ({
    owner: targetName,
    qt,
  }));
  for (const log of cdLogs) {
    if (log.purpose.startsWith('Mail target') || log.purpose.startsWith('Web target')) {
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
            if (negKind === 'NXDOMAIN' && !curName.endsWith('.in-addr.arpa.')) {
              const danglingCnameId = `warn-dangling-cname-${lastCnameFrom}-${curName}`;
              if (!findings.some((f) => f.id === danglingCnameId)) {
                findings.push({
                  id: danglingCnameId,
                  severity: 'warning',
                  code: 'DANGLING_CNAME',
                  title: `Dangling CNAME alias: ${displayFqdn(lastCnameFrom)} -> ${displayFqdn(curName)} (NXDOMAIN)`,
                  detail: `${displayFqdn(lastCnameFrom)} aliases via CNAME to ${displayFqdn(curName)}, which does not exist (NXDOMAIN in ${authZoneName}). Dangling CNAME records pointing to unclaimed external hostnames or cloud resources pose a subdomain takeover risk.`,
                  rfc: 'RFC 1034 §3.6.2 / RFC 1912 §2.4',
                  zone: authZoneName,
                  targetId: negId,
                });
              }
            }
          }
        }
      } else if (lastCnameRrsetId && lastCnameFrom && (rcode === 2 || rcode === 5)) {
        const danglingCnameId = `warn-dangling-cname-${lastCnameFrom}-${curName}`;
        if (!findings.some((f) => f.id === danglingCnameId)) {
          findings.push({
            id: danglingCnameId,
            severity: 'warning',
            code: 'DANGLING_CNAME',
            title: `Broken CNAME target: ${displayFqdn(lastCnameFrom)} -> ${displayFqdn(curName)} (${rcodeToString(rcode)})`,
            detail: `${displayFqdn(lastCnameFrom)} aliases via CNAME to ${displayFqdn(curName)}, which failed to resolve (${rcodeToString(rcode)}).`,
            rfc: 'RFC 1034 §3.6.2',
            targetId: lastCnameRrsetId,
          });
        }
      }
    }
  }

  // 7. Packet Size / UDP Fragmentation & Extended DNS Error (RFC 8914) Audit Checks
  for (const log of queries) {
    if (
      log.purpose.startsWith('Nameserver IP') ||
      log.purpose.startsWith('Reverse FCrDNS lookup') ||
      log.purpose.startsWith('BGP ASN lookup') ||
      log.purpose.startsWith('DNSBL reputation lookup') ||
      log.purpose.startsWith('PSL lookup') ||
      log.purpose.startsWith('Consensus probe') ||
      log.purpose.startsWith('CT CAA lookup')
    ) {
      continue;
    }
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
    queries.find(
      (q) =>
        !q.cd &&
        !q.purpose.startsWith('SPF lookup') &&
        !q.purpose.startsWith('Reverse FCrDNS lookup') &&
        !q.purpose.startsWith('BGP ASN lookup') &&
        !q.purpose.startsWith('DNSBL reputation lookup') &&
        !q.purpose.startsWith('PSL lookup')
    );
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

  const isSpecializedMode = mode === 'mail' || mode === 'web';
  const targetLeafZones = zones.filter((z) => {
    const isTargetAnc = isSubdomainOrEqual(targetName, z.zoneName);
    const isCnameTargetAnc =
      !isSpecializedMode && cnameEdges.some((ce) => isSubdomainOrEqual(ce.toName, z.zoneName));
    return isTargetAnc || isCnameTargetAnc;
  });

  // Check target RRset / negativeNode statuses specifically
  const targetElementStatuses: ValidationStatus[] = [];
  for (const z of zones) {
    if (isSpecializedMode && !isSubdomainOrEqual(targetName, z.zoneName)) {
      continue;
    }
    for (const r of z.rrsets) {
      if (r.isQueryTarget && (!isSpecializedMode || r.name === targetName)) {
        targetElementStatuses.push(r.status);
      }
    }
    for (const n of z.negativeNodes) {
      if (!isSpecializedMode || n.qname === targetName) {
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
      mtaStsPolicyFetch,
    });
    mailAnalysis = mailResult.mailAnalysis;
    findings.push(...mailResult.mailFindings);
    overallStatus = mailResult.overallStatus;
    overallSummary = mailResult.overallSummary;
  }

  let webAnalysis: AnalysisSnapshot['webAnalysis'];
  if (mode === 'web') {
    const webResult = evaluateWebFromSnapshotData({
      targetName,
      queries,
      zones,
      cnameEdges,
      targetDomainStatus: overallStatus,
      ctLogFetch,
      validatedAt,
    });
    webAnalysis = webResult.webAnalysis;
    findings.push(...webResult.webFindings);
    overallStatus = webResult.overallStatus;
    overallSummary = webResult.overallSummary;
  }

  let consensusAnalysis: AnalysisSnapshot['consensusAnalysis'];
  if (mode === 'consensus') {
    const consensusResult = evaluateConsensusFromSnapshotData({
      targetName,
      primaryEndpoint: dohEndpoint,
      queries,
      zones,
      targetDomainStatus: overallStatus,
    });
    consensusAnalysis = consensusResult.consensusAnalysis;
    findings.push(...consensusResult.consensusFindings);
    overallStatus = consensusResult.overallStatus;
    overallSummary = consensusResult.overallSummary;
  }

  let reverseDns: ReverseDnsAnalysis | undefined;
  const reverseIpTarget =
    mode !== 'mail' && mode !== 'web' && mode !== 'consensus'
      ? parseReverseIpInput(queriedIp ?? targetName)
      : null;
  if (reverseIpTarget) {
    const rdnsEval = evaluateReverseDnsFromSnapshotData({
      reverseIpTarget,
      queries,
      zones,
      cnameEdges,
      overallStatus,
    });
    reverseDns = rdnsEval.reverseDns;
    findings.push(...rdnsEval.findings);
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
    ...(reverseIpTarget ? { queriedIp: reverseIpTarget.ip } : {}),
    queryTypes,
    ...(customDkimSelectors && customDkimSelectors.length > 0 ? { customDkimSelectors } : {}),
    ...(mtaStsPolicyFetch ? { mtaStsPolicyFetch } : {}),
    ...(ctLogFetch ? { ctLogFetch } : {}),
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
    ...(webAnalysis ? { webAnalysis } : {}),
    ...(consensusAnalysis ? { consensusAnalysis } : {}),
    ...(reverseDns ? { reverseDns } : {}),
  };
}

function evaluateReverseDnsFromSnapshotData(params: {
  reverseIpTarget: ParsedReverseIpTarget;
  queries: DohQueryLog[];
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  overallStatus: ValidationStatus;
}): { reverseDns: ReverseDnsAnalysis; findings: AuditFinding[] } {
  const { reverseIpTarget, queries, zones, cnameEdges, overallStatus } = params;
  const findings: AuditFinding[] = [];

  // 1. Walk any CNAME chain from reverseIpTarget.arpaFqdn to terminal PTR owner (e.g. RFC 2317 classless delegation)
  const cnameChain: string[] = [];
  let resolvedOwner = reverseIpTarget.arpaFqdn;
  const seenCname = new Set<string>([resolvedOwner]);
  for (let hop = 0; hop < 8; hop++) {
    const edge = cnameEdges.find((e) => e.fromName === resolvedOwner && e.qtypeName === 'PTR');
    if (edge) {
      cnameChain.push(edge.toName);
      resolvedOwner = edge.toName;
      if (seenCname.has(resolvedOwner)) break;
      seenCname.add(resolvedOwner);
      continue;
    }
    const log = queries.find((q) => q.qname === resolvedOwner && q.qtype === RR_TYPES.PTR && q.cd);
    const cnameAns = log?.packet.answers.find(
      (r) => r.name === resolvedOwner && r.type === RR_TYPES.CNAME
    );
    if (cnameAns && cnameAns.parsed.kind === 'GENERIC' && cnameAns.parsed.target) {
      const next = normalizeFqdn(cnameAns.parsed.target);
      if (seenCname.has(next)) break;
      cnameChain.push(next);
      resolvedOwner = next;
      seenCname.add(next);
    } else {
      break;
    }
  }

  const isRfc2317ClasslessDelegation =
    cnameChain.length > 0 && reverseIpTarget.arpaFqdn.endsWith('.in-addr.arpa.');
  if (isRfc2317ClasslessDelegation) {
    findings.push({
      id: `info-rfc2317-${reverseIpTarget.arpaFqdn}`,
      severity: 'info',
      code: 'RFC2317_CLASSLESS_RDNS',
      title: `RFC 2317 classless IN-ADDR.ARPA CNAME delegation (${reverseIpTarget.displayArpa})`,
      detail: `${reverseIpTarget.displayArpa} delegates reverse DNS via CNAME chain (${cnameChain.map(displayFqdn).join(' -> ')}) per RFC 2317.`,
      rfc: 'RFC 2317',
    });
  }

  // Locate PTR RRset or negativeNode across analyzed zones
  let ptrRrset: AnalyzedRrset | undefined;
  let ptrNegNode: ZoneAnalysis['negativeNodes'][number] | undefined;
  for (const z of zones) {
    const rr = z.rrsets.find((r) => r.name === resolvedOwner && r.type === RR_TYPES.PTR);
    if (rr) ptrRrset = rr;
    const neg = z.negativeNodes.find(
      (n) => (n.qname === resolvedOwner || n.qname === reverseIpTarget.arpaFqdn) && n.qtypeName === 'PTR'
    );
    if (neg) ptrNegNode = neg;
  }

  const ptrLog =
    queries.find((q) => q.qname === resolvedOwner && q.qtype === RR_TYPES.PTR && q.cd) ??
    queries.find((q) => q.qname === reverseIpTarget.arpaFqdn && q.qtype === RR_TYPES.PTR);

  const ptrNames: string[] = [];
  for (const ans of ptrRrset?.records ?? ptrLog?.packet.answers ?? []) {
    if (ans.type === RR_TYPES.PTR && ans.parsed.kind === 'GENERIC' && ans.parsed.target) {
      const target = normalizeFqdn(ans.parsed.target);
      if (!ptrNames.includes(target)) ptrNames.push(target);
    }
  }

  let ptrStatus: ReverseDnsAnalysis['ptrStatus'] = 'resolved';
  if (ptrNames.length > 0) {
    ptrStatus = 'resolved';
  } else if (ptrLog?.packet.flags.rcode === 3 || ptrNegNode?.kind === 'NXDOMAIN') {
    ptrStatus = 'nxdomain';
  } else if (ptrLog && ptrLog.packet.flags.rcode !== 0) {
    ptrStatus = 'servfail';
  } else {
    ptrStatus = 'nodata';
  }

  const ptrDnssecStatus: ValidationStatus =
    ptrRrset?.status ?? ptrNegNode?.status ?? overallStatus;

  // 2. Evaluate Forward-Confirmed Reverse DNS (FCrDNS) for each PTR target hostname
  const canonicalTargetIp =
    reverseIpTarget.family === 4
      ? parseIpv4Octets(reverseIpTarget.ip)?.join('.') ?? reverseIpTarget.ip
      : (() => {
          const g = parseIpv6Groups(reverseIpTarget.ip);
          return g ? formatCanonicalIpv6(g) : reverseIpTarget.ip.toLowerCase();
        })();

  const targets: ReversePtrTargetEntry[] = ptrNames.map((hostname) => {
    const aLog =
      queries.find((q) => q.qname === hostname && q.qtype === RR_TYPES.A && !q.cd) ??
      queries.find((q) => q.qname === hostname && q.qtype === RR_TYPES.A);
    const aaaaLog =
      queries.find((q) => q.qname === hostname && q.qtype === RR_TYPES.AAAA && !q.cd) ??
      queries.find((q) => q.qname === hostname && q.qtype === RR_TYPES.AAAA);

    const forwardIpv4: string[] = [];
    const forwardIpv6: string[] = [];

    for (const ans of aLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.A && ans.rdataText) {
        const octs = parseIpv4Octets(ans.rdataText);
        const normV4 = octs ? octs.join('.') : ans.rdataText.trim();
        if (!forwardIpv4.includes(normV4)) forwardIpv4.push(normV4);
      }
    }
    for (const ans of aaaaLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.AAAA && ans.rdataText) {
        const grps = parseIpv6Groups(ans.rdataText);
        const normV6 = grps ? formatCanonicalIpv6(grps) : ans.rdataText.trim().toLowerCase();
        if (!forwardIpv6.includes(normV6)) forwardIpv6.push(normV6);
      }
    }

    let forwardStatus: ReversePtrTargetEntry['forwardStatus'] = 'unchecked';
    if (!aLog && !aaaaLog) {
      forwardStatus = 'unchecked';
    } else {
      const relevantList = reverseIpTarget.family === 4 ? forwardIpv4 : forwardIpv6;
      if (relevantList.includes(canonicalTargetIp)) {
        forwardStatus = 'match';
      } else if (forwardIpv4.length > 0 || forwardIpv6.length > 0) {
        forwardStatus = 'mismatch';
      } else if (
        (aLog && aLog.packet.flags.rcode === 3) ||
        (aaaaLog && aaaaLog.packet.flags.rcode === 3)
      ) {
        forwardStatus = 'nxdomain';
      } else if (
        (aLog && aLog.packet.flags.rcode !== 0) ||
        (aaaaLog && aaaaLog.packet.flags.rcode !== 0)
      ) {
        forwardStatus = 'temperror';
      } else {
        forwardStatus = 'nodata';
      }
    }

    const relevantForwardLog = reverseIpTarget.family === 4 ? aLog : aaaaLog;
    const forwardDnssecStatus: ValidationStatus = relevantForwardLog
      ? relevantForwardLog.packet.flags.rcode !== 0 && relevantForwardLog.packet.flags.rcode !== 3
        ? 'bogus'
        : relevantForwardLog.packet.flags.ad
          ? 'secure'
          : 'insecure'
      : 'indeterminate';

    return {
      hostname,
      displayHostname: displayFqdn(hostname),
      forwardStatus,
      forwardIpv4,
      forwardIpv6,
      forwardDnssecStatus,
    };
  });

  let fcrdnsStatus: ReverseDnsAnalysis['fcrdnsStatus'] = 'not-applicable';
  let fcrdnsSummary = '';
  if (ptrStatus !== 'resolved' || targets.length === 0) {
    fcrdnsStatus = ptrStatus === 'servfail' ? 'temperror' : 'no-ptr';
    fcrdnsSummary =
      ptrStatus === 'nxdomain'
        ? `No PTR record published for ${reverseIpTarget.ip} (${reverseIpTarget.displayArpa} returned NXDOMAIN).`
        : ptrStatus === 'servfail'
          ? `Reverse DNS PTR query for ${reverseIpTarget.ip} failed (SERVFAIL).`
          : `No PTR record published at ${reverseIpTarget.displayArpa} (NODATA).`;

    if (ptrStatus === 'nxdomain' || ptrStatus === 'nodata') {
      findings.push({
        id: `info-rdns-no-ptr-${reverseIpTarget.ip}`,
        severity: 'info',
        code: 'RDNS_PTR_MISSING',
        title: `No PTR record published for ${reverseIpTarget.ip} (${reverseIpTarget.displayArpa})`,
        detail: fcrdnsSummary,
        rfc: 'RFC 1912 §2.1',
        targetId: ptrNegNode?.id,
      });
    }
  } else {
    const checkedTargets = targets.filter((t) => t.forwardStatus !== 'unchecked');
    const matchedTargets = targets.filter((t) => t.forwardStatus === 'match');
    if (checkedTargets.length === 0) {
      fcrdnsStatus = 'not-applicable';
      fcrdnsSummary = `PTR resolves to ${targets.map((t) => t.displayHostname).join(', ')}.`;
    } else if (matchedTargets.length === targets.length) {
      fcrdnsStatus = 'valid';
      fcrdnsSummary = `Forward-Confirmed Reverse DNS (FCrDNS) verified: ${targets.map((t) => t.displayHostname).join(', ')} resolves back to ${reverseIpTarget.ip}.`;
    } else if (matchedTargets.length > 0) {
      fcrdnsStatus = 'partial';
      fcrdnsSummary = `Partial FCrDNS match (${matchedTargets.length}/${targets.length} PTR hostnames resolve back to ${reverseIpTarget.ip}).`;
      findings.push({
        id: `warn-rdns-fcrdns-partial-${reverseIpTarget.ip}`,
        severity: 'warning',
        code: 'RDNS_FCRDNS_MISMATCH',
        title: `Partial Forward-Confirmed Reverse DNS (FCrDNS) mismatch for ${reverseIpTarget.ip}`,
        detail: fcrdnsSummary,
        rfc: 'RFC 1912 §2.1',
        targetId: ptrRrset?.id,
      });
    } else {
      fcrdnsStatus = 'ptr-mismatch';
      const detailParts = targets.map((t) => {
        const ips = [...t.forwardIpv4, ...t.forwardIpv6];
        return `${t.displayHostname} (${ips.length > 0 ? ips.join(', ') : t.forwardStatus.toUpperCase()})`;
      });
      fcrdnsSummary = `FCrDNS mismatch: PTR target ${detailParts.join('; ')} does not resolve back to ${reverseIpTarget.ip}.`;
      findings.push({
        id: `warn-rdns-fcrdns-mismatch-${reverseIpTarget.ip}`,
        severity: 'warning',
        code: 'RDNS_FCRDNS_MISMATCH',
        title: `Forward-Confirmed Reverse DNS (FCrDNS) mismatch for ${reverseIpTarget.ip}`,
        detail: fcrdnsSummary,
        rfc: 'RFC 1912 §2.1',
        targetId: ptrRrset?.id,
      });
    }
  }

  // 3. Parse BGP ASN & Prefix Ownership from Team Cymru DNS TXT logs
  let bgp: ReverseIpBgpInfo | undefined;
  if (reverseIpTarget.cymruOriginQname) {
    const originLog = queries.find(
      (q) => q.qname === reverseIpTarget.cymruOriginQname && q.qtype === RR_TYPES.TXT
    );
    if (originLog) {
      const originTxts: string[] = [];
      for (const ans of originLog.packet.answers) {
        if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
          originTxts.push(ans.parsed.joinedText);
        }
      }
      const parsedOrigins = parseCymruOriginTxt(originTxts);
      if (parsedOrigins.length > 0) {
        const primaryOrigin = parsedOrigins[0];
        const uniqueAsns = Array.from(new Set(parsedOrigins.flatMap((o) => o.asns)));
        const asns: BgpAsnOrganization[] = uniqueAsns.map((asn) => {
          const asnQname = `as${asn}.asn.cymru.com.`;
          const asnLog = queries.find((q) => q.qname === asnQname && q.qtype === RR_TYPES.TXT);
          const asnTxts: string[] = [];
          for (const ans of asnLog?.packet.answers ?? []) {
            if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
              asnTxts.push(ans.parsed.joinedText);
            }
          }
          const parsedAsn = parseCymruAsnTxt(asnTxts);
          return {
            asn,
            asName: parsedAsn?.asName,
            country: parsedAsn?.country ?? primaryOrigin.country,
            rir: parsedAsn?.rir ?? primaryOrigin.rir,
            allocatedDate: parsedAsn?.allocatedDate ?? primaryOrigin.allocatedDate,
          };
        });

        const rpkiValidations: RpkiRouteValidation[] = [];
        for (const o of parsedOrigins) {
          if (!o.bgpPrefix) continue;
          for (const asn of o.asns) {
            const rv = getCachedRpkiValidation(asn, o.bgpPrefix);
            if (rv && !rpkiValidations.some((ex) => ex.asn === rv.asn && ex.prefix === rv.prefix)) {
              rpkiValidations.push(rv);
            }
          }
        }
        const primaryRpki =
          rpkiValidations.find(
            (v) => v.status === 'invalid-asn' || v.status === 'invalid-length'
          ) ?? rpkiValidations[0];

        for (const rv of rpkiValidations) {
          if (rv.status === 'invalid-asn' || rv.status === 'invalid-length') {
            findings.push({
              id: `warn-rdns-rpki-invalid-${reverseIpTarget.ip}-${rv.asn}-${rv.prefix}`,
              severity: 'warning',
              code: 'BGP_RPKI_ROA_INVALID',
              title: `BGP route origin RPKI ROA invalid (${
                rv.status === 'invalid-asn' ? 'unauthorized ASN' : 'maxLength exceeded'
              }) for ${reverseIpTarget.ip} (AS${rv.asn} / ${rv.prefix})`,
              detail: rv.summary,
              rfc: 'RFC 6811 / RFC 6480',
            });
          }
        }

        bgp = {
          originQueryName: reverseIpTarget.cymruOriginQname,
          bgpPrefix: primaryOrigin.bgpPrefix,
          country: primaryOrigin.country,
          rir: primaryOrigin.rir,
          allocatedDate: primaryOrigin.allocatedDate,
          asns,
          rawOriginTxt: primaryOrigin.raw,
          ...(primaryRpki ? { rpki: primaryRpki } : {}),
          ...(rpkiValidations.length > 0 ? { rpkiValidations } : {}),
        };
      }
    }
  }

  // 4. Evaluate DNSBL IP Reputation (RFC 5782)
  const dnsbl = evaluateDnsblAuditForIp(
    reverseIpTarget.ip,
    reverseIpTarget.family,
    reverseIpTarget.isPublic,
    queries
  );
  if (dnsbl.status === 'listed') {
    const listedDetails = dnsbl.providers
      .filter((p) => p.status === 'listed')
      .map(
        (p) =>
          `${p.label} [${p.returnCodes.join(', ')}${p.reasons.length > 0 ? `: "${p.reasons[0]}"` : ''}]`
      )
      .join('; ');
    findings.push({
      id: `warn-rdns-dnsbl-${reverseIpTarget.ip}`,
      severity: 'warning',
      code: 'DNSBL_IP_LISTED',
      title: `IP ${reverseIpTarget.ip} is listed on ${dnsbl.listedCount} DNSBL blocklist${dnsbl.listedCount === 1 ? '' : 's'}`,
      detail: `${dnsbl.summary} Details: ${listedDetails}.`,
      rfc: 'RFC 5782',
    });
  }

  return {
    reverseDns: {
      ip: reverseIpTarget.ip,
      family: reverseIpTarget.family,
      arpaFqdn: reverseIpTarget.arpaFqdn,
      displayArpa: reverseIpTarget.displayArpa,
      isPublic: reverseIpTarget.isPublic,
      specialRangeNote: reverseIpTarget.specialRangeNote,
      ptrStatus,
      ptrDnssecStatus,
      ptrRrsetId: ptrRrset?.id,
      ptrNegativeNodeId: ptrNegNode?.id,
      cnameChain,
      isRfc2317ClasslessDelegation,
      targets,
      fcrdnsStatus,
      fcrdnsSummary,
      ...(bgp ? { bgp } : {}),
      ...(dnsbl.status !== 'unchecked' ? { dnsbl } : {}),
    },
    findings,
  };
}

const SAAS_TXT_PATTERNS: ReadonlyArray<{
  prefixRegex: RegExp;
  keyPrefix: string;
  provider: string;
  category: TxtRecordCategory;
}> = [
  {
    prefixRegex: /^google-site-verification=(.+)$/i,
    keyPrefix: 'google-site-verification=',
    provider: 'Google Workspace / Search Console',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^MS=(.+)$/i,
    keyPrefix: 'MS=',
    provider: 'Microsoft 365 / Entra ID',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^apple-domain-verification=(.+)$/i,
    keyPrefix: 'apple-domain-verification=',
    provider: 'Apple Business / Domain Verification',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^atlassian-domain-verification=(.+)$/i,
    keyPrefix: 'atlassian-domain-verification=',
    provider: 'Atlassian Cloud',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^stripe-verification=(.+)$/i,
    keyPrefix: 'stripe-verification=',
    provider: 'Stripe',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^docusign=(.+)$/i,
    keyPrefix: 'docusign=',
    provider: 'DocuSign',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^facebook-domain-verification=(.+)$/i,
    keyPrefix: 'facebook-domain-verification=',
    provider: 'Meta / Facebook Business',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^protonmail-verification=(.+)$/i,
    keyPrefix: 'protonmail-verification=',
    provider: 'Proton Mail',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^keybase-site-verification=(.+)$/i,
    keyPrefix: 'keybase-site-verification=',
    provider: 'Keybase',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^openai-domain-verification=(.+)$/i,
    keyPrefix: 'openai-domain-verification=',
    provider: 'OpenAI',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^anthropic-domain-verification=(.+)$/i,
    keyPrefix: 'anthropic-domain-verification=',
    provider: 'Anthropic',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^slack-domain-verification=(.+)$/i,
    keyPrefix: 'slack-domain-verification=',
    provider: 'Slack',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^(?:ZOOM_verify_|zoom-domain-verification=)(.+)$/i,
    keyPrefix: 'ZOOM_verify_',
    provider: 'Zoom',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^hubspot-(?:developer|domain)-verification=(.+)$/i,
    keyPrefix: 'hubspot-verification=',
    provider: 'HubSpot',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^miro-verification=(.+)$/i,
    keyPrefix: 'miro-verification=',
    provider: 'Miro',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^(?:notion-domain-verification=|notion_verify_)(.+)$/i,
    keyPrefix: 'notion-domain-verification=',
    provider: 'Notion',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^canva-site-verification=(.+)$/i,
    keyPrefix: 'canva-site-verification=',
    provider: 'Canva',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^(?:cisco-ci-domain-verification=|webexdomainverification\.=)(.+)$/i,
    keyPrefix: 'cisco-ci-domain-verification=',
    provider: 'Cisco Webex',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^adobe-(?:idp-site|sign)-verification=(.+)$/i,
    keyPrefix: 'adobe-verification=',
    provider: 'Adobe',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^fastly-domain-delegation-(.+)$/i,
    keyPrefix: 'fastly-domain-delegation-',
    provider: 'Fastly',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^cloudflare-verify=(.+)$/i,
    keyPrefix: 'cloudflare-verify=',
    provider: 'Cloudflare',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^amazonses:(.+)$/i,
    keyPrefix: 'amazonses:',
    provider: 'Amazon SES',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^have-i-been-pwned-verification=(.+)$/i,
    keyPrefix: 'have-i-been-pwned-verification=',
    provider: 'Have I Been Pwned',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^(?:_github-challenge-[^=]+=|github-verification=)(.+)$/i,
    keyPrefix: 'github-verification=',
    provider: 'GitHub',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^vercel-domain-verification=(.+)$/i,
    keyPrefix: 'vercel-domain-verification=',
    provider: 'Vercel',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^tailscale-domain-verification=(.+)$/i,
    keyPrefix: 'tailscale-domain-verification=',
    provider: 'Tailscale',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^1password-site-verification=(.+)$/i,
    keyPrefix: '1password-site-verification=',
    provider: '1Password',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^linear-domain-verification=(.+)$/i,
    keyPrefix: 'linear-domain-verification=',
    provider: 'Linear',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^figma-domain-verification=(.+)$/i,
    keyPrefix: 'figma-domain-verification=',
    provider: 'Figma',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^postman-domain-verification=(.+)$/i,
    keyPrefix: 'postman-domain-verification=',
    provider: 'Postman',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^zendesk-verification=(.+)$/i,
    keyPrefix: 'zendesk-verification=',
    provider: 'Zendesk',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^brave-ledger-verification=(.+)$/i,
    keyPrefix: 'brave-ledger-verification=',
    provider: 'Brave Creators',
    category: 'saas-verification',
  },
  {
    prefixRegex: /^did=(did:[a-z0-9]+:.+)$/i,
    keyPrefix: 'did=',
    provider: 'Bluesky / AT Protocol (DID)',
    category: 'decentralized-id',
  },
  {
    prefixRegex: /^_?globalsign-domain-verification=(.+)$/i,
    keyPrefix: 'globalsign-domain-verification=',
    provider: 'GlobalSign CA Validation',
    category: 'ca-validation',
  },
];

/**
 * Classifies a single zone apex TXT string into protocol, SaaS verification, CA validation,
 * or misplaced/malformed categories.
 */
export function classifyApexTxtRecord(rawText: string, byteLength?: number): TxtVerificationEntry {
  const trimmed = rawText.trim();
  const bytes = byteLength ?? new TextEncoder().encode(rawText).byteLength;

  // 1. SPF Policy at zone apex (RFC 7208)
  if (/^v=spf1(?:\s|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'email-auth',
      provider: 'SPF Policy (RFC 7208)',
      keyPrefix: 'v=spf1',
      tokenValue: trimmed.slice(6).trim(),
      status: 'valid',
    };
  }
  if (/^(?:spf1\s|v=spf[2-9]|spf2\.0)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'email-auth',
      provider: 'Malformed / Legacy SPF Tag',
      keyPrefix: trimmed.split(/\s+/)[0],
      status: 'malformed',
      issue:
        'Malformed or deprecated SPF version tag at zone apex; RFC 7208 §4.5 requires exact "v=spf1".',
    };
  }

  // 2. Misplaced underscore-prefixed protocol policies accidentally published at zone apex
  if (/^v=DMARC1(?:\s|;|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'email-auth',
      provider: 'DMARC Policy (Misplaced at Apex)',
      keyPrefix: 'v=DMARC1',
      status: 'misplaced-at-apex',
      issue:
        'DMARC policy is published at the zone apex instead of _dmarc.<domain>; RFC 7489 §6.1 receivers will ignore it.',
    };
  }
  if (/^v=DKIM1(?:\s|;|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'email-auth',
      provider: 'DKIM Public Key (Misplaced at Apex)',
      keyPrefix: 'v=DKIM1',
      status: 'misplaced-at-apex',
      issue:
        'DKIM key is published at the zone apex instead of <selector>._domainkey.<domain> (RFC 6376 §3.6.2).',
    };
  }
  if (/^v=BIMI1(?:\s|;|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'email-auth',
      provider: 'BIMI Record (Misplaced at Apex)',
      keyPrefix: 'v=BIMI1',
      status: 'misplaced-at-apex',
      issue: 'BIMI record is published at the zone apex instead of default._bimi.<domain>.',
    };
  }
  if (/^v=STSv1(?:\s|;|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'tls-security',
      provider: 'MTA-STS Policy (Misplaced at Apex)',
      keyPrefix: 'v=STSv1',
      status: 'misplaced-at-apex',
      issue:
        'MTA-STS TXT record is published at the zone apex instead of _mta-sts.<domain> (RFC 8461 §3.1).',
    };
  }
  if (/^v=TLSRPTv1(?:\s|;|$)/i.test(trimmed)) {
    return {
      rawText,
      byteLength: bytes,
      category: 'tls-security',
      provider: 'SMTP TLS-RPT (Misplaced at Apex)',
      keyPrefix: 'v=TLSRPTv1',
      status: 'misplaced-at-apex',
      issue:
        'TLS-RPT TXT record is published at the zone apex instead of _smtp._tls.<domain> (RFC 8460 §3.1).',
    };
  }

  // 3. Known SaaS / Cloud / Identity / CA verification patterns
  for (const pat of SAAS_TXT_PATTERNS) {
    const m = pat.prefixRegex.exec(trimmed);
    if (m) {
      return {
        rawText,
        byteLength: bytes,
        category: pat.category,
        provider: pat.provider,
        keyPrefix: pat.keyPrefix,
        tokenValue: m[1].trim(),
        status: 'valid',
      };
    }
  }

  // Generic <vendor>-site-verification=... or <vendor>-domain-verification=...
  const genericVerif = /^([a-z0-9._-]+-(?:site|domain)-verification)=(.+)$/i.exec(trimmed);
  if (genericVerif) {
    const prefixName = genericVerif[1];
    return {
      rawText,
      byteLength: bytes,
      category: 'saas-verification',
      provider: `${prefixName.split('-')[0].toUpperCase()} Verification`,
      keyPrefix: `${prefixName}=`,
      tokenValue: genericVerif[2].trim(),
      status: 'valid',
    };
  }

  return {
    rawText,
    byteLength: bytes,
    category: 'custom-other',
    provider: 'Custom / Unclassified TXT',
    status: 'valid',
  };
}

function evaluateTxtHygieneForZone(params: {
  zoneName: string;
  queries: DohQueryLog[];
  findings: AuditFinding[];
}): TxtHygieneAudit | undefined {
  const { zoneName, queries, findings } = params;
  const txtLogs = queries.filter(
    (q) => q.qname === zoneName && q.qtype === RR_TYPES.TXT
  );
  if (txtLogs.length === 0) return undefined;

  // Prefer the first TXT log that returned TXT answers (or the first TXT log overall)
  const primaryLog =
    txtLogs.find((l) => l.packet.answers.some((r) => r.name === zoneName && r.type === RR_TYPES.TXT)) ??
    txtLogs[0];

  const txtRecords = primaryLog.packet.answers.filter(
    (r) => r.name === zoneName && r.type === RR_TYPES.TXT
  );
  if (txtRecords.length === 0) {
    return {
      recordCount: 0,
      totalWireBytes: 0,
      saasVerificationCount: 0,
      duplicateCount: 0,
      misplacedCount: 0,
      malformedCount: 0,
      bloatWarning: false,
      status: 'clean',
      entries: [],
      summary: `No TXT records published at ${zoneName} apex.`,
    };
  }

  const seenExactText = new Set<string>();
  const seenProviderTokens = new Set<string>();
  let spfCount = 0;
  let totalWireBytes = 0;
  const entries: TxtVerificationEntry[] = [];

  for (const rec of txtRecords) {
    const rawText = rec.parsed.kind === 'TXT' ? rec.parsed.joinedText : rec.rdataText;
    const wireLen = base64ToBytes(rec.canonicalRdataBase64).byteLength;
    totalWireBytes += wireLen;

    const entry = classifyApexTxtRecord(rawText, wireLen);
    const normText = rawText.trim();

    if (entry.keyPrefix === 'v=spf1') {
      spfCount++;
      if (spfCount > 1) {
        entry.status = 'duplicate';
        entry.issue =
          'Multiple v=spf1 TXT records published at zone apex violate RFC 7208 §3.2 (causes SPF PermError).';
      }
    }

    const tokenKey =
      entry.keyPrefix && entry.tokenValue
        ? `${entry.provider}|${entry.tokenValue}`
        : null;

    if (seenExactText.has(normText) || (tokenKey && seenProviderTokens.has(tokenKey))) {
      entry.status = 'duplicate';
      entry.issue = entry.issue ?? `Duplicate ${entry.provider} TXT token at zone apex.`;
    }
    seenExactText.add(normText);
    if (tokenKey) seenProviderTokens.add(tokenKey);

    entries.push(entry);
  }

  const saasVerificationCount = entries.filter(
    (e) =>
      e.category === 'saas-verification' ||
      e.category === 'ca-validation' ||
      e.category === 'decentralized-id'
  ).length;
  const duplicateCount = entries.filter((e) => e.status === 'duplicate').length;
  const misplacedCount = entries.filter((e) => e.status === 'misplaced-at-apex').length;
  const malformedCount = entries.filter((e) => e.status === 'malformed').length;
  const bloatWarning = txtRecords.length > 12 || totalWireBytes > 1232;

  let status: TxtHygieneAudit['status'] = 'clean';
  if (duplicateCount > 0 || misplacedCount > 0 || malformedCount > 0 || bloatWarning) {
    status = 'warning';
  } else if (saasVerificationCount > 0) {
    status = 'info-saas';
  }

  for (const e of entries) {
    if (e.status === 'misplaced-at-apex' || e.status === 'malformed') {
      findings.push({
        id: `warn-txt-misplaced-${zoneName}-${e.keyPrefix ?? e.provider}`,
        severity: 'warning',
        code: 'TXT_APEX_MISPLACED_POLICY',
        title: `${e.provider} at ${zoneName} apex`,
        detail: e.issue ?? `${e.provider} record at ${zoneName} apex is misplaced or malformed.`,
        rfc: 'RFC 7489 / RFC 8461 / RFC 7208',
        zone: zoneName,
      });
    }
  }

  if (duplicateCount > 0) {
    const dupProviders = Array.from(
      new Set(entries.filter((e) => e.status === 'duplicate').map((e) => e.provider))
    ).join(', ');
    findings.push({
      id: `warn-txt-duplicate-${zoneName}`,
      severity: 'warning',
      code: 'TXT_DUPLICATE_VERIFICATION',
      title: `${duplicateCount} duplicate TXT record${duplicateCount === 1 ? '' : 's'} at ${zoneName} apex (${dupProviders})`,
      detail: `Found ${duplicateCount} duplicate or redundant TXT record${duplicateCount === 1 ? '' : 's'} at ${zoneName} (${dupProviders}). Remove duplicate tokens to reduce apex TXT RRset size.`,
      zone: zoneName,
    });
  }

  if (bloatWarning) {
    findings.push({
      id: `warn-txt-bloat-${zoneName}`,
      severity: totalWireBytes > 1232 ? 'warning' : 'info',
      code: 'TXT_APEX_BLOAT',
      title: `Large apex TXT RRset at ${zoneName} (${txtRecords.length} records, ${totalWireBytes} bytes RDATA)`,
      detail: `${zoneName} publishes ${txtRecords.length} TXT records totaling ${totalWireBytes} bytes of RDATA${totalWireBytes > 1232 ? ' — exceeding the 1232-byte EDNS0 UDP payload recommendation and risking IPv6 UDP truncation/TCP fallback' : ''}. Periodically prune stale SaaS domain-verification tokens.`,
      rfc: 'RFC 8900 / DNS Flag Day 2020',
      zone: zoneName,
    });
  }
  if (saasVerificationCount > 0) {
    const saasProviders = Array.from(
      new Set(
        entries
          .filter(
            (e) =>
              e.category === 'saas-verification' ||
              e.category === 'ca-validation' ||
              e.category === 'decentralized-id'
          )
          .map((e) => e.provider)
      )
    );
    findings.push({
      id: `info-txt-saas-${zoneName}`,
      severity: 'info',
      code: 'TXT_SAAS_VERIFICATIONS_PRESENT',
      title: `${saasVerificationCount} domain verification TXT token${saasVerificationCount === 1 ? '' : 's'} at ${zoneName} (${saasProviders.slice(0, 4).join(', ')}${saasProviders.length > 4 ? ` +${saasProviders.length - 4} more` : ''})`,
      detail: `${zoneName} publishes ${saasVerificationCount} SaaS/CA/identity verification TXT record${saasVerificationCount === 1 ? '' : 's'} (${saasProviders.join(', ')}) across ${txtRecords.length} total apex TXT records (${totalWireBytes} bytes RDATA).`,
      zone: zoneName,
    });
  }

  const summaryParts: string[] = [
    `${txtRecords.length} apex TXT record${txtRecords.length === 1 ? '' : 's'} (${totalWireBytes} B RDATA)`,
  ];
  if (saasVerificationCount > 0) {
    summaryParts.push(
      `${saasVerificationCount} SaaS/identity verification token${saasVerificationCount === 1 ? '' : 's'}`
    );
  }
  if (misplacedCount > 0) {
    summaryParts.push(`${misplacedCount} misplaced policy record${misplacedCount === 1 ? '' : 's'}`);
  }
  if (duplicateCount > 0) {
    summaryParts.push(`${duplicateCount} duplicate${duplicateCount === 1 ? '' : 's'}`);
  }

  return {
    recordCount: txtRecords.length,
    totalWireBytes,
    saasVerificationCount,
    duplicateCount,
    misplacedCount,
    malformedCount,
    bloatWarning,
    status,
    entries,
    summary: `${summaryParts.join(' · ')}.`,
  };
}

async function evaluateWildcardAuditForZone(params: {
  zoneName: string;
  queries: DohQueryLog[];
  zoneDnskeys: DnsRecord[];
  zoneStatus: ValidationStatus;
  validationEpochSec: number;
  findings: AuditFinding[];
}): Promise<WildcardAuditSummary | undefined> {
  const { zoneName, queries, zoneDnskeys, zoneStatus, validationEpochSec, findings } = params;
  const probeQname = normalizeFqdn(`${WILDCARD_PROBE_LABEL}.${zoneName}`);
  const qnameLabels = countDnsLabels(probeQname, true);

  const probeTypes: Array<{ qtype: 'A' | 'AAAA' | 'MX'; code: number }> = [
    { qtype: 'A', code: RR_TYPES.A },
    { qtype: 'AAAA', code: RR_TYPES.AAAA },
    { qtype: 'MX', code: RR_TYPES.MX },
  ];

  const probes: WildcardProbeTypeResult[] = [];
  for (const pt of probeTypes) {
    const log = queries.find(
      (q) => q.qname === probeQname && q.qtype === pt.code
    );
    if (!log) continue;

    const rcode = log.packet.flags.rcode;
    const rcodeName = rcodeToString(rcode);
    const nonSigAnswers = log.packet.answers.filter((r) => r.type !== RR_TYPES.RRSIG);
    const sigAnswers = log.packet.answers.filter(
      (r) => r.type === RR_TYPES.RRSIG && r.parsed.kind === 'RRSIG'
    );

    const cnameChain: string[] = [];
    const answerValues: string[] = [];
    for (const ans of nonSigAnswers) {
      if (ans.type === RR_TYPES.CNAME && ans.parsed.kind === 'GENERIC' && ans.parsed.target) {
        cnameChain.push(normalizeFqdn(ans.parsed.target));
      } else if (ans.type === pt.code) {
        answerValues.push(ans.rdataText);
      }
    }

    const synthesized = rcode === 0 && (answerValues.length > 0 || cnameChain.length > 0);
    if (!synthesized) {
      probes.push({
        qtype: pt.qtype,
        qname: probeQname,
        rcode,
        rcodeName,
        synthesized: false,
        cnameChain: [],
        answerValues: [],
        expansionMode: 'none',
        qnameLabels,
        dnssecStatus:
          zoneStatus === 'secure' || zoneStatus === 'warning' ? 'secure' : 'insecure',
      });
      continue;
    }

    // Wildcard answer was synthesized at probeQname! Verify RRSIG & RFC 4035 §5.3.4 / RFC 5155 §7.2.6 proof
    const firstOwner = probeQname;
    const firstRrset = nonSigAnswers.filter(
      (r) =>
        r.name === firstOwner &&
        (r.type === pt.code || r.type === RR_TYPES.CNAME)
    );
    const matchingSigs = sigAnswers.filter(
      (s) =>
        s.name === firstOwner &&
        s.parsed.kind === 'RRSIG' &&
        firstRrset.length > 0 &&
        s.parsed.typeCovered === firstRrset[0].type
    );

    if (matchingSigs.length === 0 || firstRrset.length === 0) {
      const isSignedZone =
        zoneStatus === 'secure' || zoneStatus === 'warning' || zoneStatus === 'bogus';
      probes.push({
        qtype: pt.qtype,
        qname: probeQname,
        rcode,
        rcodeName,
        synthesized: true,
        cnameChain,
        answerValues,
        expansionMode: 'unsigned',
        wildcardSourceName: `*.${zoneName}`,
        closestEncloser: zoneName,
        qnameLabels,
        dnssecStatus: isSignedZone ? 'bogus' : 'insecure',
      });
      continue;
    }

    const rrsigVerifications = await Promise.all(
      matchingSigs.map((s) =>
        verifyRrsigForRrset(firstRrset, s, zoneDnskeys, validationEpochSec)
      )
    );
    const validRrsig =
      rrsigVerifications.find((v) => v.cryptoValid && v.timeValid) ?? rrsigVerifications[0];
    const rrsigLabels = validRrsig.rrsig.labels;
    const rrsigStatus = validRrsig.status;

    if (rrsigLabels < qnameLabels) {
      const closestEncloser = validRrsig.wildcardClosestEncloser ?? zoneName;
      const wildcardSourceName = `*.${closestEncloser}`;

      // Verify authority NSEC / NSEC3 proving no closer match (probeQname) exists per RFC 4035 §5.3.4 / RFC 5155 §7.2.6
      const nsecRecs = log.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC);
      const nsec3Recs = log.packet.authorities.filter((r) => r.type === RR_TYPES.NSEC3);
      const authSigs = log.packet.authorities.filter(
        (r) => r.type === RR_TYPES.RRSIG && r.parsed.kind === 'RRSIG'
      );

      const negProof = await verifyNegativeProof({
        kind: 'NXDOMAIN',
        zoneApex: zoneName,
        qname: probeQname,
        nsecRecords: nsecRecs,
        nsec3Records: nsec3Recs,
      });

      // For a wildcard synthesis answer, the NSEC/NSEC3 only needs to cover the next-closer name (probeQname)
      const coversNextCloser = negProof.items.some(
        (it) => it.coversName === probeQname || it.role.includes('Covers QNAME') || it.role.includes('Covers Next Closer')
      );

      // Verify RRSIGs on authority NSEC/NSEC3 records
      let authSigValid = false;
      for (const nrec of [...nsecRecs, ...nsec3Recs]) {
        const nsigs = authSigs.filter(
          (s) =>
            s.name === nrec.name &&
            s.parsed.kind === 'RRSIG' &&
            s.parsed.typeCovered === nrec.type
        );
        for (const nsig of nsigs) {
          const nv = await verifyRrsigForRrset([nrec], nsig, zoneDnskeys, validationEpochSec);
          if (nv.cryptoValid && nv.timeValid) {
            authSigValid = true;
            break;
          }
        }
        if (authSigValid) break;
      }

      const nsecNextCloserValid = coversNextCloser && authSigValid;
      const dnssecStatus: ValidationStatus =
        (rrsigStatus === 'secure' || rrsigStatus === 'warning') && nsecNextCloserValid
          ? rrsigStatus
          : 'bogus';

      probes.push({
        qtype: pt.qtype,
        qname: probeQname,
        rcode,
        rcodeName,
        synthesized: true,
        cnameChain,
        answerValues,
        expansionMode: 'rfc4035-wildcard',
        wildcardSourceName,
        closestEncloser,
        rrsigLabels,
        qnameLabels,
        rrsigStatus,
        nsecNextCloserValid,
        nsecProofProtocol: negProof.protocol,
        nsecProofSummary: nsecNextCloserValid
          ? `${negProof.protocol} next-closer proof verified: ${probeQname} does not exist, authenticating wildcard expansion from ${wildcardSourceName}`
          : `Missing or invalid ${negProof.protocol !== 'NONE' ? negProof.protocol : 'NSEC/NSEC3'} next-closer proof for ${probeQname} (RFC 4035 §5.3.4 / RFC 5155 §7.2.6)`,
        dnssecStatus,
      });
    } else {
      // Online-signed wildcard (rrsig.labels === qnameLabels)
      probes.push({
        qtype: pt.qtype,
        qname: probeQname,
        rcode,
        rcodeName,
        synthesized: true,
        cnameChain,
        answerValues,
        expansionMode: 'online-signed',
        wildcardSourceName: `*.${zoneName}`,
        closestEncloser: zoneName,
        rrsigLabels,
        qnameLabels,
        rrsigStatus,
        nsecNextCloserValid: true,
        nsecProofProtocol: 'NONE',
        nsecProofSummary: `Online-signed wildcard response (RRSIG labels=${rrsigLabels} equals QNAME labels=${qnameLabels}; no separate NSEC/NSEC3 next-closer record required).`,
        dnssecStatus: rrsigStatus,
      });
    }
  }

  if (probes.length === 0) return undefined;

  const synthesizedProbes = probes.filter((p) => p.synthesized);
  const wildcardDetected = synthesizedProbes.length > 0;
  const wildcardTypes = synthesizedProbes.map((p) => p.qtype);
  const hasWildcardMx = wildcardTypes.includes('MX');
  const anyBogus = synthesizedProbes.some((p) => p.dnssecStatus === 'bogus');

  let status: WildcardAuditSummary['status'] = 'no-wildcard';
  if (anyBogus) {
    status = 'wildcard-bogus';
  } else if (hasWildcardMx) {
    status = 'wildcard-mx-risk';
  } else if (wildcardDetected) {
    status = 'wildcard-active';
  }

  const dnssecStatus: ValidationStatus = anyBogus
    ? 'bogus'
    : synthesizedProbes.some((p) => p.dnssecStatus === 'warning')
      ? 'warning'
      : synthesizedProbes.every((p) => p.dnssecStatus === 'secure') &&
          (synthesizedProbes.length > 0 || zoneStatus === 'secure')
        ? 'secure'
        : 'insecure';

  let summary = '';
  if (!wildcardDetected) {
    summary = `No wildcard DNS synthesis detected at *.${zoneName} (${probeQname} returned ${probes[0]?.rcodeName ?? 'NXDOMAIN'}).`;
  } else {
    const detailStr = synthesizedProbes
      .map((p) => {
        const vals =
          p.answerValues.length > 0
            ? p.answerValues.join(', ')
            : p.cnameChain.map((c) => `CNAME ${c}`).join(' → ');
        const modeTag =
          p.expansionMode === 'rfc4035-wildcard'
            ? `RFC 4035 wildcard RRSIG labels=${p.rrsigLabels}<${p.qnameLabels} + ${p.nsecProofProtocol} proof`
            : p.expansionMode === 'online-signed'
              ? `online-signed RRSIG labels=${p.rrsigLabels}`
              : 'unsigned';
        return `${p.qtype} → ${vals} (${modeTag})`;
      })
      .join('; ');
    summary = `Wildcard DNS (*.${zoneName}) synthesizes responses for nonexistent subdomains: ${detailStr}.`;
  }

  if (anyBogus) {
    findings.push({
      id: `err-wildcard-bogus-${zoneName}`,
      severity: 'error',
      code: 'WILDCARD_DNSSEC_BOGUS',
      title: `Bogus DNSSEC wildcard synthesis proof for *.${zoneName}`,
      detail: `${summary} A signed wildcard answer with RRSIG.labels < QNAME.labels must be accompanied by a valid RRSIG and an authenticated NSEC/NSEC3 record covering the next-closer name (RFC 4035 §5.3.4 / RFC 5155 §7.2.6).`,
      rfc: 'RFC 4035 §5.3.4 / RFC 5155 §7.2.6',
      zone: zoneName,
    });
  } else if (hasWildcardMx) {
    findings.push({
      id: `warn-wildcard-mx-${zoneName}`,
      severity: 'warning',
      code: 'WILDCARD_MX_RISK',
      title: `Wildcard MX record (*.${zoneName}) accepts mail for arbitrary nonexistent subdomains`,
      detail: `${summary} RFC 1912 §2.7 discourages wildcard MX records because mail addressed to typo subdomains is accepted or queued instead of immediately failing, increasing backscatter and spoofing surface.`,
      rfc: 'RFC 1912 §2.7',
      zone: zoneName,
    });
  } else if (wildcardDetected) {
    findings.push({
      id: `warn-wildcard-active-${zoneName}`,
      severity: 'warning',
      code: 'WILDCARD_DNS_ENABLED',
      title: `Wildcard DNS (*.${zoneName}) enabled for ${wildcardTypes.join(', ')}`,
      detail: `${summary} Wildcard A/AAAA/CNAME records cause every nonexistent subdomain under ${zoneName} to resolve, which can expand cookie/CORS scope and mask dangling subdomain misconfigurations.`,
      rfc: 'RFC 4592 / RFC 4035 §5.3.4',
      zone: zoneName,
    });
  }

  return {
    probeQname,
    wildcardDetected,
    wildcardTypes,
    hasWildcardMx,
    status,
    dnssecStatus,
    probes,
    summary,
  };
}
