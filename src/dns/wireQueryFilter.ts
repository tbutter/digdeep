import type { GraphSelection } from '../components/GraphInspector';
import { DOH_SERVER_PRESETS, RR_TYPES, formatDohShortLabel, rcodeToString } from './constants';
import { displayFqdn, normalizeFqdn } from './encoding';
import type {
  AnalysisSnapshot,
  AuditFinding,
  ConsensusResolverRow,
  DohQueryLog,
  EcsRegionProbeRow,
} from './types';

export type WireQueryBucket = 'target' | 'dnssec' | 'consensus' | 'ecs' | 'aux';

export type WireQueryFilterCategory =
  | 'all'
  | 'target'
  | 'dnssec'
  | 'errors'
  | 'ecs'
  | 'consensus'
  | 'aux';

export type FocusedWireSubMode = 'dig' | 'hex-resp' | 'hex-req';

export interface FocusedWireQueryRequest {
  queryId: string;
  mode?: FocusedWireSubMode;
  seq: number;
}

const DNSSEC_INFRA_QTYPES = new Set([
  'DNSKEY',
  'DS',
  'CDS',
  'CDNSKEY',
  'CSYNC',
  'ZONEMD',
  'NSEC',
  'NSEC3',
  'NSEC3PARAM',
  'RRSIG',
]);

const AUX_PURPOSE_PREFIXES = [
  'BGP ',
  'ECS BGP',
  'DNSBL ',
  'PSL ',
  'Nameserver IP',
  'Wildcard probe',
  'SPF lookup',
  'DMARC lookup',
  'DKIM probe',
  'Mail probe',
  'Mail SRV probe',
  'MX rDNS lookup',
  'CT CAA lookup',
] as const;

/**
 * Classifies a recorded DoH wire query into its primary structural bucket.
 */
export function classifyDohQueryBucket(q: DohQueryLog): WireQueryBucket {
  if (
    Boolean(q.ecsSubnet) ||
    q.purpose.startsWith('ECS Geo probe') ||
    q.purpose.startsWith('Custom ECS probe')
  ) {
    return 'ecs';
  }
  if (q.purpose.startsWith('Consensus probe')) {
    return 'consensus';
  }
  for (const prefix of AUX_PURPOSE_PREFIXES) {
    if (q.purpose.startsWith(prefix)) {
      return 'aux';
    }
  }
  if (
    DNSSEC_INFRA_QTYPES.has(q.qtypeName.toUpperCase()) ||
    q.purpose.startsWith('Zone ') ||
    q.purpose.startsWith('Zone-cut probe') ||
    q.purpose.startsWith('Delegation ')
  ) {
    return 'dnssec';
  }
  return 'target';
}

/**
 * Returns true when a DoH wire query returned a non-200 HTTP status,
 * a non-NOERROR DNS RCODE (e.g. SERVFAIL, NXDOMAIN, REFUSED), or any RFC 8914 EDE option.
 */
export function isErrorOrEdeQueryLog(q: DohQueryLog): boolean {
  return (
    q.httpStatus !== 200 ||
    q.packet.flags.rcode !== 0 ||
    (q.packet.edns?.ede.length ?? 0) > 0
  );
}

/**
 * Computes query counts for every filter pill category across a snapshot's query waterfall.
 */
export function computeWireQueryCategoryCounts(
  queries: DohQueryLog[]
): Record<WireQueryFilterCategory, number> {
  const counts: Record<WireQueryFilterCategory, number> = {
    all: queries.length,
    target: 0,
    dnssec: 0,
    errors: 0,
    ecs: 0,
    consensus: 0,
    aux: 0,
  };
  for (const q of queries) {
    const bucket = classifyDohQueryBucket(q);
    counts[bucket]++;
    if (isErrorOrEdeQueryLog(q)) {
      counts.errors++;
    }
  }
  return counts;
}

function buildQuerySearchHaystack(q: DohQueryLog): string {
  const rcode = rcodeToString(q.packet.flags.rcode);
  const edeTokens =
    q.packet.edns?.ede
      .map((e) => `ede ede${e.infoCode} ${e.infoCode} ${e.name} ${e.extraText ?? ''}`)
      .join(' ') ?? '';
  const ecsResp = q.packet.edns?.ecs?.presentation ?? '';
  const endpointShort = q.endpoint ? formatDohShortLabel(q.endpoint) : '';
  const presetMeta = q.endpoint
    ? DOH_SERVER_PRESETS.find((p) => p.url === q.endpoint)
    : undefined;
  return [
    q.qname,
    displayFqdn(q.qname),
    q.qtypeName,
    `type${q.qtype}`,
    q.purpose,
    q.endpoint ?? '',
    endpointShort,
    presetMeta ? `${presetMeta.provider} ${presetMeta.role}` : '',
    q.ecsSubnet ? `ecs ${q.ecsSubnet}` : '',
    ecsResp,
    rcode,
    q.cd ? 'cd=1' : 'cd=0',
    q.packet.flags.ad ? 'ad=1' : 'ad=0',
    edeTokens,
  ]
    .join(' ')
    .toLowerCase();
}

/**
 * Multi-token case-insensitive substring matcher across qname, qtypeName, purpose,
 * DoH endpoint/short label, ECS subnet/scope, RCODE, CD/AD bits, and RFC 8914 EDE metadata.
 */
export function matchesWireQuerySearch(q: DohQueryLog, searchText: string): boolean {
  const trimmed = searchText.trim().toLowerCase();
  if (!trimmed) return true;
  const tokens = trimmed.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const haystack = buildQuerySearchHaystack(q);
  return tokens.every((tok) => haystack.includes(tok));
}

export function matchesWireQueryCategory(
  q: DohQueryLog,
  category: WireQueryFilterCategory
): boolean {
  if (category === 'all') return true;
  if (category === 'errors') return isErrorOrEdeQueryLog(q);
  return classifyDohQueryBucket(q) === category;
}

/**
 * Filters a snapshot's recorded DoH queries by category pill and text search query.
 */
export function filterDohQueryLogs(
  queries: DohQueryLog[],
  category: WireQueryFilterCategory,
  searchText: string
): DohQueryLog[] {
  return queries.filter(
    (q) => matchesWireQueryCategory(q, category) && matchesWireQuerySearch(q, searchText)
  );
}

/**
 * Finds the best primary (non-ECS, non-secondary-consensus) DoH query matching an owner name and RR type,
 * falling back to queries whose answer or authority section carries that RRset (e.g. bundled CNAME targets).
 */
export function findWireQueryByOwnerAndType(
  queries: DohQueryLog[],
  ownerName: string,
  qtypeName: string,
  opts?: { preferCd?: boolean }
): DohQueryLog | undefined {
  const normOwner = normalizeFqdn(ownerName);
  const upperType = qtypeName.trim().toUpperCase();
  const preferCd = opts?.preferCd ?? true;

  const isPrimaryQuery = (q: DohQueryLog) =>
    !q.ecsSubnet && !q.purpose.startsWith('Consensus probe');

  const exactCandidates = queries.filter(
    (q) => normalizeFqdn(q.qname) === normOwner && q.qtypeName.toUpperCase() === upperType
  );
  const primaryExact = exactCandidates.filter(isPrimaryQuery);
  const pool = primaryExact.length > 0 ? primaryExact : exactCandidates;
  if (pool.length > 0) {
    return pool.find((q) => q.cd === preferCd) ?? pool[0];
  }

  // Fallback: bundled CNAME answer or authority record inside another primary query
  const bundled = queries.find(
    (q) =>
      isPrimaryQuery(q) &&
      (q.packet.answers.some(
        (r) => normalizeFqdn(r.name) === normOwner && r.typeName.toUpperCase() === upperType
      ) ||
        q.packet.authorities.some(
          (r) => normalizeFqdn(r.name) === normOwner && r.typeName.toUpperCase() === upperType
        ))
  );
  return bundled;
}

/**
 * Resolves a graph node/zone target ID (e.g. `rrsetId`, `negativeNodeId`, `zone-example.com.`, `dnskey-...`)
 * to its backing DoH wire query in `snapshot.queries`.
 */
export function findWireQueryByGraphTargetId(
  targetId: string | undefined,
  snapshot: AnalysisSnapshot
): DohQueryLog | undefined {
  if (!targetId) return undefined;

  for (const z of snapshot.zones) {
    const rrset = z.rrsets.find((r) => r.id === targetId);
    if (rrset) {
      return findWireQueryByOwnerAndType(snapshot.queries, rrset.name, rrset.typeName, {
        preferCd: true,
      });
    }
    if (`zone-${z.zoneName}` === targetId || `zone:${z.zoneName}` === targetId) {
      return findWireQueryByOwnerAndType(
        snapshot.queries,
        z.zoneName,
        z.dnskeys.length > 0 ? 'DNSKEY' : 'SOA',
        { preferCd: true }
      );
    }
    const dnskey = z.dnskeys.find((k) => `dnskey-${z.zoneName}-${k.keyTag}` === targetId);
    if (dnskey) {
      return findWireQueryByOwnerAndType(snapshot.queries, z.zoneName, 'DNSKEY', {
        preferCd: true,
      });
    }
    if (
      z.parentDsRrsetId === targetId ||
      z.dsVerifications.some((d) => d.id === targetId) ||
      `ds-group-${z.zoneName}` === targetId
    ) {
      return findWireQueryByOwnerAndType(snapshot.queries, z.zoneName, 'DS', { preferCd: true });
    }
    const neg = z.negativeNodes.find((n) => n.id === targetId);
    if (neg) {
      return findWireQueryByOwnerAndType(snapshot.queries, neg.qname, neg.qtypeName, {
        preferCd: true,
      });
    }
  }

  return undefined;
}

/**
 * Resolves a selected ChainGraphView inspector item (zone, DNSKEY, RRset, DS bridge, negative proof, or edge)
 * to its backing DoH wire query in `snapshot.queries`.
 */
export function findGraphSelectionWireQuery(
  selection: GraphSelection | null,
  queries: DohQueryLog[]
): DohQueryLog | undefined {
  if (!selection || queries.length === 0) return undefined;

  if (selection.kind === 'zone') {
    const qtype = selection.zone.dnskeys.length > 0 ? 'DNSKEY' : 'SOA';
    return (
      findWireQueryByOwnerAndType(queries, selection.zone.zoneName, qtype, { preferCd: true }) ??
      findWireQueryByOwnerAndType(queries, selection.zone.zoneName, 'NS', { preferCd: true })
    );
  }

  if (selection.kind === 'node') {
    const n = selection.node;
    if (n.dnskey) {
      return findWireQueryByOwnerAndType(queries, n.dnskey.zone, 'DNSKEY', { preferCd: true });
    }
    if (n.rrset) {
      return findWireQueryByOwnerAndType(queries, n.rrset.name, n.rrset.typeName, {
        preferCd: true,
      });
    }
    if (n.dsVerifications && n.dsVerifications.length > 0) {
      return findWireQueryByOwnerAndType(queries, n.zone, 'DS', { preferCd: true });
    }
    if (n.negativeNode) {
      return findWireQueryByOwnerAndType(
        queries,
        n.negativeNode.qname,
        n.negativeNode.qtypeName,
        { preferCd: true }
      );
    }
    if (n.delegationProof) {
      return findWireQueryByOwnerAndType(queries, n.zone, 'DS', { preferCd: true });
    }
  }

  if (selection.kind === 'edge') {
    const e = selection.edge;
    if (e.rrsigVerification) {
      const sig = e.rrsigVerification.rrsig;
      const covered = sig.typeCoveredName.toUpperCase();
      // Find the packet whose answers/authorities carry this RRSIG
      const exactSigPacket = queries.find(
        (q) =>
          !q.ecsSubnet &&
          !q.purpose.startsWith('Consensus probe') &&
          [...q.packet.answers, ...q.packet.authorities].some(
            (r) =>
              r.parsed.kind === 'RRSIG' &&
              r.parsed.keyTag === sig.keyTag &&
              r.parsed.typeCoveredName.toUpperCase() === covered &&
              normalizeFqdn(r.parsed.signerName) === normalizeFqdn(sig.signerName)
          )
      );
      if (exactSigPacket) return exactSigPacket;
      return findWireQueryByOwnerAndType(queries, sig.signerName, covered, { preferCd: true });
    }
    if (e.dsVerification) {
      const dsMatch = /^ds-(.+)-\d+$/.exec(e.dsVerification.id);
      const zoneName = dsMatch ? dsMatch[1] : '.';
      return findWireQueryByOwnerAndType(queries, zoneName, 'DS', { preferCd: true });
    }
    if (e.cnameEdge) {
      return findWireQueryByOwnerAndType(
        queries,
        e.cnameEdge.fromName,
        e.cnameEdge.qtypeName,
        { preferCd: true }
      );
    }
    if (e.proof) {
      return findWireQueryByOwnerAndType(queries, e.proof.qname, e.proof.qtype ?? 'DS', {
        preferCd: true,
      });
    }
  }

  return undefined;
}

/**
 * Resolves a Multi-Resolver Consensus Matrix row to its best representative DoH wire query.
 */
export function findConsensusResolverWireQuery(
  row: ConsensusResolverRow,
  snapshot: AnalysisSnapshot
): DohQueryLog | undefined {
  const candidates = snapshot.queries.filter(
    (q) =>
      !q.ecsSubnet &&
      !q.purpose.startsWith('ECS ') &&
      (q.endpoint || snapshot.dohEndpoint) === row.endpoint &&
      (q.purpose.startsWith('Consensus probe') ||
        row.endpoint === snapshot.dohEndpoint)
  );
  if (candidates.length === 0) return undefined;

  // Prefer the packet carrying an EDE or non-zero RCODE when this resolver reported an error/block
  if (row.ede.length > 0) {
    const withEde = candidates.find((q) => (q.packet.edns?.ede.length ?? 0) > 0);
    if (withEde) return withEde;
  }
  if (row.rcode !== 0) {
    const withRcode = candidates.find((q) => q.packet.flags.rcode === row.rcode);
    if (withRcode) return withRcode;
  }

  // Prefer CD=0 validating check for primary resolver or Consensus probe A for secondary resolvers
  const normTarget = normalizeFqdn(snapshot.targetName);
  return (
    candidates.find(
      (q) =>
        normalizeFqdn(q.qname) === normTarget &&
        q.qtypeName === 'A' &&
        q.cd === false
    ) ??
    candidates.find((q) => normalizeFqdn(q.qname) === normTarget && q.qtypeName === 'A') ??
    candidates.find((q) => normalizeFqdn(q.qname) === normTarget && q.qtypeName === 'AAAA') ??
    candidates[0]
  );
}

/**
 * Resolves an RFC 8914 EDE highlight item in ConsensusView to the exact wire packet containing that EDE option.
 */
export function findConsensusEdeWireQuery(
  resolverLabel: string,
  infoCode: number,
  snapshot: AnalysisSnapshot
): DohQueryLog | undefined {
  const lowerLabel = resolverLabel.toLowerCase();
  return (
    snapshot.queries.find(
      (q) =>
        !q.ecsSubnet &&
        formatDohShortLabel(q.endpoint || snapshot.dohEndpoint).toLowerCase() === lowerLabel &&
        q.packet.edns?.ede.some((e) => e.infoCode === infoCode)
    ) ??
    snapshot.queries.find((q) => q.packet.edns?.ede.some((e) => e.infoCode === infoCode))
  );
}

/**
 * Resolves an RFC 7871 7-region ECS Geo row to its recorded IPv4 (`A`) and IPv6 (`AAAA`) DoH wire queries.
 */
export function findEcsRegionWireQueries(
  row: EcsRegionProbeRow,
  queries: DohQueryLog[]
): { ipv4?: DohQueryLog; ipv6?: DohQueryLog } {
  const ecsQueries = queries.filter(
    (q) => Boolean(q.ecsSubnet) || q.purpose.startsWith('ECS Geo probe')
  );
  const ipv4 =
    ecsQueries.find((q) => q.ecsSubnet === row.ipv4.querySubnet && q.qtypeName === 'A') ??
    ecsQueries.find((q) => q.purpose.includes(`(${row.regionId} `) && q.qtypeName === 'A');
  const ipv6 =
    ecsQueries.find((q) => q.ecsSubnet === row.ipv6.querySubnet && q.qtypeName === 'AAAA') ??
    ecsQueries.find((q) => q.purpose.includes(`(${row.regionId} `) && q.qtypeName === 'AAAA');
  return { ipv4, ipv6 };
}

/**
 * Resolves an AuditFinding to its most relevant recorded DoH wire packet in `snapshot.queries`.
 */
export function findAuditFindingWireQuery(
  finding: AuditFinding,
  snapshot: AnalysisSnapshot
): DohQueryLog | undefined {
  const { queries } = snapshot;
  if (queries.length === 0) return undefined;

  // 1. Direct targetId match (rrset, negativeNode, dnskey, ds, zone)
  if (finding.targetId) {
    const byTarget = findWireQueryByGraphTargetId(finding.targetId, snapshot);
    if (byTarget) return byTarget;
  }

  const code = finding.code.toUpperCase();

  // 2. RFC 7871 ECS Geo findings
  if (code.startsWith('ECS_')) {
    const ecsQueries = queries.filter(
      (q) => Boolean(q.ecsSubnet) || q.purpose.startsWith('ECS Geo probe')
    );
    if (code === 'ECS_SCOPE_EXCEEDS_SOURCE') {
      return (
        ecsQueries.find(
          (q) =>
            (q.ecsSubnet === '0.0.0.0/0' || q.ecsSubnet === '::/0') &&
            (q.packet.edns?.ecs?.scopePrefixLength ?? 0) > 0
        ) ??
        ecsQueries.find((q) => q.ecsSubnet === '0.0.0.0/0' || q.ecsSubnet === '::/0') ??
        ecsQueries[0]
      );
    }
    if (code === 'ECS_CACHE_BUSTING_SCOPE') {
      return (
        ecsQueries.find((q) => {
          const scope = q.packet.edns?.ecs?.scopePrefixLength ?? 0;
          return q.qtypeName === 'A' ? scope > 24 : scope > 56;
        }) ?? ecsQueries[0]
      );
    }
    if (code === 'ECS_WIRE_FORMAT_ANOMALY') {
      return (
        ecsQueries.find(
          (q) =>
            q.packet.edns?.ecs?.hasNonZeroTailBits ||
            q.packet.edns?.ecs?.hasExcessAddressBytes ||
            q.packet.edns?.ecs?.invalidPrefixLength
        ) ?? ecsQueries[0]
      );
    }
    if (code === 'ECS_REGIONAL_SERVFAIL_OR_NXDOMAIN' || code === 'ECS_REGIONAL_DANGLING_CNAME') {
      return (
        ecsQueries.find((q) => q.packet.flags.rcode !== 0 || q.packet.answers.length === 0) ??
        ecsQueries[0]
      );
    }
    return ecsQueries[0];
  }

  // 3. Multi-Resolver Consensus & Protective EDE findings
  if (code.startsWith('CONSENSUS_')) {
    const consensusQueries = queries.filter(
      (q) => !q.ecsSubnet && q.purpose.startsWith('Consensus probe')
    );
    if (code === 'CONSENSUS_PROTECTIVE_BLOCKED' || code === 'CONSENSUS_DNSSEC_BOGUS') {
      return (
        queries.find((q) => !q.ecsSubnet && (q.packet.edns?.ede.length ?? 0) > 0) ??
        consensusQueries.find((q) => q.packet.flags.rcode !== 0) ??
        consensusQueries[0]
      );
    }
    if (code === 'CONSENSUS_SOA_SERIAL_SKEW') {
      return consensusQueries.find((q) => q.qtypeName === 'SOA') ?? consensusQueries[0];
    }
    if (code === 'CONSENSUS_KEYTAG_SKEW') {
      return consensusQueries.find((q) => q.qtypeName === 'DNSKEY') ?? consensusQueries[0];
    }
    return consensusQueries.find((q) => q.qtypeName === 'A') ?? consensusQueries[0];
  }

  // 4. Resolver CD=0 / EDE findings
  if (code.includes('RESOLVER') || code.includes('EDE')) {
    return (
      queries.find(
        (q) =>
          q.purpose.includes('validating check') ||
          (!q.ecsSubnet && (q.packet.edns?.ede.length ?? 0) > 0)
      ) ?? queries.find((q) => !q.cd && !q.ecsSubnet)
    );
  }

  // 5. Zone-scoped DNSSEC / RFC hygiene findings
  if (finding.zone) {
    if (code.startsWith('DS_') || code.includes('DELEGATION')) {
      return findWireQueryByOwnerAndType(queries, finding.zone, 'DS', { preferCd: true });
    }
    if (code.includes('SOA')) {
      return findWireQueryByOwnerAndType(queries, finding.zone, 'SOA', { preferCd: true });
    }
    if (code.includes('NS_') || code.includes('NAMESERVER') || code.includes('LAME')) {
      const zoneNorm = normalizeFqdn(finding.zone);
      const zoneObj = snapshot.zones.find((z) => z.zoneName === zoneNorm);

      if (code === 'NS_RRSET_INCONSISTENT') {
        const divId = zoneObj?.nsConsistency?.divergentObservations[0]?.sourceQueryId;
        if (divId) {
          const divQuery = queries.find((q) => q.id === divId);
          if (divQuery) return divQuery;
        }
      }

      if (code === 'NS_TARGET_IS_CNAME') {
        const nsEntry =
          zoneObj?.nameservers.find(
            (n) => (n.cnameChain?.length ?? 0) > 0 && finding.id.endsWith(`-${n.hostname}`)
          ) ?? zoneObj?.nameservers.find((n) => (n.cnameChain?.length ?? 0) > 0);
        if (nsEntry) {
          const cnameQuery =
            queries.find(
              (q) =>
                q.purpose.startsWith('Nameserver IP') &&
                normalizeFqdn(q.qname) === nsEntry.hostname &&
                q.packet.answers.some((a) => a.type === RR_TYPES.CNAME)
            ) ?? findWireQueryByOwnerAndType(queries, nsEntry.hostname, 'A');
          if (cnameQuery) return cnameQuery;
        }
      }

      if (code === 'NS_BOGON_IP') {
        const nsEntry =
          zoneObj?.nameservers.find(
            (n) => (n.bogonIps?.length ?? 0) > 0 && finding.id.endsWith(`-${n.hostname}`)
          ) ?? zoneObj?.nameservers.find((n) => (n.bogonIps?.length ?? 0) > 0);
        if (nsEntry) {
          const wantQtype = nsEntry.bogonIps?.[0]?.family === 6 ? 'AAAA' : 'A';
          const bogonQuery =
            queries.find(
              (q) =>
                q.purpose.startsWith('Nameserver IP') &&
                normalizeFqdn(q.qname) === nsEntry.hostname &&
                q.qtypeName === wantQtype
            ) ?? findWireQueryByOwnerAndType(queries, nsEntry.hostname, wantQtype);
          if (bogonQuery) return bogonQuery;
        }
      }

      if (code === 'DANGLING_NS_TARGET') {
        const dHost =
          zoneObj?.nsDiversity?.danglingHosts.find((h) => finding.id.endsWith(`-${h}`)) ??
          zoneObj?.nsDiversity?.danglingHosts[0];
        if (dHost) {
          const dQuery =
            queries.find(
              (q) => q.purpose.startsWith('Nameserver IP') && normalizeFqdn(q.qname) === dHost
            ) ?? findWireQueryByOwnerAndType(queries, dHost, 'A');
          if (dQuery) return dQuery;
        }
      }

      if (code === 'NS_NO_IPV6') {
        const host =
          zoneObj?.nsDiversity?.ipv4OnlyHosts?.[0] ?? zoneObj?.nameservers[0]?.hostname;
        if (host) {
          const aaaaQuery =
            queries.find(
              (q) =>
                q.purpose.startsWith('Nameserver IP') &&
                normalizeFqdn(q.qname) === host &&
                q.qtypeName === 'AAAA'
            ) ?? findWireQueryByOwnerAndType(queries, host, 'AAAA');
          if (aaaaQuery) return aaaaQuery;
        }
      }

      if (code === 'NS_NO_IPV4') {
        const host =
          zoneObj?.nsDiversity?.ipv6OnlyHosts?.[0] ?? zoneObj?.nameservers[0]?.hostname;
        if (host) {
          const aQuery =
            queries.find(
              (q) =>
                q.purpose.startsWith('Nameserver IP') &&
                normalizeFqdn(q.qname) === host &&
                q.qtypeName === 'A'
            ) ?? findWireQueryByOwnerAndType(queries, host, 'A');
          if (aQuery) return aQuery;
        }
      }

      return findWireQueryByOwnerAndType(queries, finding.zone, 'NS', { preferCd: true });
    }
    if (code.includes('ZONEMD')) {
      return findWireQueryByOwnerAndType(queries, finding.zone, 'ZONEMD', { preferCd: true });
    }
    if (code.includes('CDS') || code.includes('CDNSKEY')) {
      return (
        findWireQueryByOwnerAndType(queries, finding.zone, 'CDS', { preferCd: true }) ??
        findWireQueryByOwnerAndType(queries, finding.zone, 'CDNSKEY', { preferCd: true })
      );
    }
    return findWireQueryByOwnerAndType(queries, finding.zone, 'DNSKEY', { preferCd: true });
  }

  return undefined;
}
