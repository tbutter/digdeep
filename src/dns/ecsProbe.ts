import { formatDohShortLabel, rcodeToString, RR_TYPES } from './constants';
import { DohSession } from './doh';
import { displayFqdn, normalizeFqdn } from './encoding';
import {
  classifyIpAddress,
  formatCanonicalIpv6,
  getCachedRpkiValidation,
  ipToCymruOriginQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseIpv4Octets,
  parseIpv6Groups,
  reverseArpaToIp,
  summarizeRpkiValidationState,
  validateRpkiRoute,
} from './ipUtils';
import type {
  AuditFinding,
  BgpAsnOrganization,
  DohQueryLog,
  EcsAddressProbeResult,
  EcsGeoAnalysisResult,
  EcsRegionProbeRow,
  EdeEntry,
  RpkiRouteValidation,
} from './types';
import { formatEcsQuerySubnet, parseEcsSubnetInput } from './wire';

export interface EcsRegionalPreset {
  id: string;
  label: string;
  locationHint: string;
  ipv4Subnet: string;
  ipv6Subnet: string;
  isPrivacyOptOut?: boolean;
}

/**
 * Curated publicly routed regional IPv4 `/24` and IPv6 `/56` prefixes across 6 continents,
 * plus the RFC 7871 §7.1.2 `/0` privacy opt-out prefix.
 */
export const ECS_REGIONAL_PROBES: readonly EcsRegionalPreset[] = [
  {
    id: 'us-east',
    label: 'North America East',
    locationHint: 'Virginia / New York, US',
    ipv4Subnet: '71.252.0.0/24',
    ipv6Subnet: '2601:140:4000::/56',
  },
  {
    id: 'us-west',
    label: 'North America West',
    locationHint: 'California, US',
    ipv4Subnet: '76.102.0.0/24',
    ipv6Subnet: '2601:640:4000::/56',
  },
  {
    id: 'eu-central',
    label: 'Europe Central',
    locationHint: 'Frankfurt, DE',
    ipv4Subnet: '80.150.6.0/24',
    ipv6Subnet: '2003:c0:4000::/56',
  },
  {
    id: 'ap-east',
    label: 'Asia-Pacific East',
    locationHint: 'Tokyo, JP',
    ipv4Subnet: '210.130.1.0/24',
    ipv6Subnet: '2001:240:bb81::/56',
  },
  {
    id: 'sa-east',
    label: 'South America',
    locationHint: 'São Paulo, BR',
    ipv4Subnet: '200.160.2.0/24',
    ipv6Subnet: '2804:14d:5c00::/56',
  },
  {
    id: 'oc-syd',
    label: 'Oceania',
    locationHint: 'Sydney, AU',
    ipv4Subnet: '1.120.0.0/24',
    ipv6Subnet: '2001:8003:1000::/56',
  },
  {
    id: 'opt-out',
    label: 'Privacy Opt-Out (/0)',
    locationHint: 'RFC 7871 §7.1.2 Zero-Prefix',
    ipv4Subnet: '0.0.0.0/0',
    ipv6Subnet: '::/0',
    isPrivacyOptOut: true,
  },
] as const;

export interface EcsQuickCustomChip {
  label: string;
  subnet: string;
  qtype: 'A' | 'AAAA';
}

export const ECS_QUICK_CUSTOM_CHIPS: readonly EcsQuickCustomChip[] = [
  { label: 'London, UK (/24)', subnet: '81.2.69.0/24', qtype: 'A' },
  { label: 'Singapore (/24)', subnet: '175.156.0.0/24', qtype: 'A' },
  { label: 'Mumbai, IN (/24)', subnet: '49.36.0.0/24', qtype: 'A' },
  { label: 'Johannesburg, ZA (/24)', subnet: '197.80.0.0/24', qtype: 'A' },
  { label: '/32 Host Scope Test', subnet: '71.252.0.42/32', qtype: 'A' },
  { label: 'IPv6 /128 Scope Test', subnet: '2601:140:4000::42/128', qtype: 'AAAA' },
  { label: '0.0.0.0/0 Opt-Out', subnet: '0.0.0.0/0', qtype: 'A' },
] as const;

export const ECS_DOH_ENDPOINTS: ReadonlyArray<{
  url: string;
  label: string;
  note: string;
}> = [
  {
    url: 'https://8.8.8.8/dns-query',
    label: 'Google 8.8.8.8 DoH',
    note: 'Forwards ECS (/24, /56, /0) & echoes RFC 7871 SCOPE',
  },
  {
    url: 'https://dns.google/dns-query',
    label: 'Google dns.google DoH',
    note: 'Hostname alias for Google ECS-enabled DoH',
  },
  {
    url: 'https://9.9.9.11/dns-query',
    label: 'Quad9 9.9.9.11 (ECS)',
    note: 'Quad9 ECS-enabled Threat-Blocking DoH',
  },
];

/**
 * Selects an RFC 7871 ECS-capable DoH endpoint for multi-region geo-steering probes.
 * Note: Privacy-default resolvers like 1.1.1.1 and 9.9.9.9 intentionally strip client ECS options;
 * Google Public DNS (`8.8.8.8` / `dns.google`) and Quad9 `9.9.9.11` forward ECS and return geo-steered answers.
 */
export function selectEcsDohEndpoint(primaryEndpoint: string): string {
  const lower = primaryEndpoint.trim().toLowerCase();
  if (lower.includes('dns.google') || lower.includes('8.8.8.8') || lower.includes('8.8.4.4')) {
    return primaryEndpoint;
  }
  if (lower.includes('9.9.9.11') || lower.includes('dns11.quad9.net')) {
    return primaryEndpoint;
  }
  return 'https://8.8.8.8/dns-query';
}

function ipClusterKey(ip: string): { key: string; family: 4 | 6 } | null {
  const v4 = parseIpv4Octets(ip);
  if (v4) {
    if (!classifyIpAddress(ip, 4).isPublic) return null;
    return { key: `v4:${v4[0]}.${v4[1]}.${v4[2]}`, family: 4 };
  }
  const v6 = parseIpv6Groups(ip);
  if (v6) {
    const canon = formatCanonicalIpv6(v6);
    if (!classifyIpAddress(canon, 6).isPublic) return null;
    return {
      key: `v6:${v6[0].toString(16)}:${v6[1].toString(16)}:${v6[2].toString(16)}`,
      family: 6,
    };
  }
  return null;
}

function cymruQnameToIp(qname: string): { ip: string; family: 4 | 6 } | null {
  const norm = normalizeFqdn(qname);
  if (norm.endsWith('.origin.asn.cymru.com.')) {
    const pfx = norm.slice(0, -'.origin.asn.cymru.com.'.length);
    return reverseArpaToIp(`${pfx}.in-addr.arpa.`);
  }
  if (norm.endsWith('.origin6.asn.cymru.com.')) {
    const pfx = norm.slice(0, -'.origin6.asn.cymru.com.'.length);
    return reverseArpaToIp(`${pfx}.ip6.arpa.`);
  }
  return null;
}

interface IpBgpRecord {
  asns: number[];
  bgpPrefixes: string[];
  country?: string;
  rir?: string;
}

function buildBgpLookupFromLogs(logs: DohQueryLog[]): {
  asnOrgs: Map<number, BgpAsnOrganization>;
  byExactIp: Map<string, IpBgpRecord>;
  byClusterKey: Map<string, IpBgpRecord>;
} {
  const asnOrgs = new Map<number, BgpAsnOrganization>();
  const byExactIp = new Map<string, IpBgpRecord>();
  const byClusterKey = new Map<string, IpBgpRecord>();

  for (const l of logs) {
    if (l.qtype !== RR_TYPES.TXT) continue;
    const normQ = normalizeFqdn(l.qname).toLowerCase();
    if (/^as\d+\.asn\.cymru\.com\.$/.test(normQ)) {
      const txts = l.packet.answers
        .filter((a) => a.type === RR_TYPES.TXT)
        .map((a) => (a.parsed.kind === 'TXT' ? a.parsed.joinedText : a.rdataText));
      const parsed = parseCymruAsnTxt(txts);
      if (parsed) {
        asnOrgs.set(parsed.asn, {
          asn: parsed.asn,
          asName: parsed.asName,
          country: parsed.country,
          rir: parsed.rir,
        });
      }
    }
  }

  for (const l of logs) {
    if (l.qtype !== RR_TYPES.TXT) continue;
    const decoded = cymruQnameToIp(l.qname);
    if (!decoded) continue;
    const txts = l.packet.answers
      .filter((a) => a.type === RR_TYPES.TXT)
      .map((a) => (a.parsed.kind === 'TXT' ? a.parsed.joinedText : a.rdataText));
    const entries = parseCymruOriginTxt(txts);
    if (entries.length === 0) continue;

    const asns: number[] = [];
    const bgpPrefixes: string[] = [];
    let country: string | undefined;
    let rir: string | undefined;
    for (const e of entries) {
      for (const a of e.asns) {
        if (!asns.includes(a)) asns.push(a);
      }
      if (e.bgpPrefix && !bgpPrefixes.includes(e.bgpPrefix)) {
        bgpPrefixes.push(e.bgpPrefix);
      }
      if (!country && e.country) country = e.country;
      if (!rir && e.rir) rir = e.rir;
    }

    const rec: IpBgpRecord = { asns, bgpPrefixes, country, rir };
    byExactIp.set(decoded.ip, rec);
    const cluster = ipClusterKey(decoded.ip);
    if (cluster && !byClusterKey.has(cluster.key)) {
      byClusterKey.set(cluster.key, rec);
    }
  }

  return { asnOrgs, byExactIp, byClusterKey };
}

/**
 * Executes RFC 7871 EDNS0 `CLIENT-SUBNET` (Option 8) wire probes across `ECS_REGIONAL_PROBES`,
 * enriches unique regional edge IP clusters with Team Cymru BGP ASN origins (`TXT`),
 * and validates RPKI Route Origin Authorizations (`validateRpkiRoute`).
 */
export async function runEcsGeoProbes(params: {
  targetName: string;
  primaryEndpoint: string;
  bgpSession: DohSession;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  onQueryCompleted?: (log: DohQueryLog, endpointShort: string) => void;
}): Promise<DohQueryLog[]> {
  const { targetName, primaryEndpoint, bgpSession } = params;
  const normTarget = normalizeFqdn(targetName);
  if (normTarget === '.') return [];

  const ecsEndpoint = selectEcsDohEndpoint(primaryEndpoint);
  const ecsEndpointShort = formatDohShortLabel(ecsEndpoint);

  const ecsSession = new DohSession({
    endpoint: ecsEndpoint,
    timeoutMs: Math.min(params.timeoutMs ?? 4500, 4500),
    fetchImpl: params.fetchImpl,
  });
  ecsSession.onQueryCompleted = (_c, lastLog) => {
    params.onQueryCompleted?.(lastLog, ecsEndpointShort);
  };

  await Promise.all(
    ECS_REGIONAL_PROBES.flatMap((region) => {
      const v4Opt = parseEcsSubnetInput(region.ipv4Subnet)!;
      const v6Opt = parseEcsSubnetInput(region.ipv6Subnet)!;
      return [
        ecsSession
          .query(normTarget, RR_TYPES.A, {
            cd: false,
            doBit: true,
            ecs: v4Opt,
            purpose: `ECS Geo probe (${region.id} ${region.ipv4Subnet} A)`,
          })
          .catch(() => undefined),
        ecsSession
          .query(normTarget, RR_TYPES.AAAA, {
            cd: false,
            doBit: true,
            ecs: v6Opt,
            purpose: `ECS Geo probe (${region.id} ${region.ipv6Subnet} AAAA)`,
          })
          .catch(() => undefined),
      ];
    })
  );

  const rawEcsLogs = ecsSession.getLogs().map((l) => ({
    ...l,
    id: `${l.id}-ecs-${(l.ecsSubnet ?? 'none').replace(/[^a-z0-9]/gi, '_')}`,
  }));

  // Collect representative public edge IPs (1 per /24 IPv4 or /48 IPv6 cluster, capped at 14) for BGP + RPKI lookup
  const clusterToRepIp = new Map<string, string>();
  for (const log of rawEcsLogs) {
    for (const ans of log.packet.answers) {
      if (ans.type === RR_TYPES.A) {
        const ip = ans.rdataText.trim();
        const cl = ipClusterKey(ip);
        if (cl && !clusterToRepIp.has(cl.key) && clusterToRepIp.size < 14) {
          clusterToRepIp.set(cl.key, ip);
        }
      } else if (ans.type === RR_TYPES.AAAA) {
        const grps = parseIpv6Groups(ans.rdataText);
        if (grps) {
          const canon = formatCanonicalIpv6(grps);
          const cl = ipClusterKey(canon);
          if (cl && !clusterToRepIp.has(cl.key) && clusterToRepIp.size < 14) {
            clusterToRepIp.set(cl.key, canon);
          }
        }
      }
    }
  }

  const originLogs = await Promise.all(
    Array.from(clusterToRepIp.values()).map(async (ip) => {
      const qname = ipToCymruOriginQname(ip);
      if (!qname) return undefined;
      return bgpSession
        .query(qname, RR_TYPES.TXT, {
          cd: false,
          doBit: false,
          purpose: `ECS BGP origin lookup (${ip})`,
        })
        .catch(() => undefined);
    })
  );

  const uniqueAsns = new Set<number>();
  const rpkiPairs = new Map<string, { asn: number; prefix: string }>();
  for (const oLog of originLogs) {
    if (!oLog) continue;
    const txts = oLog.packet.answers
      .filter((a) => a.type === RR_TYPES.TXT)
      .map((a) => (a.parsed.kind === 'TXT' ? a.parsed.joinedText : a.rdataText));
    for (const entry of parseCymruOriginTxt(txts)) {
      for (const asn of entry.asns) {
        uniqueAsns.add(asn);
        if (entry.bgpPrefix && rpkiPairs.size < 8) {
          rpkiPairs.set(`${asn}|${entry.bgpPrefix}`, { asn, prefix: entry.bgpPrefix });
        }
      }
    }
  }

  await Promise.all([
    ...Array.from(uniqueAsns)
      .slice(0, 12)
      .map((asn) =>
        bgpSession
          .query(`AS${asn}.asn.cymru.com.`, RR_TYPES.TXT, {
            cd: false,
            doBit: false,
            purpose: `ECS BGP ASN name (AS${asn})`,
          })
          .catch(() => undefined)
      ),
    ...Array.from(rpkiPairs.values()).map(({ asn, prefix }) =>
      validateRpkiRoute(asn, prefix, { fetchImpl: params.fetchImpl, timeoutMs: 3500 }).catch(
        () => undefined
      )
    ),
  ]);

  return rawEcsLogs;
}

export function extractEcsAddressProbe(
  targetName: string,
  qtype: 'A' | 'AAAA',
  querySubnet: string,
  log?: DohQueryLog
): EcsAddressProbeResult {
  const parsedSub = parseEcsSubnetInput(querySubnet);
  const sourcePrefixLength = parsedSub?.sourcePrefixLength ?? (qtype === 'A' ? 24 : 56);
  const expectedFamily = qtype === 'A' ? 1 : 2;
  const normTarget = normalizeFqdn(targetName);

  if (!log) {
    return {
      qtype,
      querySubnet,
      sourcePrefixLength,
      reachable: false,
      latencyMs: 0,
      rcode: -1,
      rcodeName: 'UNREACHABLE',
      adBit: false,
      cnameChain: [],
      terminalOwner: normTarget,
      answers: [],
      ede: [],
      isDanglingCname: false,
      isCacheBustingScope: false,
      hasWireAnomaly: false,
      wireAnomalyNotes: [],
    };
  }

  const rcode = log.packet.flags.rcode;
  const rcodeName = rcodeToString(rcode);
  const adBit = Boolean(log.packet.flags.ad);
  const responseEcs = log.packet.edns?.ecs;
  const ede: EdeEntry[] = [...(log.packet.edns?.ede ?? [])];

  // Walk CNAME chain from normTarget
  const cnameChain: string[] = [];
  const seenOwners = new Set<string>([normTarget]);
  let curOwner = normTarget;
  for (let hop = 0; hop < 10; hop++) {
    const cnameRec = log.packet.answers.find(
      (r) =>
        r.type === RR_TYPES.CNAME &&
        normalizeFqdn(r.name) === curOwner &&
        r.parsed.kind === 'GENERIC' &&
        Boolean(r.parsed.target)
    );
    if (!cnameRec || cnameRec.parsed.kind !== 'GENERIC' || !cnameRec.parsed.target) break;
    const nextOwner = normalizeFqdn(cnameRec.parsed.target);
    cnameChain.push(nextOwner);
    if (seenOwners.has(nextOwner)) break;
    seenOwners.add(nextOwner);
    curOwner = nextOwner;
  }

  const rrNum = qtype === 'A' ? RR_TYPES.A : RR_TYPES.AAAA;
  const answers: string[] = [];
  let minTtl: number | undefined;
  for (const ans of log.packet.answers) {
    if (ans.type === rrNum) {
      let formatted = ans.rdataText.trim();
      if (qtype === 'AAAA') {
        const grps = parseIpv6Groups(formatted);
        formatted = grps ? formatCanonicalIpv6(grps) : formatted.toLowerCase();
      }
      if (formatted && !answers.includes(formatted)) {
        answers.push(formatted);
      }
      minTtl = minTtl === undefined ? ans.ttl : Math.min(minTtl, ans.ttl);
    }
  }
  answers.sort();

  if (minTtl === undefined && cnameChain.length > 0) {
    for (const ans of log.packet.answers) {
      if (ans.type === RR_TYPES.CNAME) {
        minTtl = minTtl === undefined ? ans.ttl : Math.min(minTtl, ans.ttl);
      }
    }
  }

  // RFC 7871 §11.1 / §7.3.1 cache-busting scope check (> /24 for IPv4, > /56 for IPv6)
  const isCacheBustingScope = Boolean(
    responseEcs &&
      ((expectedFamily === 1 && responseEcs.scopePrefixLength > 24) ||
        (expectedFamily === 2 && responseEcs.scopePrefixLength > 56))
  );

  // RFC 7871 §6 / §7.2.2 wire hygiene checks
  const wireAnomalyNotes: string[] = [];
  if (responseEcs) {
    if (responseEcs.family !== expectedFamily) {
      wireAnomalyNotes.push(
        `ECS response FAMILY=${responseEcs.family} (${responseEcs.familyName}) mismatches ${qtype} query family (${expectedFamily === 1 ? 'IPv4' : 'IPv6'}).`
      );
    }
    if (responseEcs.invalidPrefixLength) {
      wireAnomalyNotes.push(
        `Invalid ECS prefix length or truncated payload in ${responseEcs.presentation} (RFC 7871 §6).`
      );
    }
    if (responseEcs.hasNonZeroTailBits) {
      wireAnomalyNotes.push(
        `Non-zero tail bits present in ECS ADDRESS beyond SOURCE=/${responseEcs.sourcePrefixLength} (${responseEcs.presentation}, violates RFC 7871 §6).`
      );
    }
    if (responseEcs.hasExcessAddressBytes) {
      wireAnomalyNotes.push(
        `ECS ADDRESS carries ${responseEcs.addressByteLength} octets instead of ${Math.ceil(responseEcs.sourcePrefixLength / 8)} truncated octets (RFC 7871 §6).`
      );
    }
    if (sourcePrefixLength === 0 && responseEcs.scopePrefixLength > 0) {
      wireAnomalyNotes.push(
        `Privacy opt-out query (${querySubnet}) returned non-zero SCOPE=/${responseEcs.scopePrefixLength} (RFC 7871 §7.2.2 requires SCOPE=0).`
      );
    }
  }

  // CNAME target returning NXDOMAIN (rcode 3) is immediately dangling
  const isDanglingCname = cnameChain.length > 0 && rcode === 3;

  return {
    qtype,
    querySubnet,
    sourcePrefixLength,
    reachable: true,
    latencyMs: log.latencyMs,
    rcode,
    rcodeName,
    adBit,
    ...(responseEcs ? { responseEcs } : {}),
    cnameChain,
    terminalOwner: curOwner,
    answers,
    ...(minTtl !== undefined ? { minTtl } : {}),
    ede,
    isDanglingCname,
    isCacheBustingScope,
    hasWireAnomaly: wireAnomalyNotes.length > 0,
    wireAnomalyNotes,
  };
}

/**
 * Evaluates the 7-region RFC 7871 ECS Geo-Steering matrix and emits ECS hygiene & security `AuditFinding[]`
 * from recorded `DohQueryLog[]`.
 */
export function evaluateEcsGeoFromLogs(params: {
  targetName: string;
  primaryEndpoint: string;
  queries: DohQueryLog[];
}): {
  ecsGeo?: EcsGeoAnalysisResult;
  ecsFindings: AuditFinding[];
} {
  const { targetName, primaryEndpoint, queries } = params;
  const normTarget = normalizeFqdn(targetName);
  const dispTarget = displayFqdn(normTarget);
  if (normTarget === '.') {
    return { ecsFindings: [] };
  }

  const ecsLogs = queries.filter(
    (q) => Boolean(q.ecsSubnet) || q.purpose.startsWith('ECS Geo probe')
  );
  if (ecsLogs.length === 0) {
    return { ecsFindings: [] };
  }

  const ecsEndpoint = ecsLogs[0]?.endpoint ?? selectEcsDohEndpoint(primaryEndpoint);
  const ecsEndpointLabel = formatDohShortLabel(ecsEndpoint);
  const bgpLookup = buildBgpLookupFromLogs(queries);

  const rows: EcsRegionProbeRow[] = ECS_REGIONAL_PROBES.map((preset) => {
    const v4Canonical = formatEcsQuerySubnet(parseEcsSubnetInput(preset.ipv4Subnet)!);
    const v6Canonical = formatEcsQuerySubnet(parseEcsSubnetInput(preset.ipv6Subnet)!);

    const v4Log = ecsLogs.find(
      (q) =>
        normalizeFqdn(q.qname) === normTarget &&
        q.qtype === RR_TYPES.A &&
        q.ecsSubnet === v4Canonical
    );
    const v6Log = ecsLogs.find(
      (q) =>
        normalizeFqdn(q.qname) === normTarget &&
        q.qtype === RR_TYPES.AAAA &&
        q.ecsSubnet === v6Canonical
    );

    const ipv4 = extractEcsAddressProbe(normTarget, 'A', v4Canonical, v4Log);
    const ipv6 = extractEcsAddressProbe(normTarget, 'AAAA', v6Canonical, v6Log);

    const regionAsnsMap = new Map<number, BgpAsnOrganization>();
    const regionPrefixes = new Set<string>();
    const regionCountries = new Set<string>();
    const rpkiMap = new Map<string, RpkiRouteValidation>();

    for (const ip of [...ipv4.answers, ...ipv6.answers]) {
      const cl = ipClusterKey(ip);
      const bgp = bgpLookup.byExactIp.get(ip) ?? (cl ? bgpLookup.byClusterKey.get(cl.key) : undefined);
      if (!bgp) continue;
      if (bgp.country) regionCountries.add(bgp.country);
      for (const pfx of bgp.bgpPrefixes) {
        regionPrefixes.add(pfx);
      }
      for (const asn of bgp.asns) {
        if (!regionAsnsMap.has(asn)) {
          regionAsnsMap.set(
            asn,
            bgpLookup.asnOrgs.get(asn) ?? {
              asn,
              country: bgp.country,
              rir: bgp.rir,
            }
          );
        }
        for (const pfx of bgp.bgpPrefixes) {
          const cachedRpki = getCachedRpkiValidation(asn, pfx);
          if (cachedRpki) {
            rpkiMap.set(`${asn}|${pfx}`, cachedRpki);
          }
        }
      }
    }

    const rpkiValidations = Array.from(rpkiMap.values());
    const rpkiStatus = summarizeRpkiValidationState(rpkiValidations);

    return {
      regionId: preset.id,
      regionLabel: preset.label,
      locationHint: preset.locationHint,
      isPrivacyOptOut: Boolean(preset.isPrivacyOptOut),
      ipv4,
      ipv6,
      asns: Array.from(regionAsnsMap.values()).sort((a, b) => a.asn - b.asn),
      bgpPrefixes: Array.from(regionPrefixes),
      countries: Array.from(regionCountries),
      ...(rpkiStatus ? { rpkiStatus } : {}),
      ...(rpkiValidations.length > 0 ? { rpkiValidations } : {}),
    };
  });

  // Refine region-specific dangling CNAME check: if other regions resolved answers,
  // and this region steered to a CNAME where BOTH A & AAAA have 0 answers, mark dangling.
  const anyRegionHasAnswers = rows.some(
    (r) => r.ipv4.answers.length > 0 || r.ipv6.answers.length > 0
  );
  if (anyRegionHasAnswers) {
    for (const r of rows) {
      if (
        r.ipv4.reachable &&
        r.ipv6.reachable &&
        r.ipv4.answers.length === 0 &&
        r.ipv6.answers.length === 0 &&
        (r.ipv4.cnameChain.length > 0 || r.ipv6.cnameChain.length > 0)
      ) {
        if (r.ipv4.cnameChain.length > 0) r.ipv4.isDanglingCname = true;
        if (r.ipv6.cnameChain.length > 0) r.ipv6.isDanglingCname = true;
      }
    }
  }

  const geoRows = rows.filter((r) => !r.isPrivacyOptOut);
  const optOutRow = rows.find((r) => r.isPrivacyOptOut);

  const ecsSupportedByResolver = rows.some(
    (r) => Boolean(r.ipv4.responseEcs) || Boolean(r.ipv6.responseEcs)
  );

  const v4Pools = new Set<string>();
  const v6Pools = new Set<string>();
  const cnameTargets = new Set<string>();
  let v4ScopeMin = Number.POSITIVE_INFINITY;
  let v4ScopeMax = -1;
  let v6ScopeMin = Number.POSITIVE_INFINITY;
  let v6ScopeMax = -1;

  for (const r of geoRows) {
    if (r.ipv4.answers.length > 0) {
      v4Pools.add(r.ipv4.answers.join(','));
    }
    if (r.ipv6.answers.length > 0) {
      v6Pools.add(r.ipv6.answers.join(','));
    }
    if (r.ipv4.cnameChain.length > 0) {
      cnameTargets.add(r.ipv4.cnameChain[r.ipv4.cnameChain.length - 1]);
    }
    if (r.ipv6.cnameChain.length > 0) {
      cnameTargets.add(r.ipv6.cnameChain[r.ipv6.cnameChain.length - 1]);
    }
    if (r.ipv4.responseEcs) {
      v4ScopeMin = Math.min(v4ScopeMin, r.ipv4.responseEcs.scopePrefixLength);
      v4ScopeMax = Math.max(v4ScopeMax, r.ipv4.responseEcs.scopePrefixLength);
    }
    if (r.ipv6.responseEcs) {
      v6ScopeMin = Math.min(v6ScopeMin, r.ipv6.responseEcs.scopePrefixLength);
      v6ScopeMax = Math.max(v6ScopeMax, r.ipv6.responseEcs.scopePrefixLength);
    }
  }

  const ipv4ScopeRange = v4ScopeMax >= 0 ? { min: v4ScopeMin, max: v4ScopeMax } : null;
  const ipv6ScopeRange = v6ScopeMax >= 0 ? { min: v6ScopeMin, max: v6ScopeMax } : null;

  const optOutHonored = optOutRow
    ? (!optOutRow.ipv4.responseEcs || optOutRow.ipv4.responseEcs.scopePrefixLength === 0) &&
      (!optOutRow.ipv6.responseEcs || optOutRow.ipv6.responseEcs.scopePrefixLength === 0)
    : true;

  const cacheBustingRegions = rows
    .filter((r) => r.ipv4.isCacheBustingScope || r.ipv6.isCacheBustingScope)
    .map((r) => r.regionLabel);

  const danglingRegions = rows.filter(
    (r) => r.ipv4.isDanglingCname || r.ipv6.isDanglingCname
  );

  // Detect region-specific SERVFAIL / REFUSED / NXDOMAIN divergence
  const reachableGeoRows = geoRows.filter((r) => r.ipv4.reachable || r.ipv6.reachable);
  const healthyGeoRows = reachableGeoRows.filter(
    (r) =>
      (r.ipv4.rcode === 0 && r.ipv4.answers.length > 0) ||
      (r.ipv6.rcode === 0 && r.ipv6.answers.length > 0)
  );
  const failedGeoRows =
    healthyGeoRows.length > 0
      ? reachableGeoRows.filter(
          (r) =>
            !healthyGeoRows.includes(r) &&
            (r.ipv4.rcode !== 0 || r.ipv6.rcode !== 0)
        )
      : [];

  const anomalyRegionSet = new Set<string>([
    ...danglingRegions.map((r) => r.regionLabel),
    ...failedGeoRows.map((r) => r.regionLabel),
    ...rows
      .filter((r) => r.ipv4.hasWireAnomaly || r.ipv6.hasWireAnomaly)
      .map((r) => r.regionLabel),
  ]);
  const anomalyRegions = Array.from(anomalyRegionSet);

  let steeringModel: EcsGeoAnalysisResult['steeringModel'] = 'anycast-uniform';
  if (danglingRegions.length > 0 || failedGeoRows.length > 0) {
    steeringModel = 'partial-or-error';
  } else if (cnameTargets.size > 1) {
    steeringModel = 'geodns-cname';
  } else if (v4Pools.size > 1 || v6Pools.size > 1) {
    steeringModel = 'geodns-ip';
  }

  const ecsFindings: AuditFinding[] = [];

  // 1. Cache-busting SCOPE PREFIX-LENGTH audit (RFC 7871 §7.3.1 / §11.1)
  if (cacheBustingRegions.length > 0) {
    const details: string[] = [];
    for (const r of rows) {
      if (r.ipv4.isCacheBustingScope && r.ipv4.responseEcs) {
        details.push(`${r.regionLabel} A: ${r.ipv4.responseEcs.presentation}`);
      }
      if (r.ipv6.isCacheBustingScope && r.ipv6.responseEcs) {
        details.push(`${r.regionLabel} AAAA: ${r.ipv6.responseEcs.presentation}`);
      }
    }
    ecsFindings.push({
      id: `ecs-cache-busting-scope-${normTarget}`,
      severity: 'warning',
      code: 'ECS_CACHE_BUSTING_SCOPE',
      title: `Overly narrow cache-busting ECS SCOPE prefix on ${dispTarget}`,
      detail: `Authoritative GeoDNS returned narrow ECS SCOPE prefix lengths exceeding RFC 7871 §11.1 privacy/caching ceilings (/24 IPv4, /56 IPv6): ${details.join('; ')}. Narrow SCOPE masks fragment recursive resolver caches and amplify upstream query load.`,
      rfc: 'RFC 7871 §7.3.1 / §11.1',
    });
  }

  // 2. Privacy Opt-Out (/0) violation (RFC 7871 §7.2.2)
  if (!optOutHonored && optOutRow) {
    ecsFindings.push({
      id: `ecs-optout-scope-nonzero-${normTarget}`,
      severity: 'warning',
      code: 'ECS_SCOPE_EXCEEDS_SOURCE',
      title: `ECS privacy opt-out (/0) returned non-zero SCOPE on ${dispTarget}`,
      detail: `RFC 7871 §7.2.2 requires a SOURCE PREFIX-LENGTH of 0 (0.0.0.0/0 or ::/0) to receive SCOPE PREFIX-LENGTH = 0, but received ${optOutRow.ipv4.responseEcs?.presentation ?? ''} ${optOutRow.ipv6.responseEcs?.presentation ?? ''}.`.trim(),
      rfc: 'RFC 7871 §7.2.2',
    });
  }

  // 3. Wire format anomalies (mismatched FAMILY, non-zero tail bits, excess bytes)
  const wireAnomalyDetails: string[] = [];
  for (const r of rows) {
    for (const note of [...r.ipv4.wireAnomalyNotes, ...r.ipv6.wireAnomalyNotes]) {
      if (!note.includes('Privacy opt-out')) {
        wireAnomalyDetails.push(`[${r.regionLabel}] ${note}`);
      }
    }
  }
  if (wireAnomalyDetails.length > 0) {
    ecsFindings.push({
      id: `ecs-wire-anomaly-${normTarget}`,
      severity: 'warning',
      code: 'ECS_WIRE_FORMAT_ANOMALY',
      title: `Malformed RFC 7871 EDNS0 CLIENT-SUBNET option on ${dispTarget}`,
      detail: wireAnomalyDetails.slice(0, 4).join(' '),
      rfc: 'RFC 7871 §6',
    });
  }

  // 4. Region-specific dangling CNAME (subdomain takeover / broken regional CDN pool)
  if (danglingRegions.length > 0) {
    const desc = danglingRegions
      .map((r) => {
        const tgt =
          r.ipv4.cnameChain[r.ipv4.cnameChain.length - 1] ??
          r.ipv6.cnameChain[r.ipv6.cnameChain.length - 1] ??
          'unknown';
        return `${r.regionLabel} → ${displayFqdn(tgt)} (${r.ipv4.rcodeName}/${r.ipv6.rcodeName})`;
      })
      .join(', ');
    ecsFindings.push({
      id: `ecs-regional-dangling-cname-${normTarget}`,
      severity: 'error',
      code: 'ECS_REGIONAL_DANGLING_CNAME',
      title: `Region-specific dangling CNAME for ${dispTarget} (${danglingRegions.length} region${danglingRegions.length === 1 ? '' : 's'})`,
      detail: `GeoDNS ECS steering directed ${desc} to an unresolvable CNAME target while other geographic regions resolved normally — risking regional outages or CDN subdomain takeover.`,
      rfc: 'RFC 7871 / RFC 1034',
    });
  }

  // 5. Region-specific SERVFAIL / NXDOMAIN / REFUSED divergence
  if (failedGeoRows.length > 0) {
    const desc = failedGeoRows
      .map((r) => `${r.regionLabel} (A=${r.ipv4.rcodeName}, AAAA=${r.ipv6.rcodeName})`)
      .join(', ');
    ecsFindings.push({
      id: `ecs-regional-failure-${normTarget}`,
      severity: 'error',
      code: 'ECS_REGIONAL_SERVFAIL_OR_NXDOMAIN',
      title: `Geo-specific DNS failure for ${dispTarget} in ${failedGeoRows.length} ECS region${failedGeoRows.length === 1 ? '' : 's'}`,
      detail: `While ${healthyGeoRows.length} geographic ECS region(s) resolved ${dispTarget}, regional queries failed in: ${desc}. Check regional GSLB health or broken per-region DNSSEC RRSIG signing.`,
      rfc: 'RFC 7871 / RFC 8914',
    });
  }

  // 6. Regional DNSSEC AD-bit divergence (e.g. regional CNAME steering into unsigned vs signed CDN zones)
  const v4AdTrue = healthyGeoRows.filter((r) => r.ipv4.answers.length > 0 && r.ipv4.adBit);
  const v4AdFalse = healthyGeoRows.filter((r) => r.ipv4.answers.length > 0 && !r.ipv4.adBit);
  if (v4AdTrue.length > 0 && v4AdFalse.length > 0) {
    ecsFindings.push({
      id: `ecs-regional-ad-divergence-${normTarget}`,
      severity: 'warning',
      code: 'ECS_REGIONAL_AD_DIVERGENCE',
      title: `Regional DNSSEC AD-bit divergence across ECS subnets for ${dispTarget}`,
      detail: `Authenticated Data (AD=1) was verified in [${v4AdTrue.map((r) => r.regionLabel).join(', ')}], whereas [${v4AdFalse.map((r) => r.regionLabel).join(', ')}] resolved unsigned (AD=0) — typically caused by regional CNAME steering into an unsigned CDN zone.`,
      rfc: 'RFC 4035 / RFC 7871',
    });
  }

  // 7. Regional BGP RPKI ROA invalid check
  const rpkiInvalidDetails: string[] = [];
  for (const r of rows) {
    for (const rv of r.rpkiValidations ?? []) {
      if (rv.status === 'invalid-asn' || rv.status === 'invalid-length') {
        const item = `${r.regionLabel}: AS${rv.asn} ${rv.prefix} (${rv.status})`;
        if (!rpkiInvalidDetails.includes(item)) rpkiInvalidDetails.push(item);
      }
    }
  }
  if (rpkiInvalidDetails.length > 0) {
    ecsFindings.push({
      id: `ecs-rpki-invalid-${normTarget}`,
      severity: 'error',
      code: 'ECS_RPKI_ROA_INVALID',
      title: `RPKI-invalid BGP route announced for geo-steered edge IP on ${dispTarget}`,
      detail: `One or more regional edge prefixes returned via ECS failed RPKI Route Origin Authorization (RFC 6811): ${rpkiInvalidDetails.join('; ')}.`,
      rfc: 'RFC 6811 / RFC 7871',
    });
  }

  // 8. Informational summary finding when multi-region GeoDNS steering is active
  if (steeringModel === 'geodns-ip' || steeringModel === 'geodns-cname') {
    const scopeInfo = ipv4ScopeRange
      ? `IPv4 SCOPE /${ipv4ScopeRange.min}${ipv4ScopeRange.max !== ipv4ScopeRange.min ? `–/${ipv4ScopeRange.max}` : ''}`
      : 'no ECS SCOPE echoed';
    ecsFindings.push({
      id: `ecs-geodns-steering-${normTarget}`,
      severity: 'info',
      code: 'ECS_GEODNS_STEERING_DETECTED',
      title: `Active GeoDNS ${steeringModel === 'geodns-cname' ? 'CNAME' : 'IP'} traffic steering across ${Math.max(v4Pools.size, v6Pools.size, cnameTargets.size)} regional pools`,
      detail: `RFC 7871 ECS probes via ${ecsEndpointLabel} observed ${v4Pools.size} distinct IPv4 pool(s)${v6Pools.size > 0 ? `, ${v6Pools.size} IPv6 pool(s)` : ''}${cnameTargets.size > 1 ? `, and ${cnameTargets.size} regional CNAME targets` : ''} (${scopeInfo}).`,
      rfc: 'RFC 7871',
    });
  }

  let summary = '';
  if (steeringModel === 'partial-or-error') {
    summary = `Regional ECS divergence/errors detected across [${anomalyRegions.join(', ')}] via ${ecsEndpointLabel}.`;
  } else if (steeringModel === 'geodns-cname') {
    summary = `GeoDNS CNAME steering active: ${cnameTargets.size} regional CNAME targets and ${v4Pools.size} IPv4 / ${v6Pools.size} IPv6 edge pools steered across 6 continents via ${ecsEndpointLabel}.`;
  } else if (steeringModel === 'geodns-ip') {
    const v4ScopeText = ipv4ScopeRange
      ? ` (IPv4 SCOPE /${ipv4ScopeRange.min}${ipv4ScopeRange.max !== ipv4ScopeRange.min ? `–/${ipv4ScopeRange.max}` : ''})`
      : '';
    summary = `GeoDNS IP steering active: ${v4Pools.size} distinct IPv4 pool${v4Pools.size === 1 ? '' : 's'} and ${v6Pools.size} IPv6 pool${v6Pools.size === 1 ? '' : 's'} across 6 regional ECS prefixes${v4ScopeText}.`;
  } else if (v4Pools.size === 0 && v6Pools.size === 0) {
    summary = `No A/AAAA addresses returned across regional ECS probes via ${ecsEndpointLabel}.`;
  } else {
    const scopeZero =
      (!ipv4ScopeRange || ipv4ScopeRange.max === 0) && (!ipv6ScopeRange || ipv6ScopeRange.max === 0);
    summary = `Uniform Anycast / global answers across all 6 regional ECS prefixes (${scopeZero ? 'SCOPE=/0 global cache' : 'identical IP pool'}) via ${ecsEndpointLabel}.`;
  }

  return {
    ecsGeo: {
      ecsEndpoint,
      ecsEndpointLabel,
      ecsSupportedByResolver,
      regions: rows,
      steeringModel,
      uniqueIpv4PoolCount: v4Pools.size,
      uniqueIpv6PoolCount: v6Pools.size,
      uniqueCnameTargets: Array.from(cnameTargets),
      ipv4ScopeRange,
      ipv6ScopeRange,
      optOutHonored,
      cacheBustingRegions,
      anomalyRegions,
      summary,
    },
    ecsFindings,
  };
}

/**
 * Interactive single-subnet RFC 7871 ECS probe used by the custom CIDR tester in `ConsensusView`.
 */
export async function probeCustomEcsSubnet(params: {
  targetName: string;
  subnetInput: string;
  qtype: 'A' | 'AAAA';
  dohEndpoint: string;
  fetchImpl?: typeof fetch;
}): Promise<{
  probe: EcsAddressProbeResult;
  canonicalSubnet: string;
  log: DohQueryLog;
}> {
  const ecsOpt = parseEcsSubnetInput(params.subnetInput);
  if (!ecsOpt) {
    throw new Error(
      `Invalid ECS subnet "${params.subnetInput}". Enter an IPv4 CIDR (e.g. 71.252.0.0/24 or 0.0.0.0/0) or IPv6 CIDR (e.g. 2601:140:4000::/56 or ::/0).`
    );
  }
  const canonicalSubnet = formatEcsQuerySubnet(ecsOpt);
  const normTarget = normalizeFqdn(params.targetName);
  const session = new DohSession({
    endpoint: params.dohEndpoint,
    timeoutMs: 6000,
    fetchImpl: params.fetchImpl,
  });
  const rrtype = params.qtype === 'A' ? RR_TYPES.A : RR_TYPES.AAAA;
  const log = await session.query(normTarget, rrtype, {
    cd: false,
    doBit: true,
    ecs: ecsOpt,
    purpose: `Custom ECS probe (${canonicalSubnet} ${params.qtype})`,
  });
  const probe = extractEcsAddressProbe(normTarget, params.qtype, canonicalSubnet, log);
  return { probe, canonicalSubnet, log };
}
