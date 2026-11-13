import { RR_TYPES } from './constants';
import {
  displayFqdn,
  getDomainHierarchy,
  isSubdomainOrEqual,
  normalizeFqdn,
} from './encoding';
import {
  classifyIpAddress,
  formatCanonicalIpv6,
  ipToCymruOriginQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseIpv6Groups,
} from './ipUtils';
import type {
  AuditFinding,
  BgpAsnOrganization,
  CnameEdge,
  Dns64Detection,
  Dns64PrefixKind,
  Dns64RecordContext,
  DohQueryLog,
  Ipv6DelegationHopAudit,
  Ipv6HopStatus,
  Ipv6LeafParityAudit,
  Ipv6ReadinessAudit,
  MailAnalysisResult,
  NameserverEntry,
  WebAnalysisResult,
  ZoneAnalysis,
} from './types';

const POLICY_SINKHOLE_EDES = new Set([4, 15, 16, 17, 18]);

export interface DetectedDns64Info {
  canonicalIp: string;
  prefixKind: Dns64PrefixKind;
  prefixCidr: '64:ff9b::/96' | '64:ff9b:1::/48';
  embeddedIpv4?: string;
}

/**
 * Detects RFC 6052 Well-Known Prefix (`64:ff9b::/96`) and RFC 8215 Local-Use NAT64 (`64:ff9b:1::/48`)
 * DNS64/NAT64-synthesized IPv6 addresses and extracts the embedded IPv4 address when encoded in `/96` or `/64`.
 */
export function detectDns64Address(rawIp: string): DetectedDns64Info | null {
  const groups = parseIpv6Groups(rawIp.trim());
  if (!groups) return null;

  if (groups[0] !== 0x0064 || groups[1] !== 0xff9b) {
    return null;
  }

  const canonicalIp = formatCanonicalIpv6(groups);

  // RFC 6052 §2.1 Well-Known Prefix: 64:ff9b::/96 (or misconfigured non-/96 under 64:ff9b:0::/48)
  if (groups[2] === 0x0000) {
    let embeddedIpv4: string | undefined;
    if (groups[3] === 0 && groups[4] === 0 && groups[5] === 0) {
      embeddedIpv4 = `${(groups[6] >> 8) & 0xff}.${groups[6] & 0xff}.${(groups[7] >> 8) & 0xff}.${groups[7] & 0xff}`;
    } else if (((groups[4] >> 8) & 0xff) === 0 && (groups[6] & 0xff) === 0 && groups[7] === 0) {
      // RFC 6052 §2.2 /64 layout (bits 64..71 u-octet = 0, bits 72..103 = IPv4)
      embeddedIpv4 = `${groups[4] & 0xff}.${(groups[5] >> 8) & 0xff}.${groups[5] & 0xff}.${(groups[6] >> 8) & 0xff}`;
    }
    return {
      canonicalIp,
      prefixKind: 'well-known-64:ff9b::/96',
      prefixCidr: '64:ff9b::/96',
      ...(embeddedIpv4 ? { embeddedIpv4 } : {}),
    };
  }

  // RFC 8215 Local-Use IPv4/IPv6 Translation Prefix: 64:ff9b:1::/48
  if (groups[2] === 0x0001) {
    let embeddedIpv4: string | undefined;
    if (groups[3] === 0 && groups[4] === 0 && groups[5] === 0) {
      embeddedIpv4 = `${(groups[6] >> 8) & 0xff}.${groups[6] & 0xff}.${(groups[7] >> 8) & 0xff}.${groups[7] & 0xff}`;
    } else if (((groups[4] >> 8) & 0xff) === 0 && (groups[6] & 0xff) === 0 && groups[7] === 0) {
      embeddedIpv4 = `${groups[4] & 0xff}.${(groups[5] >> 8) & 0xff}.${groups[5] & 0xff}.${(groups[6] >> 8) & 0xff}`;
    }
    return {
      canonicalIp,
      prefixKind: 'local-use-64:ff9b:1::/48',
      prefixCidr: '64:ff9b:1::/48',
      ...(embeddedIpv4 ? { embeddedIpv4 } : {}),
    };
  }

  return null;
}

interface NsIpRecordSummary {
  ipv4: string[];
  ipv6: string[];
  probedA: boolean;
  probedAAAA: boolean;
  policyBlockedA?: boolean;
  policyBlockedAAAA?: boolean;
}

function buildNsIpLookupMap(queries: DohQueryLog[]): Map<string, NsIpRecordSummary> {
  const map = new Map<string, NsIpRecordSummary>();
  for (const log of queries) {
    if (!log.purpose.startsWith('Nameserver IP')) continue;
    const qnameNorm = normalizeFqdn(log.qname);
    const entry = map.get(qnameNorm) ?? {
      ipv4: [],
      ipv6: [],
      probedA: false,
      probedAAAA: false,
    };
    const isPolicyBlocked =
      log.packet.edns?.ede.some((e) => POLICY_SINKHOLE_EDES.has(e.infoCode)) ?? false;

    if (log.qtype === RR_TYPES.A) {
      entry.probedA = true;
      if (isPolicyBlocked) entry.policyBlockedA = true;
    } else if (log.qtype === RR_TYPES.AAAA) {
      entry.probedAAAA = true;
      if (isPolicyBlocked) entry.policyBlockedAAAA = true;
    }

    let owner = qnameNorm;
    const visited = new Set<string>([owner]);
    for (let hop = 0; hop < 6; hop++) {
      const cnameAns = log.packet.answers.find(
        (r) => normalizeFqdn(r.name) === owner && r.type === RR_TYPES.CNAME
      );
      if (!cnameAns || cnameAns.parsed.kind !== 'GENERIC' || !cnameAns.parsed.target) break;
      const next = normalizeFqdn(cnameAns.parsed.target);
      if (visited.has(next)) break;
      visited.add(next);
      owner = next;
    }

    for (const ans of log.packet.answers) {
      if (normalizeFqdn(ans.name) === owner && ans.type === RR_TYPES.A) {
        const ip = ans.rdataText.trim();
        if (ip && !entry.ipv4.includes(ip)) entry.ipv4.push(ip);
      } else if (normalizeFqdn(ans.name) === owner && ans.type === RR_TYPES.AAAA) {
        const ip = ans.rdataText.trim();
        if (ip && !entry.ipv6.includes(ip)) entry.ipv6.push(ip);
      }
    }
    map.set(qnameNorm, entry);
  }
  return map;
}

function buildCymruIpAsnLookup(queries: DohQueryLog[]): {
  hasAnyCymruLogs: boolean;
  lookupIpAsns: (ip: string) => BgpAsnOrganization[];
} {
  const asnNameMap = new Map<number, { asName?: string; country?: string; rir?: string }>();
  const originTxtMap = new Map<string, string[]>();

  for (const log of queries) {
    if (log.qtype !== RR_TYPES.TXT) continue;
    const qn = normalizeFqdn(log.qname);
    if (qn.endsWith('.asn.cymru.com.') && qn.startsWith('as')) {
      const numPart = Number.parseInt(qn.slice(2, qn.indexOf('.')), 10);
      if (!Number.isNaN(numPart)) {
        const txts = log.packet.answers
          .filter((a) => a.type === RR_TYPES.TXT && a.parsed.kind === 'TXT')
          .map((a) => (a.parsed as { joinedText: string }).joinedText);
        const parsed = parseCymruAsnTxt(txts);
        if (parsed) asnNameMap.set(numPart, parsed);
      }
    } else if (
      qn.endsWith('.origin.asn.cymru.com.') ||
      qn.endsWith('.origin6.asn.cymru.com.')
    ) {
      const txts = log.packet.answers
        .filter((a) => a.type === RR_TYPES.TXT && a.parsed.kind === 'TXT')
        .map((a) => (a.parsed as { joinedText: string }).joinedText);
      if (txts.length > 0) {
        originTxtMap.set(qn, txts);
      }
    }
  }

  return {
    hasAnyCymruLogs: originTxtMap.size > 0,
    lookupIpAsns: (ip: string): BgpAsnOrganization[] => {
      const originQ = ipToCymruOriginQname(ip);
      if (!originQ) return [];
      const txts = originTxtMap.get(originQ);
      if (!txts) return [];
      const parsedOrigins = parseCymruOriginTxt(txts);
      const asns = new Map<number, BgpAsnOrganization>();
      for (const o of parsedOrigins) {
        for (const asn of o.asns) {
          if (!asns.has(asn)) {
            const meta = asnNameMap.get(asn);
            asns.set(asn, {
              asn,
              asName: meta?.asName,
              country: meta?.country ?? o.country,
              rir: meta?.rir ?? o.rir,
              allocatedDate: o.allocatedDate,
            });
          }
        }
      }
      return Array.from(asns.values());
    },
  };
}

function recordDns64Detection(
  detections: Dns64Detection[],
  seenKeys: Set<string>,
  rawIp: string,
  ownerName: string,
  recordContext: Dns64RecordContext
): Dns64Detection | null {
  const info = detectDns64Address(rawIp);
  if (!info) return null;
  const normOwner = normalizeFqdn(ownerName);
  const key = `${recordContext}|${normOwner}|${info.canonicalIp}`;
  const det: Dns64Detection = {
    ip: rawIp.trim(),
    canonicalIp: info.canonicalIp,
    prefixKind: info.prefixKind,
    prefixCidr: info.prefixCidr,
    ...(info.embeddedIpv4 ? { embeddedIpv4: info.embeddedIpv4 } : {}),
    ownerName: normOwner,
    recordContext,
  };
  if (!seenKeys.has(key)) {
    seenKeys.add(key);
    detections.push(det);
  }
  return det;
}

function evaluateNameserverHop(params: {
  zoneName: string;
  parentZone: string | null;
  depth: number;
  role: 'in-chain' | 'cname-chain' | 'oob-ns-zone';
  referencedByZones?: string[];
  nameservers: NameserverEntry[];
  nsIpMap: Map<string, NsIpRecordSummary>;
  cymru: ReturnType<typeof buildCymruIpAsnLookup>;
  dns64Detections: Dns64Detection[];
  dns64SeenKeys: Set<string>;
}): Ipv6DelegationHopAudit {
  const {
    zoneName,
    parentZone,
    depth,
    role,
    referencedByZones,
    nameservers,
    nsIpMap,
    cymru,
    dns64Detections,
    dns64SeenKeys,
  } = params;

  let probedNsCount = 0;
  let ipv4NsCount = 0;
  let ipv6NsCount = 0;
  let dualStackNsCount = 0;
  let inBailiwickNsCount = 0;
  const outOfBailiwickNsHosts: string[] = [];
  const ipv4OnlyHosts: string[] = [];
  const ipv6OnlyHosts: string[] = [];
  const hopDns64Ips: string[] = [];
  const ipv6AsnsMap = new Map<number, BgpAsnOrganization>();
  const overallAsnsMap = new Map<number, BgpAsnOrganization>();

  for (const ns of nameservers) {
    const host = normalizeFqdn(ns.hostname);
    if (zoneName !== '.' && isSubdomainOrEqual(host, zoneName)) {
      inBailiwickNsCount++;
    } else {
      outOfBailiwickNsHosts.push(host);
    }

    const ipLog = nsIpMap.get(host);
    const rawV4 = ns.ipv4.length > 0 ? ns.ipv4 : ipLog?.ipv4 ?? [];
    const rawV6 = ns.ipv6.length > 0 ? ns.ipv6 : ipLog?.ipv6 ?? [];
    const wasProbed =
      Boolean(ipLog && (ipLog.probedA || ipLog.probedAAAA)) ||
      ns.status !== undefined ||
      ns.addressStack !== undefined ||
      rawV4.length > 0 ||
      rawV6.length > 0;

    if (wasProbed) {
      probedNsCount++;
    }

    let nativeV4Count = 0;
    let nativeV6Count = 0;

    for (const ip of rawV4) {
      if (ipLog?.policyBlockedA && (ip === '0.0.0.0' || ip === '127.0.0.1')) continue;
      if (classifyIpAddress(ip, 4).isPublic) {
        nativeV4Count++;
        for (const a of cymru.lookupIpAsns(ip)) {
          if (!overallAsnsMap.has(a.asn)) overallAsnsMap.set(a.asn, a);
        }
      }
    }

    for (const ip of rawV6) {
      if (ipLog?.policyBlockedAAAA && (ip === '::' || ip === '::1')) continue;
      const dns64 = recordDns64Detection(dns64Detections, dns64SeenKeys, ip, host, 'ns-aaaa');
      if (dns64) {
        if (!hopDns64Ips.includes(dns64.canonicalIp)) {
          hopDns64Ips.push(dns64.canonicalIp);
        }
        continue;
      }
      if (classifyIpAddress(ip, 6).isPublic) {
        nativeV6Count++;
        for (const a of cymru.lookupIpAsns(ip)) {
          if (!ipv6AsnsMap.has(a.asn)) ipv6AsnsMap.set(a.asn, a);
          if (!overallAsnsMap.has(a.asn)) overallAsnsMap.set(a.asn, a);
        }
      }
    }

    // Support synthetic ZoneAnalysis fixtures where addressStack / asns are set without raw IPs or Cymru logs
    if (nativeV4Count === 0 && nativeV6Count === 0 && rawV4.length === 0 && rawV6.length === 0) {
      if (ns.addressStack === 'dual-stack') {
        nativeV4Count = 1;
        nativeV6Count = 1;
      } else if (ns.addressStack === 'ipv4-only') {
        nativeV4Count = 1;
      } else if (ns.addressStack === 'ipv6-only') {
        nativeV6Count = 1;
      }
    }

    if (!cymru.hasAnyCymruLogs && ns.asns) {
      for (const a of ns.asns) {
        if (!overallAsnsMap.has(a.asn)) overallAsnsMap.set(a.asn, a);
        if (nativeV6Count > 0 && !ipv6AsnsMap.has(a.asn)) {
          ipv6AsnsMap.set(a.asn, a);
        }
      }
    } else if (ns.asns) {
      for (const a of ns.asns) {
        if (!overallAsnsMap.has(a.asn)) overallAsnsMap.set(a.asn, a);
      }
    }

    if (nativeV4Count > 0 && nativeV6Count > 0) {
      ipv4NsCount++;
      ipv6NsCount++;
      dualStackNsCount++;
    } else if (nativeV4Count > 0) {
      ipv4NsCount++;
      ipv4OnlyHosts.push(host);
    } else if (nativeV6Count > 0) {
      ipv6NsCount++;
      ipv6OnlyHosts.push(host);
    }
  }

  const ipv6Asns = Array.from(ipv6AsnsMap.values());
  const overallAsns = Array.from(overallAsnsMap.values());
  const singleIpv6Asn = ipv6NsCount >= 2 && ipv6Asns.length === 1;

  let status: Ipv6HopStatus = 'unprobed';
  let badgeLabel = 'Unprobed';
  if (probedNsCount === 0) {
    status = 'unprobed';
    badgeLabel = 'Unprobed';
  } else if (ipv6NsCount === 0) {
    status = 'ipv4-only-bottleneck';
    badgeLabel = 'IPv4-Only Bottleneck';
  } else if (ipv6NsCount === 1) {
    status = 'ipv6-single-ns';
    badgeLabel = 'Single-v6 NS';
  } else if (ipv4NsCount >= 2) {
    status = 'dual-stack';
    badgeLabel = 'Dual-Stack';
  } else if (ipv4NsCount === 1) {
    status = 'dual-stack-partial-v4';
    badgeLabel = 'Dual-Stack (1v4)';
  } else {
    status = 'ipv6-only';
    badgeLabel = 'IPv6-Only';
  }

  const dispZone = zoneName === '.' ? '. (Root)' : zoneName;
  let summary = '';
  if (status === 'unprobed') {
    summary = `${dispZone}: ${nameservers.length} NS listed (address records not probed in snapshot).`;
  } else if (status === 'ipv4-only-bottleneck') {
    summary = `${dispZone}: 0/${probedNsCount} probed authoritative nameservers publish native IPv6 AAAA (${ipv4NsCount} IPv4) — blocks pure IPv6-only iterative resolution.`;
  } else if (status === 'ipv6-single-ns') {
    summary = `${dispZone}: Only 1/${probedNsCount} probed authoritative nameserver publishes IPv6 AAAA (${ipv4NsCount} IPv4) — single-NS IPv6 SPOF (RFC 2182 / RFC 3901).`;
  } else {
    summary = `${dispZone}: ${ipv6NsCount}/${probedNsCount} IPv6 AAAA and ${ipv4NsCount}/${probedNsCount} IPv4 A authoritative nameservers reachable.`;
  }

  return {
    zoneName,
    parentZone,
    depth,
    role,
    ...(referencedByZones && referencedByZones.length > 0 ? { referencedByZones } : {}),
    totalNsCount: nameservers.length,
    probedNsCount,
    ipv4NsCount,
    ipv6NsCount,
    dualStackNsCount,
    inBailiwickNsCount,
    outOfBailiwickNsHosts,
    ipv4OnlyHosts,
    ipv6OnlyHosts,
    dns64Ips: hopDns64Ips,
    ipv6Asns,
    overallAsns,
    singleIpv6Asn,
    status,
    badgeLabel,
    summary,
  };
}

function isPrimaryTargetLog(q: DohQueryLog): boolean {
  if (q.ecsSubnet) return false;
  const p = q.purpose;
  if (
    p.startsWith('ECS ') ||
    p.startsWith('Consensus probe') ||
    p.startsWith('Watch probe') ||
    p.startsWith('Wildcard probe') ||
    p.startsWith('Nameserver IP') ||
    p.startsWith('OOB NS zone') ||
    p.startsWith('BGP ASN lookup') ||
    p.startsWith('DNSBL ') ||
    p.startsWith('PSL ') ||
    p.startsWith('Reverse FCrDNS') ||
    p.startsWith('MX rDNS lookup')
  ) {
    return false;
  }
  return true;
}

function resolveTerminalOwner(
  targetName: string,
  cnameEdges: CnameEdge[],
  queries: DohQueryLog[]
): string {
  let cur = normalizeFqdn(targetName);
  const seen = new Set<string>([cur]);

  for (let hop = 0; hop < 8; hop++) {
    const edge = cnameEdges.find((e) => normalizeFqdn(e.fromName) === cur);
    if (edge) {
      const next = normalizeFqdn(edge.toName);
      if (seen.has(next)) break;
      seen.add(next);
      cur = next;
      continue;
    }
    const cnameLog = queries.find(
      (q) =>
        isPrimaryTargetLog(q) &&
        q.packet.answers.some(
          (r) => normalizeFqdn(r.name) === cur && r.type === RR_TYPES.CNAME
        )
    );
    const cnameRec = cnameLog?.packet.answers.find(
      (r) => normalizeFqdn(r.name) === cur && r.type === RR_TYPES.CNAME
    );
    if (cnameRec && cnameRec.parsed.kind === 'GENERIC' && cnameRec.parsed.target) {
      const next = normalizeFqdn(cnameRec.parsed.target);
      if (seen.has(next)) break;
      seen.add(next);
      cur = next;
    } else {
      break;
    }
  }
  return cur;
}

function evaluateLeafIpv6Parity(params: {
  targetName: string;
  queriedIp?: string;
  queriedEmail?: string;
  cnameEdges: CnameEdge[];
  queries: DohQueryLog[];
  mailAnalysis?: MailAnalysisResult;
  webAnalysis?: WebAnalysisResult;
  dns64Detections: Dns64Detection[];
  dns64SeenKeys: Set<string>;
}): Ipv6LeafParityAudit {
  const {
    targetName,
    queriedIp,
    queriedEmail,
    cnameEdges,
    queries,
    mailAnalysis,
    webAnalysis,
    dns64Detections,
    dns64SeenKeys,
  } = params;

  const normTarget = normalizeFqdn(targetName);
  const hierLen = getDomainHierarchy(normTarget).length;
  const isSpecialTarget =
    normTarget === '.' ||
    hierLen <= 2 ||
    normTarget.endsWith('.in-addr.arpa.') ||
    normTarget.endsWith('.ip6.arpa.') ||
    Boolean(queriedIp) ||
    Boolean(queriedEmail) ||
    normTarget.includes('._openpgpkey.') ||
    normTarget.includes('._smimea.');

  if (isSpecialTarget) {
    return {
      evaluated: false,
      effectiveOwner: normTarget,
      aQueried: false,
      aaaaQueried: false,
      nativeIpv4Addresses: [],
      nativeIpv6Addresses: [],
      dns64TargetIps: [],
      httpsEvaluated: false,
      httpsIpv4Hints: [],
      httpsNativeIpv6Hints: [],
      httpsDns64Hints: [],
      mxEvaluated: false,
      mxTotalCount: 0,
      mxProbedCount: 0,
      mxIpv6ReadyCount: 0,
      mxIpv4OnlyExchanges: [],
      status: 'not-applicable',
      summary: 'Leaf endpoint Web/Mail IPv6 parity is not applicable to zone-root/reverse/DANE QNAME traces.',
    };
  }

  const effectiveOwner = resolveTerminalOwner(normTarget, cnameEdges, queries);
  const primaryLogs = queries.filter(isPrimaryTargetLog);

  const aLogs = primaryLogs.filter(
    (q) =>
      q.qtype === RR_TYPES.A &&
      (normalizeFqdn(q.qname) === effectiveOwner || normalizeFqdn(q.qname) === normTarget)
  );
  const aaaaLogs = primaryLogs.filter(
    (q) =>
      q.qtype === RR_TYPES.AAAA &&
      (normalizeFqdn(q.qname) === effectiveOwner || normalizeFqdn(q.qname) === normTarget)
  );

  const aQueried = aLogs.length > 0 || Boolean(webAnalysis);
  const aaaaQueried = aaaaLogs.length > 0 || Boolean(webAnalysis);

  const rawV4Set = new Set<string>();
  for (const l of aLogs) {
    for (const ans of l.packet.answers) {
      if (
        ans.type === RR_TYPES.A &&
        (normalizeFqdn(ans.name) === effectiveOwner || normalizeFqdn(ans.name) === normTarget)
      ) {
        const ip = ans.rdataText.trim();
        if (ip) rawV4Set.add(ip);
      }
    }
  }
  if (rawV4Set.size === 0 && webAnalysis) {
    for (const ip of webAnalysis.ipv4Addresses) rawV4Set.add(ip);
  }

  const rawV6Set = new Set<string>();
  for (const l of aaaaLogs) {
    for (const ans of l.packet.answers) {
      if (
        ans.type === RR_TYPES.AAAA &&
        (normalizeFqdn(ans.name) === effectiveOwner || normalizeFqdn(ans.name) === normTarget)
      ) {
        const ip = ans.rdataText.trim();
        if (ip) rawV6Set.add(ip);
      }
    }
  }
  if (rawV6Set.size === 0 && webAnalysis) {
    for (const ip of webAnalysis.ipv6Addresses) rawV6Set.add(ip);
  }

  const nativeIpv4Addresses: string[] = [];
  for (const ip of rawV4Set) {
    if (classifyIpAddress(ip, 4).isPublic) {
      nativeIpv4Addresses.push(ip);
    }
  }

  const nativeIpv6Addresses: string[] = [];
  const dns64TargetIps: Dns64Detection[] = [];
  for (const ip of rawV6Set) {
    const dns64 = recordDns64Detection(
      dns64Detections,
      dns64SeenKeys,
      ip,
      effectiveOwner,
      'target-aaaa'
    );
    if (dns64) {
      dns64TargetIps.push(dns64);
      continue;
    }
    if (classifyIpAddress(ip, 6).isPublic) {
      nativeIpv6Addresses.push(ip);
    }
  }

  // Evaluate HTTPS (TYPE65) / SVCB (TYPE64) ipv4hint & ipv6hint parity
  const httpsLogs = primaryLogs.filter(
    (q) =>
      (q.qtype === RR_TYPES.HTTPS || q.qtype === RR_TYPES.SVCB) &&
      (normalizeFqdn(q.qname) === effectiveOwner || normalizeFqdn(q.qname) === normTarget)
  );
  const httpsIpv4HintsSet = new Set<string>();
  const httpsRawV6HintsSet = new Set<string>();
  let hasServiceModeRecord = false;

  for (const l of httpsLogs) {
    for (const ans of l.packet.answers) {
      if (
        (ans.type === RR_TYPES.HTTPS || ans.type === RR_TYPES.SVCB) &&
        ans.parsed.kind === 'SVCB' &&
        !ans.parsed.isAliasMode
      ) {
        hasServiceModeRecord = true;
        for (const param of ans.parsed.params) {
          for (const v4h of param.ipv4Hints ?? []) httpsIpv4HintsSet.add(v4h.trim());
          for (const v6h of param.ipv6Hints ?? []) httpsRawV6HintsSet.add(v6h.trim());
        }
      }
    }
  }
  if (!hasServiceModeRecord && webAnalysis) {
    for (const rec of [...webAnalysis.httpsRecords, ...webAnalysis.svcbRecords]) {
      if (!rec.isAliasMode) {
        hasServiceModeRecord = true;
        for (const v4h of rec.ipv4Hints) httpsIpv4HintsSet.add(v4h.trim());
        for (const v6h of rec.ipv6Hints) httpsRawV6HintsSet.add(v6h.trim());
      }
    }
  }

  const httpsIpv4Hints = Array.from(httpsIpv4HintsSet).filter(Boolean);
  const httpsNativeIpv6Hints: string[] = [];
  const httpsDns64Hints: Dns64Detection[] = [];
  for (const v6h of httpsRawV6HintsSet) {
    if (!v6h) continue;
    const dns64 = recordDns64Detection(
      dns64Detections,
      dns64SeenKeys,
      v6h,
      effectiveOwner,
      'https-ipv6hint'
    );
    if (dns64) {
      httpsDns64Hints.push(dns64);
    } else if (classifyIpAddress(v6h, 6).isPublic) {
      httpsNativeIpv6Hints.push(v6h);
    }
  }

  // Evaluate MX host AAAA reachability parity
  const mxExchanges = new Set<string>();
  const mxLogs = primaryLogs.filter(
    (q) =>
      q.qtype === RR_TYPES.MX &&
      (normalizeFqdn(q.qname) === normTarget || normalizeFqdn(q.qname) === effectiveOwner)
  );
  for (const l of mxLogs) {
    for (const ans of l.packet.answers) {
      if (ans.type === RR_TYPES.MX && ans.parsed.kind === 'MX') {
        const exch = normalizeFqdn(ans.parsed.exchange);
        if (exch && exch !== '.') {
          mxExchanges.add(exch);
        }
      }
    }
  }
  if (mxExchanges.size === 0 && mailAnalysis) {
    for (const mh of mailAnalysis.mxHosts) {
      if (!mh.isNullMx && mh.exchange !== '.') {
        mxExchanges.add(normalizeFqdn(mh.exchange));
      }
    }
  }

  let mxProbedCount = 0;
  let mxIpv6ReadyCount = 0;
  const mxIpv4OnlyExchanges: string[] = [];

  for (const exch of mxExchanges) {
    const mxTerm = resolveTerminalOwner(exch, cnameEdges, queries);
    const mxALogs = primaryLogs.filter(
      (q) =>
        q.qtype === RR_TYPES.A &&
        (normalizeFqdn(q.qname) === mxTerm || normalizeFqdn(q.qname) === exch)
    );
    const mxAaaaLogs = primaryLogs.filter(
      (q) =>
        q.qtype === RR_TYPES.AAAA &&
        (normalizeFqdn(q.qname) === mxTerm || normalizeFqdn(q.qname) === exch)
    );
    const mailHostEntry = mailAnalysis?.mxHosts.find(
      (m) => normalizeFqdn(m.exchange) === exch
    );

    const probedThisMx = mxAaaaLogs.length > 0 || Boolean(mailHostEntry);
    if (!probedThisMx) continue;
    mxProbedCount++;

    let hasV4 = false;
    let hasNativeV6 = false;

    for (const l of mxALogs) {
      for (const ans of l.packet.answers) {
        if (ans.type === RR_TYPES.A && classifyIpAddress(ans.rdataText.trim(), 4).isPublic) {
          hasV4 = true;
        }
      }
    }
    for (const l of mxAaaaLogs) {
      for (const ans of l.packet.answers) {
        if (ans.type === RR_TYPES.AAAA) {
          const ip = ans.rdataText.trim();
          const dns64 = recordDns64Detection(dns64Detections, dns64SeenKeys, ip, exch, 'mx-aaaa');
          if (!dns64 && classifyIpAddress(ip, 6).isPublic) {
            hasNativeV6 = true;
          }
        }
      }
    }

    if (!hasV4 && !hasNativeV6 && mailHostEntry) {
      for (const addr of mailHostEntry.addresses) {
        if (addr.family === 4 && addr.isPublic) hasV4 = true;
        if (addr.family === 6) {
          const dns64 = recordDns64Detection(
            dns64Detections,
            dns64SeenKeys,
            addr.ip,
            exch,
            'mx-aaaa'
          );
          if (!dns64 && addr.isPublic) hasNativeV6 = true;
        }
      }
    }

    if (hasNativeV6) {
      mxIpv6ReadyCount++;
    } else if (hasV4) {
      mxIpv4OnlyExchanges.push(exch);
    }
  }

  const evaluated = aQueried || aaaaQueried || hasServiceModeRecord || mxProbedCount > 0;
  let status: Ipv6LeafParityAudit['status'] = 'no-address-records';
  if (!evaluated) {
    status = 'not-applicable';
  } else if (dns64TargetIps.length > 0 && nativeIpv6Addresses.length === 0) {
    status = 'dns64-only';
  } else if (nativeIpv6Addresses.length > 0 && nativeIpv4Addresses.length > 0) {
    const hasHttpsGap = httpsIpv4Hints.length > 0 && httpsNativeIpv6Hints.length === 0;
    const hasMxGap = mxProbedCount > 0 && mxIpv6ReadyCount === 0 && mxIpv4OnlyExchanges.length > 0;
    status = hasHttpsGap || hasMxGap ? 'partial' : 'dual-stack';
  } else if (nativeIpv6Addresses.length > 0 && nativeIpv4Addresses.length === 0) {
    status = 'ipv6-only';
  } else if (nativeIpv4Addresses.length > 0 && aaaaQueried && nativeIpv6Addresses.length === 0) {
    status = 'ipv4-only';
  } else if (mxProbedCount > 0) {
    status =
      mxIpv6ReadyCount === mxProbedCount
        ? 'dual-stack'
        : mxIpv6ReadyCount > 0
          ? 'partial'
          : 'ipv4-only';
  } else {
    status = 'no-address-records';
  }

  const parts: string[] = [];
  if (aQueried || aaaaQueried) {
    parts.push(
      `Web A/AAAA: ${nativeIpv4Addresses.length} native IPv4, ${nativeIpv6Addresses.length} native IPv6${dns64TargetIps.length > 0 ? ` (${dns64TargetIps.length} DNS64 synthesized)` : ''}`
    );
  }
  if (hasServiceModeRecord && (httpsIpv4Hints.length > 0 || httpsNativeIpv6Hints.length > 0 || httpsDns64Hints.length > 0)) {
    parts.push(
      `HTTPS hints: ${httpsIpv4Hints.length} ipv4hint, ${httpsNativeIpv6Hints.length} ipv6hint`
    );
  }
  if (mxProbedCount > 0) {
    parts.push(`Mail MX: ${mxIpv6ReadyCount}/${mxProbedCount} IPv6-capable`);
  }

  return {
    evaluated,
    effectiveOwner,
    aQueried,
    aaaaQueried,
    nativeIpv4Addresses,
    nativeIpv6Addresses,
    dns64TargetIps,
    httpsEvaluated: hasServiceModeRecord,
    httpsIpv4Hints,
    httpsNativeIpv6Hints,
    httpsDns64Hints,
    mxEvaluated: mxProbedCount > 0,
    mxTotalCount: mxExchanges.size,
    mxProbedCount,
    mxIpv6ReadyCount,
    mxIpv4OnlyExchanges,
    status,
    summary: parts.length > 0 ? `${parts.join(' · ')}.` : `No A/AAAA/HTTPS/MX address records evaluated for ${displayFqdn(normTarget)}.`,
  };
}

export function evaluateIpv6ReadinessAudit(params: {
  targetName: string;
  queriedIp?: string;
  queriedEmail?: string;
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  queries: DohQueryLog[];
  mailAnalysis?: MailAnalysisResult;
  webAnalysis?: WebAnalysisResult;
}): {
  audit: Ipv6ReadinessAudit;
  findings: AuditFinding[];
} {
  const {
    targetName,
    queriedIp,
    queriedEmail,
    zones,
    cnameEdges,
    queries,
    mailAnalysis,
    webAnalysis,
  } = params;

  const normTarget = normalizeFqdn(targetName);
  const nsIpMap = buildNsIpLookupMap(queries);
  const cymru = buildCymruIpAsnLookup(queries);
  const dns64Detections: Dns64Detection[] = [];
  const dns64SeenKeys = new Set<string>();
  const findings: AuditFinding[] = [];

  // 1. Evaluate all in-chain & CNAME-branch zones in snapshot.zones
  const hops: Ipv6DelegationHopAudit[] = zones.map((z) => {
    const isDirectTargetChain = isSubdomainOrEqual(normTarget, z.zoneName);
    return evaluateNameserverHop({
      zoneName: z.zoneName,
      parentZone: z.parentZone,
      depth: z.depth,
      role: isDirectTargetChain ? 'in-chain' : 'cname-chain',
      nameservers: z.nameservers,
      nsIpMap,
      cymru,
      dns64Detections,
      dns64SeenKeys,
    });
  });

  // 2. Reconstruct Out-of-Bailiwick (OOB) NS provider zones from auxiliary `OOB NS zone NS` logs
  const oobNsZones: Ipv6DelegationHopAudit[] = [];
  const existingZoneSet = new Set(zones.map((z) => normalizeFqdn(z.zoneName)));
  const seenOobZones = new Set<string>();

  for (const log of queries) {
    if (!log.purpose.startsWith('OOB NS zone NS') || log.qtype !== RR_TYPES.NS) continue;
    const oobZone = normalizeFqdn(log.qname);
    if (existingZoneSet.has(oobZone) || seenOobZones.has(oobZone)) continue;
    seenOobZones.add(oobZone);

    const oobNsHosts: string[] = [];
    for (const r of [...log.packet.answers, ...log.packet.authorities]) {
      if (
        normalizeFqdn(r.name) === oobZone &&
        r.type === RR_TYPES.NS &&
        r.parsed.kind === 'GENERIC' &&
        r.parsed.target
      ) {
        const h = normalizeFqdn(r.parsed.target);
        if (!oobNsHosts.includes(h)) oobNsHosts.push(h);
      }
    }
    if (oobNsHosts.length === 0) continue;

    const referencedByZones = zones
      .filter((z) =>
        z.nameservers.some((ns) => isSubdomainOrEqual(normalizeFqdn(ns.hostname), oobZone))
      )
      .map((z) => z.zoneName);

    const oobEntries: NameserverEntry[] = oobNsHosts.map((h) => {
      const ips = nsIpMap.get(h);
      return {
        hostname: h,
        ipv4: ips?.ipv4 ?? [],
        ipv6: ips?.ipv6 ?? [],
        ...(ips && (ips.probedA || ips.probedAAAA) ? { status: 'ok' as const } : {}),
      };
    });

    const hier = getDomainHierarchy(oobZone);
    oobNsZones.push(
      evaluateNameserverHop({
        zoneName: oobZone,
        parentZone: hier.length >= 2 ? hier[hier.length - 2] : '.',
        depth: Math.max(0, hier.length - 1),
        role: 'oob-ns-zone',
        referencedByZones,
        nameservers: oobEntries,
        nsIpMap,
        cymru,
        dns64Detections,
        dns64SeenKeys,
      })
    );
  }

  // 3. Evaluate leaf target Web (A/AAAA/HTTPS) & Mail (MX) IPv6 parity
  const leaf = evaluateLeafIpv6Parity({
    targetName: normTarget,
    queriedIp,
    queriedEmail,
    cnameEdges,
    queries,
    mailAnalysis,
    webAnalysis,
    dns64Detections,
    dns64SeenKeys,
  });

  // 4. Aggregate end-to-end IPv6-only iterative resolution verdict
  const allAuditedHops = [...hops, ...oobNsZones];
  const probedHops = allAuditedHops.filter((h) => h.probedNsCount > 0);
  const bottleneckZones = probedHops
    .filter((h) => h.status === 'ipv4-only-bottleneck')
    .map((h) => h.zoneName);
  const singleIpv6NsZones = probedHops
    .filter((h) => h.status === 'ipv6-single-ns')
    .map((h) => h.zoneName);

  const resolvableViaIpv6Only = bottleneckZones.length === 0;
  let overallStatus: Ipv6ReadinessAudit['overallStatus'] = 'ipv6-ready';
  if (probedHops.length === 0 && dns64Detections.length === 0) {
    overallStatus = 'unprobed';
  } else if (!resolvableViaIpv6Only) {
    overallStatus = 'broken-ipv6-path';
  } else if (
    dns64Detections.some(
      (d) => d.recordContext === 'target-aaaa' || d.recordContext === 'ns-aaaa'
    ) &&
    leaf.nativeIpv6Addresses.length === 0
  ) {
    overallStatus = 'dns64-synthesized';
  } else if (singleIpv6NsZones.length > 0 || dns64Detections.length > 0) {
    overallStatus = 'degraded-redundancy';
  } else {
    overallStatus = 'ipv6-ready';
  }

  let summary = '';
  if (overallStatus === 'broken-ipv6-path') {
    const names = bottleneckZones
      .map((z) => (z === '.' ? '. (Root)' : displayFqdn(z)))
      .join(', ');
    summary = `End-to-end IPv6-only iterative resolution FAILS at ${names}: zero authoritative nameservers publish native IPv6 AAAA records.`;
  } else if (overallStatus === 'dns64-synthesized') {
    summary = `Synthesized NAT64/DNS64 AAAA records (${dns64Detections[0].prefixCidr}) detected without native IPv6 — pure IPv6-only networks without DNS64 cannot reach ${displayFqdn(normTarget)}.`;
  } else if (overallStatus === 'degraded-redundancy') {
    if (singleIpv6NsZones.length > 0) {
      const names = singleIpv6NsZones
        .map((z) => (z === '.' ? '. (Root)' : displayFqdn(z)))
        .join(', ');
      summary = `IPv6-only iterative resolution succeeds across ${probedHops.length} delegation hop${probedHops.length === 1 ? '' : 's'}, but ${names} has only 1 IPv6-reachable nameserver (single-NS SPOF).`;
    } else {
      summary = `Delegation chain is IPv6-ready across ${probedHops.length} hop${probedHops.length === 1 ? '' : 's'}, with NAT64/DNS64 translation prefix detected on auxiliary records.`;
    }
  } else if (overallStatus === 'unprobed') {
    summary = `Nameserver A/AAAA records were not probed in this snapshot.`;
  } else {
    summary = `End-to-end IPv6-only iterative resolution verified across ${probedHops.length} delegation hop${probedHops.length === 1 ? '' : 's'} (${hops.filter((h) => h.probedNsCount > 0).length} in-chain${oobNsZones.filter((h) => h.probedNsCount > 0).length > 0 ? ` + ${oobNsZones.filter((h) => h.probedNsCount > 0).length} out-of-bailiwick NS zone${oobNsZones.length === 1 ? '' : 's'}` : ''}) with >=2 IPv6 nameservers per hop.`;
  }

  // 5. Emit structured RFC-backed AuditFindings with actionable remediation
  for (const hop of probedHops) {
    const dispZone = hop.zoneName === '.' ? '. (Root Zone)' : displayFqdn(hop.zoneName);
    const isOob = hop.role === 'oob-ns-zone';
    const refText =
      isOob && hop.referencedByZones && hop.referencedByZones.length > 0
        ? ` (authoritative parent zone for out-of-bailiwick NS used by ${hop.referencedByZones.map(displayFqdn).join(', ')})`
        : '';

    if (hop.status === 'ipv4-only-bottleneck') {
      const glueNote =
        hop.inBailiwickNsCount > 0 && hop.parentZone
          ? ` Because ${hop.inBailiwickNsCount} nameserver${hop.inBailiwickNsCount === 1 ? ' is' : 's are'} in-bailiwick under ${dispZone}, you must also register matching IPv6 AAAA glue records at the ${hop.parentZone === '.' ? 'IANA Root' : displayFqdn(hop.parentZone)} parent registry/registrar.`
          : '';
      findings.push({
        id: `warn-ipv6-delegation-gap-${hop.role}-${hop.zoneName}`,
        severity: 'warning',
        code: 'IPV6_NS_DELEGATION_GAP',
        title: isOob
          ? `Out-of-bailiwick NS zone ${dispZone} has zero IPv6 AAAA nameservers — breaks IPv6-only resolution${refText}`
          : `IPv6 delegation bottleneck at ${dispZone}: 0 of ${hop.probedNsCount} authoritative nameservers have AAAA`,
        detail: isOob
          ? `Out-of-bailiwick DNS provider zone ${dispZone}${refText} has ${hop.ipv4NsCount} IPv4-only authoritative nameserver${hop.ipv4NsCount === 1 ? '' : 's'} and 0 native IPv6 AAAA nameservers. Even if child NS hostnames publish AAAA records, a pure IPv6-only iterative resolver cannot contact ${dispZone} to resolve them without NAT64/DNS64.`
          : `At delegation hop ${dispZone}, ${hop.ipv4NsCount} of ${hop.probedNsCount} probed authoritative nameservers resolve over IPv4 while 0 publish native globally routable IPv6 AAAA addresses (${hop.ipv4OnlyHosts.map(displayFqdn).join(', ') || 'none'}). Pure IPv6-only iterative resolvers stall at this zone cut.`,
        remediation: isOob
          ? `Enable dual-stack IPv6 AAAA addresses on at least two authoritative nameservers for ${dispZone}, or delegate ${hop.referencedByZones?.map(displayFqdn).join(', ') || 'the child zone'} to a dual-stack DNS provider whose parent NS zone is reachable over native IPv6.`
          : `Configure globally routable IPv6 (2000::/3) AAAA records on at least two authoritative nameservers for ${dispZone}.${glueNote}`,
        rfc: 'RFC 3901 / BCP 91',
        ...(isOob ? {} : { zone: hop.zoneName }),
      });
    } else if (hop.status === 'ipv6-single-ns') {
      const glueNote =
        hop.inBailiwickNsCount > 0 && hop.parentZone
          ? ` Ensure parent ${hop.parentZone === '.' ? 'Root' : displayFqdn(hop.parentZone)} glue includes AAAA records for at least two nameservers.`
          : '';
      findings.push({
        id: `warn-ipv6-single-ns-${hop.role}-${hop.zoneName}`,
        severity: 'warning',
        code: 'IPV6_SINGLE_NS_ONLY',
        title: isOob
          ? `Out-of-bailiwick NS zone ${dispZone} has only 1 IPv6 AAAA nameserver${refText}`
          : `Single IPv6 authoritative nameserver at ${dispZone} (1 of ${hop.probedNsCount} NS has AAAA)`,
        detail: `Delegation hop ${dispZone}${refText} has only 1 authoritative nameserver reachable over native IPv6 (${hop.ipv4NsCount} over IPv4)${hop.ipv4OnlyHosts.length > 0 ? `, leaving ${hop.ipv4OnlyHosts.map(displayFqdn).join(', ')} IPv4-only` : ''}. Any maintenance or outage on that single IPv6 nameserver causes SERVFAIL for pure IPv6-only iterative resolvers.`,
        remediation: `Publish native IPv6 AAAA records on at least 2 topologically diverse authoritative nameservers for ${dispZone} per RFC 2182 §5 and RFC 3901.${glueNote}`,
        rfc: 'RFC 2182 §5 / RFC 3901',
        ...(isOob ? {} : { zone: hop.zoneName }),
      });
    }

    // Emit IPv6-specific single-ASN concentration when IPv4 is multi-ASN (or on OOB NS zones)
    if (
      hop.singleIpv6Asn &&
      hop.ipv6Asns[0] &&
      (hop.overallAsns.length >= 2 || isOob)
    ) {
      const v6Asn = hop.ipv6Asns[0];
      findings.push({
        id: `info-ipv6-single-asn-${hop.role}-${hop.zoneName}`,
        severity: 'info',
        code: 'IPV6_SINGLE_ASN_CONCENTRATION',
        title: `IPv6 nameservers for ${dispZone} are concentrated in a single BGP ASN (AS${v6Asn.asn})`,
        detail:
          hop.overallAsns.length >= 2
            ? `Although ${dispZone} spans ${hop.overallAsns.length} BGP ASNs overall (${hop.overallAsns.map((a) => `AS${a.asn}`).join(', ')}), 100% of its IPv6 AAAA nameserver addresses route exclusively through AS${v6Asn.asn}${v6Asn.asName ? ` (${v6Asn.asName})` : ''}. An AS${v6Asn.asn} IPv6 routing incident would blackhole all IPv6 authoritative resolution.`
            : `All ${hop.ipv6NsCount} IPv6-reachable nameservers for out-of-bailiwick NS zone ${dispZone}${refText} route through a single autonomous system, AS${v6Asn.asn}${v6Asn.asName ? ` (${v6Asn.asName})` : ''}.`,
        remediation: `Add secondary IPv6-enabled authoritative nameservers in an independent BGP autonomous system so IPv6-only resolvers retain multi-ASN resilience (RFC 2182 §3.1).`,
        rfc: 'RFC 2182 §3.1 / RFC 3901',
        ...(isOob ? {} : { zone: hop.zoneName }),
      });
    }
  }

  // DNS64 / NAT64 synthesized AAAA findings
  if (dns64Detections.length > 0) {
    const formattedList = dns64Detections
      .slice(0, 4)
      .map(
        (d) =>
          `${displayFqdn(d.ownerName)} (${d.recordContext}): ${d.canonicalIp}${d.embeddedIpv4 ? ` → embedded IPv4 ${d.embeddedIpv4}` : ''}`
      )
      .join('; ');
    const usesLocalPrefix = dns64Detections.some(
      (d) => d.prefixKind === 'local-use-64:ff9b:1::/48'
    );
    const usesWkp = dns64Detections.some((d) => d.prefixKind === 'well-known-64:ff9b::/96');
    const prefixDesc =
      usesWkp && usesLocalPrefix
        ? '64:ff9b::/96 & 64:ff9b:1::/48'
        : usesLocalPrefix
          ? '64:ff9b:1::/48'
          : '64:ff9b::/96';

    findings.push({
      id: `warn-dns64-synthesized-${normTarget}`,
      severity: 'warning',
      code: 'DNS64_SYNTHESIZED_AAAA',
      title: `Synthesized NAT64/DNS64 AAAA address detected (${prefixDesc}) on ${displayFqdn(normTarget)}`,
      detail: `Detected ${dns64Detections.length} IPv4-embedded NAT64/DNS64 translation address${dns64Detections.length === 1 ? '' : 'es'} (${formattedList}). DNS64 synthesis masks missing native AAAA records on NAT64 networks and is unreachable from native IPv6-only networks without a stateful NAT64 translator.`,
      remediation: `Publish native globally routable IPv6 (2000::/3) AAAA records on the authoritative zone/origin instead of publishing or relying on synthesized ${prefixDesc} NAT64 translation addresses; verify directly with a DNSSEC-aware non-DNS64 resolver.`,
      rfc: usesLocalPrefix ? 'RFC 6052 / RFC 6147 / RFC 8215' : 'RFC 6052 / RFC 6147',
    });
  }

  // Leaf Web & Mail IPv6 parity findings
  if (leaf.evaluated) {
    const dispLeaf = displayFqdn(normTarget);
    if (
      leaf.aQueried &&
      leaf.aaaaQueried &&
      leaf.nativeIpv4Addresses.length > 0 &&
      leaf.nativeIpv6Addresses.length === 0 &&
      leaf.dns64TargetIps.length === 0
    ) {
      findings.push({
        id: `info-ipv6-leaf-no-aaaa-${normTarget}`,
        severity: 'info',
        code: 'IPV6_LEAF_NO_AAAA',
        title: `Leaf target ${dispLeaf} is IPv4-only (${leaf.nativeIpv4Addresses.length} A record${leaf.nativeIpv4Addresses.length === 1 ? '' : 's'}, 0 native AAAA)`,
        detail: `Although DNS delegation can be traversed, ${dispLeaf} publishes ${leaf.nativeIpv4Addresses.length} public IPv4 A address${leaf.nativeIpv4Addresses.length === 1 ? '' : 'es'} (${leaf.nativeIpv4Addresses.slice(0, 3).join(', ')}) and no native IPv6 AAAA records. Clients on pure IPv6-only networks require NAT64/DNS64 translation to connect.`,
        remediation: `Enable dual-stack IPv6 listeners on the origin/CDN for ${dispLeaf} and publish matching AAAA records.`,
        rfc: 'RFC 6540 / BCP 177',
      });
    }

    if (
      leaf.httpsEvaluated &&
      leaf.httpsIpv4Hints.length > 0 &&
      leaf.httpsNativeIpv6Hints.length === 0
    ) {
      findings.push({
        id: `warn-ipv6-https-missing-ipv6hint-${normTarget}`,
        severity: leaf.nativeIpv6Addresses.length > 0 ? 'warning' : 'info',
        code: 'IPV6_HTTPS_MISSING_IPV6HINT',
        title: `HTTPS/SVCB record for ${dispLeaf} publishes ipv4hint without native ipv6hint`,
        detail: `${dispLeaf} advertises ipv4hint=${leaf.httpsIpv4Hints.join(',')} in its ServiceMode HTTPS/SVCB record without any native ipv6hint${leaf.nativeIpv6Addresses.length > 0 ? `, despite publishing ${leaf.nativeIpv6Addresses.length} AAAA record${leaf.nativeIpv6Addresses.length === 1 ? '' : 's'}` : ''}. RFC 9460 §7.3 clients using hints for 0-extra-RTT Happy Eyeballs may fall back to IPv4 or wait on AAAA resolution.`,
        remediation:
          leaf.nativeIpv6Addresses.length > 0
            ? `Include ipv6hint="${leaf.nativeIpv6Addresses.slice(0, 2).join(',')}" alongside ipv4hint in the HTTPS/SVCB RRset for ${dispLeaf}, or omit IP hints so clients use A/AAAA directly.`
            : `Deploy IPv6 AAAA on ${dispLeaf} and add matching ipv6hint values to the HTTPS/SVCB record.`,
        rfc: 'RFC 9460 §7.3',
      });
    }

    if (
      leaf.mxEvaluated &&
      leaf.mxProbedCount > 0 &&
      leaf.mxIpv6ReadyCount === 0 &&
      leaf.mxIpv4OnlyExchanges.length > 0
    ) {
      findings.push({
        id: `info-ipv6-mx-no-aaaa-${normTarget}`,
        severity: 'info',
        code: 'IPV6_MX_NO_AAAA',
        title: `Inbound MX hosts for ${dispLeaf} are IPv4-only (0 of ${leaf.mxProbedCount} MX publish AAAA)`,
        detail: `None of the probed MX mail exchangers for ${dispLeaf} (${leaf.mxIpv4OnlyExchanges.map(displayFqdn).join(', ')}) publish native IPv6 AAAA records. IPv6-only outbound SMTP MTAs cannot deliver mail to ${dispLeaf} without NAT64.`,
        remediation: `Publish native IPv6 AAAA records (with matching forward-confirmed IPv6 PTR records per RFC 5321 / RFC 1912) on at least one primary or backup MX host for ${dispLeaf}.`,
        rfc: 'RFC 5321 §5.1 / RFC 6540',
      });
    }
  }

  return {
    audit: {
      overallStatus,
      resolvableViaIpv6Only,
      probedHopCount: probedHops.length,
      bottleneckZones,
      singleIpv6NsZones,
      hops,
      oobNsZones,
      leaf,
      dns64Detections,
      summary,
    },
    findings,
  };
}
