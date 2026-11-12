import {
  CONSENSUS_DOH_RESOLVERS,
  DEFAULT_DOH_ENDPOINT,
  DOH_SERVER_PRESETS,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  formatDohShortLabel,
  rcodeToString,
  type DohServerPreset,
} from './constants';
import {
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
  probeLeafNameserverAddresses,
  type AnalyzeOptions,
} from './analyzer';
import { DohSession } from './doh';
import { evaluateEcsGeoFromLogs, runEcsGeoProbes } from './ecsProbe';
import { parseEmailDaneInput } from './emailDane';
import { displayFqdn, isSubdomainOrEqual, normalizeFqdn } from './encoding';
import { formatCanonicalIpv6, parseIpv6Groups } from './ipUtils';
import type {
  AnalysisProgress,
  AnalysisSnapshot,
  AuditFinding,
  ConsensusAnalysisResult,
  ConsensusResolverClassification,
  ConsensusResolverRow,
  DohQueryLog,
  EdeEntry,
  ValidationStatus,
  ZoneAnalysis,
} from './types';

const DNSSEC_BOGUS_EDE_CODES = new Set([6, 7, 8, 9, 10, 11, 12]);
const POLICY_BLOCKED_EDE_CODES = new Set([4, 15, 16, 17, 18]);
const UPSTREAM_REACHABILITY_EDE_CODES = new Set([22, 23]);

export function categorizeEdeCode(
  infoCode: number
): 'dnssec-bogus' | 'policy-blocked' | 'upstream-reachability' | 'other' {
  if (DNSSEC_BOGUS_EDE_CODES.has(infoCode)) return 'dnssec-bogus';
  if (POLICY_BLOCKED_EDE_CODES.has(infoCode)) return 'policy-blocked';
  if (UPSTREAM_REACHABILITY_EDE_CODES.has(infoCode)) return 'upstream-reachability';
  return 'other';
}

export function isSinkholeIpAddress(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase();
  if (
    ip === '0.0.0.0' ||
    ip === '127.0.0.1' ||
    ip === '127.0.0.2' ||
    ip === '::' ||
    ip === '::1' ||
    ip === '0:0:0:0:0:0:0:0' ||
    ip === '0:0:0:0:0:0:0:1'
  ) {
    return true;
  }
  const v6 = parseIpv6Groups(ip);
  if (v6) {
    const canon = formatCanonicalIpv6(v6);
    if (canon === '::' || canon === '::1') return true;
  }
  return false;
}

function getResolverPresetList(primaryEndpoint: string): DohServerPreset[] {
  const list: DohServerPreset[] = [...CONSENSUS_DOH_RESOLVERS];
  if (!list.some((r) => r.url === primaryEndpoint)) {
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

/**
 * Evaluates multi-resolver DoH consensus, SOA propagation skew, DNSSEC AD-bit consistency,
 * and RFC 8914 Extended DNS Error (`EDE`) / protective DNS filtering from recorded `DohQueryLog[]`.
 */
export function evaluateConsensusFromSnapshotData(params: {
  targetName: string;
  primaryEndpoint: string;
  queries: DohQueryLog[];
  zones: ZoneAnalysis[];
  targetDomainStatus: ValidationStatus;
}): {
  consensusAnalysis: ConsensusAnalysisResult;
  consensusFindings: AuditFinding[];
  overallStatus: ValidationStatus;
  overallSummary: string;
} {
  const { targetName, primaryEndpoint, queries, zones, targetDomainStatus } = params;
  const dispTarget = displayFqdn(targetName);
  const consensusFindings: AuditFinding[] = [];

  // Determine deepest authoritative zone covering targetName
  const deepestZone =
    [...zones]
      .filter((z) => isSubdomainOrEqual(targetName, z.zoneName))
      .sort((a, b) => b.depth - a.depth)[0]?.zoneName ?? targetName;

  const presetList = getResolverPresetList(primaryEndpoint);
  const activeResolvers = presetList;

  // First pass: extract raw per-resolver observations
  const rawRows: ConsensusResolverRow[] = activeResolvers.map((preset) => {
    const epLogs = queries.filter(
      (q) =>
        !q.ecsSubnet &&
        !q.purpose.startsWith('ECS ') &&
        q.endpoint === preset.url &&
        (q.purpose.startsWith('Consensus probe') || preset.url === primaryEndpoint)
    );

    if (epLogs.length === 0) {
      return {
        endpoint: preset.url,
        shortLabel: preset.shortLabel,
        provider: preset.provider,
        role: preset.role,
        reachable: false,
        error: 'Resolver timeout or CORS / network unreachable',
        latencyMs: 0,
        rcode: -1,
        rcodeName: 'UNREACHABLE',
        adBit: false,
        ipv4Answers: [],
        ipv6Answers: [],
        cnameChain: [],
        dsKeyTags: [],
        dnskeyKeyTags: [],
        ede: [],
        isSinkholed: false,
        classification: 'unreachable',
        summary: `${preset.shortLabel} (${preset.provider}) did not respond within the timeout.`,
      };
    }

    const aLog =
      epLogs.find((q) => q.qname === targetName && q.qtype === RR_TYPES.A && !q.cd) ??
      epLogs.find((q) => q.qname === targetName && q.qtype === RR_TYPES.A);
    const aaaaLog =
      epLogs.find((q) => q.qname === targetName && q.qtype === RR_TYPES.AAAA && !q.cd) ??
      epLogs.find((q) => q.qname === targetName && q.qtype === RR_TYPES.AAAA);
    const soaLog =
      epLogs.find((q) => q.qtype === RR_TYPES.SOA && q.qname === deepestZone) ??
      epLogs.find((q) => q.qtype === RR_TYPES.SOA);
    const dnskeyLog = epLogs.find(
      (q) => q.qtype === RR_TYPES.DNSKEY && q.qname === deepestZone
    );
    const dsLog = epLogs.find((q) => q.qtype === RR_TYPES.DS && q.qname === deepestZone);

    const primaryLog = aLog ?? aaaaLog ?? soaLog ?? epLogs[0];
    const rcode = primaryLog.packet.flags.rcode;
    const rcodeName = rcodeToString(rcode);
    const adBit = Boolean(
      (aLog && aLog.packet.flags.rcode === 0 && aLog.packet.flags.ad) ||
        (aaaaLog && aaaaLog.packet.flags.rcode === 0 && aaaaLog.packet.flags.ad) ||
        (!aLog && !aaaaLog && primaryLog.packet.flags.ad)
    );

    const avgLatency = Math.max(
      1,
      Math.round(epLogs.reduce((acc, l) => acc + l.latencyMs, 0) / epLogs.length)
    );

    const ipv4Answers: string[] = [];
    const cnameChain: string[] = [];
    for (const ans of aLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.A) {
        const ip = ans.rdataText.trim();
        if (ip && !ipv4Answers.includes(ip)) ipv4Answers.push(ip);
      } else if (ans.type === RR_TYPES.CNAME && ans.parsed.kind === 'GENERIC' && ans.parsed.target) {
        const t = normalizeFqdn(ans.parsed.target);
        if (!cnameChain.includes(t)) cnameChain.push(t);
      }
    }
    ipv4Answers.sort();

    const ipv6Answers: string[] = [];
    for (const ans of aaaaLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.AAAA) {
        const grps = parseIpv6Groups(ans.rdataText);
        const normV6 = grps ? formatCanonicalIpv6(grps) : ans.rdataText.trim().toLowerCase();
        if (normV6 && !ipv6Answers.includes(normV6)) ipv6Answers.push(normV6);
      }
    }
    ipv6Answers.sort();

    let soaSerial: number | undefined;
    let soaZone: string | undefined;
    for (const l of [soaLog, aLog, aaaaLog]) {
      if (!l) continue;
      for (const rec of [...l.packet.answers, ...l.packet.authorities]) {
        if (rec.type === RR_TYPES.SOA && rec.parsed.kind === 'SOA') {
          soaSerial = rec.parsed.serial;
          soaZone = rec.name;
          break;
        }
      }
      if (soaSerial !== undefined) break;
    }

    const dnskeyKeyTags: number[] = [];
    for (const ans of dnskeyLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.DNSKEY && ans.parsed.kind === 'DNSKEY' && ans.parsed.keyTag !== undefined) {
        if (!dnskeyKeyTags.includes(ans.parsed.keyTag)) {
          dnskeyKeyTags.push(ans.parsed.keyTag);
        }
      }
    }
    dnskeyKeyTags.sort((a, b) => a - b);

    const dsKeyTags: number[] = [];
    for (const ans of dsLog?.packet.answers ?? []) {
      if (ans.type === RR_TYPES.DS && ans.parsed.kind === 'DS') {
        if (!dsKeyTags.includes(ans.parsed.keyTag)) {
          dsKeyTags.push(ans.parsed.keyTag);
        }
      }
    }
    dsKeyTags.sort((a, b) => a - b);

    // Collect deduplicated EDE entries across this resolver's logs
    const ede: EdeEntry[] = [];
    for (const l of epLogs) {
      for (const e of l.packet.edns?.ede ?? []) {
        if (!ede.some((x) => x.infoCode === e.infoCode && x.extraText === e.extraText)) {
          ede.push(e);
        }
      }
    }

    const hasSinkholeIp = [...ipv4Answers, ...ipv6Answers].some(isSinkholeIpAddress);
    const hasValidNonSinkholeIp = [...ipv4Answers, ...ipv6Answers].some(
      (ip) => !isSinkholeIpAddress(ip)
    );
    const isSinkholed =
      hasSinkholeIp ||
      ((rcode !== 0 || !hasValidNonSinkholeIp) &&
        ede.some((e) => categorizeEdeCode(e.infoCode) === 'policy-blocked'));

    let classification: ConsensusResolverClassification = 'resolved-insecure';
    if (isSinkholed) {
      classification = 'policy-blocked';
    } else if (
      (rcode !== 0 || !hasValidNonSinkholeIp) &&
      ede.some((e) => categorizeEdeCode(e.infoCode) === 'dnssec-bogus')
    ) {
      classification = 'dnssec-bogus';
    } else if (
      (rcode !== 0 || !hasValidNonSinkholeIp) &&
      ede.some((e) => categorizeEdeCode(e.infoCode) === 'upstream-reachability')
    ) {
      classification = 'upstream-error';
    } else if (rcode === 2) {
      // Distinguish SERVFAIL caused by DNSSEC validation failure vs upstream error
      const cdSuccess = Boolean(soaLog && soaLog.cd && soaLog.packet.flags.rcode === 0);
      classification =
        cdSuccess || targetDomainStatus === 'bogus' ? 'dnssec-bogus' : 'upstream-error';
    } else if (rcode === 5) {
      classification = preset.role !== 'unfiltered' ? 'policy-blocked' : 'upstream-error';
    } else if (rcode === 3) {
      classification = 'nxdomain';
    } else if (rcode === 0) {
      if (ipv4Answers.length === 0 && ipv6Answers.length === 0 && targetName !== '.') {
        classification = 'nodata';
      } else if (adBit) {
        classification = 'resolved-secure';
      } else {
        classification = 'resolved-insecure';
      }
    } else {
      classification = 'upstream-error';
    }

    return {
      endpoint: preset.url,
      shortLabel: preset.shortLabel,
      provider: preset.provider,
      role: preset.role,
      reachable: true,
      latencyMs: avgLatency,
      rcode,
      rcodeName,
      adBit,
      ipv4Answers,
      ipv6Answers,
      cnameChain,
      soaSerial,
      soaZone,
      dsKeyTags,
      dnskeyKeyTags,
      ede,
      isSinkholed,
      classification,
      summary: '',
    };
  });

  // Second pass: if unfiltered resolvers resolved the domain with valid IPs, check if any protective/family resolver returned NXDOMAIN without EDE (silent protective NXDOMAIN block!)
  const unfilteredResolvedCount = rawRows.filter(
    (r) =>
      r.reachable &&
      r.role === 'unfiltered' &&
      (r.classification === 'resolved-secure' || r.classification === 'resolved-insecure') &&
      (r.ipv4Answers.length > 0 || r.ipv6Answers.length > 0)
  ).length;

  const resolvers: ConsensusResolverRow[] = rawRows.map((row) => {
    let classification = row.classification;
    let isSinkholed = row.isSinkholed;
    if (
      unfilteredResolvedCount >= 2 &&
      row.role !== 'unfiltered' &&
      (row.classification === 'nxdomain' ||
        (row.classification === 'nodata' && row.ipv4Answers.length === 0 && row.ipv6Answers.length === 0))
    ) {
      classification = 'policy-blocked';
      isSinkholed = true;
    }

    const edeText =
      row.ede.length > 0
        ? ` [EDE ${row.ede.map((e) => `${e.infoCode}: ${e.name}${e.extraText ? ` (${e.extraText})` : ''}`).join('; ')}]`
        : '';

    let summary = '';
    switch (classification) {
      case 'resolved-secure':
        summary = `${row.rcodeName} (AD=1) · ${[...row.ipv4Answers, ...row.ipv6Answers].slice(0, 3).join(', ') || 'Signed'}${edeText}`;
        break;
      case 'resolved-insecure':
        summary = `${row.rcodeName} (AD=0) · ${[...row.ipv4Answers, ...row.ipv6Answers].slice(0, 3).join(', ') || 'Unsigned'}${edeText}`;
        break;
      case 'policy-blocked':
        summary = `Filtered / Blocked by ${row.provider} (${row.rcodeName}${row.ipv4Answers.length > 0 ? ` → ${row.ipv4Answers.join(', ')}` : ''})${edeText}`;
        break;
      case 'dnssec-bogus':
        summary = `DNSSEC Validation Failure (${row.rcodeName})${edeText}`;
        break;
      case 'nxdomain':
        summary = `NXDOMAIN (Non-Existent Domain)${edeText}`;
        break;
      case 'nodata':
        summary = `NOERROR / NODATA (0 A/AAAA records)${edeText}`;
        break;
      case 'upstream-error':
        summary = `Upstream / Resolver Error (${row.rcodeName})${edeText}`;
        break;
      case 'unreachable':
        summary = row.error ?? 'Resolver unreachable';
        break;
    }

    return {
      ...row,
      isSinkholed,
      classification,
      summary,
    };
  });

  const reachableResolvers = resolvers.filter((r) => r.reachable);
  const reachableCount = reachableResolvers.length;
  const protectiveBlockedResolvers = reachableResolvers
    .filter((r) => r.classification === 'policy-blocked')
    .map((r) => `${r.shortLabel} (${r.provider})`);
  const dnssecBogusResolvers = reachableResolvers
    .filter((r) => r.classification === 'dnssec-bogus')
    .map((r) => `${r.shortLabel} (${r.provider})`);
  const upstreamErrorResolvers = reachableResolvers
    .filter((r) => r.classification === 'upstream-error')
    .map((r) => `${r.shortLabel} (${r.provider})`);

  // Evaluate AD-bit consensus across non-blocked NOERROR/NXDOMAIN responses
  const validResponses = reachableResolvers.filter(
    (r) =>
      r.classification === 'resolved-secure' ||
      r.classification === 'resolved-insecure' ||
      r.classification === 'nodata' ||
      r.classification === 'nxdomain'
  );
  let adBitConsensus: ConsensusAnalysisResult['adBitConsensus'] = 'all-failed';
  if (validResponses.length > 0) {
    const adTrue = validResponses.filter((r) => r.adBit).length;
    if (adTrue === validResponses.length) {
      adBitConsensus = 'all-ad';
    } else if (adTrue === 0) {
      adBitConsensus = 'all-unsigned';
    } else {
      adBitConsensus = 'mixed-ad';
    }
  }

  // Evaluate RCODE consensus
  const uniqueRcodes = new Set(reachableResolvers.map((r) => r.rcode));
  const nonBlockedRcodes = new Set(
    reachableResolvers
      .filter((r) => r.classification !== 'policy-blocked')
      .map((r) => r.rcode)
  );
  const rcodeConsensus: ConsensusAnalysisResult['rcodeConsensus'] =
    uniqueRcodes.size <= 1
      ? 'unanimous'
      : nonBlockedRcodes.size <= 1 && protectiveBlockedResolvers.length > 0
        ? 'protective-filtered'
        : 'divergent';

  // Evaluate SOA Serial consensus
  const serialMap = new Map<number, string[]>();
  for (const r of reachableResolvers) {
    if (r.soaSerial !== undefined) {
      const list = serialMap.get(r.soaSerial) ?? [];
      list.push(r.shortLabel);
      serialMap.set(r.soaSerial, list);
    }
  }
  const uniqueSoaSerials = Array.from(serialMap.entries())
    .map(([serial, resList]) => ({ serial, resolvers: resList }))
    .sort((a, b) => b.serial - a.serial);

  const soaSerialConsensus: ConsensusAnalysisResult['soaSerialConsensus'] =
    uniqueSoaSerials.length === 0
      ? 'unavailable'
      : uniqueSoaSerials.length === 1
        ? 'synchronized'
        : 'skew-detected';

  // Evaluate DNSKEY / DS KeyTag consensus
  const keyTagFingerprints = new Set(
    reachableResolvers
      .filter((r) => r.dnskeyKeyTags.length > 0)
      .map((r) => r.dnskeyKeyTags.join(','))
  );
  const keyTagConsensus: ConsensusAnalysisResult['keyTagConsensus'] =
    keyTagFingerprints.size === 0
      ? 'unsigned'
      : keyTagFingerprints.size === 1
        ? 'synchronized'
        : 'rollover-skew';

  // Evaluate IP Answer consensus across non-blocked resolved responses
  const resolvedNonBlocked = reachableResolvers.filter(
    (r) =>
      (r.classification === 'resolved-secure' || r.classification === 'resolved-insecure') &&
      (r.ipv4Answers.length > 0 || r.ipv6Answers.length > 0)
  );
  const v4Fingerprints = new Set(
    resolvedNonBlocked.filter((r) => r.ipv4Answers.length > 0).map((r) => r.ipv4Answers.join(','))
  );
  let answerConsensus: ConsensusAnalysisResult['answerConsensus'] = 'no-answers';
  if (protectiveBlockedResolvers.length > 0 && resolvedNonBlocked.length > 0) {
    answerConsensus = 'protective-sinkhole';
  } else if (resolvedNonBlocked.length > 0) {
    if (v4Fingerprints.size <= 1) {
      answerConsensus = 'identical';
    } else if (soaSerialConsensus !== 'skew-detected' && rcodeConsensus === 'unanimous') {
      answerConsensus = 'geodns-anycast';
    } else {
      answerConsensus = 'divergent';
    }
  }

  // Collect EDE highlights
  const edeHighlights: ConsensusAnalysisResult['edeHighlights'] = [];
  for (const r of reachableResolvers) {
    for (const e of r.ede) {
      edeHighlights.push({
        resolverLabel: `${r.shortLabel} (${r.provider})`,
        infoCode: e.infoCode,
        name: e.name,
        category: categorizeEdeCode(e.infoCode),
        extraText: e.extraText,
      });
    }
  }

  // Emit structured AuditFindings for Consensus anomalies
  if (protectiveBlockedResolvers.length > 0) {
    consensusFindings.push({
      id: `consensus-warn-protective-blocked-${targetName}`,
      severity: 'warning',
      code: 'CONSENSUS_PROTECTIVE_BLOCKED',
      title: `Domain blocked or filtered by ${protectiveBlockedResolvers.length} protective DoH resolver(s): ${protectiveBlockedResolvers.join(', ')}`,
      detail: `Unfiltered resolvers resolve ${dispTarget}, whereas protective/family resolvers (${protectiveBlockedResolvers.join(', ')}) blocked or sinkholed the response (RFC 8914 EDE 15/16/17 or policy sinkhole).`,
      rfc: 'RFC 8914 §4.16-4.18',
    });
  }

  if (dnssecBogusResolvers.length > 0) {
    consensusFindings.push({
      id: `consensus-err-dnssec-bogus-${targetName}`,
      severity: 'error',
      code: 'CONSENSUS_DNSSEC_BOGUS',
      title: `${dnssecBogusResolvers.length} validating DoH resolver(s) rejected ${dispTarget} as DNSSEC BOGUS (${dnssecBogusResolvers.join(', ')})`,
      detail: `Validating resolvers returned SERVFAIL / RFC 8914 Extended DNS Error (EDE 6..12) when validating ${dispTarget}.`,
      rfc: 'RFC 4035 / RFC 8914',
    });
  }

  if (soaSerialConsensus === 'skew-detected') {
    const serialDesc = uniqueSoaSerials
      .map((s) => `${s.serial} (${s.resolvers.join(', ')})`)
      .join(' vs ');
    consensusFindings.push({
      id: `consensus-warn-soa-skew-${targetName}`,
      severity: 'warning',
      code: 'CONSENSUS_SOA_SERIAL_SKEW',
      title: `SOA serial propagation skew detected across resolvers: ${serialDesc}`,
      detail: `Public DoH resolvers are serving different SOA serial numbers for ${displayFqdn(deepestZone)} (${serialDesc}). This indicates an active zone update or out-of-sync authoritative secondaries.`,
      rfc: 'RFC 1035 / RFC 1982',
    });
  }

  if (keyTagConsensus === 'rollover-skew') {
    consensusFindings.push({
      id: `consensus-warn-keytag-skew-${targetName}`,
      severity: 'warning',
      code: 'CONSENSUS_KEYTAG_SKEW',
      title: `DNSKEY key-tag skew across DoH resolvers for ${displayFqdn(deepestZone)}`,
      detail: `Different public resolvers cached different DNSKEY RRsets for ${displayFqdn(deepestZone)}, indicating an active ZSK/KSK rollover in progress.`,
      rfc: 'RFC 6781',
    });
  }

  if (adBitConsensus === 'mixed-ad') {
    const adOn = validResponses.filter((r) => r.adBit).map((r) => r.shortLabel);
    const adOff = validResponses.filter((r) => !r.adBit).map((r) => r.shortLabel);
    consensusFindings.push({
      id: `consensus-warn-ad-mismatch-${targetName}`,
      severity: 'warning',
      code: 'CONSENSUS_AD_MISMATCH',
      title: `Inconsistent DNSSEC AD-bit across public resolvers (AD=1: ${adOn.join(', ')}; AD=0: ${adOff.join(', ')})`,
      detail: `Some public resolvers validated ${dispTarget} as DNSSEC-authenticated (AD=1) while others returned AD=0. This can occur with unsupported DNSSEC algorithms or transient cache states.`,
      rfc: 'RFC 4035 / RFC 6840',
    });
  }

  if (answerConsensus === 'geodns-anycast') {
    consensusFindings.push({
      id: `consensus-info-geodns-${targetName}`,
      severity: 'info',
      code: 'CONSENSUS_GEODNS_ANYCAST',
      title: `GeoDNS / CDN anycast steering detected across resolvers for ${dispTarget}`,
      detail: `Public resolvers received distinct IP answer sets (${v4Fingerprints.size} distinct IPv4 pools) while agreeing on SOA serial ${uniqueSoaSerials[0]?.serial ?? 'N/A'} and RCODE NOERROR.`,
      rfc: 'RFC 7871',
    });
  }

  const { ecsGeo, ecsFindings } = evaluateEcsGeoFromLogs({
    targetName,
    primaryEndpoint,
    queries,
  });
  consensusFindings.push(...ecsFindings);

  // Compute overall verdict & summary
  let overallVerdict: ConsensusAnalysisResult['overallVerdict'] = 'unanimous-secure';
  let summary = '';

  if (dnssecBogusResolvers.length > 0) {
    overallVerdict = 'dnssec-bogus';
    summary = `DNSSEC validation failed (BOGUS / SERVFAIL) across ${dnssecBogusResolvers.length}/${reachableCount} DoH resolvers (${dnssecBogusResolvers.join(', ')}).`;
  } else if (protectiveBlockedResolvers.length > 0) {
    overallVerdict = 'protective-blocked';
    summary = `Blocked/filtered by ${protectiveBlockedResolvers.length} protective resolver(s) (${protectiveBlockedResolvers.join(', ')}), while ${unfilteredResolvedCount} unfiltered resolver(s) resolved ${dispTarget}.`;
  } else if (soaSerialConsensus === 'skew-detected' || keyTagConsensus === 'rollover-skew') {
    overallVerdict = 'propagation-skew';
    summary = `Propagation skew detected across ${reachableCount} resolvers (${uniqueSoaSerials.map((s) => `SOA ${s.serial}`).join(' vs ')}).`;
  } else if (rcodeConsensus === 'divergent' || adBitConsensus === 'mixed-ad') {
    overallVerdict = 'split-horizon-divergent';
    summary = `Resolver divergence across ${reachableCount} DoH endpoints (RCODE / AD-bit mismatch).`;
  } else if (
    answerConsensus === 'geodns-anycast' ||
    ecsGeo?.steeringModel === 'geodns-ip' ||
    ecsGeo?.steeringModel === 'geodns-cname'
  ) {
    overallVerdict = 'geodns-consistent';
    summary = `All ${reachableCount} DoH resolvers agree on RCODE & SOA serial (${uniqueSoaSerials[0]?.serial ?? 'sync'}) with GeoDNS/CDN anycast IP steering (${adBitConsensus === 'all-ad' ? 'AD=1 verified' : 'AD=0 unsigned'}).`;
  } else if (adBitConsensus === 'all-ad') {
    overallVerdict = 'unanimous-secure';
    summary = `Unanimous DNSSEC-authenticated consensus (AD=1, ${uniqueSoaSerials[0] ? `SOA ${uniqueSoaSerials[0].serial}` : 'NOERROR'}) across all ${reachableCount} DoH resolvers.`;
  } else {
    overallVerdict = 'unanimous-unsigned';
    summary = `Unanimous consensus (AD=0 unsigned, ${uniqueSoaSerials[0] ? `SOA ${uniqueSoaSerials[0].serial}` : 'NOERROR'}) across all ${reachableCount} DoH resolvers.`;
  }

  let overallStatus: ValidationStatus = targetDomainStatus;
  if (overallVerdict === 'dnssec-bogus') {
    overallStatus = 'bogus';
  } else if (
    (overallVerdict === 'protective-blocked' ||
      overallVerdict === 'propagation-skew' ||
      overallVerdict === 'split-horizon-divergent' ||
      ecsFindings.some((f) => f.severity === 'error' || f.severity === 'warning')) &&
    overallStatus === 'secure'
  ) {
    overallStatus = 'warning';
  }

  return {
    consensusAnalysis: {
      targetDomain: targetName,
      displayDomain: dispTarget,
      soaZone: deepestZone,
      resolvers,
      reachableCount,
      unfilteredResolvedCount,
      protectiveBlockedResolvers,
      dnssecBogusResolvers,
      upstreamErrorResolvers,
      adBitConsensus,
      rcodeConsensus,
      answerConsensus,
      soaSerialConsensus,
      uniqueSoaSerials,
      keyTagConsensus,
      edeHighlights,
      ...(ecsGeo ? { ecsGeo } : {}),
      overallVerdict,
      summary,
    },
    consensusFindings,
    overallStatus,
    overallSummary: summary,
  };
}

/**
 * Runs a full live Multi-Resolver DoH Consensus & Protective Filtering analysis across all
 * `CONSENSUS_DOH_RESOLVERS` in parallel, combined with WebCrypto DNSSEC chain verification.
 */
export async function runConsensusAnalysis(
  rawDomain: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisSnapshot> {
  const startedAt = Date.now();
  const emailParsed = parseEmailDaneInput(rawDomain);
  const targetName = emailParsed ? emailParsed.domain : normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const queryTypes = ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS'];
  const trustAnchors = options.trustAnchors ?? IANA_ROOT_TRUST_ANCHORS;
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;

  const primarySession = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs,
    fetchImpl: options.fetchImpl,
  });

  let completedCount = 0;
  let currentPhase: AnalysisProgress['phase'] = 'zone-cuts';
  primarySession.onQueryCompleted = (_c, lastLog) => {
    completedCount++;
    options.onProgress?.({
      phase: currentPhase,
      message: `Resolved ${lastLog.qname} ${lastLog.qtypeName} via ${formatDohShortLabel(endpoint)} (${lastLog.latencyMs}ms)`,
      completedQueries: completedCount,
    });
  };

  options.onProgress?.({
    phase: 'zone-cuts',
    message: `Discovering zone cuts & DNSSEC chain for ${displayDomain}…`,
    completedQueries: 0,
  });

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);

  await Promise.all([
    discoverZoneCutsForName(primarySession, targetName, discoveredZones, checkedCandidates),
    primarySession.query(targetName, RR_TYPES.A, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} A)`,
    }),
    primarySession.query(targetName, RR_TYPES.AAAA, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} AAAA)`,
    }),
    primarySession.query(targetName, RR_TYPES.A, {
      cd: false,
      doBit: true,
      purpose: 'Resolver validating check (CD=0)',
    }),
  ]);

  // Include authoritative SOA zones from CD=1 responses
  for (const log of primarySession.getLogs()) {
    if (!log.cd) continue;
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Fetch DNSKEY, DS, SOA & NS across discovered zones on primary session
  currentPhase = 'security-records';
  const zoneList = Array.from(discoveredZones);
  await Promise.all(
    zoneList.flatMap((z) => {
      const tasks = [
        primarySession.query(z, RR_TYPES.DNSKEY, {
          cd: true,
          doBit: true,
          purpose: `Zone DNSKEY (${z})`,
        }),
        primarySession.query(z, RR_TYPES.SOA, {
          cd: true,
          doBit: true,
          purpose: `Zone SOA (${z})`,
        }),
        primarySession.query(z, RR_TYPES.NS, {
          cd: true,
          doBit: true,
          purpose: `Zone NS (${z})`,
        }),
      ];
      if (z !== '.') {
        tasks.push(
          primarySession.query(z, RR_TYPES.DS, {
            cd: true,
            doBit: true,
            purpose: `Delegation DS (${z})`,
          })
        );
      }
      return tasks;
    })
  );

  // Determine the leaf SOA zone to probe across all resolvers
  const deepestSoaZone =
    zoneList
      .filter((z) => isSubdomainOrEqual(targetName, z))
      .sort((a, b) => b.length - a.length)[0] ?? targetName;

  // Step 2: Query all CONSENSUS_DOH_RESOLVERS & RFC 7871 ECS regional prefixes in parallel
  currentPhase = 'consensus-probes';
  const resolverPresets = getResolverPresetList(endpoint);
  options.onProgress?.({
    phase: 'consensus-probes',
    message: `Querying ${resolverPresets.length} DoH resolvers & 7 RFC 7871 ECS regional subnets in parallel for ${displayDomain}…`,
    completedQueries: completedCount,
  });

  const consensusLogs: DohQueryLog[] = [];
  let ecsLogs: DohQueryLog[] = [];
  await Promise.all([
    ...resolverPresets.map(async (preset) => {
      const rSession = new DohSession({
        endpoint: preset.url,
        timeoutMs: Math.min(options.timeoutMs ?? 4500, 4500),
        fetchImpl: options.fetchImpl,
      });
      rSession.onQueryCompleted = (_c, lastLog) => {
        completedCount++;
        options.onProgress?.({
          phase: 'consensus-probes',
          message: `[${preset.shortLabel}] ${lastLog.qname} ${lastLog.qtypeName} → ${rcodeToString(lastLog.packet.flags.rcode)} (${lastLog.latencyMs}ms)`,
          completedQueries: completedCount,
        });
      };

      const tasks: Promise<unknown>[] = [
        rSession
          .query(targetName, RR_TYPES.A, {
            cd: false,
            doBit: true,
            purpose: `Consensus probe (${preset.shortLabel} A)`,
          })
          .catch(() => undefined),
        rSession
          .query(targetName, RR_TYPES.AAAA, {
            cd: false,
            doBit: true,
            purpose: `Consensus probe (${preset.shortLabel} AAAA)`,
          })
          .catch(() => undefined),
        rSession
          .query(deepestSoaZone, RR_TYPES.SOA, {
            cd: true,
            doBit: true,
            purpose: `Consensus probe (${preset.shortLabel} SOA)`,
          })
          .catch(() => undefined),
        rSession
          .query(deepestSoaZone, RR_TYPES.DNSKEY, {
            cd: true,
            doBit: true,
            purpose: `Consensus probe (${preset.shortLabel} DNSKEY)`,
          })
          .catch(() => undefined),
        rSession
          .query(deepestSoaZone, RR_TYPES.NS, {
            cd: true,
            doBit: true,
            purpose: `Consensus probe (${preset.shortLabel} NS)`,
          })
          .catch(() => undefined),
      ];
      if (deepestSoaZone !== '.') {
        tasks.push(
          rSession
            .query(deepestSoaZone, RR_TYPES.DS, {
              cd: true,
              doBit: true,
              purpose: `Consensus probe (${preset.shortLabel} DS)`,
            })
            .catch(() => undefined)
        );
      }

      await Promise.all(tasks);
      for (const l of rSession.getLogs()) {
        consensusLogs.push({
          ...l,
          id: `${l.id}-${preset.shortLabel.replace(/[^a-z0-9]/gi, '_')}`,
        });
      }
    }),
    runEcsGeoProbes({
      targetName,
      primaryEndpoint: endpoint,
      bgpSession: primarySession,
      timeoutMs: options.timeoutMs,
      fetchImpl: options.fetchImpl,
      onQueryCompleted: (lastLog, epShort) => {
        completedCount++;
        options.onProgress?.({
          phase: 'consensus-probes',
          message: `[ECS ${lastLog.ecsSubnet ?? ''} via ${epShort}] ${lastLog.qname} ${lastLog.qtypeName} → ${rcodeToString(lastLog.packet.flags.rcode)} (${lastLog.latencyMs}ms)`,
          completedQueries: completedCount,
        });
      },
    }).then((logs) => {
      ecsLogs = logs;
    }),
    probeLeafNameserverAddresses(primarySession, zoneList, targetName),
  ]);

  currentPhase = 'validating';
  options.onProgress?.({
    phase: 'validating',
    message: 'Synthesizing multi-resolver DoH consensus, RFC 7871 ECS steering, RFC 8914 EDE & DNSSEC chain…',
    completedQueries: completedCount,
  });

  const allQueries = [...primarySession.getLogs(), ...consensusLogs, ...ecsLogs];
  const capturedAt = Date.now();
  const validatedAt = options.validationTimeMs ?? capturedAt;
  const durationMs = Math.max(1, capturedAt - startedAt);

  return evaluateSnapshotFromLogs({
    id: `snap-${capturedAt}-${Math.random().toString(36).slice(2, 8)}`,
    mode: 'consensus',
    targetName,
    queryTypes,
    dohEndpoint: endpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries: allQueries,
    trustAnchors,
  });
}
