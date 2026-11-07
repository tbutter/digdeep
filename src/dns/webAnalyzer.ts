import {
  DEFAULT_DOH_ENDPOINT,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  SSHFP_FP_TYPES,
  TLSA_MATCHING_TYPES,
  TLSA_SELECTORS,
  TLSA_USAGES,
  svcParamKeyToString,
} from './constants';
import {
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
  findLog,
  type AnalyzeOptions,
} from './analyzer';
import { DohSession } from './doh';
import { displayFqdn, getDomainHierarchy, normalizeFqdn } from './encoding';
import { formatCanonicalIpv6, parseIpv6Groups } from './ipUtils';
import type {
  AnalysisProgress,
  AnalysisSnapshot,
  AnalyzedRrset,
  AuditFinding,
  CaaRecordEntry,
  CaaTreeHop,
  CnameEdge,
  DaneHostStatus,
  DohQueryLog,
  EchConfigEntry,
  NegativeNode,
  SshfpRecordDetail,
  SvcParamEntry,
  SvcbRdata,
  TlsaRecordDetail,
  ValidationStatus,
  WebAnalysisResult,
  WebCaaAnalysis,
  WebSvcbRecordDetail,
  ZoneAnalysis,
} from './types';

const RECOGNIZED_CAA_TAGS = new Set([
  'issue',
  'issuewild',
  'iodef',
  'contactemail',
  'contactphone',
]);

const KNOWN_ACME_VALIDATION_METHODS = new Set([
  'http-01',
  'dns-01',
  'tls-alpn-01',
  'dns-account-01',
  'dns-persist-01',
]);

function findAnyLog(logs: DohQueryLog[], qname: string, qtype: number): DohQueryLog | undefined {
  return findLog(logs, qname, qtype, true) ?? findLog(logs, qname, qtype, false);
}

function resolveCnameChainInLogs(
  logs: DohQueryLog[],
  startName: string,
  qtype: number
): { finalOwner: string; cnameChain: string[] } {
  let cur = normalizeFqdn(startName);
  const chain: string[] = [];
  const seen = new Set<string>([cur]);

  for (let step = 0; step < 8; step++) {
    const log =
      findLog(logs, cur, qtype, true) ??
      findLog(logs, cur, qtype, false) ??
      logs.find((l) => l.packet.answers.some((r) => r.name === cur && r.type === RR_TYPES.CNAME));
    if (!log) break;
    const cnameRec = log.packet.answers.find((r) => r.name === cur && r.type === RR_TYPES.CNAME);
    if (!cnameRec || cnameRec.parsed.kind !== 'GENERIC' || !cnameRec.parsed.target) break;
    const next = normalizeFqdn(cnameRec.parsed.target);
    if (seen.has(next)) break;
    seen.add(next);
    chain.push(next);
    cur = next;
  }

  return { finalOwner: cur, cnameChain: chain };
}

function combineDnssecChainStatus(statuses: ValidationStatus[]): ValidationStatus {
  if (statuses.length === 0) return 'indeterminate';
  if (statuses.includes('bogus')) return 'bogus';
  if (statuses.includes('insecure')) return 'insecure';
  if (statuses.includes('indeterminate')) return 'indeterminate';
  if (statuses.includes('warning')) return 'warning';
  return 'secure';
}

function findRrsetInZones(
  zones: ZoneAnalysis[],
  owner: string,
  rrtype: number
): AnalyzedRrset | undefined {
  const norm = normalizeFqdn(owner);
  for (const z of zones) {
    const found = z.rrsets.find((r) => r.name === norm && r.type === rrtype);
    if (found) return found;
  }
  return undefined;
}

function findNegativeNodeInZones(
  zones: ZoneAnalysis[],
  qname: string,
  qtypeName: string
): NegativeNode | undefined {
  const norm = normalizeFqdn(qname);
  for (const z of zones) {
    const found = z.negativeNodes.find((n) => n.qname === norm && n.qtypeName === qtypeName);
    if (found) return found;
  }
  return undefined;
}

function findEffectiveDnssecStatusForQuery(
  zones: ZoneAnalysis[],
  startName: string,
  cnameChain: string[],
  finalOwner: string,
  rrtype: number,
  qtypeName: string
): {
  status: ValidationStatus;
  rrset?: AnalyzedRrset;
  negativeNode?: NegativeNode;
} {
  const chainStatuses: ValidationStatus[] = [];
  const hops = [normalizeFqdn(startName), ...cnameChain.slice(0, -1)];
  if (cnameChain.length > 0) {
    for (const hopOwner of hops) {
      const cnameRrset = findRrsetInZones(zones, hopOwner, RR_TYPES.CNAME);
      if (cnameRrset) {
        chainStatuses.push(cnameRrset.status);
      }
    }
  }

  const rrset = findRrsetInZones(zones, finalOwner, rrtype);
  if (rrset) {
    chainStatuses.push(rrset.status);
    return { status: combineDnssecChainStatus(chainStatuses), rrset };
  }

  const neg = findNegativeNodeInZones(zones, finalOwner, qtypeName);
  if (neg) {
    chainStatuses.push(neg.status);
    return { status: combineDnssecChainStatus(chainStatuses), negativeNode: neg };
  }

  const covering = [...zones]
    .filter(
      (z) => z.zoneName === '.' || finalOwner === z.zoneName || finalOwner.endsWith(`.${z.zoneName}`)
    )
    .sort((a, b) => b.depth - a.depth)[0];
  if (covering) {
    chainStatuses.push(covering.status);
    return { status: combineDnssecChainStatus(chainStatuses) };
  }

  return { status: 'indeterminate' };
}

function canonicalizeIpv6ForMatch(ip: string): string {
  const groups = parseIpv6Groups(ip);
  return groups ? formatCanonicalIpv6(groups) : ip.trim().toLowerCase();
}

/**
 * Parses and validates an RFC 8659 / RFC 8657 CAA record value.
 */
export function parseCaaRecordEntry(
  ownerName: string,
  flags: number,
  tag: string,
  rawValue: string
): CaaRecordEntry {
  const normTag = tag.trim().toLowerCase();
  const critical = (flags & 0x80) !== 0;
  const recognizedTag = RECOGNIZED_CAA_TAGS.has(normTag);
  const issues: string[] = [];
  let valid = true;
  let caDomain: string | undefined;
  const parameters: { key: string; value: string }[] = [];

  if (critical && !recognizedTag) {
    valid = false;
    issues.push(
      `Critical flag (0x80) set on unrecognized CAA tag "${normTag}" — RFC 8659 §3 forbids all CAs from issuing certificates when an unknown critical property is present`
    );
  }

  if (normTag === 'issue' || normTag === 'issuewild') {
    const trimmed = rawValue.trim();
    const semiIdx = trimmed.indexOf(';');
    const domainPart = (semiIdx === -1 ? trimmed : trimmed.slice(0, semiIdx)).trim().toLowerCase();
    const paramPart = semiIdx === -1 ? '' : trimmed.slice(semiIdx + 1).trim();

    caDomain = domainPart;
    if (domainPart.length > 0) {
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domainPart.replace(/\.$/, ''))) {
        valid = false;
        issues.push(`Malformed issuer domain name "${domainPart}" in CAA ${normTag} property`);
      }
    }

    if (paramPart.length > 0) {
      const paramTokens = paramPart
        .split(';')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      for (const tok of paramTokens) {
        const eqIdx = tok.indexOf('=');
        if (eqIdx <= 0) {
          valid = false;
          issues.push(`Malformed CAA parameter "${tok}" in ${normTag} (expected key=value)`);
          continue;
        }
        const pKey = tok.slice(0, eqIdx).trim().toLowerCase();
        const pVal = tok.slice(eqIdx + 1).trim();
        parameters.push({ key: pKey, value: pVal });

        if (pKey === 'accounturi') {
          if (!/^https:\/\/[^\s]+$/i.test(pVal)) {
            valid = false;
            issues.push(
              `RFC 8657 §3 "accounturi" parameter must be a valid https:// URI (got "${pVal}")`
            );
          }
        } else if (pKey === 'validationmethods') {
          const methods = pVal
            .split(',')
            .map((m) => m.trim().toLowerCase())
            .filter(Boolean);
          if (methods.length === 0) {
            valid = false;
            issues.push('RFC 8657 §4 "validationmethods" parameter is empty');
          } else {
            for (const m of methods) {
              if (!KNOWN_ACME_VALIDATION_METHODS.has(m)) {
                issues.push(`Unrecognized ACME validation method "${m}" in validationmethods`);
              }
            }
          }
        }
      }
    }
  } else if (normTag === 'iodef') {
    const trimmed = rawValue.trim();
    if (!/^(?:mailto:|https?:\/\/)/i.test(trimmed)) {
      valid = false;
      issues.push(
        `RFC 8659 §4.4 "iodef" value must be a mailto:, https://, or http:// URL (got "${trimmed}")`
      );
    }
  }

  return {
    ownerName,
    flags,
    critical,
    tag: normTag,
    rawValue,
    caDomain,
    parameters,
    recognizedTag,
    valid,
    issues,
  };
}

/**
 * Evaluates a single `HTTPS` (`TYPE65`) or `SVCB` (`TYPE64`) record against the target domain's
 * resolved `A`/`AAAA` addresses and RFC 9460 SvcParam rules.
 */
function evaluateSvcbRecordDetail(
  ownerName: string,
  ttl: number,
  parsed: SvcbRdata,
  resolvedIpv4: string[],
  resolvedIpv6: string[]
): WebSvcbRecordDetail {
  const issues: string[] = [];
  const params: SvcParamEntry[] = parsed.params;

  const alpnParam = params.find((p) => p.key === 1);
  const alpns = alpnParam?.alpns ?? [];
  const hasH3 = alpns.some((a) => a === 'h3' || a.startsWith('h3-'));
  const hasH2 = alpns.includes('h2');
  const noDefaultAlpn = params.some((p) => p.key === 2);

  const portParam = params.find((p) => p.key === 3);
  const port = portParam?.port;

  const ipv4Param = params.find((p) => p.key === 4);
  const ipv4Hints = ipv4Param?.ipv4Hints ?? [];
  const ipv6Param = params.find((p) => p.key === 6);
  const ipv6Hints = ipv6Param?.ipv6Hints ?? [];

  const ipv4Set = new Set(resolvedIpv4);
  const ipv4HintsMatched: string[] = [];
  const ipv4HintsDrifted: string[] = [];
  for (const h4 of ipv4Hints) {
    if (resolvedIpv4.length > 0 && !ipv4Set.has(h4)) {
      ipv4HintsDrifted.push(h4);
    } else {
      ipv4HintsMatched.push(h4);
    }
  }

  const ipv6Set = new Set(resolvedIpv6.map(canonicalizeIpv6ForMatch));
  const ipv6HintsMatched: string[] = [];
  const ipv6HintsDrifted: string[] = [];
  for (const h6 of ipv6Hints) {
    const canonH6 = canonicalizeIpv6ForMatch(h6);
    if (resolvedIpv6.length > 0 && !ipv6Set.has(canonH6)) {
      ipv6HintsDrifted.push(h6);
    } else {
      ipv6HintsMatched.push(h6);
    }
  }

  const echParam = params.find((p) => p.key === 5);
  const echConfigs: EchConfigEntry[] = echParam?.echConfigs ?? [];

  if (parsed.isAliasMode && params.length > 0) {
    issues.push(
      'RFC 9460 §2.4.2 AliasMode (priority 0) records SHOULD NOT contain SvcParams; clients ignore SvcParams in AliasMode'
    );
  }

  if (noDefaultAlpn && alpns.length === 0) {
    issues.push(
      'RFC 9460 §7.1.2 violation: "no-default-alpn" is set without an accompanying "alpn" parameter'
    );
  }

  const mandatoryParam = params.find((p) => p.key === 0);
  if (mandatoryParam?.mandatoryKeys) {
    const presentKeys = new Set(params.map((p) => svcParamKeyToString(p.key)));
    for (const reqKey of mandatoryParam.mandatoryKeys) {
      if (reqKey === 'mandatory') {
        issues.push('RFC 9460 §8 violation: "mandatory" cannot list itself');
      } else if (!presentKeys.has(reqKey)) {
        issues.push(
          `RFC 9460 §8 violation: mandatory SvcParamKey "${reqKey}" is not present in record`
        );
      }
    }
  }

  if (ipv4HintsDrifted.length > 0) {
    issues.push(
      `ipv4hint drift: ${ipv4HintsDrifted.join(', ')} does not match ${displayFqdn(ownerName)} A RRset (${resolvedIpv4.join(', ')})`
    );
  }
  if (ipv6HintsDrifted.length > 0) {
    issues.push(
      `ipv6hint drift: ${ipv6HintsDrifted.join(', ')} does not match ${displayFqdn(ownerName)} AAAA RRset (${resolvedIpv6.join(', ')})`
    );
  }

  return {
    ownerName,
    rrtypeName: parsed.rrtypeName,
    ttl,
    priority: parsed.priority,
    isAliasMode: parsed.isAliasMode,
    target: parsed.target,
    params,
    alpns,
    hasH3,
    hasH2,
    noDefaultAlpn,
    port,
    ipv4Hints,
    ipv6Hints,
    ipv4HintsMatched,
    ipv4HintsDrifted,
    ipv6HintsMatched,
    ipv6HintsDrifted,
    echConfigs,
    issues,
  };
}

function evaluateTlsaRecordDetail(
  ownerName: string,
  ttl: number,
  usage: number,
  selector: number,
  matchingType: number,
  certAssociationHex: string
): TlsaRecordDetail {
  const usageInfo = TLSA_USAGES[usage];
  const selInfo = TLSA_SELECTORS[selector];
  const matchInfo = TLSA_MATCHING_TYPES[matchingType];

  const issues: string[] = [];
  let rdataValid = true;

  if (!usageInfo) {
    rdataValid = false;
    issues.push(`Unassigned TLSA certificate usage ${usage} (expected 0..3)`);
  }
  if (!selInfo) {
    rdataValid = false;
    issues.push(`Unassigned TLSA selector ${selector} (expected 0=Cert or 1=SPKI)`);
  }
  if (!matchInfo) {
    rdataValid = false;
    issues.push(
      `Unassigned TLSA matching type ${matchingType} (expected 0=Full, 1=SHA-256, 2=SHA-512)`
    );
  } else if (matchInfo.expectedHexLength !== undefined) {
    if (certAssociationHex.length !== matchInfo.expectedHexLength) {
      rdataValid = false;
      issues.push(
        `${matchInfo.mnemonic} digest must be ${matchInfo.expectedHexLength} hex chars (${matchInfo.expectedHexLength / 2} bytes), got ${certAssociationHex.length} hex chars`
      );
    }
  } else if (certAssociationHex.length < 2) {
    rdataValid = false;
    issues.push('Empty TLSA certificate association data');
  }

  return {
    ownerName,
    ttl,
    usage,
    usageMnemonic: usageInfo ? usageInfo.mnemonic : `USAGE-${usage}`,
    usageDescription: usageInfo ? usageInfo.description : 'Unknown certificate usage',
    selector,
    selectorMnemonic: selInfo ? selInfo.mnemonic : `SEL-${selector}`,
    matchingType,
    matchingTypeMnemonic: matchInfo ? matchInfo.mnemonic : `MATCH-${matchingType}`,
    certAssociationHex: certAssociationHex.toLowerCase(),
    smtpRecommended: Boolean(usageInfo?.smtpRecommended),
    rdataValid,
    issues,
  };
}

/**
 * Evaluates Web & HTTPS records (HTTPS/SVCB RFC 9460, ECH, tree-walking CAA RFC 8659/8657,
 * `_443._tcp` DANE TLSA, and SSHFP) deterministically from captured `DohQueryLog[]` and `ZoneAnalysis[]`.
 */
export function evaluateWebFromSnapshotData(params: {
  targetName: string;
  queries: DohQueryLog[];
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  targetDomainStatus: ValidationStatus;
}): {
  webAnalysis: WebAnalysisResult;
  webFindings: AuditFinding[];
  overallStatus: ValidationStatus;
  overallSummary: string;
} {
  const { targetName, queries, zones, targetDomainStatus } = params;
  const webFindings: AuditFinding[] = [];
  const dispTarget = displayFqdn(targetName);

  // 1. Resolve CNAME chain on targetName (A / AAAA / HTTPS)
  const aChainRes = resolveCnameChainInLogs(queries, targetName, RR_TYPES.A);
  const httpsChainRes = resolveCnameChainInLogs(queries, targetName, RR_TYPES.HTTPS);
  const cnameChain =
    aChainRes.cnameChain.length >= httpsChainRes.cnameChain.length
      ? aChainRes.cnameChain
      : httpsChainRes.cnameChain;
  const effectiveDomain =
    cnameChain.length > 0 ? cnameChain[cnameChain.length - 1] : targetName;

  // 2. Collect resolved IPv4 (A) and IPv6 (AAAA) addresses
  const aLog =
    findAnyLog(queries, effectiveDomain, RR_TYPES.A) ?? findAnyLog(queries, targetName, RR_TYPES.A);
  const aaaaLog =
    findAnyLog(queries, effectiveDomain, RR_TYPES.AAAA) ??
    findAnyLog(queries, targetName, RR_TYPES.AAAA);

  const ipv4Addresses: string[] = [];
  for (const ans of aLog?.packet.answers ?? []) {
    if ((ans.name === effectiveDomain || ans.name === targetName) && ans.type === RR_TYPES.A) {
      const ip = ans.rdataText.trim();
      if (ip && !ipv4Addresses.includes(ip)) ipv4Addresses.push(ip);
    }
  }

  const ipv6Addresses: string[] = [];
  for (const ans of aaaaLog?.packet.answers ?? []) {
    if ((ans.name === effectiveDomain || ans.name === targetName) && ans.type === RR_TYPES.AAAA) {
      const ip = ans.rdataText.trim();
      if (ip && !ipv6Addresses.includes(ip)) ipv6Addresses.push(ip);
    }
  }

  const aDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    cnameChain,
    effectiveDomain,
    RR_TYPES.A,
    'A'
  );
  const aaaaDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    cnameChain,
    effectiveDomain,
    RR_TYPES.AAAA,
    'AAAA'
  );
  const addressDnssecStatus = combineDnssecChainStatus(
    [aDnssec.status, aaaaDnssec.status].filter((s) => s !== 'indeterminate')
  );

  // 3. Evaluate HTTPS (TYPE65) & SVCB (TYPE64) records
  const httpsLog =
    findAnyLog(queries, effectiveDomain, RR_TYPES.HTTPS) ??
    findAnyLog(queries, targetName, RR_TYPES.HTTPS);
  const svcbLog =
    findAnyLog(queries, effectiveDomain, RR_TYPES.SVCB) ??
    findAnyLog(queries, targetName, RR_TYPES.SVCB);

  const httpsDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    httpsChainRes.cnameChain,
    httpsChainRes.finalOwner,
    RR_TYPES.HTTPS,
    'HTTPS'
  );

  const httpsRecords: WebSvcbRecordDetail[] = [];
  for (const ans of httpsLog?.packet.answers ?? []) {
    if (ans.type === RR_TYPES.HTTPS && ans.parsed.kind === 'SVCB') {
      httpsRecords.push(
        evaluateSvcbRecordDetail(ans.name, ans.ttl, ans.parsed, ipv4Addresses, ipv6Addresses)
      );
    }
  }

  // If HTTPS record is in AliasMode (priority 0), also check if we queried the alias target's HTTPS record
  for (const rec of [...httpsRecords]) {
    if (rec.isAliasMode && rec.target !== '.' && rec.target !== effectiveDomain) {
      const aliasHttpsLog = findAnyLog(queries, rec.target, RR_TYPES.HTTPS);
      const aliasALog = findAnyLog(queries, rec.target, RR_TYPES.A);
      const aliasAaaaLog = findAnyLog(queries, rec.target, RR_TYPES.AAAA);
      const aliasV4 = (aliasALog?.packet.answers ?? [])
        .filter((r) => r.name === rec.target && r.type === RR_TYPES.A)
        .map((r) => r.rdataText.trim());
      const aliasV6 = (aliasAaaaLog?.packet.answers ?? [])
        .filter((r) => r.name === rec.target && r.type === RR_TYPES.AAAA)
        .map((r) => r.rdataText.trim());
      for (const ans of aliasHttpsLog?.packet.answers ?? []) {
        if (ans.type === RR_TYPES.HTTPS && ans.parsed.kind === 'SVCB') {
          httpsRecords.push(
            evaluateSvcbRecordDetail(
              ans.name,
              ans.ttl,
              ans.parsed,
              aliasV4.length > 0 ? aliasV4 : ipv4Addresses,
              aliasV6.length > 0 ? aliasV6 : ipv6Addresses
            )
          );
        }
      }
    }
  }

  const svcbRecords: WebSvcbRecordDetail[] = [];
  for (const ans of svcbLog?.packet.answers ?? []) {
    if (ans.type === RR_TYPES.SVCB && ans.parsed.kind === 'SVCB') {
      svcbRecords.push(
        evaluateSvcbRecordDetail(ans.name, ans.ttl, ans.parsed, ipv4Addresses, ipv6Addresses)
      );
    }
  }

  const allServiceRecords = [...httpsRecords, ...svcbRecords].filter((r) => !r.isAliasMode);
  const supportsHttp3 = allServiceRecords.some((r) => r.hasH3);
  const supportsHttp2 = allServiceRecords.some((r) => r.hasH2);
  const allEchConfigs = allServiceRecords.flatMap((r) => r.echConfigs);
  const echEnabled = allEchConfigs.length > 0;
  const echPublicNames = Array.from(
    new Set(allEchConfigs.map((c) => c.publicName).filter(Boolean))
  );

  const anyHintsPresent = allServiceRecords.some(
    (r) => r.ipv4Hints.length > 0 || r.ipv6Hints.length > 0
  );
  const allDriftedV4 = Array.from(
    new Set(allServiceRecords.flatMap((r) => r.ipv4HintsDrifted))
  );
  const allDriftedV6 = Array.from(
    new Set(allServiceRecords.flatMap((r) => r.ipv6HintsDrifted))
  );
  const ipHintStatus: WebAnalysisResult['ipHintStatus'] = !anyHintsPresent
    ? 'not-used'
    : allDriftedV4.length > 0 || allDriftedV6.length > 0
      ? 'drift-detected'
      : 'matched';

  const hasSvcbIssues = [...httpsRecords, ...svcbRecords].some((r) => r.issues.length > 0);
  let httpsStatus: WebAnalysisResult['httpsStatus'] = 'not-deployed';
  let httpsSummary = '';

  if (httpsDnssec.status === 'bogus') {
    httpsStatus = 'bogus';
    httpsSummary = `HTTPS (TYPE65) RRset for ${dispTarget} failed DNSSEC validation (BOGUS).`;
  } else if (httpsRecords.length === 0 && svcbRecords.length === 0) {
    httpsStatus = 'not-deployed';
    httpsSummary = `No HTTPS (TYPE65) or SVCB (TYPE64) service binding records published for ${dispTarget}. Clients fall back to A/AAAA + TCP/TLS ALPN negotiation.`;
    webFindings.push({
      id: `web-info-no-https-${targetName}`,
      severity: 'info',
      code: 'HTTPS_RR_NOT_DEPLOYED',
      title: `No HTTPS (TYPE65) record published for ${dispTarget}`,
      detail: `Publishing an RFC 9460 HTTPS record enables single-RTT HTTP/3 (QUIC) discovery via alpn="h3,h2" and TLS Encrypted ClientHello (ECH) privacy.`,
      rfc: 'RFC 9460',
      targetId: httpsDnssec.negativeNode?.id,
    });
  } else if (hasSvcbIssues) {
    httpsStatus = 'warning';
    const firstIssue = [...httpsRecords, ...svcbRecords].flatMap((r) => r.issues)[0];
    httpsSummary = `HTTPS record published for ${dispTarget} with configuration warnings: ${firstIssue}.`;
  } else if (echEnabled) {
    httpsStatus = 'ech-enabled';
    httpsSummary = `HTTPS ServiceMode record active with TLS Encrypted ClientHello (ECH outer SNI: ${echPublicNames.join(', ')}) and ALPN ${Array.from(new Set(allServiceRecords.flatMap((r) => r.alpns))).join(', ') || 'default'}.`;
  } else if (httpsRecords.every((r) => r.isAliasMode)) {
    httpsStatus = 'alias-mode';
    httpsSummary = `HTTPS AliasMode (priority 0) aliases ${dispTarget} to ${httpsRecords.map((r) => displayFqdn(r.target)).join(', ')}.`;
  } else {
    httpsStatus = 'valid';
    const alpnList = Array.from(new Set(allServiceRecords.flatMap((r) => r.alpns)));
    httpsSummary = `HTTPS ServiceMode record active (${alpnList.length > 0 ? `ALPN: ${alpnList.join(', ')}` : 'default ALPN'}${supportsHttp3 ? ', HTTP/3 QUIC ready' : ''}).`;
  }

  if (echEnabled) {
    const suiteSummary = allEchConfigs
      .map(
        (c) =>
          `configId=${c.configId} ${c.kemName} (${c.cipherSuites.map((s) => `${s.kdfName}/${s.aeadName}`).join(', ')}) public_name="${c.publicName}"`
      )
      .join('; ');
    webFindings.push({
      id: `web-info-ech-enabled-${targetName}`,
      severity: 'info',
      code: 'HTTPS_ECH_ENABLED',
      title: `TLS Encrypted ClientHello (ECH) advertised via HTTPS record for ${dispTarget}`,
      detail: `Decoded ECHConfigList: ${suiteSummary}. Clients supporting ECH encrypt the inner SNI using HPKE before the TLS handshake.`,
      rfc: 'RFC 9460 §7.1 / draft-ietf-tls-esni',
      targetId: httpsDnssec.rrset?.id,
    });
  }

  if (allDriftedV4.length > 0 || allDriftedV6.length > 0) {
    const driftedList = [...allDriftedV4, ...allDriftedV6];
    webFindings.push({
      id: `web-warn-https-ip-hint-drift-${targetName}`,
      severity: 'warning',
      code: 'HTTPS_IP_HINT_DRIFT',
      title: `HTTPS ipv4hint/ipv6hint drift detected for ${dispTarget} (${driftedList.join(', ')})`,
      detail: `The HTTPS record hints IP address(es) (${driftedList.join(', ')}) that do not appear in the domain's authoritative A/AAAA RRsets (${[...ipv4Addresses, ...ipv6Addresses].join(', ') || 'none'}). Stale IP hints cause connection timeouts or suboptimal routing.`,
      rfc: 'RFC 9460 §7.3',
      targetId: httpsDnssec.rrset?.id,
    });
  }

  for (const rec of [...httpsRecords, ...svcbRecords]) {
    if (rec.noDefaultAlpn && rec.alpns.length === 0) {
      webFindings.push({
        id: `web-err-https-no-default-alpn-${rec.ownerName}`,
        severity: 'error',
        code: 'HTTPS_NO_DEFAULT_ALPN_WITHOUT_ALPN',
        title: `HTTPS record at ${displayFqdn(rec.ownerName)} sets no-default-alpn without alpn`,
        detail: `Per RFC 9460 §7.1.2, "no-default-alpn" MUST be accompanied by a non-empty "alpn" SvcParam in the same record; otherwise clients have no usable ALPN protocol.`,
        rfc: 'RFC 9460 §7.1.2',
        targetId: httpsDnssec.rrset?.id,
      });
    }
  }

  // 4. Tree-Walking CAA Evaluation (RFC 8659 §3 & RFC 8657)
  // Build tree walk order: if targetName had CNAME(s), check targetName first, then effectiveDomain, then climb parents up to TLD.
  const climbNames: string[] = [];
  const pushClimb = (n: string) => {
    const norm = normalizeFqdn(n);
    if (norm !== '.' && !climbNames.includes(norm)) {
      climbNames.push(norm);
    }
  };
  pushClimb(targetName);
  for (const c of cnameChain) {
    pushClimb(c);
  }
  const targetAncestors = getDomainHierarchy(targetName).slice(1).reverse();
  for (const anc of targetAncestors) {
    pushClimb(anc);
  }
  const effectiveAncestors = getDomainHierarchy(effectiveDomain).slice(1).reverse();
  for (const anc of effectiveAncestors) {
    pushClimb(anc);
  }

  const caaHops: CaaTreeHop[] = [];
  let effectiveCaaHop: CaaTreeHop | undefined;

  climbNames.forEach((hopName, idx) => {
    const caaRes = resolveCnameChainInLogs(queries, hopName, RR_TYPES.CAA);
    const hopOwner = caaRes.finalOwner;
    const hopLog =
      findAnyLog(queries, hopOwner, RR_TYPES.CAA) ?? findAnyLog(queries, hopName, RR_TYPES.CAA);
    const hopDnssec = findEffectiveDnssecStatusForQuery(
      zones,
      hopName,
      caaRes.cnameChain,
      hopOwner,
      RR_TYPES.CAA,
      'CAA'
    );

    const hopRecords: CaaRecordEntry[] = [];
    for (const ans of hopLog?.packet.answers ?? []) {
      if ((ans.name === hopOwner || ans.name === hopName) && ans.type === RR_TYPES.CAA && ans.parsed.kind === 'CAA') {
        hopRecords.push(
          parseCaaRecordEntry(
            ans.name,
            ans.parsed.flags,
            ans.parsed.tag,
            ans.parsed.value
          )
        );
      }
    }

    const isEffective = !effectiveCaaHop && hopRecords.length > 0;
    const hopEntry: CaaTreeHop = {
      name: hopName,
      displayName: displayFqdn(hopName),
      depth: idx,
      dnssecStatus: hopDnssec.status,
      rrsetId: hopDnssec.rrset?.id,
      negativeNodeId: hopDnssec.negativeNode?.id,
      records: hopRecords,
      isEffectivePolicySource: isEffective,
    };
    if (isEffective) {
      effectiveCaaHop = hopEntry;
    }
    caaHops.push(hopEntry);
  });

  const caaIssues: string[] = [];
  const issueCas: string[] = [];
  const issuewildCas: string[] = [];
  const iodefUris: string[] = [];
  let hasAcmeAccountBinding = false;
  let hasCriticalUnknownTag = false;
  let hasEmptyIssueDeny = false;

  if (effectiveCaaHop) {
    for (const rec of effectiveCaaHop.records) {
      for (const iss of rec.issues) {
        if (!caaIssues.includes(iss)) caaIssues.push(iss);
      }
      if (rec.critical && !rec.recognizedTag) {
        hasCriticalUnknownTag = true;
      }
      if (rec.parameters.some((p) => p.key === 'accounturi' || p.key === 'validationmethods')) {
        hasAcmeAccountBinding = true;
      }
      if (rec.tag === 'issue') {
        if (rec.caDomain === '') {
          hasEmptyIssueDeny = true;
        } else if (rec.caDomain && !issueCas.includes(rec.caDomain)) {
          issueCas.push(rec.caDomain);
        }
      } else if (rec.tag === 'issuewild') {
        if (rec.caDomain !== undefined && !issuewildCas.includes(rec.caDomain || '; (deny all wildcards)')) {
          issuewildCas.push(rec.caDomain || '; (deny all wildcards)');
        }
      } else if (rec.tag === 'iodef') {
        if (rec.rawValue && !iodefUris.includes(rec.rawValue)) {
          iodefUris.push(rec.rawValue);
        }
      }
    }

    if (hasEmptyIssueDeny && issueCas.length > 0) {
      const msg = `CAA RRset at ${effectiveCaaHop.displayName} contains both an empty ";" deny tag and explicit issue tags (${issueCas.join(', ')}) — under RFC 8659 §4.2 the empty ";" tag is redundant when other issue tags authorize CAs`;
      caaIssues.push(msg);
      webFindings.push({
        id: `web-warn-caa-contradictory-${effectiveCaaHop.name}`,
        severity: 'warning',
        code: 'CAA_REDUNDANT_EMPTY_ISSUE',
        title: `CAA RRset at ${effectiveCaaHop.displayName} mixes empty ";" deny with authorized CAs`,
        detail: msg,
        rfc: 'RFC 8659 §4.2',
        targetId: effectiveCaaHop.rrsetId,
      });
    }

    if (hasCriticalUnknownTag) {
      webFindings.push({
        id: `web-err-caa-critical-unknown-${effectiveCaaHop.name}`,
        severity: 'error',
        code: 'CAA_CRITICAL_UNKNOWN_TAG',
        title: `CAA RRset at ${effectiveCaaHop.displayName} sets critical flag (0x80) on unrecognized tag`,
        detail: `Per RFC 8659 §3, all compliant Certificate Authorities MUST refuse to issue certificates when any CAA record carries an unrecognized tag with the issuer-critical bit set.`,
        rfc: 'RFC 8659 §3',
        targetId: effectiveCaaHop.rrsetId,
      });
    }

    if (hasAcmeAccountBinding) {
      webFindings.push({
        id: `web-info-caa-acme-binding-${effectiveCaaHop.name}`,
        severity: 'info',
        code: 'CAA_ACME_BINDING',
        title: `RFC 8657 CAA ACME account/method binding active at ${effectiveCaaHop.displayName}`,
        detail: `CAA policy restricts certificate issuance using RFC 8657 ACME parameters (accounturi / validationmethods).`,
        rfc: 'RFC 8657',
        targetId: effectiveCaaHop.rrsetId,
      });
    }
  } else {
    webFindings.push({
      id: `web-info-caa-missing-${targetName}`,
      severity: 'info',
      code: 'CAA_NOT_PUBLISHED',
      title: `No CAA policy found for ${dispTarget} (tree-walked ${caaHops.length} level${caaHops.length === 1 ? '' : 's'} to TLD)`,
      detail: `Without a CAA RRset at ${dispTarget} or its parent zones, any WebPKI-trusted Certificate Authority is permitted to issue TLS certificates for ${dispTarget} (RFC 8659).`,
      rfc: 'RFC 8659 §3',
      targetId: caaHops[0]?.negativeNodeId,
    });
  }

  let caaStatus: WebCaaAnalysis['status'] = 'unprotected';
  let caaSummary = '';
  if (!effectiveCaaHop) {
    caaStatus = 'unprotected';
    caaSummary = `No CAA records found across tree walk (${caaHops.map((h) => h.displayName).join(' → ')}). Any public CA may issue certificates.`;
  } else if (
    hasCriticalUnknownTag ||
    effectiveCaaHop.dnssecStatus === 'bogus' ||
    effectiveCaaHop.records.some((r) => !r.valid)
  ) {
    caaStatus = 'invalid';
    caaSummary = `CAA policy at ${effectiveCaaHop.displayName} has validation errors: ${caaIssues[0] ?? 'DNSSEC validation failed'}.`;
  } else if (issueCas.length === 0 && !hasEmptyIssueDeny) {
    caaStatus = 'permissive';
    caaSummary = `CAA RRset at ${effectiveCaaHop.displayName} contains no "issue" property (${issuewildCas.length > 0 ? `issuewild=${issuewildCas.join(', ')}` : 'only non-issue tags'}) — non-wildcard issuance is not restricted.`;
    webFindings.push({
      id: `web-warn-caa-no-issue-${effectiveCaaHop.name}`,
      severity: 'warning',
      code: 'CAA_NO_ISSUE_TAG',
      title: `CAA RRset at ${effectiveCaaHop.displayName} lacks an "issue" tag`,
      detail: `Per RFC 8659 §4.2, if a CAA RRset exists but contains no "issue" property tag, any CA is permitted to issue non-wildcard certificates.`,
      rfc: 'RFC 8659 §4.2',
      targetId: effectiveCaaHop.rrsetId,
    });
  } else if (effectiveCaaHop.name === targetName || effectiveCaaHop.name === effectiveDomain) {
    caaStatus = 'enforced';
    caaSummary = hasEmptyIssueDeny && issueCas.length === 0
      ? `CAA policy at ${effectiveCaaHop.displayName} explicitly forbids all TLS certificate issuance (issue ";").`
      : `CAA policy enforced directly at ${effectiveCaaHop.displayName}: authorized CAs = ${issueCas.join(', ')}${hasAcmeAccountBinding ? ' (with RFC 8657 ACME binding)' : ''}.`;
  } else {
    caaStatus = 'inherited';
    caaSummary = `CAA policy inherited via RFC 8659 tree-walk from parent ${effectiveCaaHop.displayName}: authorized CAs = ${issueCas.join(', ') || '; (deny all)'}.`;
  }

  const caaAnalysis: WebCaaAnalysis = {
    status: caaStatus,
    effectiveOwner: effectiveCaaHop?.name,
    dnssecStatus: effectiveCaaHop?.dnssecStatus ?? caaHops[0]?.dnssecStatus ?? targetDomainStatus,
    hops: caaHops,
    issueCas,
    issuewildCas,
    iodefUris,
    hasAcmeAccountBinding,
    hasCriticalUnknownTag,
    issues: caaIssues,
    summary: caaSummary,
  };

  // 5. Evaluate Web DANE (`_443._tcp.<effectiveDomain>` TLSA)
  const tlsaQname = normalizeFqdn(`_443._tcp.${effectiveDomain}`);
  const tlsaChainRes = resolveCnameChainInLogs(queries, tlsaQname, RR_TYPES.TLSA);
  const tlsaLog =
    findAnyLog(queries, tlsaChainRes.finalOwner, RR_TYPES.TLSA) ??
    findAnyLog(queries, tlsaQname, RR_TYPES.TLSA);
  const tlsaDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    tlsaQname,
    tlsaChainRes.cnameChain,
    tlsaChainRes.finalOwner,
    RR_TYPES.TLSA,
    'TLSA'
  );

  const tlsaRecords: TlsaRecordDetail[] = [];
  for (const ans of tlsaLog?.packet.answers ?? []) {
    if (
      (ans.name === tlsaChainRes.finalOwner || ans.name === tlsaQname) &&
      ans.type === RR_TYPES.TLSA &&
      ans.parsed.kind === 'TLSA'
    ) {
      tlsaRecords.push(
        evaluateTlsaRecordDetail(
          ans.name,
          ans.ttl,
          ans.parsed.usage,
          ans.parsed.selector,
          ans.parsed.matchingType,
          ans.parsed.certAssociationHex
        )
      );
    }
  }

  let webDaneStatus: DaneHostStatus = 'no-tlsa-unsigned';
  let webDaneSummary = '';
  const rolloverReady = tlsaRecords.length >= 2;

  if (tlsaDnssec.status === 'bogus') {
    webDaneStatus = 'dane-bogus';
    webDaneSummary = `Web DANE TLSA at ${displayFqdn(tlsaQname)} failed DNSSEC validation (BOGUS).`;
  } else if (tlsaRecords.length === 0) {
    webDaneStatus =
      tlsaDnssec.status === 'secure' || tlsaDnssec.status === 'warning'
        ? 'no-tlsa-secure'
        : 'no-tlsa-unsigned';
    webDaneSummary =
      webDaneStatus === 'no-tlsa-secure'
        ? `No _443._tcp TLSA record published for ${dispTarget} (authenticated NSEC/NSEC3 absence proof).`
        : `No _443._tcp TLSA record published for ${dispTarget}.`;
  } else if (tlsaDnssec.status === 'insecure') {
    webDaneStatus = 'dane-unsigned-ignored';
    webDaneSummary = `UNUSABLE Web DANE: ${tlsaRecords.length} TLSA record(s) published at ${displayFqdn(tlsaQname)}, but zone is unsigned (INSECURE) — DANE requires DNSSEC!`;
    webFindings.push({
      id: `web-warn-dane-unsigned-${tlsaQname}`,
      severity: 'warning',
      code: 'WEB_DANE_UNSIGNED',
      title: `_443._tcp TLSA record at ${displayFqdn(tlsaQname)} is unsigned (ignored by DANE validators)`,
      detail: `Per RFC 6698 §4, TLSA records MUST be validated with DNSSEC. Because ${displayFqdn(tlsaQname)} is in an unsigned zone, clients cannot trust these TLSA bindings.`,
      rfc: 'RFC 6698 §4',
      targetId: tlsaDnssec.rrset?.id,
    });
  } else if (tlsaRecords.some((r) => !r.rdataValid)) {
    webDaneStatus = 'dane-warning';
    webDaneSummary = `Web DANE TLSA published at ${displayFqdn(tlsaQname)} with malformed RDATA parameters.`;
  } else {
    webDaneStatus = 'dane-valid';
    webDaneSummary = `DNSSEC-validated _443._tcp DANE TLSA active (${tlsaRecords.map((r) => `${r.usageMnemonic} ${r.selectorMnemonic} ${r.matchingTypeMnemonic}`).join(', ')}).`;
  }

  // 6. Evaluate SSHFP (`TYPE44`)
  const sshfpLog =
    findAnyLog(queries, effectiveDomain, RR_TYPES.SSHFP) ??
    findAnyLog(queries, targetName, RR_TYPES.SSHFP);
  const sshfpDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    cnameChain,
    effectiveDomain,
    RR_TYPES.SSHFP,
    'SSHFP'
  );

  const sshfpRecords: SshfpRecordDetail[] = [];
  for (const ans of sshfpLog?.packet.answers ?? []) {
    if (
      (ans.name === effectiveDomain || ans.name === targetName) &&
      ans.type === RR_TYPES.SSHFP &&
      ans.parsed.kind === 'SSHFP'
    ) {
      const fpInfo = SSHFP_FP_TYPES[ans.parsed.fpType];
      const issues: string[] = [];
      let valid = true;
      const deprecated = ans.parsed.fpType === 1 || ans.parsed.algorithm === 2;

      if (!fpInfo) {
        valid = false;
        issues.push(`Unassigned SSHFP fingerprint type ${ans.parsed.fpType}`);
      } else if (ans.parsed.fingerprintHex.length !== fpInfo.expectedHexLength) {
        valid = false;
        issues.push(
          `${fpInfo.name} fingerprint must be ${fpInfo.expectedHexLength} hex chars, got ${ans.parsed.fingerprintHex.length}`
        );
      }

      if (ans.parsed.fpType === 1) {
        issues.push('SHA-1 SSHFP fingerprint is deprecated in favor of SHA-256 (RFC 6594 / RFC 7479)');
      }
      if (ans.parsed.algorithm === 2) {
        issues.push('DSA (algorithm 2) SSH host keys are deprecated');
      }

      sshfpRecords.push({
        ownerName: ans.name,
        ttl: ans.ttl,
        algorithm: ans.parsed.algorithm,
        algorithmName: ans.parsed.algorithmName,
        fpType: ans.parsed.fpType,
        fpTypeName: ans.parsed.fpTypeName,
        fingerprintHex: ans.parsed.fingerprintHex,
        deprecated,
        valid,
        issues,
      });
    }
  }

  let sshfpStatus: WebAnalysisResult['sshfp']['status'] = 'not-deployed';
  let sshfpSummary = '';
  if (sshfpRecords.length === 0) {
    sshfpStatus = 'not-deployed';
    sshfpSummary = `No SSHFP (TYPE44) host key fingerprints published at ${dispTarget}.`;
  } else if (sshfpDnssec.status === 'bogus') {
    sshfpStatus = 'bogus';
    sshfpSummary = `SSHFP RRset at ${dispTarget} failed DNSSEC validation (BOGUS).`;
  } else if (sshfpDnssec.status === 'insecure') {
    sshfpStatus = 'insecure-ignored';
    sshfpSummary = `${sshfpRecords.length} SSHFP record(s) published at ${dispTarget}, but zone is unsigned (INSECURE) — OpenSSH VerifyHostKeyDNS requires DNSSEC (AD=1)!`;
    webFindings.push({
      id: `web-warn-sshfp-unsigned-${effectiveDomain}`,
      severity: 'warning',
      code: 'SSHFP_UNSIGNED',
      title: `SSHFP records at ${dispTarget} are unsigned (ignored by OpenSSH VerifyHostKeyDNS)`,
      detail: `Per RFC 4255 §3, SSH clients MUST NOT implicitly trust SSHFP records unless authenticated with DNSSEC.`,
      rfc: 'RFC 4255 §3',
      targetId: sshfpDnssec.rrset?.id,
    });
  } else if (
    sshfpRecords.some((r) => !r.valid) ||
    sshfpRecords.every((r) => r.deprecated)
  ) {
    sshfpStatus = 'warning';
    sshfpSummary = `SSHFP records at ${dispTarget} use deprecated SHA-1/DSA or invalid parameters.`;
    webFindings.push({
      id: `web-warn-sshfp-deprecated-${effectiveDomain}`,
      severity: 'warning',
      code: 'SSHFP_DEPRECATED_CRYPTO',
      title: `SSHFP RRset at ${dispTarget} relies only on deprecated SHA-1 or DSA fingerprints`,
      detail: `Publish SHA-256 (fingerprint type 2) SSHFP records for Ed25519/ECDSA/RSA host keys (RFC 6594 / RFC 7479).`,
      rfc: 'RFC 6594 / RFC 7479',
      targetId: sshfpDnssec.rrset?.id,
    });
  } else {
    sshfpStatus = 'secure';
    const algos = Array.from(new Set(sshfpRecords.map((r) => `${r.algorithmName}/${r.fpTypeName}`)));
    sshfpSummary = `DNSSEC-validated SSHFP host key fingerprints active (${algos.join(', ')}).`;
  }

  const webAnalysis: WebAnalysisResult = {
    targetDomain: targetName,
    displayDomain: dispTarget,
    cnameChain,
    ipv4Addresses,
    ipv6Addresses,
    addressDnssecStatus,
    httpsStatus,
    httpsDnssecStatus: httpsDnssec.status,
    httpsRrsetId: httpsDnssec.rrset?.id,
    httpsNegativeNodeId: httpsDnssec.negativeNode?.id,
    httpsRecords,
    svcbRecords,
    supportsHttp3,
    supportsHttp2,
    echEnabled,
    echPublicNames,
    ipHintStatus,
    httpsSummary,
    caa: caaAnalysis,
    webDane: {
      qname: tlsaQname,
      resolvedOwner: tlsaChainRes.finalOwner,
      cnameChain: tlsaChainRes.cnameChain,
      status: webDaneStatus,
      dnssecStatus: tlsaDnssec.status,
      rrsetId: tlsaDnssec.rrset?.id,
      negativeNodeId: tlsaDnssec.negativeNode?.id,
      records: tlsaRecords,
      rolloverReady,
      summary: webDaneSummary,
    },
    sshfp: {
      present: sshfpRecords.length > 0,
      status: sshfpStatus,
      dnssecStatus: sshfpDnssec.status,
      rrsetId: sshfpDnssec.rrset?.id,
      negativeNodeId: sshfpDnssec.negativeNode?.id,
      records: sshfpRecords,
      summary: sshfpSummary,
    },
  };

  // Synthesize overall status & summary for Web mode
  let overallStatus: ValidationStatus = targetDomainStatus;
  if (
    httpsStatus === 'bogus' ||
    caaStatus === 'invalid' ||
    webDaneStatus === 'dane-bogus' ||
    sshfpStatus === 'bogus'
  ) {
    overallStatus = 'bogus';
  } else if (
    webFindings.some((f) => f.severity === 'error' || f.severity === 'warning') &&
    overallStatus === 'secure'
  ) {
    overallStatus = 'warning';
  }

  const parts: string[] = [];
  if (httpsRecords.length > 0) {
    parts.push(
      `HTTPS (${supportsHttp3 ? 'HTTP/3' : supportsHttp2 ? 'HTTP/2' : 'SVCB'}${echEnabled ? ' + ECH' : ''})`
    );
  } else {
    parts.push('No HTTPS RR');
  }
  parts.push(
    caaStatus === 'enforced'
      ? `CAA enforced (${issueCas.join(', ') || 'deny'})`
      : caaStatus === 'inherited'
        ? `CAA inherited from ${ displayFqdn(effectiveCaaHop?.name ?? '') }`
        : caaStatus === 'unprotected'
          ? 'CAA unprotected'
          : `CAA ${caaStatus}`
  );
  if (tlsaRecords.length > 0) {
    parts.push(`_443._tcp DANE (${webDaneStatus})`);
  }
  if (sshfpRecords.length > 0) {
    parts.push(`SSHFP (${sshfpStatus})`);
  }

  const overallSummary = `Web & TLS analysis for ${dispTarget}: ${parts.join(' · ')}.`;

  return {
    webAnalysis,
    webFindings,
    overallStatus,
    overallSummary,
  };
}

/**
 * Runs a full live client-side Web & HTTPS DNS analysis (`HTTPS`/`SVCB`, ECH, tree-walking `CAA`,
 * `_443._tcp` DANE `TLSA`, and `SSHFP`) with DNSSEC verification via 1.1.1.1 DoH.
 */
export async function runWebAnalysis(
  rawDomain: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisSnapshot> {
  const startedAt = Date.now();
  const targetName = normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const queryTypes = ['A', 'AAAA', 'HTTPS', 'SVCB', 'CAA', 'TLSA', 'SSHFP'];
  const trustAnchors = options.trustAnchors ?? IANA_ROOT_TRUST_ANCHORS;
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;

  const session = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs,
    fetchImpl: options.fetchImpl,
  });

  let currentPhase: AnalysisProgress['phase'] = 'web-https';
  session.onQueryCompleted = (count, lastLog) => {
    options.onProgress?.({
      phase: currentPhase,
      message: `Resolved ${lastLog.qname} ${lastLog.qtypeName} (${lastLog.latencyMs}ms)`,
      completedQueries: count,
    });
  };

  options.onProgress?.({
    phase: 'web-https',
    message: `Querying A, AAAA, HTTPS (TYPE65), SVCB & CAA for ${displayDomain}…`,
    completedQueries: 0,
  });

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);

  // Step 1: Discover zone cuts + query A, AAAA, HTTPS, SVCB, CAA, SSHFP at targetName (+ CD=0 validating check)
  await Promise.all([
    discoverZoneCutsForName(session, targetName, discoveredZones, checkedCandidates),
    session.query(targetName, RR_TYPES.A, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} A)`,
    }),
    session.query(targetName, RR_TYPES.AAAA, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} AAAA)`,
    }),
    session.query(targetName, RR_TYPES.HTTPS, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} HTTPS)`,
    }),
    session.query(targetName, RR_TYPES.SVCB, {
      cd: true,
      doBit: true,
      purpose: `Web target (${targetName} SVCB)`,
    }),
    session.query(targetName, RR_TYPES.CAA, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} CAA)`,
    }),
    session.query(targetName, RR_TYPES.SSHFP, {
      cd: true,
      doBit: true,
      purpose: `Web target (${targetName} SSHFP)`,
    }),
    session.query(targetName, RR_TYPES.HTTPS, {
      cd: false,
      doBit: true,
      purpose: 'Resolver validating check (CD=0)',
    }),
  ]);

  // Follow any CNAME chain on targetName
  let effectiveDomain = targetName;
  const visitedCnames = new Set<string>([targetName]);
  for (let hop = 0; hop < 6; hop++) {
    const logsNow = session.getLogs();
    const res = resolveCnameChainInLogs(logsNow, effectiveDomain, RR_TYPES.A);
    const nextUnvisited = res.cnameChain.find((c) => !visitedCnames.has(c));
    if (!nextUnvisited) {
      effectiveDomain = res.finalOwner;
      break;
    }
    visitedCnames.add(nextUnvisited);
    effectiveDomain = nextUnvisited;
    await Promise.all([
      discoverZoneCutsForName(session, nextUnvisited, discoveredZones, checkedCandidates),
      session.query(nextUnvisited, RR_TYPES.A, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} A)`,
      }),
      session.query(nextUnvisited, RR_TYPES.AAAA, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} AAAA)`,
      }),
      session.query(nextUnvisited, RR_TYPES.HTTPS, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} HTTPS)`,
      }),
      session.query(nextUnvisited, RR_TYPES.CAA, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} CAA)`,
      }),
      session.query(nextUnvisited, RR_TYPES.SSHFP, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} SSHFP)`,
      }),
    ]);
  }

  // If HTTPS returned AliasMode (priority 0) to another target name, query that target's HTTPS/A/AAAA
  const httpsLog = findAnyLog(session.getLogs(), effectiveDomain, RR_TYPES.HTTPS);
  const aliasTargets = (httpsLog?.packet.answers ?? [])
    .filter(
      (r) =>
        r.type === RR_TYPES.HTTPS &&
        r.parsed.kind === 'SVCB' &&
        r.parsed.isAliasMode &&
        r.parsed.target !== '.' &&
        !visitedCnames.has(r.parsed.target)
    )
    .map((r) => (r.parsed as SvcbRdata).target);

  if (aliasTargets.length > 0) {
    await Promise.all(
      aliasTargets.flatMap((aliasTarget) => [
        discoverZoneCutsForName(session, aliasTarget, discoveredZones, checkedCandidates),
        session.query(aliasTarget, RR_TYPES.HTTPS, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} HTTPS)`,
        }),
        session.query(aliasTarget, RR_TYPES.A, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} A)`,
        }),
        session.query(aliasTarget, RR_TYPES.AAAA, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} AAAA)`,
        }),
      ])
    );
  }

  // Step 2: RFC 8659 Tree-Walking CAA up the domain hierarchy (from parent up to TLD)
  currentPhase = 'web-caa';
  const caaHierarchyToProbe = Array.from(
    new Set([
      ...getDomainHierarchy(targetName).slice(1),
      ...getDomainHierarchy(effectiveDomain).slice(1),
    ])
  ).filter((n) => !visitedCnames.has(n));

  if (caaHierarchyToProbe.length > 0) {
    options.onProgress?.({
      phase: 'web-caa',
      message: `Climbing RFC 8659 CAA hierarchy (${caaHierarchyToProbe.map(displayFqdn).join(' → ')})…`,
      completedQueries: session.getLogs().length,
    });
    await Promise.all(
      caaHierarchyToProbe.map((anc) =>
        session.query(anc, RR_TYPES.CAA, {
          cd: true,
          doBit: true,
          purpose: `Web target (${anc} CAA)`,
        })
      )
    );
  }

  // Step 3: Probe _443._tcp.<effectiveDomain> TLSA (Web DANE)
  currentPhase = 'web-dane';
  const tlsaOwner = normalizeFqdn(`_443._tcp.${effectiveDomain}`);
  options.onProgress?.({
    phase: 'web-dane',
    message: `Probing _443._tcp DANE TLSA at ${displayFqdn(tlsaOwner)}…`,
    completedQueries: session.getLogs().length,
  });

  await Promise.all([
    discoverZoneCutsForName(session, tlsaOwner, discoveredZones, checkedCandidates),
    session.query(tlsaOwner, RR_TYPES.TLSA, {
      cd: true,
      doBit: true,
      purpose: `Web target (${tlsaOwner} TLSA)`,
    }),
  ]);

  // Follow any CNAME chain on _443._tcp.<effectiveDomain> TLSA
  const visitedTlsaCnames = new Set<string>([tlsaOwner]);
  for (let hop = 0; hop < 4; hop++) {
    const res = resolveCnameChainInLogs(session.getLogs(), tlsaOwner, RR_TYPES.TLSA);
    const nextC = res.cnameChain.find((c) => !visitedTlsaCnames.has(c));
    if (!nextC) break;
    visitedTlsaCnames.add(nextC);
    await Promise.all([
      discoverZoneCutsForName(session, nextC, discoveredZones, checkedCandidates),
      session.query(nextC, RR_TYPES.TLSA, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextC} TLSA)`,
      }),
    ]);
  }

  // Include any authoritative SOA zones returned in CD=1 responses
  for (const log of session.getLogs()) {
    if (!log.cd || log.purpose.startsWith('Nameserver IP')) continue;
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Step 4: Fetch DNSKEY, DS, SOA & NS across all discovered zones for WebCrypto verification
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

  currentPhase = 'validating';
  options.onProgress?.({
    phase: 'validating',
    message: 'Verifying DNSSEC, HTTPS/SVCB, ECH, CAA & Web DANE via WebCrypto…',
    completedQueries: session.getLogs().length,
  });

  const capturedAt = Date.now();
  const validatedAt = options.validationTimeMs ?? capturedAt;
  const durationMs = Math.max(1, capturedAt - startedAt);

  return evaluateSnapshotFromLogs({
    id: `snap-${capturedAt}-${Math.random().toString(36).slice(2, 8)}`,
    mode: 'web',
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
