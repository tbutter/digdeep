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
import { parseEmailDaneInput } from './emailDane';
import {
  countDnsLabels,
  displayFqdn,
  getDomainHierarchy,
  isSubdomainOrEqual,
  normalizeFqdn,
} from './encoding';
import { formatCanonicalIpv6, parseIpv6Groups } from './ipUtils';
import type {
  AnalysisProgress,
  AnalysisSnapshot,
  AnalyzedRrset,
  AuditFinding,
  CaaRecordEntry,
  CaaTreeHop,
  CnameEdge,
  CtCertificateEntry,
  CtIssuerSummary,
  CtLogFetchResult,
  CtSubdomainCaaPolicy,
  DaneHostStatus,
  DohQueryLog,
  EchConfigEntry,
  NegativeNode,
  RawCtIssuanceEntry,
  SshfpRecordDetail,
  SvcParamEntry,
  SvcbRdata,
  TlsaRecordDetail,
  ValidationStatus,
  WebAnalysisResult,
  WebCaaAnalysis,
  WebCtAnalysis,
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

const CT_CA_DOMAIN_MAPPINGS: Array<{
  pattern: RegExp;
  caaDomains: string[];
}> = [
  {
    pattern: /\b(let'?s\s*encrypt|letsencrypt|isrg\b|cn=(?:r3|r10|r11|r12|r13|r14|e1|e5|e6|e7|e8|e9)\b)/i,
    caaDomains: ['letsencrypt.org'],
  },
  {
    pattern: /\b(google\s+trust\s+services|gts\s+ca|cn=(?:wr1|wr2|wr3|we1|we2|gts\s+ca))\b/i,
    caaDomains: ['pki.goog'],
  },
  {
    pattern: /\b(digicert|geotrust|thawte|rapidssl|quovadis|encryption\s+everywhere|symantec)\b/i,
    caaDomains: [
      'digicert.com',
      'geotrust.com',
      'thawte.com',
      'rapidssl.com',
      'quovadisglobal.com',
      'symantec.com',
    ],
  },
  {
    pattern: /\b(sectigo|comodo|zerossl|usertrust|incommon|gandi|trust-provider)\b/i,
    caaDomains: [
      'sectigo.com',
      'comodoca.com',
      'usertrust.com',
      'incommon.org',
      'gandi.net',
      'trust-provider.com',
    ],
  },
  {
    pattern: /\b(amazon|amazontrust|awstrust|starfield)\b/i,
    caaDomains: [
      'amazon.com',
      'amazontrust.com',
      'awstrust.com',
      'amazonaws.com',
      'starfieldtech.com',
    ],
  },
  {
    pattern: /\b(ssl\.com|ssl\s+corporation)\b/i,
    caaDomains: ['ssl.com'],
  },
  {
    pattern: /\b(globalsign|alphassl)\b/i,
    caaDomains: ['globalsign.com'],
  },
  {
    pattern: /\b(entrust)\b/i,
    caaDomains: ['entrust.net'],
  },
  {
    pattern: /\b(godaddy|go\s*daddy)\b/i,
    caaDomains: ['godaddy.com', 'starfieldtech.com'],
  },
  {
    pattern: /\b(cloudflare)\b/i,
    caaDomains: ['cloudflare.com', 'comodoca.com', 'digicert.com', 'letsencrypt.org', 'pki.goog', 'ssl.com'],
  },
  {
    pattern: /\b(harica|hellenic\s+academic)\b/i,
    caaDomains: ['harica.gr'],
  },
  {
    pattern: /\b(buypass)\b/i,
    caaDomains: ['buypass.com', 'buypass.no'],
  },
  {
    pattern: /\b(actalis)\b/i,
    caaDomains: ['actalis.it'],
  },
  {
    pattern: /\b(certum|asseco)\b/i,
    caaDomains: ['certum.pl'],
  },
  {
    pattern: /\b(swisssign)\b/i,
    caaDomains: ['swisssign.com'],
  },
  {
    pattern: /\b(microsoft)\b/i,
    caaDomains: ['microsoft.com'],
  },
  {
    pattern: /\b(apple)\b/i,
    caaDomains: ['apple.com'],
  },
  {
    pattern: /\b(identrust)\b/i,
    caaDomains: ['identrust.com'],
  },
  {
    pattern: /\b(trustwave|securetrust|vikingcloud)\b/i,
    caaDomains: ['trustwave.com', 'securetrust.com'],
  },
  {
    pattern: /\b(telia)\b/i,
    caaDomains: ['telia.com', 'telia.fi'],
  },
  {
    pattern: /\b(certigna|dhimyotis)\b/i,
    caaDomains: ['certigna.fr'],
  },
  {
    pattern: /\b(firmaprofesional)\b/i,
    caaDomains: ['firmaprofesional.com'],
  },
  {
    pattern: /\b(dfn-verein|dfn-pki|deutsche\s+forschungsnetz)\b/i,
    caaDomains: ['dfn.de', 'harica.gr', 'sectigo.com'],
  },
  {
    pattern: /\b(g[eé]ant|terena)\b/i,
    caaDomains: ['sectigo.com', 'comodoca.com', 'harica.gr', 'geant.org'],
  },
];

/**
 * Maps a Certificate Transparency X.509 issuer (`friendly_name` and Distinguished Name `issuerDn`)
 * to its corresponding RFC 8659 `CAA` issuer domain name(s) (e.g. `letsencrypt.org`, `pki.goog`).
 */
export function mapCtIssuerToCaaDomains(
  friendlyName: string,
  issuerDn: string,
  candidateCaaDomains: string[] = []
): string[] {
  const combined = `${friendlyName} ${issuerDn}`;
  const matched = new Set<string>();

  for (const rule of CT_CA_DOMAIN_MAPPINGS) {
    if (rule.pattern.test(combined)) {
      for (const dom of rule.caaDomains) {
        matched.add(dom);
      }
    }
  }

  const lowerCombined = combined.toLowerCase();
  for (const cand of candidateCaaDomains) {
    const cleanCand = cand.trim().toLowerCase().replace(/\.$/, '');
    if (!cleanCand || cleanCand.startsWith(';')) continue;
    if (lowerCombined.includes(cleanCand)) {
      matched.add(cleanCand);
      continue;
    }
    const baseLabel = cleanCand.split('.')[0];
    if (baseLabel && baseLabel.length >= 4 && lowerCombined.includes(baseLabel)) {
      matched.add(cleanCand);
    }
  }

  return Array.from(matched);
}

/**
 * Parses a CertSpotter `/v1/issuances` JSON array into normalized `RawCtIssuanceEntry[]`.
 */
export function parseCertSpotterJson(rawJson: unknown): RawCtIssuanceEntry[] {
  if (!Array.isArray(rawJson)) return [];
  const entries: RawCtIssuanceEntry[] = [];

  for (const item of rawJson) {
    if (!item || typeof item !== 'object') continue;
    const obj = item as Record<string, unknown>;
    const id = String(obj.id ?? '').trim();
    const rawNames = Array.isArray(obj.dns_names) ? obj.dns_names : [];
    const dnsNames = Array.from(
      new Set(
        rawNames
          .map((n) => String(n ?? '').trim().toLowerCase().replace(/\.$/, ''))
          .filter(Boolean)
      )
    );
    const issuerObj =
      obj.issuer && typeof obj.issuer === 'object'
        ? (obj.issuer as Record<string, unknown>)
        : {};
    const issuerFriendlyName = String(issuerObj.friendly_name ?? '').trim();
    const issuerDn = String(issuerObj.name ?? '').trim();
    const notBefore = String(obj.not_before ?? '').trim();
    const notAfter = String(obj.not_after ?? '').trim();
    const revoked = Boolean(obj.revoked);
    const certSha256 =
      typeof obj.cert_sha256 === 'string' && obj.cert_sha256.trim().length > 0
        ? obj.cert_sha256.trim().toLowerCase()
        : undefined;
    const pubkeySha256 =
      typeof obj.pubkey_sha256 === 'string' && obj.pubkey_sha256.trim().length > 0
        ? obj.pubkey_sha256.trim().toLowerCase()
        : undefined;
    const issuerPubkeySha256 =
      typeof issuerObj.pubkey_sha256 === 'string' && issuerObj.pubkey_sha256.trim().length > 0
        ? issuerObj.pubkey_sha256.trim().toLowerCase()
        : undefined;

    if (!id && dnsNames.length === 0) continue;
    entries.push({
      id: id || `${notBefore}-${dnsNames[0] ?? 'cert'}`,
      dnsNames,
      issuerFriendlyName: issuerFriendlyName || extractFriendlyIssuerFromDn(issuerDn),
      issuerDn,
      notBefore,
      notAfter,
      revoked,
      certSha256,
      pubkeySha256,
      issuerPubkeySha256,
    });
  }

  return entries;
}

function extractFriendlyIssuerFromDn(dn: string): string {
  const oMatch = dn.match(/(?:^|,\s*)O=([^,]+)/i);
  if (oMatch?.[1]) return oMatch[1].trim().replace(/^"|"$/g, '');
  const cnMatch = dn.match(/(?:^|,\s*)CN=([^,]+)/i);
  if (cnMatch?.[1]) return cnMatch[1].trim().replace(/^"|"$/g, '');
  return dn.trim() || 'Unknown CA';
}

/**
 * Parses a `crt.sh/?q=<domain>&output=json` JSON array into normalized `RawCtIssuanceEntry[]`.
 */
export function parseCrtShJson(rawJson: unknown): RawCtIssuanceEntry[] {
  if (!Array.isArray(rawJson)) return [];
  const entries: RawCtIssuanceEntry[] = [];
  const seenIds = new Set<string>();

  for (const item of rawJson) {
    if (!item || typeof item !== 'object') continue;
    const obj = item as Record<string, unknown>;
    const id = String(obj.id ?? obj.min_cert_id ?? '').trim();
    if (id && seenIds.has(id)) continue;
    if (id) seenIds.add(id);

    const nameVal = String(obj.name_value ?? '');
    const commonName = String(obj.common_name ?? '');
    const dnsNames = Array.from(
      new Set(
        [...nameVal.split(/\r?\n/), commonName]
          .map((n) => n.trim().toLowerCase().replace(/\.$/, ''))
          .filter(Boolean)
      )
    );
    const issuerDn = String(obj.issuer_name ?? '').trim();
    const notBefore = String(obj.not_before ?? '').trim();
    const notAfter = String(obj.not_after ?? '').trim();
    if (dnsNames.length === 0) continue;

    entries.push({
      id: id || `${notBefore}-${dnsNames[0]}`,
      dnsNames,
      issuerFriendlyName: extractFriendlyIssuerFromDn(issuerDn),
      issuerDn,
      notBefore,
      notAfter,
      revoked: false,
    });
  }

  return entries;
}

const ctFetchCache = new Map<string, CtLogFetchResult>();

export function clearCtFetchCache(): void {
  ctFetchCache.clear();
}

export function seedCtFetchCache(
  domain: string,
  result: CtLogFetchResult,
  includeSubdomains = false
): void {
  const clean = displayFqdn(normalizeFqdn(domain)).toLowerCase();
  ctFetchCache.set(`${clean}|${includeSubdomains ? 'sub' : 'direct'}`, result);
}

/**
 * Queries CORS-enabled Certificate Transparency logs (`api.certspotter.com` with `crt.sh` fallback)
 * for certificates covering `domain`.
 */
export async function fetchCtLogEntries(
  domain: string,
  options: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    includeSubdomains?: boolean;
    bypassCache?: boolean;
  } = {}
): Promise<CtLogFetchResult> {
  const cleanDomain = displayFqdn(normalizeFqdn(domain)).toLowerCase();
  const includeSub = Boolean(options.includeSubdomains);
  const cacheKey = `${cleanDomain}|${includeSub ? 'sub' : 'direct'}`;
  if (!options.bypassCache) {
    const cached = ctFetchCache.get(cacheKey);
    if (cached) return cached;
  }

  const fetchFn = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const certSpotterUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanDomain)}&include_subdomains=${includeSub ? 'true' : 'false'}&expand=dns_names&expand=issuer`;

  if (!fetchFn || !cleanDomain || cleanDomain === '.' || !cleanDomain.includes('.')) {
    return {
      source: 'unavailable',
      url: certSpotterUrl,
      fetchedAt: Date.now(),
      ok: false,
      includeSubdomains: includeSub,
      entries: [],
      error: 'CT log lookup unavailable for this target',
    };
  }

  const timeoutMs = options.timeoutMs ?? 4500;

  const tryCertSpotter = async (subFlag: boolean): Promise<CtLogFetchResult> => {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanDomain)}&include_subdomains=${subFlag ? 'true' : 'false'}&expand=dns_names&expand=issuer`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchFn(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!res.ok) {
        return {
          source: 'certspotter',
          url,
          fetchedAt: Date.now(),
          ok: false,
          httpStatus: res.status,
          includeSubdomains: subFlag,
          entries: [],
          error: `CertSpotter HTTP ${res.status}`,
        };
      }
      const ctype = res.headers?.get?.('content-type') ?? '';
      if (ctype.includes('application/dns-message')) {
        return {
          source: 'unavailable',
          url,
          fetchedAt: Date.now(),
          ok: false,
          includeSubdomains: subFlag,
          entries: [],
          error: 'Mock DoH transport active (skipped external CT HTTP query)',
        };
      }
      const data = await res.json();
      const entries = parseCertSpotterJson(data);
      return {
        source: 'certspotter',
        url,
        fetchedAt: Date.now(),
        ok: true,
        httpStatus: res.status,
        includeSubdomains: subFlag,
        entries,
      };
    } catch (err) {
      return {
        source: 'certspotter',
        url,
        fetchedAt: Date.now(),
        ok: false,
        includeSubdomains: subFlag,
        entries: [],
        error: err instanceof Error ? err.message : String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  };

  let primary = await tryCertSpotter(includeSub);

  // If direct domain lookup succeeded with 0 entries and includeSubdomains was false, try include_subdomains=true once
  if (primary.ok && primary.entries.length === 0 && !includeSub) {
    const subAttempt = await tryCertSpotter(true);
    if (subAttempt.ok && subAttempt.entries.length > 0) {
      primary = subAttempt;
    }
  }

  if (primary.ok) {
    ctFetchCache.set(cacheKey, primary);
    return primary;
  }

  // If mock DoH transport was detected, do not attempt crt.sh
  if (primary.source === 'unavailable') {
    return primary;
  }

  // Fallback to crt.sh JSON endpoint
  const crtUrl = `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json&exclude=expired&deduplicate=Y`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, 3500));
  try {
    const res = await fetchFn(crtUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (res.ok) {
      const data = await res.json();
      const entries = parseCrtShJson(data);
      const fallbackResult: CtLogFetchResult = {
        source: 'crt.sh',
        url: crtUrl,
        fetchedAt: Date.now(),
        ok: true,
        httpStatus: res.status,
        includeSubdomains: true,
        entries,
      };
      ctFetchCache.set(cacheKey, fallbackResult);
      return fallbackResult;
    }
  } catch {
    // Keep primary error
  } finally {
    clearTimeout(timer);
  }

  return primary;
}

function isValidDiscoveredSubdomain(candidate: string, baseDomain: string): boolean {
  if (!candidate || candidate === baseDomain) return false;
  if (!candidate.endsWith(`.${baseDomain}`)) return false;
  if (candidate.includes('*') || candidate.includes(' ') || candidate.includes('_')) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
    candidate
  );
}

interface ResolvedDomainCaaPolicy {
  effectiveOwner?: string;
  records: CaaRecordEntry[];
  issueCas: string[];
  issuewildCas: string[];
  hasEmptyIssueDeny: boolean;
  issueRestricted: boolean;
  hasExplicitIssuewild: boolean;
  wildcardRestricted: boolean;
  authorizedIssueCas: Set<string>;
  authorizedWildcardCas: Set<string>;
}

/**
 * Evaluates the effective RFC 8659 §3 CAA policy for any domain name (`domainFqdn`) by climbing
 * from `domainFqdn` (and any CNAME targets) up its full ancestor hierarchy in `queries`, falling back
 * to the target domain's evaluated `fallbackCaa` when no closer CAA RRset is present in `queries`.
 */
function resolveEffectiveCaaForDomain(
  domainFqdn: string,
  queries: DohQueryLog[],
  fallbackCaa: WebCaaAnalysis
): ResolvedDomainCaaPolicy {
  const normDomain = normalizeFqdn(domainFqdn);
  const climbNames: string[] = [];
  const pushClimb = (n: string) => {
    const norm = normalizeFqdn(n);
    if (norm !== '.' && !climbNames.includes(norm)) {
      climbNames.push(norm);
    }
  };

  pushClimb(normDomain);
  const initialCname = resolveCnameChainInLogs(queries, normDomain, RR_TYPES.CAA);
  for (const c of initialCname.cnameChain) {
    pushClimb(c);
  }
  const ancestors = getDomainHierarchy(normDomain).slice(1).reverse();
  for (const anc of ancestors) {
    pushClimb(anc);
    const ancCname = resolveCnameChainInLogs(queries, anc, RR_TYPES.CAA);
    for (const c of ancCname.cnameChain) {
      pushClimb(c);
    }
  }
  if (initialCname.finalOwner !== normDomain) {
    const finalAncestors = getDomainHierarchy(initialCname.finalOwner).slice(1).reverse();
    for (const anc of finalAncestors) {
      pushClimb(anc);
    }
  }

  let effectiveOwner: string | undefined;
  let effectiveRecords: CaaRecordEntry[] = [];

  for (const hopName of climbNames) {
    const caaRes = resolveCnameChainInLogs(queries, hopName, RR_TYPES.CAA);
    const hopOwner = caaRes.finalOwner;
    const hopLog =
      findAnyLog(queries, hopOwner, RR_TYPES.CAA) ?? findAnyLog(queries, hopName, RR_TYPES.CAA);
    const hopRecords: CaaRecordEntry[] = [];
    for (const ans of hopLog?.packet.answers ?? []) {
      if (
        (ans.name === hopOwner || ans.name === hopName) &&
        ans.type === RR_TYPES.CAA &&
        ans.parsed.kind === 'CAA'
      ) {
        hopRecords.push(
          parseCaaRecordEntry(ans.name, ans.parsed.flags, ans.parsed.tag, ans.parsed.value)
        );
      }
    }
    if (hopRecords.length > 0) {
      effectiveOwner = hopName;
      effectiveRecords = hopRecords;
      break;
    }
  }

  if (!effectiveOwner && fallbackCaa.effectiveOwner) {
    const fallbackHop = fallbackCaa.hops.find((h) => h.isEffectivePolicySource);
    if (fallbackHop && isSubdomainOrEqual(normDomain, fallbackHop.name)) {
      effectiveOwner = fallbackHop.name;
      effectiveRecords = fallbackHop.records;
    }
  }

  const issueCas: string[] = [];
  const issuewildCas: string[] = [];
  let hasEmptyIssueDeny = false;

  for (const rec of effectiveRecords) {
    if (rec.tag === 'issue') {
      if (rec.caDomain === '') {
        hasEmptyIssueDeny = true;
      } else if (rec.caDomain && !issueCas.includes(rec.caDomain)) {
        issueCas.push(rec.caDomain);
      }
    } else if (rec.tag === 'issuewild') {
      const val = rec.caDomain || '; (deny all wildcards)';
      if (rec.caDomain !== undefined && !issuewildCas.includes(val)) {
        issuewildCas.push(val);
      }
    }
  }

  const issueRestricted =
    Boolean(effectiveOwner) && (issueCas.length > 0 || hasEmptyIssueDeny);
  const hasExplicitIssuewild = issuewildCas.length > 0;
  const wildcardRestricted = hasExplicitIssuewild || issueRestricted;

  const authorizedIssueCas = new Set(
    issueCas
      .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
      .filter((c) => c && !c.startsWith(';'))
  );
  const authorizedWildcardCas = hasExplicitIssuewild
    ? new Set(
        issuewildCas
          .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
          .filter((c) => c && !c.startsWith(';'))
      )
    : authorizedIssueCas;

  return {
    effectiveOwner,
    records: effectiveRecords,
    issueCas,
    issuewildCas,
    hasEmptyIssueDeny,
    issueRestricted,
    hasExplicitIssuewild,
    wildcardRestricted,
    authorizedIssueCas,
    authorizedWildcardCas,
  };
}

/**
 * Cross-checks Certificate Transparency (`CT`) log issuances against the evaluated RFC 8659 `CAA`
 * policy (walking the full domain chain for every CT certificate SAN) and `_443._tcp` DANE `TLSA`
 * bindings, and extracts discovered subdomains from SANs.
 */
function evaluateWebCertificateTransparency(params: {
  targetName: string;
  effectiveDomain: string;
  queries: DohQueryLog[];
  caa: WebCaaAnalysis;
  tlsaRecords: TlsaRecordDetail[];
  ctLogFetch?: CtLogFetchResult;
  validatedAtMs: number;
  webFindings: AuditFinding[];
}): WebCtAnalysis | undefined {
  const {
    targetName,
    effectiveDomain,
    queries,
    caa,
    tlsaRecords,
    ctLogFetch,
    validatedAtMs,
    webFindings,
  } = params;
  if (!ctLogFetch) return undefined;

  const dispTarget = displayFqdn(targetName).toLowerCase();
  const dispEffective = displayFqdn(effectiveDomain).toLowerCase();

  if (!ctLogFetch.ok) {
    return {
      status: 'unavailable',
      source: ctLogFetch.source,
      queriedDomain: dispTarget,
      fetchedAt: ctLogFetch.fetchedAt,
      error: ctLogFetch.error ?? 'Certificate Transparency log query failed or timed out',
      totalEntries: 0,
      activeCertCount: 0,
      expiredCertCount: 0,
      mismatchedActiveCertCount: 0,
      issuers: [],
      certificates: [],
      discoveredSubdomains: [],
      tlsaMatchedCertCount: 0,
      summary: `Certificate Transparency log lookup unavailable (${ctLogFetch.error ?? 'network/timeout'}).`,
    };
  }

  const issueRestricted =
    caa.status === 'enforced' || caa.status === 'inherited' || caa.issueCas.length > 0;
  const hasExplicitIssuewild = caa.issuewildCas.length > 0;
  const wildcardRestricted = hasExplicitIssuewild || issueRestricted;

  const authorizedIssueCas = new Set(
    caa.issueCas
      .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
      .filter((c) => c && !c.startsWith(';'))
  );
  const authorizedWildcardCas = hasExplicitIssuewild
    ? new Set(
        caa.issuewildCas
          .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
          .filter((c) => c && !c.startsWith(';'))
      )
    : authorizedIssueCas;

  const domainCaaPolicyCache = new Map<string, ResolvedDomainCaaPolicy>();
  const subdomainCaaPolicyMap = new Map<string, CtSubdomainCaaPolicy>();
  const getPolicyForSanBase = (baseFqdn: string): ResolvedDomainCaaPolicy => {
    const norm = normalizeFqdn(baseFqdn);
    const cached = domainCaaPolicyCache.get(norm);
    if (cached) return cached;
    const resolved = resolveEffectiveCaaForDomain(norm, queries, caa);
    domainCaaPolicyCache.set(norm, resolved);
    if (
      resolved.effectiveOwner &&
      resolved.effectiveOwner !== targetName &&
      resolved.effectiveOwner !== effectiveDomain &&
      isSubdomainOrEqual(resolved.effectiveOwner, targetName) &&
      !subdomainCaaPolicyMap.has(resolved.effectiveOwner)
    ) {
      subdomainCaaPolicyMap.set(resolved.effectiveOwner, {
        owner: resolved.effectiveOwner,
        displayOwner: displayFqdn(resolved.effectiveOwner),
        issueCas: resolved.issueCas,
        issuewildCas: resolved.issuewildCas,
        records: resolved.records,
      });
    }
    return resolved;
  };

  // Sort entries newest notBefore first
  const sortedRaw = [...ctLogFetch.entries].sort((a, b) => {
    const ta = Date.parse(a.notBefore) || 0;
    const tb = Date.parse(b.notBefore) || 0;
    return tb - ta;
  });

  const activeSubdomains = new Set<string>();
  const historicalSubdomains = new Set<string>();
  const certificates: CtCertificateEntry[] = [];

  let activeCertCount = 0;
  let expiredCertCount = 0;
  let mismatchedActiveCertCount = 0;
  let tlsaMatchedCertCount = 0;

  for (const raw of sortedRaw) {
    const notAfterMs = Date.parse(raw.notAfter);
    const isExpired = Number.isFinite(notAfterMs) ? notAfterMs < validatedAtMs : false;
    const isActive = !isExpired && !raw.revoked;

    if (isActive) {
      activeCertCount++;
    } else {
      expiredCertCount++;
    }

    for (const san of raw.dnsNames) {
      const cleanSan = san.replace(/^\*\./, '').trim().toLowerCase();
      if (isValidDiscoveredSubdomain(cleanSan, dispTarget)) {
        if (isActive) {
          activeSubdomains.add(cleanSan);
        } else {
          historicalSubdomains.add(cleanSan);
        }
      }
    }

    const coversTargetDirectly = raw.dnsNames.some(
      (n) =>
        n === dispTarget ||
        n === `*.${dispTarget}` ||
        n === dispEffective ||
        n === `*.${dispEffective}`
    );
    const hasWildcardForTarget = raw.dnsNames.some(
      (n) =>
        n === `*.${dispTarget}` ||
        n === `*.${dispEffective}` ||
        (!coversTargetDirectly && n.startsWith('*.'))
    );

    // Filter SANs to those within targetName / effectiveDomain hierarchy (or all SANs if none match)
    const inScopeSans = raw.dnsNames.filter((san) => {
      const baseFqdn = normalizeFqdn(san.replace(/^\*\./, ''));
      return (
        isSubdomainOrEqual(baseFqdn, targetName) ||
        isSubdomainOrEqual(baseFqdn, effectiveDomain)
      );
    });
    const sansToEvaluate = inScopeSans.length > 0 ? inScopeSans : [dispTarget];

    // Collect all candidate CAA domains across the SANs' effective CAA policies
    const candidateCaaSet = new Set<string>([...authorizedIssueCas, ...authorizedWildcardCas]);
    const sanPolicies = sansToEvaluate.map((san) => {
      const isWild = san.startsWith('*.');
      const baseFqdn = normalizeFqdn(san.replace(/^\*\./, ''));
      const policy = getPolicyForSanBase(baseFqdn);
      for (const c of policy.authorizedIssueCas) candidateCaaSet.add(c);
      for (const c of policy.authorizedWildcardCas) candidateCaaSet.add(c);
      return { san, isWild, baseFqdn, policy };
    });

    const mappedCaaDomains = mapCtIssuerToCaaDomains(
      raw.issuerFriendlyName,
      raw.issuerDn,
      Array.from(candidateCaaSet)
    );

    let caaAuthorized: CtCertificateEntry['caaAuthorized'] = 'unrestricted';
    let caaNote = 'No restricting CAA policy active';
    const effectiveOwnerDisplaySet = new Set<string>();
    const authorizedMatchedDomSet = new Set<string>();
    let firstUnauthNote: string | undefined;
    let firstUnauthVerdict: 'unauthorized-ca' | 'unauthorized-wildcard' | undefined;

    for (const { san, isWild, policy } of sanPolicies) {
      const ownerDisp = policy.effectiveOwner ? displayFqdn(policy.effectiveOwner) : dispTarget;
      if (policy.effectiveOwner) {
        effectiveOwnerDisplaySet.add(ownerDisp);
      }
      const matchesSanIssue = mappedCaaDomains.some((d) => policy.authorizedIssueCas.has(d));
      const matchesSanWild = mappedCaaDomains.some((d) => policy.authorizedWildcardCas.has(d));

      if (isWild && policy.wildcardRestricted) {
        if (!matchesSanWild) {
          if (matchesSanIssue && policy.hasExplicitIssuewild) {
            if (!firstUnauthVerdict) {
              firstUnauthVerdict = 'unauthorized-wildcard';
              firstUnauthNote = `${raw.issuerFriendlyName} (${mappedCaaDomains.join(', ') || 'unmapped'}) is in CAA issue at ${ownerDisp}, but not authorized by explicit issuewild (${Array.from(policy.authorizedWildcardCas).join(', ') || 'deny all'}) for ${san}`;
            }
          } else if (!firstUnauthVerdict) {
            firstUnauthVerdict = 'unauthorized-ca';
            firstUnauthNote = `${raw.issuerFriendlyName} (${mappedCaaDomains.join(', ') || 'unmapped'}) is not authorized by CAA ${policy.hasExplicitIssuewild ? 'issuewild' : 'issue'} policy at ${ownerDisp} (${Array.from(policy.authorizedWildcardCas).join(', ') || 'deny all'}) for ${san}`;
          }
        } else {
          const matchedDom = mappedCaaDomains.find((d) => policy.authorizedWildcardCas.has(d));
          if (matchedDom) authorizedMatchedDomSet.add(matchedDom);
        }
      } else if (!isWild && policy.issueRestricted) {
        if (!matchesSanIssue) {
          if (!firstUnauthVerdict) {
            firstUnauthVerdict = 'unauthorized-ca';
            firstUnauthNote = `${raw.issuerFriendlyName} (${mappedCaaDomains.join(', ') || 'unmapped'}) is not listed in CAA issue at ${ownerDisp} (${Array.from(policy.authorizedIssueCas).join(', ') || 'deny all'}) for ${san}`;
          }
        } else {
          const matchedDom = mappedCaaDomains.find((d) => policy.authorizedIssueCas.has(d));
          if (matchedDom) authorizedMatchedDomSet.add(matchedDom);
        }
      }
    }

    const effectiveCaaOwners = Array.from(effectiveOwnerDisplaySet);

    if (firstUnauthVerdict) {
      caaAuthorized = firstUnauthVerdict;
      caaNote = firstUnauthNote!;
    } else if (authorizedMatchedDomSet.size > 0) {
      caaAuthorized = 'authorized';
      const matchedList = Array.from(authorizedMatchedDomSet).join(', ');
      const viaSubdomain = effectiveCaaOwners.some(
        (o) => o.toLowerCase() !== dispTarget && o.toLowerCase() !== dispEffective
      );
      caaNote = viaSubdomain
        ? `Authorized by CAA at ${effectiveCaaOwners.join(', ')} (${matchedList})`
        : `Authorized by CAA (${matchedList})`;
    }

    if (
      isActive &&
      (caaAuthorized === 'unauthorized-ca' || caaAuthorized === 'unauthorized-wildcard')
    ) {
      mismatchedActiveCertCount++;
    }

    // Cross-reference against _443._tcp DANE TLSA SHA-256 digests
    let matchesTlsa: boolean | undefined;
    let matchedTlsaSummary: string | undefined;
    const validSha256Tlsas = tlsaRecords.filter((t) => t.rdataValid && t.matchingType === 1);
    if (validSha256Tlsas.length > 0 && (raw.certSha256 || raw.pubkeySha256 || raw.issuerPubkeySha256)) {
      matchesTlsa = false;
      for (const tlsa of validSha256Tlsas) {
        const hex = tlsa.certAssociationHex.toLowerCase();
        if (tlsa.selector === 0 && raw.certSha256 && hex === raw.certSha256) {
          matchesTlsa = true;
          matchedTlsaSummary = `Matches TLSA ${tlsa.usage} (${tlsa.usageMnemonic}) Selector 0 (Cert SHA-256)`;
          break;
        }
        if (tlsa.selector === 1) {
          if (raw.pubkeySha256 && hex === raw.pubkeySha256) {
            matchesTlsa = true;
            matchedTlsaSummary = `Matches TLSA ${tlsa.usage} (${tlsa.usageMnemonic}) Selector 1 (Leaf SPKI SHA-256)`;
            break;
          }
          if (
            (tlsa.usage === 2 || tlsa.usage === 0) &&
            raw.issuerPubkeySha256 &&
            hex === raw.issuerPubkeySha256
          ) {
            matchesTlsa = true;
            matchedTlsaSummary = `Matches TLSA ${tlsa.usage} (${tlsa.usageMnemonic}) Selector 1 (Issuer TA SPKI SHA-256)`;
            break;
          }
        }
      }
      if (matchesTlsa) {
        tlsaMatchedCertCount++;
      }
    }

    certificates.push({
      id: raw.id,
      dnsNames: raw.dnsNames,
      hasWildcardForTarget,
      coversTargetDirectly,
      issuerFriendlyName: raw.issuerFriendlyName,
      issuerDn: raw.issuerDn,
      mappedCaaDomains,
      notBefore: raw.notBefore,
      notAfter: raw.notAfter,
      isExpired,
      revoked: raw.revoked,
      certSha256: raw.certSha256,
      pubkeySha256: raw.pubkeySha256,
      issuerPubkeySha256: raw.issuerPubkeySha256,
      caaAuthorized,
      caaNote,
      ...(effectiveCaaOwners.length > 0 ? { effectiveCaaOwners } : {}),
      matchesTlsa,
      matchedTlsaSummary,
    });
  }

  // Summarize active certificate issuers (or all issuers if no active certs exist)
  const certsForIssuerSummary =
    activeCertCount > 0
      ? certificates.filter((c) => !c.isExpired && !c.revoked)
      : certificates;
  const issuerMap = new Map<string, CtIssuerSummary>();
  for (const cert of certsForIssuerSummary) {
    const key = cert.issuerFriendlyName || cert.issuerDn || 'Unknown CA';
    const existing = issuerMap.get(key);
    const certAuth = cert.caaAuthorized === 'authorized' || cert.caaAuthorized === 'unrestricted';
    const authIssue =
      certAuth || !issueRestricted || cert.mappedCaaDomains.some((d) => authorizedIssueCas.has(d));
    const authWild =
      certAuth ||
      !wildcardRestricted ||
      cert.mappedCaaDomains.some((d) => authorizedWildcardCas.has(d));

    if (!existing) {
      issuerMap.set(key, {
        friendlyName: key,
        mappedCaaDomains: cert.mappedCaaDomains,
        activeCertCount: !cert.isExpired && !cert.revoked ? 1 : 0,
        wildcardCertCount: cert.hasWildcardForTarget ? 1 : 0,
        latestNotBefore: cert.notBefore,
        caaAuthorized: certAuth,
        authorizedForIssue: authIssue,
        authorizedForWildcard: authWild,
      });
    } else {
      if (!cert.isExpired && !cert.revoked) existing.activeCertCount++;
      if (cert.hasWildcardForTarget) existing.wildcardCertCount++;
      if (!certAuth) existing.caaAuthorized = false;
    }
  }

  const issuers = Array.from(issuerMap.values()).sort(
    (a, b) => b.activeCertCount - a.activeCertCount
  );

  const discoveredSubdomains = [
    ...Array.from(activeSubdomains).sort(),
    ...Array.from(historicalSubdomains)
      .filter((s) => !activeSubdomains.has(s))
      .sort(),
  ].slice(0, 60);

  const subdomainCaaPolicies = Array.from(subdomainCaaPolicyMap.values()).sort((a, b) =>
    a.displayOwner.localeCompare(b.displayOwner)
  );
  const anyCertCaaEnforced =
    issueRestricted ||
    wildcardRestricted ||
    subdomainCaaPolicies.length > 0 ||
    certificates.some((c) => c.caaAuthorized === 'authorized');

  let status: WebCtAnalysis['status'] = 'no-active-certs';
  let summary = '';

  if (certificates.length === 0 || activeCertCount === 0) {
    status = 'no-active-certs';
    summary =
      certificates.length === 0
        ? `No Certificate Transparency log entries found for ${dispTarget}.`
        : `Found ${certificates.length} historical CT certificate(s) for ${dispTarget}, none currently unexpired.`;
  } else if (mismatchedActiveCertCount > 0) {
    status = 'caa-mismatch';
    const unauthorizedIssuers = Array.from(
      new Set(
        certificates
          .filter(
            (c) =>
              !c.isExpired &&
              !c.revoked &&
              (c.caaAuthorized === 'unauthorized-ca' ||
                c.caaAuthorized === 'unauthorized-wildcard')
          )
          .map(
            (c) =>
              `${c.issuerFriendlyName} (${c.mappedCaaDomains.join(', ') || 'unmapped'})`
          )
      )
    );
    summary = `CAA Policy Mismatch: ${mismatchedActiveCertCount} active certificate(s) in CT logs were issued by ${unauthorizedIssuers.join(', ')}, which is not authorized by the current CAA policy (${caa.issueCas.join(', ') || 'none'}).`;
    webFindings.push({
      id: `web-warn-ct-caa-mismatch-${targetName}`,
      severity: 'warning',
      code: 'CT_CAA_ISSUER_MISMATCH',
      title: `CT log shows ${mismatchedActiveCertCount} active certificate(s) for ${dispTarget} from CA not in current CAA policy`,
      detail: `Active unexpired certificate(s) in Certificate Transparency logs were issued by ${unauthorizedIssuers.join(', ')}, whereas the effective CAA policy at ${displayFqdn(caa.effectiveOwner ?? targetName)} only authorizes: issue=[${caa.issueCas.join(', ') || 'none'}]${caa.issuewildCas.length > 0 ? `, issuewild=[${caa.issuewildCas.join(', ')}]` : ''}. This occurs when CAA records were tightened after certificate issuance (potentially breaking automated ACME renewals) or if a sub-delegation/CA bypassed policy.`,
      rfc: 'RFC 8659 / RFC 6962',
    });
  } else if (anyCertCaaEnforced) {
    status = 'caa-compliant';
    const issuerNames = issuers.map((i) => i.friendlyName).join(', ');
    const subPolicySummary =
      subdomainCaaPolicies.length > 0
        ? ` (including ${subdomainCaaPolicies.length} subdomain CAA polic${subdomainCaaPolicies.length === 1 ? 'y' : 'ies'} at ${subdomainCaaPolicies
            .slice(0, 4)
            .map((p) => `${p.displayOwner}: ${p.issueCas.join(', ') || 'none'}`)
            .join('; ')}${subdomainCaaPolicies.length > 4 ? ` +${subdomainCaaPolicies.length - 4} more` : ''})`
        : ` (${caa.issueCas.join(', ')})`;
    summary = `All ${activeCertCount} active CT certificate(s) for ${dispTarget} (issued by ${issuerNames}) match the enforced RFC 8659 CAA policy chain${subPolicySummary}${discoveredSubdomains.length > 0 ? ` · ${discoveredSubdomains.length} subdomain${discoveredSubdomains.length === 1 ? '' : 's'} discovered in SANs` : ''}.`;
    webFindings.push({
      id: `web-info-ct-caa-compliant-${targetName}`,
      severity: 'info',
      code: 'CT_CAA_COMPLIANT',
      title: `Certificate Transparency (CT) logs match CAA policy for ${dispTarget} (${activeCertCount} active cert${activeCertCount === 1 ? '' : 's'})`,
      detail: `Verified ${activeCertCount} active unexpired TLS certificate(s) in CT logs (${issuerNames}); every active issuer is authorized by the full RFC 8659 CAA hierarchy${subPolicySummary}.`,
      rfc: 'RFC 8659 / RFC 6962',
    });
  } else {
    status = 'unrestricted';
    const issuerNames = issuers.map((i) => i.friendlyName).join(', ');
    summary = `${activeCertCount} active CT certificate(s) found for ${dispTarget} (issued by ${issuerNames}), but no restricting CAA policy is published.${discoveredSubdomains.length > 0 ? ` Discovered ${discoveredSubdomains.length} subdomain${discoveredSubdomains.length === 1 ? '' : 's'} in CT SANs.` : ''}`;
  }

  return {
    status,
    source: ctLogFetch.source,
    queriedDomain: dispTarget,
    fetchedAt: ctLogFetch.fetchedAt,
    totalEntries: certificates.length,
    activeCertCount,
    expiredCertCount,
    mismatchedActiveCertCount,
    issuers,
    certificates: certificates.slice(0, 25),
    discoveredSubdomains,
    ...(subdomainCaaPolicies.length > 0 ? { subdomainCaaPolicies } : {}),
    tlsaMatchedCertCount,
    summary,
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
  ctLogFetch?: CtLogFetchResult;
  validatedAt?: number;
}): {
  webAnalysis: WebAnalysisResult;
  webFindings: AuditFinding[];
  overallStatus: ValidationStatus;
  overallSummary: string;
} {
  const { targetName, queries, zones, targetDomainStatus, ctLogFetch, validatedAt } = params;
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

  // 7. Evaluate Certificate Transparency (CT) Log Issuances vs. CAA Policy & Web DANE TLSA
  const ctAnalysis = evaluateWebCertificateTransparency({
    targetName,
    effectiveDomain,
    queries,
    caa: caaAnalysis,
    tlsaRecords,
    ctLogFetch,
    validatedAtMs: validatedAt ?? Date.now(),
    webFindings,
  });

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
    ...(ctAnalysis ? { ctAnalysis } : {}),
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
        ? `CAA inherited from ${displayFqdn(effectiveCaaHop?.name ?? '')}`
        : caaStatus === 'unprotected'
          ? 'CAA unprotected'
          : `CAA ${caaStatus}`
  );
  if (ctAnalysis && ctAnalysis.status !== 'unavailable' && ctAnalysis.activeCertCount > 0) {
    parts.push(
      ctAnalysis.status === 'caa-compliant'
        ? `CT ↔ CAA compliant (${ctAnalysis.activeCertCount} active)`
        : ctAnalysis.status === 'caa-mismatch'
          ? `CT ↔ CAA MISMATCH (${ctAnalysis.mismatchedActiveCertCount})`
          : `CT (${ctAnalysis.activeCertCount} active)`
    );
  }
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
  const emailParsed = parseEmailDaneInput(rawDomain);
  const targetName = emailParsed ? emailParsed.domain : normalizeFqdn(rawDomain);
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

  // Launch Certificate Transparency (CT) log fetch concurrently with DNS queries
  const ctLogPromise = fetchCtLogEntries(displayDomain, {
    fetchImpl: options.fetchImpl,
    timeoutMs: options.timeoutMs ? Math.min(options.timeoutMs, 4500) : 4500,
  });

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
    if (
      !log.cd ||
      log.purpose.startsWith('Nameserver IP') ||
      log.purpose.startsWith('CT CAA lookup')
    ) {
      continue;
    }
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Step 3.5: Probe CAA across full domain chains of CT log certificate SANs
  const ctLogFetch = await ctLogPromise;
  if (ctLogFetch.ok && ctLogFetch.entries.length > 0) {
    currentPhase = 'web-caa';
    const existingCaaQueried = new Set(
      session
        .getLogs()
        .filter((l) => l.qtype === RR_TYPES.CAA)
        .map((l) => l.qname)
    );
    const nowMs = options.validationTimeMs ?? Date.now();
    const sortedCt = [...ctLogFetch.entries].sort((a, b) => {
      const ta = Date.parse(a.notBefore) || 0;
      const tb = Date.parse(b.notBefore) || 0;
      return tb - ta;
    });
    const relevantCtEntries = sortedCt.filter((e, idx) => {
      const na = Date.parse(e.notAfter);
      const isActive = (!Number.isFinite(na) || na >= nowMs) && !e.revoked;
      return isActive || idx < 25;
    });

    const ctChainCandidates = new Set<string>();
    for (const entry of relevantCtEntries) {
      for (const rawSan of entry.dnsNames) {
        const cleanSan = rawSan.replace(/^\*\./, '').trim().toLowerCase();
        if (!cleanSan || cleanSan.includes('*') || cleanSan.includes(' ')) continue;
        const sanFqdn = normalizeFqdn(cleanSan);
        if (sanFqdn === '.' || !sanFqdn.includes('.')) continue;
        if (
          !isSubdomainOrEqual(sanFqdn, targetName) &&
          !isSubdomainOrEqual(sanFqdn, effectiveDomain)
        ) {
          continue;
        }
        for (const anc of getDomainHierarchy(sanFqdn).slice(1)) {
          if (!existingCaaQueried.has(anc)) {
            ctChainCandidates.add(anc);
          }
        }
      }
    }

    const sortedCtCaaToProbe = Array.from(ctChainCandidates)
      .sort((a, b) => countDnsLabels(a) - countDnsLabels(b) || a.localeCompare(b))
      .slice(0, 50);

    if (sortedCtCaaToProbe.length > 0) {
      options.onProgress?.({
        phase: 'web-caa',
        message: `Probing RFC 8659 CAA chain for ${sortedCtCaaToProbe.length} CT log domain${sortedCtCaaToProbe.length === 1 ? '' : 's'}…`,
        completedQueries: session.getLogs().length,
      });
      for (const d of sortedCtCaaToProbe) {
        existingCaaQueried.add(d);
      }
      await Promise.all(
        sortedCtCaaToProbe.map((d) =>
          session.query(d, RR_TYPES.CAA, {
            cd: true,
            doBit: true,
            purpose: `CT CAA lookup (${d} CAA)`,
          })
        )
      );

      // Follow any CNAME chain returned on CT CAA lookups
      const cnameFollowups = new Set<string>();
      for (const log of session.getLogs()) {
        if (!log.purpose.startsWith('CT CAA lookup')) continue;
        for (const ans of log.packet.answers) {
          if (ans.type === RR_TYPES.CNAME && ans.parsed.kind === 'GENERIC' && ans.parsed.target) {
            const cnameTarget = normalizeFqdn(ans.parsed.target);
            for (const anc of getDomainHierarchy(cnameTarget).slice(1)) {
              if (!existingCaaQueried.has(anc)) {
                cnameFollowups.add(anc);
              }
            }
          }
        }
      }
      if (cnameFollowups.size > 0) {
        const followupList = Array.from(cnameFollowups).slice(0, 20);
        await Promise.all(
          followupList.map((d) =>
            session.query(d, RR_TYPES.CAA, {
              cd: true,
              doBit: true,
              purpose: `CT CAA lookup (${d} CAA)`,
            })
          )
        );
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
    message: 'Verifying DNSSEC, HTTPS/SVCB, ECH, CAA, CT logs & Web DANE via WebCrypto…',
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
    ctLogFetch,
    dohEndpoint: endpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries: session.getLogs(),
    trustAnchors,
  });
}
