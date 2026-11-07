import {
  DEFAULT_DOH_ENDPOINT,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  TLSA_MATCHING_TYPES,
  TLSA_SELECTORS,
  TLSA_USAGES,
  rcodeToString,
} from './constants';
import {
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
  findLog,
  type AnalyzeOptions,
} from './analyzer';
import { DohSession } from './doh';
import { displayFqdn, normalizeFqdn } from './encoding';
import type {
  AnalysisProgress,
  AnalysisSnapshot,
  AnalyzedRrset,
  AuditFinding,
  CnameEdge,
  DaneHostStatus,
  DohQueryLog,
  MailAnalysisResult,
  MxAddressEntry,
  MxHostAnalysis,
  NegativeNode,
  SpfDomainNode,
  SpfPolicyVerdict,
  SpfQualifier,
  SpfTerm,
  TlsaRecordDetail,
  ValidationStatus,
  ZoneAnalysis,
} from './types';

const MAX_PROBED_MX_HOSTS = 12;
const SPF_DNS_LOOKUP_LIMIT = 10;
const SPF_VOID_LOOKUP_LIMIT = 2;
const MAX_SPF_NETWORK_QUERIES = 22;
const MAX_SPF_RECURSION_DEPTH = 10;

export function isIpLiteralHostname(exchange: string): boolean {
  const clean = exchange.replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return true;
  if (clean.includes(':')) return true;
  return false;
}

export function classifyIpAddress(ip: string, family: 4 | 6): MxAddressEntry {
  if (family === 4) {
    const parts = ip.split('.').map((n) => Number.parseInt(n, 10));
    if (parts.length === 4 && parts.every((n) => !Number.isNaN(n) && n >= 0 && n <= 255)) {
      const [a, b, c] = parts;
      if (a === 127) return { ip, family: 4, isPublic: false, note: 'Loopback (RFC 1122)' };
      if (a === 0) return { ip, family: 4, isPublic: false, note: 'Unspecified (RFC 1122)' };
      if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
        return { ip, family: 4, isPublic: false, note: 'Private RFC 1918' };
      }
      if (a === 169 && b === 254) {
        return { ip, family: 4, isPublic: false, note: 'Link-Local (RFC 3927)' };
      }
      if (a === 100 && b >= 64 && b <= 127) {
        return { ip, family: 4, isPublic: false, note: 'CGNAT Shared Space (RFC 6598)' };
      }
      if (
        (a === 192 && b === 0 && c === 2) ||
        (a === 198 && b === 51 && c === 100) ||
        (a === 203 && b === 0 && c === 113)
      ) {
        return { ip, family: 4, isPublic: false, note: 'Documentation TEST-NET (RFC 5737)' };
      }
      if (a >= 224) {
        return { ip, family: 4, isPublic: false, note: 'Multicast / Reserved' };
      }
    }
    return { ip, family: 4, isPublic: true };
  }

  const lower = ip.toLowerCase();
  if (lower === '::1') return { ip, family: 6, isPublic: false, note: 'Loopback (::1)' };
  if (lower === '::') return { ip, family: 6, isPublic: false, note: 'Unspecified (::)' };
  if (/^fe[89ab][0-9a-f]:/.test(lower)) {
    return { ip, family: 6, isPublic: false, note: 'Link-Local (fe80::/10)' };
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) {
    return { ip, family: 6, isPublic: false, note: 'Unique Local (RFC 4193)' };
  }
  if (lower.startsWith('2001:db8:') || lower.startsWith('2001:0db8:')) {
    return { ip, family: 6, isPublic: false, note: 'Documentation (RFC 3849)' };
  }
  if (lower.startsWith('ff')) {
    return { ip, family: 6, isPublic: false, note: 'Multicast (ff00::/8)' };
  }
  return { ip, family: 6, isPublic: true };
}

function extractTxtJoinedStrings(log: DohQueryLog | undefined, owner: string, rrtype: number): string[] {
  if (!log) return [];
  const normOwner = normalizeFqdn(owner);
  // Follow CNAME chain inside packet if owner is aliased
  let cur = normOwner;
  const visited = new Set<string>([cur]);
  for (let hop = 0; hop < 8; hop++) {
    const cname = log.packet.answers.find((r) => r.name === cur && r.type === RR_TYPES.CNAME);
    if (!cname || cname.parsed.kind !== 'GENERIC' || !cname.parsed.target) break;
    const next = normalizeFqdn(cname.parsed.target);
    if (visited.has(next)) break;
    visited.add(next);
    cur = next;
  }

  const results: string[] = [];
  for (const ans of log.packet.answers) {
    if (ans.name === cur && ans.type === rrtype) {
      if (ans.parsed.kind === 'TXT') {
        results.push(ans.parsed.joinedText);
      } else {
        // Fallback if synthesized record only populated rdataText
        results.push(ans.rdataText.replace(/^"|"$/g, '').replace(/"\s+"/g, ''));
      }
    }
  }
  return results;
}

export function isSpfRecordText(txt: string): boolean {
  return /^v=spf1(?:\s|$)/i.test(txt.trim());
}

export function hasSpfMacro(domainSpec: string): boolean {
  return /%[{_%-]/.test(domainSpec);
}

function isValidIpv4Address(addr: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = m[i];
    if (octet.length > 1 && octet.startsWith('0')) return false;
    const n = Number.parseInt(octet, 10);
    if (Number.isNaN(n) || n < 0 || n > 255) return false;
  }
  return true;
}

function isValidIpv6Address(addr: string): boolean {
  if (!addr.includes(':')) return false;
  if (/[^0-9a-fA-F:.]/.test(addr)) return false;
  if (addr.includes(':::')) return false;
  const doubleColonParts = addr.split('::');
  if (doubleColonParts.length > 2) return false;
  return true;
}

function parseDualCidrSuffix(rawArg: string): {
  domainPart: string;
  cidr4?: number;
  cidr6?: number;
  error?: string;
} {
  // RFC 7208 §5.3 / §5.4: [:<domain-spec>][/<ip4-cidr-length>][//<ip6-cidr-length>]
  let working = rawArg;
  let cidr6: number | undefined;
  let cidr4: number | undefined;

  const dualIdx = working.indexOf('//');
  if (dualIdx !== -1) {
    const c6Str = working.slice(dualIdx + 2);
    working = working.slice(0, dualIdx);
    if (!/^\d+$/.test(c6Str)) {
      return { domainPart: working, error: `Invalid IPv6 CIDR suffix "//${c6Str}"` };
    }
    cidr6 = Number.parseInt(c6Str, 10);
    if (cidr6 < 0 || cidr6 > 128) {
      return { domainPart: working, cidr6, error: `IPv6 CIDR //${cidr6} out of range (0..128)` };
    }
  }

  const slashIdx = working.lastIndexOf('/');
  if (slashIdx !== -1) {
    const c4Str = working.slice(slashIdx + 1);
    working = working.slice(0, slashIdx);
    if (!/^\d+$/.test(c4Str)) {
      return { domainPart: working, cidr6, error: `Invalid IPv4 CIDR suffix "/${c4Str}"` };
    }
    cidr4 = Number.parseInt(c4Str, 10);
    if (cidr4 < 0 || cidr4 > 32) {
      return { domainPart: working, cidr4, cidr6, error: `IPv4 CIDR /${cidr4} out of range (0..32)` };
    }
  }

  if (working === '') {
    return { domainPart: '', cidr4, cidr6 };
  }
  if (!working.startsWith(':')) {
    return {
      domainPart: working,
      cidr4,
      cidr6,
      error: `Expected ":" before domain argument (got "${working}")`,
    };
  }
  const dom = working.slice(1);
  if (!dom) {
    return { domainPart: '', cidr4, cidr6, error: 'Empty domain-spec after ":"' };
  }
  return { domainPart: dom, cidr4, cidr6 };
}

/**
 * Parses an RFC 7208 `v=spf1` policy string into structured terms with strict syntax & CIDR validation.
 */
export function parseSpfTerms(recordText: string): SpfTerm[] {
  const trimmed = recordText.trim();
  if (!trimmed) return [];
  const tokens = trimmed.split(/\s+/);
  const terms: SpfTerm[] = [];

  let seenAll = false;
  let seenRedirect = false;
  let seenExp = false;

  tokens.forEach((tok, idx) => {
    if (idx === 0) {
      const validVer = tok.toLowerCase() === 'v=spf1';
      terms.push({
        raw: tok,
        kind: 'version',
        countsTowardLookupLimit: false,
        syntaxValid: validVer,
        error: validVer ? undefined : `Invalid SPF version token "${tok}" (expected "v=spf1")`,
      });
      return;
    }

    // Check modifier: name=value (without leading qualifier)
    const modMatch = /^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$/.exec(tok);
    if (modMatch) {
      const modName = modMatch[1].toLowerCase();
      const modVal = modMatch[2];

      if (modName === 'redirect') {
        const dup = seenRedirect;
        seenRedirect = true;
        const empty = modVal.length === 0;
        const counts = !dup && !empty && !seenAll;
        terms.push({
          raw: tok,
          kind: 'modifier',
          modifier: 'redirect',
          value: modVal,
          countsTowardLookupLimit: counts,
          syntaxValid: !dup && !empty,
          error: dup
            ? 'Duplicate "redirect=" modifier causes RFC 7208 §6.1 permerror'
            : empty
              ? 'Empty target domain in "redirect=" modifier'
              : undefined,
          warning:
            seenAll && !dup && !empty
              ? 'Ignored per RFC 7208 §6.1 because an "all" mechanism is also present in this record'
              : undefined,
        });
        return;
      }

      if (modName === 'exp') {
        const dup = seenExp;
        seenExp = true;
        const empty = modVal.length === 0;
        terms.push({
          raw: tok,
          kind: 'modifier',
          modifier: 'exp',
          value: modVal,
          countsTowardLookupLimit: false,
          syntaxValid: !dup && !empty,
          error: dup
            ? 'Duplicate "exp=" modifier causes RFC 7208 §6.2 permerror'
            : empty
              ? 'Empty target domain in "exp=" modifier'
              : undefined,
        });
        return;
      }

      terms.push({
        raw: tok,
        kind: 'modifier',
        modifier: modName,
        value: modVal,
        countsTowardLookupLimit: false,
        syntaxValid: true,
      });
      return;
    }

    // Parse mechanism with optional qualifier (+, -, ~, ?)
    let qualifier: SpfQualifier = '+';
    let rest = tok;
    if (rest.startsWith('+') || rest.startsWith('-') || rest.startsWith('~') || rest.startsWith('?')) {
      qualifier = rest[0] as SpfQualifier;
      rest = rest.slice(1);
    }

    const mechMatch = /^([a-zA-Z][a-zA-Z0-9_-]*)(.*)$/.exec(rest);
    if (!mechMatch) {
      terms.push({
        raw: tok,
        kind: 'unknown',
        qualifier,
        countsTowardLookupLimit: false,
        syntaxValid: false,
        error: `Malformed SPF token "${tok}"`,
      });
      return;
    }

    const mechLower = mechMatch[1].toLowerCase();
    const arg = mechMatch[2];
    const afterAll = seenAll;

    if (mechLower === 'all') {
      const valid = arg === '';
      if (valid) {
        seenAll = true;
        // If redirect= appeared earlier in the same record before `all`, mark that redirect as ignored & non-counting!
        for (const prev of terms) {
          if (prev.kind === 'modifier' && prev.modifier === 'redirect' && prev.syntaxValid) {
            prev.countsTowardLookupLimit = false;
            prev.warning =
              'Ignored per RFC 7208 §6.1 because an "all" mechanism is present in this record';
          }
        }
      }
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: 'all',
        countsTowardLookupLimit: false,
        syntaxValid: valid,
        unreachableAfterAll: afterAll,
        error: valid ? undefined : `"all" mechanism takes no arguments (got "${tok}")`,
        warning: afterAll ? 'Unreachable mechanism placed after a prior "all"' : undefined,
      });
      return;
    }

    if (mechLower === 'ip4') {
      if (!arg.startsWith(':')) {
        terms.push({
          raw: tok,
          kind: 'mechanism',
          qualifier,
          mechanism: 'ip4',
          countsTowardLookupLimit: false,
          syntaxValid: false,
          unreachableAfterAll: afterAll,
          error: `"ip4" requires ":<ipv4-network>" (got "${tok}")`,
        });
        return;
      }
      const addrSpec = arg.slice(1);
      const slashPos = addrSpec.indexOf('/');
      const ipPart = slashPos === -1 ? addrSpec : addrSpec.slice(0, slashPos);
      const cidrStr = slashPos === -1 ? undefined : addrSpec.slice(slashPos + 1);
      let cidr4: number | undefined;
      let err: string | undefined;
      if (!isValidIpv4Address(ipPart)) {
        err = `Invalid IPv4 literal "${ipPart}" in "${tok}"`;
      } else if (cidrStr !== undefined) {
        if (!/^\d+$/.test(cidrStr) || (cidrStr.length > 1 && cidrStr.startsWith('0'))) {
          err = `Invalid IPv4 CIDR "/${cidrStr}" in "${tok}"`;
        } else {
          cidr4 = Number.parseInt(cidrStr, 10);
          if (cidr4 < 0 || cidr4 > 32) err = `IPv4 CIDR /${cidr4} out of range (0..32)`;
        }
      }
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: 'ip4',
        value: ipPart,
        cidr4,
        countsTowardLookupLimit: false,
        syntaxValid: !err,
        unreachableAfterAll: afterAll,
        error: err,
        warning: afterAll ? 'Unreachable mechanism after "all"' : undefined,
      });
      return;
    }

    if (mechLower === 'ip6') {
      if (!arg.startsWith(':')) {
        terms.push({
          raw: tok,
          kind: 'mechanism',
          qualifier,
          mechanism: 'ip6',
          countsTowardLookupLimit: false,
          syntaxValid: false,
          unreachableAfterAll: afterAll,
          error: `"ip6" requires ":<ipv6-network>" (got "${tok}")`,
        });
        return;
      }
      const addrSpec = arg.slice(1);
      const slashPos = addrSpec.indexOf('/');
      const ipPart = slashPos === -1 ? addrSpec : addrSpec.slice(0, slashPos);
      const cidrStr = slashPos === -1 ? undefined : addrSpec.slice(slashPos + 1);
      let cidr6: number | undefined;
      let err: string | undefined;
      if (!isValidIpv6Address(ipPart)) {
        err = `Invalid IPv6 literal "${ipPart}" in "${tok}"`;
      } else if (cidrStr !== undefined) {
        if (!/^\d+$/.test(cidrStr) || (cidrStr.length > 1 && cidrStr.startsWith('0'))) {
          err = `Invalid IPv6 CIDR "/${cidrStr}" in "${tok}"`;
        } else {
          cidr6 = Number.parseInt(cidrStr, 10);
          if (cidr6 < 0 || cidr6 > 128) err = `IPv6 CIDR /${cidr6} out of range (0..128)`;
        }
      }
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: 'ip6',
        value: ipPart,
        cidr6,
        countsTowardLookupLimit: false,
        syntaxValid: !err,
        unreachableAfterAll: afterAll,
        error: err,
        warning: afterAll ? 'Unreachable mechanism after "all"' : undefined,
      });
      return;
    }

    if (mechLower === 'a' || mechLower === 'mx') {
      const parsed = parseDualCidrSuffix(arg);
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: mechLower,
        value: parsed.domainPart || undefined,
        cidr4: parsed.cidr4,
        cidr6: parsed.cidr6,
        countsTowardLookupLimit: !parsed.error && !afterAll,
        syntaxValid: !parsed.error,
        unreachableAfterAll: afterAll,
        error: parsed.error,
        warning: afterAll ? 'Unreachable mechanism after "all"' : undefined,
      });
      return;
    }

    if (mechLower === 'include' || mechLower === 'exists') {
      const hasColon = arg.startsWith(':');
      const dom = hasColon ? arg.slice(1) : '';
      const valid = hasColon && dom.length > 0;
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: mechLower,
        value: dom || undefined,
        countsTowardLookupLimit: valid && !afterAll,
        syntaxValid: valid,
        unreachableAfterAll: afterAll,
        error: valid ? undefined : `"${mechLower}" requires ":<domain-spec>" (got "${tok}")`,
        warning: afterAll ? 'Unreachable mechanism after "all"' : undefined,
      });
      return;
    }

    if (mechLower === 'ptr') {
      let dom: string | undefined;
      let err: string | undefined;
      if (arg !== '') {
        if (!arg.startsWith(':') || arg.length < 2) {
          err = `Invalid "ptr" argument in "${tok}"`;
        } else {
          dom = arg.slice(1);
        }
      }
      terms.push({
        raw: tok,
        kind: 'mechanism',
        qualifier,
        mechanism: 'ptr',
        value: dom,
        countsTowardLookupLimit: !err && !afterAll,
        syntaxValid: !err,
        unreachableAfterAll: afterAll,
        error: err,
        warning: afterAll
          ? 'Unreachable mechanism after "all"'
          : 'Deprecated mechanism: RFC 7208 §5.5 states "ptr" SHOULD NOT be published',
      });
      return;
    }

    terms.push({
      raw: tok,
      kind: 'unknown',
      qualifier,
      countsTowardLookupLimit: false,
      syntaxValid: false,
      unreachableAfterAll: afterAll,
      error: `Unknown SPF mechanism "${mechMatch[1]}" causes RFC 7208 §4.6.1 permerror`,
    });
  });

  return terms;
}

/**
 * Resolves a CNAME chain starting at `startName` using recorded `DohQueryLog` answers.
 */
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

  // Fallback to deepest covering zone status
  const covering = [...zones]
    .filter((z) => z.zoneName === '.' || finalOwner === z.zoneName || finalOwner.endsWith(`.${z.zoneName}`))
    .sort((a, b) => b.depth - a.depth)[0];
  if (covering) {
    chainStatuses.push(covering.status);
    return { status: combineDnssecChainStatus(chainStatuses) };
  }

  return { status: 'indeterminate' };
}

function evaluateTlsaRecordDetail(ownerName: string, ttl: number, usage: number, selector: number, matchingType: number, certAssociationHex: string): TlsaRecordDetail {
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
    issues.push(`Unassigned TLSA matching type ${matchingType} (expected 0=Full, 1=SHA-256, 2=SHA-512)`);
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

function findAnyLog(logs: DohQueryLog[], qname: string, qtype: number): DohQueryLog | undefined {
  return findLog(logs, qname, qtype, true) ?? findLog(logs, qname, qtype, false);
}

/**
 * Pure, deterministic evaluation of MX, SMTP DANE (TLSA), and SPF from already-captured
 * `DohQueryLog[]` and WebCrypto-evaluated `ZoneAnalysis[]`.
 * Runs both after live `runMailAnalysis` AND offline inside `reverifySnapshot`!
 */
export function evaluateMailFromSnapshotData(params: {
  targetName: string;
  queries: DohQueryLog[];
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  targetDomainStatus: ValidationStatus;
}): {
  mailAnalysis: MailAnalysisResult;
  mailFindings: AuditFinding[];
  overallStatus: ValidationStatus;
  overallSummary: string;
} {
  const { targetName, queries, zones, targetDomainStatus } = params;
  const mailFindings: AuditFinding[] = [];
  const dispTarget = displayFqdn(targetName);

  // 1. Check CNAME at targetName itself & MX RRset
  const mxResolution = resolveCnameChainInLogs(queries, targetName, RR_TYPES.MX);
  const mxAtCname = mxResolution.cnameChain[0];
  const effectiveMailDomain = mxResolution.finalOwner;

  if (mxAtCname) {
    mailFindings.push({
      id: `mail-warn-mx-at-cname-${targetName}`,
      severity: 'warning',
      code: 'MAIL_DOMAIN_IS_CNAME',
      title: `Mail domain ${dispTarget} is a CNAME alias to ${displayFqdn(mxAtCname)}`,
      detail: `RFC 2181 §10.1 forbids CNAME owners from holding MX or TXT records directly; MTAs rewrite or follow the alias to ${displayFqdn(effectiveMailDomain)}.`,
      rfc: 'RFC 5321 §5.1 / RFC 2181 §10.1',
    });
  }

  const mxLog = findAnyLog(queries, effectiveMailDomain, RR_TYPES.MX) ?? findAnyLog(queries, targetName, RR_TYPES.MX);
  const mxDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    mxResolution.cnameChain,
    effectiveMailDomain,
    RR_TYPES.MX,
    'MX'
  );

  const rawMxRecords = (mxLog?.packet.answers ?? [])
    .filter((r) => r.name === effectiveMailDomain && r.type === RR_TYPES.MX && r.parsed.kind === 'MX')
    .map((r) => {
      const parsed = r.parsed as { kind: 'MX'; preference: number; exchange: string };
      return {
        preference: parsed.preference,
        exchange: normalizeFqdn(parsed.exchange),
        ttl: r.ttl,
      };
    })
    .sort((a, b) => (a.preference !== b.preference ? a.preference - b.preference : a.exchange.localeCompare(b.exchange)));

  // Deduplicate identical (preference, exchange)
  const uniqueMxList: Array<{ preference: number; exchange: string }> = [];
  for (const item of rawMxRecords) {
    if (!uniqueMxList.some((u) => u.preference === item.preference && u.exchange === item.exchange)) {
      uniqueMxList.push({ preference: item.preference, exchange: item.exchange });
    }
  }

  let mxStatus: MailAnalysisResult['mxStatus'] = 'valid';
  let implicitFallbackAddresses: MxAddressEntry[] | undefined;
  const mxHosts: MxHostAnalysis[] = [];

  const isDomainNxdomain = mxLog?.packet.flags.rcode === 3;

  if (isDomainNxdomain) {
    mxStatus = 'broken';
    mailFindings.push({
      id: `mail-err-nxdomain-${targetName}`,
      severity: 'error',
      code: 'MAIL_DOMAIN_NXDOMAIN',
      title: `Domain ${dispTarget} does not exist (NXDOMAIN)`,
      detail: `DNS lookup for ${dispTarget} returned NXDOMAIN (RCODE 3); mail cannot be delivered to this domain.`,
      rfc: 'RFC 5321 §5.1',
    });
  } else if (uniqueMxList.length === 0) {
    // Check implicit A / AAAA fallback per RFC 5321 §5.1
    const aLog = findAnyLog(queries, effectiveMailDomain, RR_TYPES.A);
    const aaaaLog = findAnyLog(queries, effectiveMailDomain, RR_TYPES.AAAA);
    const fallbackIps: MxAddressEntry[] = [];
    for (const ans of aLog?.packet.answers ?? []) {
      if (ans.name === effectiveMailDomain && ans.type === RR_TYPES.A) {
        fallbackIps.push(classifyIpAddress(ans.rdataText, 4));
      }
    }
    for (const ans of aaaaLog?.packet.answers ?? []) {
      if (ans.name === effectiveMailDomain && ans.type === RR_TYPES.AAAA) {
        fallbackIps.push(classifyIpAddress(ans.rdataText, 6));
      }
    }

    if (fallbackIps.length > 0) {
      mxStatus = 'implicit-a';
      implicitFallbackAddresses = fallbackIps;
      mailFindings.push({
        id: `mail-warn-implicit-mx-${targetName}`,
        severity: 'warning',
        code: 'MX_IMPLICIT_ADDRESS_FALLBACK',
        title: `No MX record at ${dispTarget} — falls back to implicit A/AAAA (${fallbackIps.length} IP${fallbackIps.length === 1 ? '' : 's'})`,
        detail: `Per RFC 5321 §5.1, remote MTAs will attempt SMTP delivery directly to ${dispTarget}'s address record(s). Publish explicit MX records if this domain receives mail, or "0 ." (RFC 7505 Null MX) if it does not.`,
        rfc: 'RFC 5321 §5.1 / RFC 7505',
      });
    } else {
      mxStatus = 'none';
      mailFindings.push({
        id: `mail-info-no-mx-${targetName}`,
        severity: 'info',
        code: 'NO_MX_OR_ADDRESS_RECORDS',
        title: `No MX, A, or AAAA records published at ${dispTarget}`,
        detail: `Domain accepts no mail, but remote MTAs must wait for negative lookups. Publishing an explicit "0 ." Null MX (RFC 7505) rejects mail immediately.`,
        rfc: 'RFC 7505',
      });
    }
  } else if (uniqueMxList.some((m) => m.exchange === '.')) {
    // Null MX (RFC 7505)
    if (uniqueMxList.length > 1) {
      mxStatus = 'broken';
      mailFindings.push({
        id: `mail-err-null-mx-mixed-${targetName}`,
        severity: 'error',
        code: 'NULL_MX_MIXED_RECORDS',
        title: `Invalid RFC 7505 Null MX mixed with other MX exchangers at ${dispTarget}`,
        detail: `RFC 7505 §3 requires a Null MX ("0 .") to be the sole MX record in the RRset, but ${uniqueMxList.length} MX records were found.`,
        rfc: 'RFC 7505 §3',
      });
    } else {
      const only = uniqueMxList[0];
      mxStatus = 'null-mx';
      if (only.preference !== 0) {
        mailFindings.push({
          id: `mail-warn-null-mx-pref-${targetName}`,
          severity: 'warning',
          code: 'NULL_MX_NONZERO_PREFERENCE',
          title: `Null MX at ${dispTarget} uses preference ${only.preference} instead of 0`,
          detail: `RFC 7505 §3 specifies that a Null MX RR MUST have preference 0 ("0 .").`,
          rfc: 'RFC 7505 §3',
        });
      } else {
        mailFindings.push({
          id: `mail-info-null-mx-${targetName}`,
          severity: 'info',
          code: 'RFC7505_NULL_MX',
          title: `Explicit Null MX ("0 .") published at ${dispTarget}`,
          detail: `${dispTarget} explicitly declares that it accepts no incoming email, enabling immediate permanent rejection without SMTP connection timeouts.`,
          rfc: 'RFC 7505',
          targetId: mxDnssec.rrset?.id,
        });
      }
    }

    for (const m of uniqueMxList) {
      if (m.exchange === '.') {
        mxHosts.push({
          preference: m.preference,
          exchange: '.',
          displayExchange: '. (Null MX)',
          isNullMx: true,
          isIpLiteral: false,
          cnameChain: [],
          addresses: [],
          ipv4Status: mxDnssec.status,
          ipv6Status: mxDnssec.status,
          addressRrsetIds: [],
          dane: {
            qname: '.',
            resolvedOwner: '.',
            cnameChain: [],
            status: 'no-tlsa-secure',
            dnssecStatus: mxDnssec.status,
            records: [],
            rolloverReady: false,
            summary: 'Not applicable (Null MX accepts no mail)',
          },
        });
      }
    }
  }

  // Evaluate real MX hosts (when non-Null MX)
  const realMxItems = uniqueMxList.filter((m) => m.exchange !== '.').slice(0, MAX_PROBED_MX_HOSTS);
  for (const m of realMxItems) {
    const exch = m.exchange;
    const dispExch = displayFqdn(exch);
    const ipLit = isIpLiteralHostname(exch);

    if (ipLit) {
      mailFindings.push({
        id: `mail-err-mx-iplit-${exch}`,
        severity: 'error',
        code: 'MX_TARGET_IS_IP_LITERAL',
        title: `MX record points directly to IP literal "${dispExch}"`,
        detail: `RFC 5321 §2.3.5 and RFC 2181 §10.3 require MX exchange targets to be canonical hostnames with A/AAAA records, never raw IP addresses.`,
        rfc: 'RFC 5321 §2.3.5 / RFC 2181 §10.3',
        targetId: mxDnssec.rrset?.id,
      });
      mxHosts.push({
        preference: m.preference,
        exchange: exch,
        displayExchange: dispExch,
        isNullMx: false,
        isIpLiteral: true,
        cnameChain: [],
        addresses: [],
        ipv4Status: 'bogus',
        ipv6Status: 'bogus',
        addressRrsetIds: [],
        dane: {
          qname: `_25._tcp.${exch}`,
          resolvedOwner: `_25._tcp.${exch}`,
          cnameChain: [],
          status: 'no-tlsa-unsigned',
          dnssecStatus: 'insecure',
          records: [],
          rolloverReady: false,
          summary: 'Invalid IP literal MX target',
        },
      });
      continue;
    }

    const aRes = resolveCnameChainInLogs(queries, exch, RR_TYPES.A);
    const aaaaRes = resolveCnameChainInLogs(queries, exch, RR_TYPES.AAAA);
    const cnameChain = aRes.cnameChain.length > 0 ? aRes.cnameChain : aaaaRes.cnameChain;
    const finalHost = aRes.cnameChain.length > 0 ? aRes.finalOwner : aaaaRes.finalOwner;

    if (cnameChain.length > 0) {
      mailFindings.push({
        id: `mail-warn-mx-cname-${exch}`,
        severity: 'warning',
        code: 'MX_POINTS_TO_CNAME',
        title: `MX target ${dispExch} is a CNAME alias to ${displayFqdn(finalHost)}`,
        detail: `RFC 2181 §10.3 and RFC 5321 §5.1 state that MX exchange targets MUST NOT be aliases (CNAMEs). Point MX directly to the canonical hostname.`,
        rfc: 'RFC 2181 §10.3 / RFC 5321 §5.1',
      });
    }

    const aLog = findAnyLog(queries, finalHost, RR_TYPES.A) ?? findAnyLog(queries, exch, RR_TYPES.A);
    const aaaaLog = findAnyLog(queries, finalHost, RR_TYPES.AAAA) ?? findAnyLog(queries, exch, RR_TYPES.AAAA);

    const addresses: MxAddressEntry[] = [];
    for (const ans of aLog?.packet.answers ?? []) {
      if (ans.name === finalHost && ans.type === RR_TYPES.A && !addresses.some((x) => x.ip === ans.rdataText)) {
        addresses.push(classifyIpAddress(ans.rdataText, 4));
      }
    }
    for (const ans of aaaaLog?.packet.answers ?? []) {
      if (ans.name === finalHost && ans.type === RR_TYPES.AAAA && !addresses.some((x) => x.ip === ans.rdataText)) {
        addresses.push(classifyIpAddress(ans.rdataText, 6));
      }
    }

    const ipv4Eval = findEffectiveDnssecStatusForQuery(zones, exch, cnameChain, finalHost, RR_TYPES.A, 'A');
    const ipv6Eval = findEffectiveDnssecStatusForQuery(zones, exch, cnameChain, finalHost, RR_TYPES.AAAA, 'AAAA');
    const addressRrsetIds: string[] = [];
    if (ipv4Eval.rrset) addressRrsetIds.push(ipv4Eval.rrset.id);
    if (ipv6Eval.rrset) addressRrsetIds.push(ipv6Eval.rrset.id);

    for (const addr of addresses) {
      if (!addr.isPublic) {
        const isLoopbackOrZero = addr.ip.startsWith('127.') || addr.ip.startsWith('0.') || addr.ip === '::1' || addr.ip === '::';
        mailFindings.push({
          id: `mail-bogon-${exch}-${addr.ip}`,
          severity: isLoopbackOrZero ? 'error' : 'warning',
          code: 'MX_NON_PUBLIC_IP',
          title: `MX host ${dispExch} resolves to non-public IP ${addr.ip} (${addr.note})`,
          detail: `Public internet MTAs cannot deliver mail to ${addr.ip}. If ${dispTarget} intentionally rejects mail, use an RFC 7505 Null MX ("0 .") instead of loopback/private IPs.`,
          rfc: 'RFC 5321 / RFC 7505',
          targetId: ipv4Eval.rrset?.id ?? ipv6Eval.rrset?.id,
        });
      }
    }

    // Evaluate SMTP DANE (_25._tcp.<exch> TLSA) per RFC 6698 / RFC 7671 / RFC 7672
    let tlsaQname = normalizeFqdn(`_25._tcp.${exch}`);
    let tlsaRes = resolveCnameChainInLogs(queries, tlsaQname, RR_TYPES.TLSA);
    let tlsaLog = findAnyLog(queries, tlsaRes.finalOwner, RR_TYPES.TLSA) ?? findAnyLog(queries, tlsaQname, RR_TYPES.TLSA);

    // RFC 7672 §2.2.2: If MX itself was a DNSSEC-secure CNAME and _25._tcp.<alias> had no TLSA, check _25._tcp.<canonical>
    const hasInitialTlsa = (tlsaLog?.packet.answers ?? []).some(
      (r) => r.name === tlsaRes.finalOwner && r.type === RR_TYPES.TLSA
    );
    if (!hasInitialTlsa && cnameChain.length > 0) {
      const fallbackQname = normalizeFqdn(`_25._tcp.${finalHost}`);
      const fallbackRes = resolveCnameChainInLogs(queries, fallbackQname, RR_TYPES.TLSA);
      const fallbackLog =
        findAnyLog(queries, fallbackRes.finalOwner, RR_TYPES.TLSA) ??
        findAnyLog(queries, fallbackQname, RR_TYPES.TLSA);
      const hasFallbackTlsa = (fallbackLog?.packet.answers ?? []).some(
        (r) => r.name === fallbackRes.finalOwner && r.type === RR_TYPES.TLSA
      );
      if (hasFallbackTlsa) {
        tlsaQname = fallbackQname;
        tlsaRes = fallbackRes;
        tlsaLog = fallbackLog;
      }
    }

    const tlsaDnssec = findEffectiveDnssecStatusForQuery(
      zones,
      tlsaQname,
      tlsaRes.cnameChain,
      tlsaRes.finalOwner,
      RR_TYPES.TLSA,
      'TLSA'
    );

    const rawTlsaAnswers = (tlsaLog?.packet.answers ?? []).filter(
      (r) => r.name === tlsaRes.finalOwner && r.type === RR_TYPES.TLSA
    );

    const tlsaDetails: TlsaRecordDetail[] = rawTlsaAnswers.map((r) => {
      if (r.parsed.kind === 'TLSA') {
        return evaluateTlsaRecordDetail(
          r.name,
          r.ttl,
          r.parsed.usage,
          r.parsed.selector,
          r.parsed.matchingType,
          r.parsed.certAssociationHex
        );
      }
      const parts = r.rdataText.trim().split(/\s+/);
      return evaluateTlsaRecordDetail(
        r.name,
        r.ttl,
        Number.parseInt(parts[0] ?? '255', 10),
        Number.parseInt(parts[1] ?? '255', 10),
        Number.parseInt(parts[2] ?? '255', 10),
        parts[3] ?? ''
      );
    });

    // Rollover readiness check (RFC 7671 §8.1 / §8.4):
    // True if at least one DANE-TA (usage 2) is published OR >= 2 valid DANE-EE (usage 3) pins exist
    const validRecords = tlsaDetails.filter((d) => d.rdataValid);
    const hasDaneTa = validRecords.some((d) => d.usage === 2);
    const validDaneEeCount = validRecords.filter((d) => d.usage === 3).length;
    const rolloverReady = hasDaneTa || validDaneEeCount >= 2;

    let daneHostStatus: DaneHostStatus;
    let daneSummary = '';

    if (tlsaDetails.length === 0) {
      if (tlsaDnssec.status === 'bogus' || tlsaLog?.packet.flags.rcode === 2) {
        daneHostStatus = 'dane-bogus';
        daneSummary = 'DNSSEC denial-of-existence / lookup for _25._tcp TLSA failed (BOGUS) — MTA MUST defer delivery';
        mailFindings.push({
          id: `mail-err-dane-neg-bogus-${exch}`,
          severity: 'error',
          code: 'DANE_TLSA_LOOKUP_BOGUS',
          title: `Bogus DNSSEC proof on ${displayFqdn(tlsaQname)} TLSA`,
          detail: `Lookup or NSEC/NSEC3 non-existence proof for ${displayFqdn(tlsaQname)} TLSA failed DNSSEC validation. Per RFC 7672 §2.1.1, DANE-enabled MTAs treat this as a downgrade attack and MUST defer delivery.`,
          rfc: 'RFC 7672 §2.1.1',
          targetId: tlsaDnssec.negativeNode?.id,
        });
      } else if (tlsaDnssec.status === 'secure' || tlsaDnssec.status === 'warning') {
        daneHostStatus = 'no-tlsa-secure';
        daneSummary = 'No _25._tcp TLSA published (authenticated non-existence via DNSSEC)';
      } else {
        daneHostStatus = 'no-tlsa-unsigned';
        daneSummary = 'No _25._tcp TLSA published (MX zone is unsigned)';
      }
    } else {
      // TLSA records exist!
      for (const d of tlsaDetails) {
        if (!d.rdataValid) {
          mailFindings.push({
            id: `mail-err-tlsa-rdata-${exch}-${d.usage}-${d.selector}-${d.matchingType}`,
            severity: 'error',
            code: 'DANE_INVALID_TLSA_RDATA',
            title: `Malformed TLSA record at ${displayFqdn(tlsaQname)} (${d.usage} ${d.selector} ${d.matchingType})`,
            detail: d.issues.join('; '),
            rfc: 'RFC 6698 §2.1 / RFC 7671',
            targetId: tlsaDnssec.rrset?.id,
          });
        }
      }

      if (tlsaDnssec.status === 'bogus') {
        daneHostStatus = 'dane-bogus';
        daneSummary = 'TLSA signature / DNSSEC chain is BOGUS — DANE senders MUST abort delivery!';
        mailFindings.push({
          id: `mail-err-dane-bogus-${exch}`,
          severity: 'error',
          code: 'DANE_TLSA_BOGUS',
          title: `BOGUS DNSSEC chain for ${displayFqdn(tlsaQname)} TLSA`,
          detail: `Cryptographic DNSSEC verification failed on ${displayFqdn(tlsaQname)} TLSA. Per RFC 7672 §2.1.1, DANE SMTP senders MUST NOT deliver mail to ${dispExch}.`,
          rfc: 'RFC 7672 §2.1.1',
          targetId: tlsaDnssec.rrset?.id,
        });
      } else if (tlsaDnssec.status === 'insecure' || tlsaDnssec.status === 'indeterminate') {
        daneHostStatus = 'dane-unsigned-ignored';
        daneSummary = 'TLSA published in an UNSIGNED zone — ignored by all RFC 7672 SMTP validators!';
        mailFindings.push({
          id: `mail-warn-dane-unsigned-${exch}`,
          severity: 'warning',
          code: 'DANE_TLSA_UNSIGNED',
          title: `Unsigned TLSA record at ${displayFqdn(tlsaQname)} provides zero DANE protection`,
          detail: `${displayFqdn(tlsaQname)} publishes ${tlsaDetails.length} TLSA record(s), but its DNS zone is unsigned (${tlsaDnssec.status.toUpperCase()}). Per RFC 7672 §2.1, SMTP validators MUST ignore unauthenticated TLSA records.`,
          rfc: 'RFC 7672 §2.1',
          targetId: tlsaDnssec.rrset?.id,
        });
      } else if (validRecords.length === 0) {
        daneHostStatus = 'dane-bogus';
        daneSummary = 'All published TLSA records at _25._tcp have invalid parameters/digests';
      } else {
        // TLSA RRset is DNSSEC SECURE and has >= 1 valid TLSA record!
        const onlyPkixUsages = validRecords.every((d) => !d.smtpRecommended);
        const singleCertLeafPin =
          validRecords.length === 1 && validRecords[0].usage === 3 && validRecords[0].selector === 0;
        const mxUnsigned = mxDnssec.status === 'insecure' || mxDnssec.status === 'indeterminate';

        if (onlyPkixUsages) {
          mailFindings.push({
            id: `mail-warn-dane-pkix-${exch}`,
            severity: 'warning',
            code: 'DANE_PKIX_USAGE_DISCOURAGED',
            title: `${displayFqdn(tlsaQname)} uses ${validRecords[0].usageMnemonic} (${validRecords[0].usage}) instead of DANE-EE (3) / DANE-TA (2)`,
            detail: `RFC 7672 §3.1.3 discourages PKIX-TA(0) and PKIX-EE(1) for SMTP because MTAs often lack a shared WebPKI root store configuration, causing TLSA records to be treated as unusable.`,
            rfc: 'RFC 7672 §3.1.3',
            targetId: tlsaDnssec.rrset?.id,
          });
        }

        if (singleCertLeafPin) {
          mailFindings.push({
            id: `mail-warn-dane-301-rollover-${exch}`,
            severity: 'warning',
            code: 'DANE_SINGLE_CERT_ROLLOVER_RISK',
            title: `Single "3 0 ${validRecords[0].matchingType}" (DANE-EE + Full Cert) at ${displayFqdn(tlsaQname)} risks outage on cert renewal`,
            detail: `Selector 0 hashes the entire X.509 certificate (including serial and validity dates), breaking immediately on ACME/Let's Encrypt renewal unless staged in advance. Prefer "3 1 1" (SPKI public key hash) with a backup key or "2 1 1" (DANE-TA).`,
            rfc: 'RFC 7671 §5.2.1 / §8.1',
            targetId: tlsaDnssec.rrset?.id,
          });
        }

        if (onlyPkixUsages || singleCertLeafPin || mxUnsigned || tlsaDetails.some((d) => !d.rdataValid)) {
          daneHostStatus = 'dane-warning';
          daneSummary = mxUnsigned
            ? `TLSA authenticated via DNSSEC (${validRecords.map((r) => `${r.usage} ${r.selector} ${r.matchingType}`).join(', ')}), but ${dispTarget} MX RRset is unsigned`
            : `DANE TLSA authenticated via DNSSEC with RFC 7671/7672 operational warnings`;
        } else {
          daneHostStatus = 'dane-valid';
          daneSummary = `Authenticated SMTP DANE (${validRecords.map((r) => `${r.usageMnemonic} ${r.usage} ${r.selector} ${r.matchingType}`).join(', ')})`;
        }
      }
    }

    mxHosts.push({
      preference: m.preference,
      exchange: exch,
      displayExchange: dispExch,
      isNullMx: false,
      isIpLiteral: false,
      cnameChain,
      addresses,
      ipv4Status: ipv4Eval.status,
      ipv6Status: ipv6Eval.status,
      addressRrsetIds,
      dane: {
        qname: tlsaQname,
        resolvedOwner: tlsaRes.finalOwner,
        cnameChain: tlsaRes.cnameChain,
        status: daneHostStatus,
        dnssecStatus: tlsaDnssec.status,
        rrsetId: tlsaDnssec.rrset?.id,
        negativeNodeId: tlsaDnssec.negativeNode?.id,
        records: tlsaDetails,
        rolloverReady,
        summary: daneSummary,
      },
    });
  }

  // Cross-host MX & DANE checks
  const nonNullHosts = mxHosts.filter((h) => !h.isNullMx);
  if (nonNullHosts.length > 0) {
    const hostsWithoutIps = nonNullHosts.filter((h) => !h.isIpLiteral && h.addresses.length === 0);
    const hostsWithPublicIps = nonNullHosts.filter((h) => h.addresses.some((a) => a.isPublic));

    if (hostsWithPublicIps.length === 0) {
      mxStatus = 'broken';
      for (const h of hostsWithoutIps) {
        mailFindings.push({
          id: `mail-err-mx-noip-${h.exchange}`,
          severity: 'error',
          code: 'MX_HOST_NO_ADDRESS',
          title: `MX exchanger ${h.displayExchange} has no A or AAAA address records`,
          detail: `Remote mail servers cannot resolve any IPv4 or IPv6 address for ${h.displayExchange}, breaking incoming mail delivery.`,
          rfc: 'RFC 5321 §5.1',
        });
      }
    } else {
      if (hostsWithoutIps.length > 0) {
        mxStatus = 'warning';
        for (const h of hostsWithoutIps) {
          mailFindings.push({
            id: `mail-warn-mx-noip-${h.exchange}`,
            severity: 'warning',
            code: 'MX_HOST_NO_ADDRESS',
            title: `Secondary/MX exchanger ${h.displayExchange} has no A or AAAA records`,
            detail: `Dangling MX target ${h.displayExchange} resolves to zero IP addresses, causing delays or failures when selected.`,
            rfc: 'RFC 5321 §5.1',
          });
        }
      }
      if (
        mxAtCname ||
        nonNullHosts.some(
          (h) =>
            h.isIpLiteral ||
            h.cnameChain.length > 0 ||
            h.addresses.some((a) => !a.isPublic) ||
            h.ipv4Status === 'bogus' ||
            h.ipv6Status === 'bogus'
        )
      ) {
        if (mxStatus === 'valid') mxStatus = 'warning';
      }
      if (nonNullHosts.some((h) => h.ipv4Status === 'bogus' || h.ipv6Status === 'bogus') || mxDnssec.status === 'bogus') {
        mxStatus = 'broken';
      }

      const anyIpv6 = nonNullHosts.some((h) => h.addresses.some((a) => a.family === 6 && a.isPublic));
      if (!anyIpv6) {
        mailFindings.push({
          id: `mail-info-mx-no-ipv6-${targetName}`,
          severity: 'info',
          code: 'MX_NO_IPV6_REACHABILITY',
          title: `No IPv6 (AAAA) mail exchangers configured for ${dispTarget}`,
          detail: `All MX exchangers resolve only to IPv4 (A) addresses. Adding dual-stack AAAA records improves IPv6-only MTA reachability.`,
          rfc: 'RFC 5321',
        });
      }
      if (nonNullHosts.length === 1) {
        mailFindings.push({
          id: `mail-info-single-mx-${targetName}`,
          severity: 'info',
          code: 'MX_SINGLE_EXCHANGER',
          title: `Single MX hostname (${nonNullHosts[0].displayExchange}) published for ${dispTarget}`,
          detail: `Only one MX hostname is listed (acceptable if backed by anycast/load-balanced infrastructure, otherwise a single point of failure).`,
          rfc: 'RFC 5321 §5.1',
        });
      }
    }
  }

  // Aggregate DANE Posture across MX hosts
  let daneStatus: MailAnalysisResult['daneStatus'] = 'not-applicable';
  let daneSummary = '';

  if (mxStatus === 'null-mx' || nonNullHosts.length === 0) {
    daneStatus = 'not-applicable';
    daneSummary =
      mxStatus === 'null-mx'
        ? 'Not applicable — domain publishes an RFC 7505 Null MX (0 .).'
        : 'No explicit MX hosts published to evaluate _25._tcp TLSA records.';
  } else {
    const statuses = nonNullHosts.map((h) => h.dane.status);
    const anyValidOrWarn = statuses.some((s) => s === 'dane-valid' || s === 'dane-warning');
    const allValid = statuses.every((s) => s === 'dane-valid');
    const allValidOrWarn = statuses.every((s) => s === 'dane-valid' || s === 'dane-warning');
    const anyBogus = statuses.includes('dane-bogus');
    const anyUnsignedTlsa = statuses.includes('dane-unsigned-ignored');
    const mxUnsigned = mxDnssec.status === 'insecure' || mxDnssec.status === 'indeterminate';

    if (anyValidOrWarn && mxUnsigned) {
      mailFindings.push({
        id: `mail-warn-dane-mx-unsigned-${targetName}`,
        severity: 'warning',
        code: 'DANE_MX_RRSET_UNSIGNED',
        title: `MX hosts publish DNSSEC-valid DANE TLSA, but ${dispTarget} MX RRset is unsigned`,
        detail: `Per RFC 7672 §2.2.1, DANE authenticates TLS on ${nonNullHosts.filter((h) => h.dane.status === 'dane-valid' || h.dane.status === 'dane-warning').map((h) => h.displayExchange).join(', ')}, but because ${dispTarget} itself is unsigned, an active attacker could spoof the initial MX lookup to redirect mail to an untrusted host. Sign ${dispTarget} with DNSSEC for full end-to-end SMTP DANE protection.`,
        rfc: 'RFC 7672 §2.2.1',
      });
    }

    if (anyBogus) {
      daneStatus = 'bogus';
      daneSummary = 'SMTP DANE validation FAILED (BOGUS) on one or more MX exchangers — DANE-capable senders will defer/abort mail delivery!';
    } else if (allValid && !mxUnsigned) {
      daneStatus = 'all-valid';
      daneSummary = `End-to-end SMTP DANE (RFC 7672) cryptographically verified across all ${nonNullHosts.length} MX exchanger${nonNullHosts.length === 1 ? '' : 's'}.`;
      mailFindings.push({
        id: `mail-info-dane-verified-${targetName}`,
        severity: 'info',
        code: 'SMTP_DANE_VERIFIED',
        title: `End-to-end SMTP DANE verified for ${dispTarget}`,
        detail: `Both ${dispTarget} MX records and _25._tcp TLSA records are DNSSEC-signed and cryptographically verified via WebCrypto.`,
        rfc: 'RFC 7671 / RFC 7672',
      });
    } else if (allValidOrWarn || anyValidOrWarn) {
      daneStatus = 'partial';
      const protectedCount = statuses.filter((s) => s === 'dane-valid' || s === 'dane-warning').length;
      daneSummary = mxUnsigned
        ? `TLSA records on ${protectedCount}/${nonNullHosts.length} MX host(s) are DNSSEC-valid, but ${dispTarget} MX selection is unsigned (RFC 7672 §2.2.1).`
        : protectedCount < nonNullHosts.length
          ? `Partial SMTP DANE: ${protectedCount} of ${nonNullHosts.length} MX exchangers publish valid DNSSEC-signed TLSA records.`
          : `SMTP DANE active across ${protectedCount} MX exchanger(s) with RFC 7671/7672 rollover or usage advisories.`;
    } else if (anyUnsignedTlsa) {
      daneStatus = 'unsigned-ignored';
      daneSummary = 'TLSA record(s) published without DNSSEC — ignored by SMTP DANE validators (RFC 7672 §2.1).';
    } else {
      daneStatus = 'not-deployed';
      const mxSigned = mxDnssec.status === 'secure' || mxDnssec.status === 'warning';
      daneSummary = mxSigned
        ? 'No _25._tcp TLSA records published on MX hosts (STARTTLS relies on opportunistic TLS unless MTA-STS is used).'
        : 'Not deployed — neither DNSSEC nor _25._tcp TLSA records are published for MX exchangers.';
      mailFindings.push({
        id: `mail-info-dane-missing-${targetName}`,
        severity: mxSigned ? 'warning' : 'info',
        code: 'SMTP_DANE_NOT_DEPLOYED',
        title: `SMTP DANE (_25._tcp TLSA) not deployed for ${dispTarget}`,
        detail: mxSigned
          ? `${dispTarget} is already DNSSEC-signed, making it ready for SMTP DANE! Publishing _25._tcp.<mx> TLSA records (e.g. "3 1 1" or "2 1 1") prevents active STARTTLS downgrade attacks (RFC 7672).`
          : `No _25._tcp TLSA records found on MX exchangers. Enable DNSSEC and publish _25._tcp TLSA records to protect inbound SMTP against STARTTLS stripping.`,
        rfc: 'RFC 7672',
      });
    }
  }

  // 2. Evaluate SPF (TXT v=spf1 + legacy TYPE99 + recursive lookup budget)
  const spfState = {
    dnsLookupCount: 0,
    voidLookupCount: 0,
    hasSyntaxOrPermError: false,
    hasTempError: false,
    effectiveAllQualifier: undefined as SpfQualifier | undefined,
  };

  const txtRes = resolveCnameChainInLogs(queries, targetName, RR_TYPES.TXT);
  const effectiveSpfOwner = txtRes.finalOwner;
  const rootTxtDnssec = findEffectiveDnssecStatusForQuery(
    zones,
    targetName,
    txtRes.cnameChain,
    effectiveSpfOwner,
    RR_TYPES.TXT,
    'TXT'
  );

  const legacySpfLog = findAnyLog(queries, effectiveSpfOwner, RR_TYPES.SPF) ?? findAnyLog(queries, targetName, RR_TYPES.SPF);
  const legacySpfRecords = extractTxtJoinedStrings(legacySpfLog, effectiveSpfOwner, RR_TYPES.SPF).filter(
    isSpfRecordText
  );
  if (legacySpfRecords.length > 0) {
    mailFindings.push({
      id: `mail-warn-spf-type99-${targetName}`,
      severity: 'warning',
      code: 'SPF_LEGACY_TYPE99_PRESENT',
      title: `Obsolete DNS RR type SPF (TYPE99) published at ${dispTarget}`,
      detail: `RFC 7208 §3.1 formally discontinued the dedicated SPF RR type (99) in 2014. Keep SPF policies solely in TXT records and remove TYPE99 to prevent drift.`,
      rfc: 'RFC 7208 §3.1',
    });
  }

  const evaluateSpfDomainSync = (
    domainFqdn: string,
    via: 'root' | 'include' | 'redirect',
    depth: number,
    ancestors: Set<string>
  ): SpfDomainNode => {
    const normDom = normalizeFqdn(domainFqdn);
    const dispDom = displayFqdn(normDom);

    if (ancestors.has(normDom)) {
      spfState.hasSyntaxOrPermError = true;
      return {
        domain: normDom,
        displayDomain: dispDom,
        via,
        depth,
        spfRecords: [],
        terms: [],
        loopDetected: true,
        error: `Circular SPF ${via} loop detected back to ${dispDom} (RFC 7208 §4.6.4 permerror)`,
      };
    }

    if (depth > MAX_SPF_RECURSION_DEPTH) {
      spfState.hasSyntaxOrPermError = true;
      return {
        domain: normDom,
        displayDomain: dispDom,
        via,
        depth,
        spfRecords: [],
        terms: [],
        error: `Exceeded maximum SPF recursion depth (${MAX_SPF_RECURSION_DEPTH})`,
      };
    }

    const domRes = resolveCnameChainInLogs(queries, normDom, RR_TYPES.TXT);
    const txtOwner = domRes.finalOwner;
    const txtLog = findAnyLog(queries, txtOwner, RR_TYPES.TXT) ?? findAnyLog(queries, normDom, RR_TYPES.TXT);
    const rcode = txtLog?.packet.flags.rcode;
    const rcodeName = rcode !== undefined ? rcodeToString(rcode) : undefined;
    const allTxt = extractTxtJoinedStrings(txtLog, txtOwner, RR_TYPES.TXT);
    const spfRecords = allTxt.filter(isSpfRecordText);

    const nodeDnssecStatus =
      via === 'root'
        ? rootTxtDnssec.status
        : txtLog?.packet.flags.rcode === 2
          ? 'bogus'
          : txtLog?.packet.flags.ad
            ? 'secure'
            : 'insecure';

    if (txtLog && rcode === 2) {
      spfState.hasTempError = true;
      return {
        domain: normDom,
        displayDomain: dispDom,
        via,
        depth,
        spfRecords: [],
        dnssecStatus: nodeDnssecStatus,
        adBit: txtLog.packet.flags.ad,
        rcodeName,
        terms: [],
        error: `DNS lookup for ${dispDom} TXT returned SERVFAIL (RFC 7208 temperror)`,
      };
    }

    // Track void lookup on include / redirect returning NXDOMAIN or 0 TXT records
    if (via !== 'root' && txtLog && (rcode === 3 || allTxt.length === 0)) {
      spfState.voidLookupCount++;
    }

    if (spfRecords.length === 0) {
      if (via !== 'root') {
        // RFC 7208 §5.2 / §6.1: include: or redirect= target with NO SPF record causes permerror!
        spfState.hasSyntaxOrPermError = true;
      }
      return {
        domain: normDom,
        displayDomain: dispDom,
        via,
        depth,
        spfRecords: [],
        legacySpfType99Records: via === 'root' ? legacySpfRecords : undefined,
        dnssecStatus: nodeDnssecStatus,
        adBit: txtLog?.packet.flags.ad,
        rcodeName,
        terms: [],
        error:
          via === 'root'
            ? undefined
            : `Target ${dispDom} (${via}) publishes no v=spf1 TXT record — causes RFC 7208 ${via === 'include' ? '§5.2' : '§6.1'} permerror`,
      };
    }

    if (spfRecords.length > 1) {
      spfState.hasSyntaxOrPermError = true;
      return {
        domain: normDom,
        displayDomain: dispDom,
        via,
        depth,
        spfRecords,
        legacySpfType99Records: via === 'root' ? legacySpfRecords : undefined,
        dnssecStatus: nodeDnssecStatus,
        adBit: txtLog?.packet.flags.ad,
        rcodeName,
        terms: [],
        error: `${dispDom} publishes ${spfRecords.length} v=spf1 TXT records — RFC 7208 §3.2 / §4.5 requires at most one (permerror)`,
      };
    }

    const terms = parseSpfTerms(spfRecords[0]);
    const nextAncestors = new Set(ancestors);
    nextAncestors.add(normDom);

    for (const term of terms) {
      if (!term.syntaxValid) {
        spfState.hasSyntaxOrPermError = true;
      }
      if (!term.countsTowardLookupLimit) {
        if (
          via === 'root' &&
          term.kind === 'mechanism' &&
          term.mechanism === 'all' &&
          term.syntaxValid &&
          !term.unreachableAfterAll
        ) {
          spfState.effectiveAllQualifier = term.qualifier ?? '+';
        }
        continue;
      }

      spfState.dnsLookupCount++;

      if (term.kind === 'mechanism' && term.mechanism === 'include' && term.value) {
        if (hasSpfMacro(term.value)) {
          term.warning = 'Uses runtime SPF macro expansion (RFC 7208 §7); +1 DNS lookup counted';
        } else {
          const child = evaluateSpfDomainSync(term.value, 'include', depth + 1, nextAncestors);
          term.childNode = child;
          if (child.rcodeName === 'NXDOMAIN' || (child.spfRecords.length === 0 && !child.error?.includes('SERVFAIL'))) {
            term.isVoidLookup = true;
          }
        }
      } else if (term.kind === 'modifier' && term.modifier === 'redirect' && term.value) {
        if (hasSpfMacro(term.value)) {
          term.warning = 'Uses runtime SPF macro expansion (RFC 7208 §7); +1 DNS lookup counted';
        } else {
          const child = evaluateSpfDomainSync(term.value, 'redirect', depth + 1, nextAncestors);
          term.childNode = child;
          if (via === 'root' && spfState.effectiveAllQualifier === undefined) {
            const redirAll = child.terms.find(
              (t) => t.kind === 'mechanism' && t.mechanism === 'all' && t.syntaxValid && !t.unreachableAfterAll
            );
            if (redirAll) {
              spfState.effectiveAllQualifier = redirAll.qualifier ?? '+';
            }
          }
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'a') {
        const lookupDom = term.value ?? normDom;
        if (!hasSpfMacro(lookupDom)) {
          const normTarget = normalizeFqdn(lookupDom);
          const aRes = resolveCnameChainInLogs(queries, normTarget, RR_TYPES.A);
          const aL = findAnyLog(queries, aRes.finalOwner, RR_TYPES.A) ?? findAnyLog(queries, normTarget, RR_TYPES.A);
          const aaaaL =
            findAnyLog(queries, aRes.finalOwner, RR_TYPES.AAAA) ?? findAnyLog(queries, normTarget, RR_TYPES.AAAA);
          const ips: string[] = [];
          for (const r of aL?.packet.answers ?? []) {
            if (r.name === aRes.finalOwner && r.type === RR_TYPES.A && !ips.includes(r.rdataText)) ips.push(r.rdataText);
          }
          for (const r of aaaaL?.packet.answers ?? []) {
            if (r.name === aRes.finalOwner && r.type === RR_TYPES.AAAA && !ips.includes(r.rdataText)) {
              ips.push(r.rdataText);
            }
          }
          term.resolvedIps = ips;
          if (aL && ips.length === 0 && (aL.packet.flags.rcode === 3 || aL.packet.flags.rcode === 0)) {
            if (!aaaaL || aaaaL.packet.answers.filter((r) => r.type === RR_TYPES.AAAA).length === 0) {
              term.isVoidLookup = true;
              spfState.voidLookupCount++;
            }
          }
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'mx') {
        const lookupDom = term.value ?? normDom;
        if (!hasSpfMacro(lookupDom)) {
          const normTarget = normalizeFqdn(lookupDom);
          const mRes = resolveCnameChainInLogs(queries, normTarget, RR_TYPES.MX);
          const mL = findAnyLog(queries, mRes.finalOwner, RR_TYPES.MX) ?? findAnyLog(queries, normTarget, RR_TYPES.MX);
          const mxExchanges = (mL?.packet.answers ?? [])
            .filter((r) => r.name === mRes.finalOwner && r.type === RR_TYPES.MX && r.parsed.kind === 'MX')
            .map((r) => normalizeFqdn((r.parsed as { kind: 'MX'; exchange: string }).exchange))
            .filter((e) => e !== '.');

          if (mxExchanges.length > 10) {
            // RFC 7208 §4.6.4: Evaluating an "mx" mechanism MUST NOT result in querying > 10 MX A/AAAA records!
            spfState.hasSyntaxOrPermError = true;
            term.error = `"mx" mechanism resolves ${mxExchanges.length} MX records, exceeding the RFC 7208 §4.6.4 10-MX limit (permerror)`;
          }

          const ips: string[] = [];
          for (const ex of mxExchanges.slice(0, 10)) {
            const exRes = resolveCnameChainInLogs(queries, ex, RR_TYPES.A);
            const aL = findAnyLog(queries, exRes.finalOwner, RR_TYPES.A) ?? findAnyLog(queries, ex, RR_TYPES.A);
            const aaaaL = findAnyLog(queries, exRes.finalOwner, RR_TYPES.AAAA) ?? findAnyLog(queries, ex, RR_TYPES.AAAA);
            for (const r of aL?.packet.answers ?? []) {
              if (r.name === exRes.finalOwner && r.type === RR_TYPES.A && !ips.includes(r.rdataText)) {
                ips.push(r.rdataText);
              }
            }
            for (const r of aaaaL?.packet.answers ?? []) {
              if (r.name === exRes.finalOwner && r.type === RR_TYPES.AAAA && !ips.includes(r.rdataText)) {
                ips.push(r.rdataText);
              }
            }
          }
          term.resolvedIps = ips;
          if (mL && mxExchanges.length === 0 && (mL.packet.flags.rcode === 3 || mL.packet.flags.rcode === 0)) {
            term.isVoidLookup = true;
            spfState.voidLookupCount++;
          }
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'exists' && term.value) {
        if (hasSpfMacro(term.value)) {
          term.warning = 'Uses runtime SPF macro expansion (RFC 7208 §7); +1 DNS lookup counted';
        } else {
          const exNorm = normalizeFqdn(term.value);
          const aL = findAnyLog(queries, exNorm, RR_TYPES.A);
          const ips = (aL?.packet.answers ?? [])
            .filter((r) => r.type === RR_TYPES.A)
            .map((r) => r.rdataText);
          term.resolvedIps = ips;
        }
      }
    }

    return {
      domain: normDom,
      displayDomain: dispDom,
      via,
      depth,
      spfRecords,
      legacySpfType99Records: via === 'root' ? legacySpfRecords : undefined,
      dnssecStatus: nodeDnssecStatus,
      adBit: txtLog?.packet.flags.ad,
      rcodeName,
      terms,
    };
  };

  const rootSpfNode = evaluateSpfDomainSync(effectiveSpfOwner, 'root', 0, new Set<string>());
  const spfPresent = rootSpfNode.spfRecords.length > 0;

  if (spfState.dnsLookupCount > SPF_DNS_LOOKUP_LIMIT) {
    spfState.hasSyntaxOrPermError = true;
  }

  let spfVerdict: SpfPolicyVerdict = 'none';
  let spfSummary = '';

  if (!spfPresent) {
    spfVerdict = rootSpfNode.error?.includes('SERVFAIL') ? 'temperror' : 'none';
    spfSummary =
      spfVerdict === 'temperror'
        ? `SPF TXT lookup failed with SERVFAIL (temperror).`
        : `No v=spf1 TXT record published at ${dispTarget}.`;

    if (!isDomainNxdomain && spfVerdict === 'none') {
      mailFindings.push({
        id: `mail-warn-spf-missing-${targetName}`,
        severity: 'warning',
        code: mxStatus === 'null-mx' ? 'SPF_MISSING_ON_NULL_MX' : 'SPF_RECORD_MISSING',
        title:
          mxStatus === 'null-mx'
            ? `Null MX domain ${dispTarget} lacks a strict "v=spf1 -all" TXT record`
            : `No SPF (v=spf1) TXT policy published for ${dispTarget}`,
        detail:
          mxStatus === 'null-mx'
            ? `RFC 7505 Null MX blocks inbound mail to ${dispTarget}, but does not stop attackers from spoofing outbound MAIL FROM:<user@${dispTarget}>. Publish TXT "v=spf1 -all" to block envelope spoofing.`
            : `No TXT record starting with "v=spf1" was found at ${dispTarget}. Publish an SPF policy (ending in "-all" or "~all") to authorize legitimate outbound mail servers.`,
        rfc: 'RFC 7208',
      });
    }
  } else {
    // Emit specific findings for SPF errors/warnings across the evaluated tree
    const collectSpfNodeIssues = (node: SpfDomainNode) => {
      if (node.spfRecords.length > 1) {
        mailFindings.push({
          id: `mail-err-spf-multi-${node.domain}`,
          severity: 'error',
          code: 'SPF_MULTIPLE_TXT_RECORDS',
          title: `Multiple v=spf1 TXT records at ${node.displayDomain} (${node.spfRecords.length} found)`,
          detail: `RFC 7208 §3.2 & §4.5 strictly forbid publishing more than one v=spf1 record at the same domain; receivers MUST return permerror.`,
          rfc: 'RFC 7208 §3.2 / §4.5',
          targetId: node.via === 'root' ? rootTxtDnssec.rrset?.id : undefined,
        });
      } else if (node.loopDetected && node.error) {
        mailFindings.push({
          id: `mail-err-spf-loop-${node.domain}`,
          severity: 'error',
          code: 'SPF_INCLUDE_REDIRECT_LOOP',
          title: `Circular SPF loop detected at ${node.displayDomain}`,
          detail: node.error,
          rfc: 'RFC 7208 §4.6.4',
        });
      } else if (node.error && node.via !== 'root') {
        mailFindings.push({
          id: `mail-err-spf-child-${node.domain}`,
          severity: 'error',
          code: 'SPF_BROKEN_INCLUDE_OR_REDIRECT',
          title: `Broken SPF ${node.via} target: ${node.displayDomain}`,
          detail: node.error,
          rfc: 'RFC 7208 §5.2 / §6.1',
        });
      }

      for (const t of node.terms) {
        if (!t.syntaxValid && t.error) {
          mailFindings.push({
            id: `mail-err-spf-syntax-${node.domain}-${t.raw}`,
            severity: 'error',
            code: 'SPF_SYNTAX_PERMERROR',
            title: `SPF syntax error in ${node.displayDomain}: "${t.raw}"`,
            detail: t.error,
            rfc: 'RFC 7208 §4.6.1',
            targetId: node.via === 'root' ? rootTxtDnssec.rrset?.id : undefined,
          });
        }
        if (t.mechanism === 'ptr' && !t.unreachableAfterAll) {
          mailFindings.push({
            id: `mail-warn-spf-ptr-${node.domain}`,
            severity: 'warning',
            code: 'SPF_DEPRECATED_PTR',
            title: `Deprecated SPF "ptr" mechanism used in ${node.displayDomain}`,
            detail: `RFC 7208 §5.5 states the "ptr" mechanism SHOULD NOT be published due to slow reverse-DNS lookups and reliability failures.`,
            rfc: 'RFC 7208 §5.5',
          });
        }
        if (t.unreachableAfterAll) {
          mailFindings.push({
            id: `mail-warn-spf-after-all-${node.domain}-${t.raw}`,
            severity: 'warning',
            code: 'SPF_UNREACHABLE_AFTER_ALL',
            title: `Unreachable SPF term "${t.raw}" after "all" in ${node.displayDomain}`,
            detail: `Because "all" matches every IP address, any mechanism placed after it is never evaluated.`,
            rfc: 'RFC 7208 §5.1',
          });
        }
        if (t.kind === 'modifier' && t.modifier === 'redirect' && t.warning?.includes('Ignored')) {
          mailFindings.push({
            id: `mail-warn-spf-redir-ignored-${node.domain}`,
            severity: 'warning',
            code: 'SPF_REDIRECT_IGNORED_WITH_ALL',
            title: `SPF "redirect=" modifier in ${node.displayDomain} is ignored because "all" is present`,
            detail: t.warning,
            rfc: 'RFC 7208 §6.1',
          });
        }
        if (t.childNode) collectSpfNodeIssues(t.childNode);
      }
    };
    collectSpfNodeIssues(rootSpfNode);

    if (spfState.dnsLookupCount > SPF_DNS_LOOKUP_LIMIT) {
      mailFindings.push({
        id: `mail-err-spf-lookup-limit-${targetName}`,
        severity: 'error',
        code: 'SPF_DNS_LOOKUP_LIMIT_EXCEEDED',
        title: `SPF policy exceeds 10-DNS-lookup limit (${spfState.dnsLookupCount} / ${SPF_DNS_LOOKUP_LIMIT} lookups)`,
        detail: `RFC 7208 §4.6.4 mandates that SPF evaluation MUST abort with permerror when more than 10 DNS-querying mechanisms/modifiers (include, a, mx, ptr, exists, redirect) are evaluated.`,
        rfc: 'RFC 7208 §4.6.4',
        targetId: rootTxtDnssec.rrset?.id,
      });
    } else if (spfState.dnsLookupCount >= 8) {
      mailFindings.push({
        id: `mail-info-spf-lookup-near-${targetName}`,
        severity: 'info',
        code: 'SPF_DNS_LOOKUP_NEAR_LIMIT',
        title: `SPF policy uses ${spfState.dnsLookupCount} of ${SPF_DNS_LOOKUP_LIMIT} allowed DNS lookups`,
        detail: `Currently within RFC 7208 §4.6.4 limits, but adding third-party "include:" providers could push evaluation past 10 lookups (permerror).`,
        rfc: 'RFC 7208 §4.6.4',
      });
    }

    if (spfState.voidLookupCount > SPF_VOID_LOOKUP_LIMIT) {
      mailFindings.push({
        id: `mail-warn-spf-void-limit-${targetName}`,
        severity: 'warning',
        code: 'SPF_EXCESSIVE_VOID_LOOKUPS',
        title: `SPF policy triggers ${spfState.voidLookupCount} void DNS lookups (RFC limit: ${SPF_VOID_LOOKUP_LIMIT})`,
        detail: `RFC 7208 §4.6.4 allows receivers to abort SPF with permerror after more than 2 lookups return NXDOMAIN or empty answers (0 records). Remove stale includes/mechanisms.`,
        rfc: 'RFC 7208 §4.6.4',
      });
    }

    if (rootTxtDnssec.status === 'bogus') {
      mailFindings.push({
        id: `mail-err-spf-dnssec-bogus-${targetName}`,
        severity: 'error',
        code: 'SPF_TXT_DNSSEC_BOGUS',
        title: `SPF TXT RRset at ${dispTarget} failed DNSSEC validation (BOGUS)`,
        detail: `Validating resolvers return SERVFAIL for ${dispTarget} TXT, causing SPF evaluation to fail with temperror.`,
        rfc: 'RFC 7208 / RFC 4035',
        targetId: rootTxtDnssec.rrset?.id,
      });
    }

    if (spfState.hasSyntaxOrPermError) {
      spfVerdict = 'permerror';
      spfSummary = `SPF evaluation results in PERMERROR (${spfState.dnsLookupCount}/${SPF_DNS_LOOKUP_LIMIT} DNS lookups).`;
    } else if (spfState.hasTempError || rootTxtDnssec.status === 'bogus') {
      spfVerdict = 'temperror';
      spfSummary = `SPF evaluation encountered DNS SERVFAIL (TEMPERROR).`;
    } else if (spfState.effectiveAllQualifier === '+') {
      spfVerdict = 'pass-all';
      spfSummary = `CRITICAL: SPF ends with "+all", authorizing EVERY IP on the internet to spoof ${dispTarget}!`;
      mailFindings.push({
        id: `mail-err-spf-pass-all-${targetName}`,
        severity: 'error',
        code: 'SPF_DANGEROUS_PASS_ALL',
        title: `SPF policy at ${dispTarget} uses "+all" (authorizes universal spoofing!)`,
        detail: `An unqualified "all" or "+all" mechanism evaluates to PASS for every IPv4 and IPv6 host on the internet. Replace "+all" with "~all" or "-all" immediately.`,
        rfc: 'RFC 7208 §5.1',
        targetId: rootTxtDnssec.rrset?.id,
      });
    } else if (spfState.effectiveAllQualifier === '?') {
      spfVerdict = 'neutral';
      spfSummary = `SPF policy ends with neutral "?all" (${spfState.dnsLookupCount}/${SPF_DNS_LOOKUP_LIMIT} DNS lookups) — provides no spoofing rejection.`;
      mailFindings.push({
        id: `mail-warn-spf-neutral-all-${targetName}`,
        severity: 'warning',
        code: 'SPF_WEAK_NEUTRAL_ALL',
        title: `SPF policy at ${dispTarget} uses neutral "?all"`,
        detail: `"?all" instructs receivers to treat unauthorized senders as Neutral (same as having no SPF policy). Prefer "~all" (SoftFail) or "-all" (Fail).`,
        rfc: 'RFC 7208 §5.1',
        targetId: rootTxtDnssec.rrset?.id,
      });
    } else if (spfState.effectiveAllQualifier === '~') {
      spfVerdict = 'soft-fail';
      spfSummary = `Valid SPF SoftFail policy (~all) using ${spfState.dnsLookupCount}/${SPF_DNS_LOOKUP_LIMIT} DNS lookups.`;
    } else if (spfState.effectiveAllQualifier === '-') {
      spfVerdict = 'strict-fail';
      spfSummary = `Valid strict SPF Fail policy (-all) using ${spfState.dnsLookupCount}/${SPF_DNS_LOOKUP_LIMIT} DNS lookups.`;
    } else {
      spfVerdict = 'no-default';
      spfSummary = `SPF policy has no terminal "all" or "redirect=" (${spfState.dnsLookupCount}/${SPF_DNS_LOOKUP_LIMIT} DNS lookups; defaults to Neutral).`;
      mailFindings.push({
        id: `mail-warn-spf-no-all-${targetName}`,
        severity: 'warning',
        code: 'SPF_MISSING_TERMINAL_ALL',
        title: `SPF policy at ${dispTarget} lacks a terminal "-all", "~all", or "redirect="`,
        detail: `Per RFC 7208 §4.7, reaching the end of an SPF record without matching returns Neutral (?all), leaving unauthorized IPs unrejected.`,
        rfc: 'RFC 7208 §4.7',
        targetId: rootTxtDnssec.rrset?.id,
      });
    }
  }

  const mailAnalysis: MailAnalysisResult = {
    mxStatus,
    mxDnssecStatus: mxDnssec.status,
    mxRrsetId: mxDnssec.rrset?.id,
    mxAtCname,
    mxHosts,
    implicitFallbackAddresses,
    daneStatus,
    daneSummary,
    spf: {
      present: spfPresent,
      verdict: spfVerdict,
      dnsLookupCount: spfState.dnsLookupCount,
      dnsLookupLimit: SPF_DNS_LOOKUP_LIMIT,
      voidLookupCount: spfState.voidLookupCount,
      voidLookupLimit: SPF_VOID_LOOKUP_LIMIT,
      dnssecStatus: rootTxtDnssec.status,
      txtRrsetId: rootTxtDnssec.rrset?.id,
      rawRecord: rootSpfNode.spfRecords[0],
      allSpfRecords: rootSpfNode.spfRecords,
      legacySpfRecords,
      effectiveAllQualifier: spfState.effectiveAllQualifier,
      rootNode: rootSpfNode,
      summary: spfSummary,
    },
  };

  // Compute unified top-level status & summary for Mail Mode
  const hasMailError =
    targetDomainStatus === 'bogus' ||
    mxStatus === 'broken' ||
    daneStatus === 'bogus' ||
    spfVerdict === 'permerror' ||
    spfVerdict === 'temperror' ||
    spfVerdict === 'pass-all' ||
    mailFindings.some((f) => f.severity === 'error');

  const hasMailWarning = mailFindings.some((f) => f.severity === 'warning');

  let overallStatus: ValidationStatus;
  if (hasMailError) {
    overallStatus = 'bogus';
  } else if (
    (daneStatus === 'all-valid' && (spfVerdict === 'strict-fail' || spfVerdict === 'soft-fail') && !hasMailWarning) ||
    (mxStatus === 'null-mx' &&
      spfVerdict === 'strict-fail' &&
      (targetDomainStatus === 'secure' || targetDomainStatus === 'warning') &&
      !hasMailWarning)
  ) {
    overallStatus = targetDomainStatus === 'warning' ? 'warning' : 'secure';
  } else if (targetDomainStatus === 'insecure' && daneStatus === 'not-deployed' && !hasMailWarning) {
    overallStatus = 'insecure';
  } else if (hasMailWarning || targetDomainStatus === 'secure' || targetDomainStatus === 'warning') {
    overallStatus = 'warning';
  } else {
    overallStatus = 'insecure';
  }

  let overallSummary: string;
  if (overallStatus === 'bogus') {
    const firstErr = mailFindings.find((f) => f.severity === 'error');
    overallSummary = firstErr
      ? `Mail DNS audit failed: ${firstErr.title}.`
      : `DNSSEC or mail policy validation failed for ${dispTarget}.`;
  } else if (mxStatus === 'null-mx') {
    overallSummary = `${dispTarget} publishes an RFC 7505 Null MX (0 .) · SPF: ${spfPresent ? `${spfState.effectiveAllQualifier ?? ''}all (${spfState.dnsLookupCount}/10 lookups)` : 'missing'}.`;
  } else {
    const mxCountLabel =
      nonNullHosts.length > 0
        ? `${nonNullHosts.length} MX host${nonNullHosts.length === 1 ? '' : 's'}`
        : mxStatus === 'implicit-a'
          ? 'Implicit A/AAAA MX'
          : 'No MX';
    const daneLabel =
      daneStatus === 'all-valid'
        ? 'SMTP DANE verified'
        : daneStatus === 'partial'
          ? 'Partial DANE'
          : daneStatus === 'unsigned-ignored'
            ? 'Unsigned TLSA (ignored)'
            : 'No DANE TLSA';
    const spfLabel = spfPresent
      ? `SPF ${spfState.effectiveAllQualifier ?? '?'}all (${spfState.dnsLookupCount}/10 lookups)`
      : 'No SPF';
    overallSummary = `${mxCountLabel} · ${daneLabel} · ${spfLabel} · DNSSEC ${targetDomainStatus.toUpperCase()}.`;
  }

  return {
    mailAnalysis,
    mailFindings,
    overallStatus,
    overallSummary,
  };
}

/**
 * Recursively prefetches DNS records needed to evaluate an SPF policy tree via `session`.
 */
async function prefetchSpfTree(
  session: DohSession,
  startDomain: string
): Promise<void> {
  let networkBudget = 0;

  const walk = async (domain: string, depth: number, visited: Set<string>): Promise<void> => {
    const norm = normalizeFqdn(domain);
    if (visited.has(norm) || depth > MAX_SPF_RECURSION_DEPTH || networkBudget >= MAX_SPF_NETWORK_QUERIES) {
      return;
    }
    const nextVisited = new Set(visited);
    nextVisited.add(norm);

    let txtLog = findAnyLog(session.getLogs(), norm, RR_TYPES.TXT);
    if (!txtLog) {
      networkBudget++;
      txtLog = await session
        .query(norm, RR_TYPES.TXT, {
          cd: false,
          doBit: true,
          purpose: `SPF lookup (${norm} TXT)`,
        })
        .catch(() => undefined);
    }
    if (!txtLog) return;

    const spfRecords = extractTxtJoinedStrings(txtLog, norm, RR_TYPES.TXT).filter(isSpfRecordText);
    if (spfRecords.length !== 1) return;

    const terms = parseSpfTerms(spfRecords[0]);
    for (const term of terms) {
      if (!term.syntaxValid || !term.countsTowardLookupLimit) continue;
      if (networkBudget >= MAX_SPF_NETWORK_QUERIES) break;

      if (
        (term.kind === 'mechanism' && term.mechanism === 'include' && term.value) ||
        (term.kind === 'modifier' && term.modifier === 'redirect' && term.value)
      ) {
        if (!hasSpfMacro(term.value)) {
          await walk(term.value, depth + 1, nextVisited);
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'a') {
        const target = term.value ?? norm;
        if (!hasSpfMacro(target)) {
          const normT = normalizeFqdn(target);
          const logsNow = session.getLogs();
          const tasks: Promise<unknown>[] = [];
          if (!findAnyLog(logsNow, normT, RR_TYPES.A)) {
            networkBudget++;
            tasks.push(
              session
                .query(normT, RR_TYPES.A, { cd: false, doBit: true, purpose: `SPF lookup (${normT} A)` })
                .catch(() => undefined)
            );
          }
          if (!findAnyLog(logsNow, normT, RR_TYPES.AAAA)) {
            tasks.push(
              session
                .query(normT, RR_TYPES.AAAA, { cd: false, doBit: true, purpose: `SPF lookup (${normT} AAAA)` })
                .catch(() => undefined)
            );
          }
          if (tasks.length > 0) await Promise.all(tasks);
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'mx') {
        const target = term.value ?? norm;
        if (!hasSpfMacro(target)) {
          const normT = normalizeFqdn(target);
          let mLog = findAnyLog(session.getLogs(), normT, RR_TYPES.MX);
          if (!mLog) {
            networkBudget++;
            mLog = await session
              .query(normT, RR_TYPES.MX, { cd: false, doBit: true, purpose: `SPF lookup (${normT} MX)` })
              .catch(() => undefined);
          }
          const exchanges = (mLog?.packet.answers ?? [])
            .filter((r) => r.type === RR_TYPES.MX && r.parsed.kind === 'MX')
            .map((r) => normalizeFqdn((r.parsed as { kind: 'MX'; exchange: string }).exchange))
            .filter((e) => e !== '.')
            .slice(0, 10);

          const addrTasks: Promise<unknown>[] = [];
          const logsNow = session.getLogs();
          for (const ex of exchanges) {
            if (!findAnyLog(logsNow, ex, RR_TYPES.A)) {
              addrTasks.push(
                session
                  .query(ex, RR_TYPES.A, { cd: false, doBit: true, purpose: `SPF lookup (${ex} A)` })
                  .catch(() => undefined)
              );
            }
            if (!findAnyLog(logsNow, ex, RR_TYPES.AAAA)) {
              addrTasks.push(
                session
                  .query(ex, RR_TYPES.AAAA, { cd: false, doBit: true, purpose: `SPF lookup (${ex} AAAA)` })
                  .catch(() => undefined)
              );
            }
          }
          if (addrTasks.length > 0) await Promise.all(addrTasks);
        }
      } else if (term.kind === 'mechanism' && term.mechanism === 'exists' && term.value) {
        if (!hasSpfMacro(term.value)) {
          const exNorm = normalizeFqdn(term.value);
          if (!findAnyLog(session.getLogs(), exNorm, RR_TYPES.A)) {
            networkBudget++;
            await session
              .query(exNorm, RR_TYPES.A, { cd: false, doBit: true, purpose: `SPF lookup (${exNorm} A)` })
              .catch(() => undefined);
          }
        }
      }
    }
  };

  await walk(startDomain, 0, new Set<string>());
}

/**
 * Runs a full live client-side Mail DNS analysis (MX + SMTP DANE TLSA + SPF + WebCrypto DNSSEC)
 * via RFC 8484 DoH.
 */
export async function runMailAnalysis(
  rawDomain: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisSnapshot> {
  const startedAt = Date.now();
  const targetName = normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const queryTypes = ['MX', 'TXT'];
  const trustAnchors = options.trustAnchors ?? IANA_ROOT_TRUST_ANCHORS;
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;

  const session = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs,
    fetchImpl: options.fetchImpl,
  });

  let currentPhase: AnalysisProgress['phase'] = 'mail-mx';
  session.onQueryCompleted = (count, lastLog) => {
    options.onProgress?.({
      phase: currentPhase,
      message: `Resolved ${lastLog.qname} ${lastLog.qtypeName} (${lastLog.latencyMs}ms)`,
      completedQueries: count,
    });
  };

  options.onProgress?.({
    phase: 'mail-mx',
    message: `Querying MX, SPF TXT & zone cuts for ${displayDomain}…`,
    completedQueries: 0,
  });

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);

  // Step 1: Query MX, TXT, legacy SPF (TYPE99), zone cuts, and CD=0 validating check
  await Promise.all([
    discoverZoneCutsForName(session, targetName, discoveredZones, checkedCandidates),
    session.query(targetName, RR_TYPES.MX, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} MX)`,
    }),
    session.query(targetName, RR_TYPES.TXT, {
      cd: true,
      doBit: true,
      purpose: `Target RRset (${targetName} TXT)`,
    }),
    session
      .query(targetName, RR_TYPES.SPF, {
        cd: false,
        doBit: true,
        purpose: `SPF lookup (${targetName} TYPE99 SPF)`,
      })
      .catch(() => undefined),
    session.query(targetName, RR_TYPES.MX, {
      cd: false,
      doBit: true,
      purpose: `1.1.1.1 validating check (${targetName} MX, CD=0)`,
    }),
  ]);

  // Follow any CNAME chain at targetName itself
  let effectiveMailDomain = targetName;
  const visitedMailOwners = new Set<string>([targetName]);
  for (let hop = 0; hop < 6; hop++) {
    const logsNow = session.getLogs();
    const res = resolveCnameChainInLogs(logsNow, effectiveMailDomain, RR_TYPES.MX);
    const nextUnvisited = res.cnameChain.find((c) => !visitedMailOwners.has(c));
    if (!nextUnvisited) {
      effectiveMailDomain = res.finalOwner;
      break;
    }
    visitedMailOwners.add(nextUnvisited);
    effectiveMailDomain = nextUnvisited;
    await Promise.all([
      discoverZoneCutsForName(session, nextUnvisited, discoveredZones, checkedCandidates),
      session.query(nextUnvisited, RR_TYPES.MX, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} MX)`,
      }),
      session.query(nextUnvisited, RR_TYPES.TXT, {
        cd: true,
        doBit: true,
        purpose: `CNAME target (${nextUnvisited} TXT)`,
      }),
    ]);
  }

  // Step 2: Resolve MX exchangers (A, AAAA, zone cuts) + SMTP DANE (_25._tcp.<mx> TLSA + zone cuts)
  const mxLog = findAnyLog(session.getLogs(), effectiveMailDomain, RR_TYPES.MX);
  const allMxAnswers = (mxLog?.packet.answers ?? []).filter(
    (r) => r.name === effectiveMailDomain && r.type === RR_TYPES.MX && r.parsed.kind === 'MX'
  );

  // If no explicit MX exists (and not NXDOMAIN), probe A/AAAA on effectiveMailDomain for RFC 5321 §5.1 implicit MX check
  if (allMxAnswers.length === 0 && mxLog && mxLog.packet.flags.rcode === 0) {
    await Promise.all([
      session.query(effectiveMailDomain, RR_TYPES.A, {
        cd: true,
        doBit: true,
        purpose: `Mail target (${effectiveMailDomain} A)`,
      }),
      session.query(effectiveMailDomain, RR_TYPES.AAAA, {
        cd: true,
        doBit: true,
        purpose: `Mail target (${effectiveMailDomain} AAAA)`,
      }),
    ]);
  }

  const mxExchanges = Array.from(
    new Set(
      allMxAnswers
        .map((r) => normalizeFqdn((r.parsed as { kind: 'MX'; exchange: string }).exchange))
        .filter((ex) => ex !== '.' && !isIpLiteralHostname(ex))
    )
  ).slice(0, MAX_PROBED_MX_HOSTS);

  if (mxExchanges.length > 0) {
    currentPhase = 'mail-dane';
    options.onProgress?.({
      phase: 'mail-dane',
      message: `Probing A/AAAA & _25._tcp DANE TLSA across ${mxExchanges.length} MX host(s)…`,
      completedQueries: session.getLogs().length,
    });

    await Promise.all(
      mxExchanges.flatMap((exch) => {
        const tlsaOwner = normalizeFqdn(`_25._tcp.${exch}`);
        return [
          discoverZoneCutsForName(session, exch, discoveredZones, checkedCandidates),
          discoverZoneCutsForName(session, tlsaOwner, discoveredZones, checkedCandidates),
          session.query(exch, RR_TYPES.A, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${exch} A)`,
          }),
          session.query(exch, RR_TYPES.AAAA, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${exch} AAAA)`,
          }),
          session.query(tlsaOwner, RR_TYPES.TLSA, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${tlsaOwner} TLSA)`,
          }),
        ];
      })
    );

    // Follow any CNAME chains on MX hosts OR on _25._tcp.<mx> TLSA aliases (RFC 7671 §7 / RFC 7672 §2.2.2)
    const visitedExtra = new Set<string>();
    for (let hop = 0; hop < 5; hop++) {
      const logsNow = session.getLogs();
      const followTasks: Promise<unknown>[] = [];

      for (const exch of mxExchanges) {
        const aRes = resolveCnameChainInLogs(logsNow, exch, RR_TYPES.A);
        for (const cnameTarget of aRes.cnameChain) {
          const key = `mx|${cnameTarget}`;
          if (!visitedExtra.has(key)) {
            visitedExtra.add(key);
            const fallbackTlsa = normalizeFqdn(`_25._tcp.${cnameTarget}`);
            followTasks.push(
              discoverZoneCutsForName(session, cnameTarget, discoveredZones, checkedCandidates),
              discoverZoneCutsForName(session, fallbackTlsa, discoveredZones, checkedCandidates),
              session.query(cnameTarget, RR_TYPES.A, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cnameTarget} A)`,
              }),
              session.query(cnameTarget, RR_TYPES.AAAA, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cnameTarget} AAAA)`,
              }),
              session.query(fallbackTlsa, RR_TYPES.TLSA, {
                cd: true,
                doBit: true,
                purpose: `Mail target (${fallbackTlsa} TLSA)`,
              })
            );
          }
        }

        const tlsaStart = normalizeFqdn(`_25._tcp.${exch}`);
        const tRes = resolveCnameChainInLogs(logsNow, tlsaStart, RR_TYPES.TLSA);
        for (const tCname of tRes.cnameChain) {
          const key = `tlsa|${tCname}`;
          if (!visitedExtra.has(key)) {
            visitedExtra.add(key);
            followTasks.push(
              discoverZoneCutsForName(session, tCname, discoveredZones, checkedCandidates),
              session.query(tCname, RR_TYPES.TLSA, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${tCname} TLSA)`,
              })
            );
          }
        }
      }

      if (followTasks.length === 0) break;
      await Promise.all(followTasks);
    }
  }

  // Step 3: Recursively walk SPF policy tree (includes, redirects, a, mx, exists)
  currentPhase = 'mail-spf';
  options.onProgress?.({
    phase: 'mail-spf',
    message: `Tracing recursive SPF mechanisms & 10-lookup budget for ${displayDomain}…`,
    completedQueries: session.getLogs().length,
  });
  await prefetchSpfTree(session, effectiveMailDomain);

  // Include any authoritative SOA zones returned in CD=1 responses
  for (const log of session.getLogs()) {
    if (!log.cd || log.purpose.startsWith('SPF lookup') || log.purpose.startsWith('Nameserver IP')) {
      continue;
    }
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

  // Step 5: Cryptographic validation + MX/DANE/SPF synthesis
  currentPhase = 'validating';
  options.onProgress?.({
    phase: 'validating',
    message: 'Verifying DNSSEC, SMTP DANE (TLSA) & SPF policies via WebCrypto…',
    completedQueries: session.getLogs().length,
  });

  const capturedAt = Date.now();
  const validatedAt = options.validationTimeMs ?? capturedAt;
  const durationMs = Math.max(1, capturedAt - startedAt);

  return evaluateSnapshotFromLogs({
    id: `snap-${capturedAt}-${Math.random().toString(36).slice(2, 8)}`,
    mode: 'mail',
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
