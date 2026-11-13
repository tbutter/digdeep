import {
  DEFAULT_DOH_ENDPOINT,
  DNSSEC_ALGORITHMS,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
  formatAlgorithm,
  formatDohShortLabel,
  rrTypeToString,
  type TrustAnchor,
} from './constants';
import {
  collectPrioritizedNsOriginQnames,
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
  findLog,
  probeLeafNameserverAddresses,
} from './analyzer';
import { DohSession } from './doh';
import {
  countDnsLabels,
  displayFqdn,
  getDomainHierarchy,
  isSubdomainOrEqual,
  normalizeFqdn,
} from './encoding';
import {
  parseCymruOriginTxt,
  parseReverseIpInput,
} from './ipUtils';
import {
  estimateOrganizationalDomain,
  evaluateMailFromSnapshotData,
  prefetchSpfTree,
} from './mailAnalyzer';
import type {
  AnalysisSnapshot,
  BgpAsnOrganization,
  DmarcPolicyValue,
  DohQueryLog,
  MailAnalysisResult,
  MtaStsAnalysis,
  MtaStsPolicyFetchResult,
  SpfPolicyVerdict,
  SpfQualifier,
  ValidationStatus,
  WebCaaAnalysis,
} from './types';
import { evaluateWebFromSnapshotData } from './webAnalyzer';

export const MAX_PORTFOLIO_DOMAINS = 50;
export const DEFAULT_PORTFOLIO_CONCURRENCY = 3;

export const SAMPLE_PORTFOLIO_DOMAINS = [
  'cloudflare.com',
  'ietf.org',
  'github.com',
  'wikipedia.org',
  'proton.me',
  'nlnetlabs.nl',
] as const;

export interface ParsedPortfolioDomainList {
  domains: string[];
  skippedTokens: string[];
  totalValidBeforeCap: number;
  truncatedCount: number;
}

const CSV_HEADER_TOKENS = new Set([
  'domain',
  'domains',
  'hostname',
  'hostnames',
  'fqdn',
  'host',
  'name',
  'url',
  'target',
]);

const CLI_PREFIX_RE = /^\s*(?:sudo\s+)?(?:dig|delv|kdig|drill|host|nslookup|curl)\b/i;
const EMAIL_HEADER_RE =
  /(?:^|\n)(?:Authentication-Results|ARC-Authentication-Results|DKIM-Signature|Received-SPF|Return-Path|Message-ID):\s/i;

function cleanCandidateDomainToken(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;

  // Strip surrounding quotes and trailing punctuation
  s = s.replace(/^["'`(<[]+|["'`>)\],;]+$/g, '').trim();
  if (!s) return null;

  // Extract hostname from URL if scheme is present
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      s = u.hostname;
    } catch {
      return null;
    }
  } else if (s.includes('/') && !s.includes(' ')) {
    s = s.split('/')[0] ?? '';
  }

  // Extract domain part from email address (user@domain)
  const atIdx = s.lastIndexOf('@');
  if (atIdx > 0 && atIdx < s.length - 1) {
    s = s.slice(atIdx + 1);
  }

  // Strip port suffix (host:443) when not IPv6
  if (s.includes(':') && !s.includes('::') && s.split(':').length === 2) {
    const [hostPart, portPart] = s.split(':');
    if (hostPart && /^\d+$/.test(portPart ?? '')) {
      s = hostPart;
    }
  }

  // Strip leading wildcard prefix from CT SANs (*.api.example.com -> api.example.com)
  s = s.replace(/^(?:\*\.)+/, '').replace(/\.+$/, '').trim().toLowerCase();
  if (!s || s.length > 253) return null;
  if (CSV_HEADER_TOKENS.has(s)) return null;

  // Skip raw IPv4 / IPv6 literals
  const parsedIp = parseReverseIpInput(s);
  if (parsedIp?.wasRawIpInput) return null;

  // Require at least 2 DNS labels (e.g. example.com) with valid label characters
  const labels = s.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!label || label.length > 63) return null;
    if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label)) return null;
  }
  // TLD must not be all-numeric
  const tld = labels[labels.length - 1]!;
  if (/^\d+$/.test(tld)) return null;

  return displayFqdn(normalizeFqdn(s));
}

/**
 * Parses pasted multi-line/comma-separated domain lists, Markdown bullets, or `.txt` / `.csv` files
 * into up to `maxDomains` deduplicated canonical domain names.
 */
export function parsePortfolioDomainList(
  rawInput: string,
  maxDomains: number = MAX_PORTFOLIO_DOMAINS
): ParsedPortfolioDomainList {
  const seen = new Set<string>();
  const allValid: string[] = [];
  const skippedTokens: string[] = [];

  const lines = rawInput.split(/\r?\n/);
  const looksLikeStructuredCsv =
    lines.length >= 2 &&
    lines[0] !== undefined &&
    lines[0].includes(',') &&
    lines[0]
      .split(',')
      .some((col) => CSV_HEADER_TOKENS.has(col.replace(/^["']|["']$/g, '').trim().toLowerCase()));

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    let line = lines[lineIdx]!.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // Strip inline comments (`example.com # prod`)
    const hashCommentIdx = line.indexOf(' #');
    if (hashCommentIdx >= 0) {
      line = line.slice(0, hashCommentIdx).trim();
    }
    // Strip Markdown list bullets (`- example.com`, `* example.com`, `1. example.com`, `1) example.com`)
    line = line.replace(/^(?:[-*•+]|\d+[.)])\s+/, '').trim();
    if (!line) continue;

    if (looksLikeStructuredCsv) {
      if (lineIdx === 0) continue; // header row
      const firstCell = line.split(',')[0]?.trim() ?? '';
      if (!firstCell) continue;
      const cleaned = cleanCandidateDomainToken(firstCell);
      if (cleaned) {
        if (!seen.has(cleaned)) {
          seen.add(cleaned);
          allValid.push(cleaned);
        }
      } else {
        skippedTokens.push(firstCell);
      }
      continue;
    }

    const rawTokens = line.split(/[\s,;|\t]+/).filter(Boolean);
    for (const tok of rawTokens) {
      if (CSV_HEADER_TOKENS.has(tok.replace(/^["']|["']$/g, '').trim().toLowerCase())) {
        continue;
      }
      const cleaned = cleanCandidateDomainToken(tok);
      if (cleaned) {
        if (!seen.has(cleaned)) {
          seen.add(cleaned);
          allValid.push(cleaned);
        }
      } else {
        skippedTokens.push(tok);
      }
    }
  }

  const cap = Math.max(1, maxDomains);
  const domains = allValid.slice(0, cap);
  return {
    domains,
    skippedTokens,
    totalValidBeforeCap: allValid.length,
    truncatedCount: Math.max(0, allValid.length - domains.length),
  };
}

/**
 * Detects when clipboard text pasted into the Omnibox is a multi-domain list (`>= 2` domains)
 * rather than a single domain, CLI command, raw email headers, or hex/base64 wire packet.
 */
export function detectMultiDomainPaste(
  rawText: string,
  maxDomains: number = MAX_PORTFOLIO_DOMAINS
): string[] | null {
  if (!rawText || !/[\n,;\s]/.test(rawText.trim())) return null;
  if (CLI_PREFIX_RE.test(rawText) || EMAIL_HEADER_RE.test(rawText)) return null;
  if (/[?&]dns=[A-Za-z0-9_-]{12,}/i.test(rawText)) return null;
  // Exclude dig-style flag inputs (`example.com +dnssec` or `@1.1.1.1 example.com`)
  if (/(?:^|\s)[+@][A-Za-z0-9._-]+/.test(rawText)) return null;

  const parsed = parsePortfolioDomainList(rawText, maxDomains);
  if (parsed.domains.length < 2) return null;
  // Require majority of tokens to be valid domains so arbitrary prose sentences don't trigger batch mode
  if (parsed.skippedTokens.length > parsed.domains.length) return null;
  return parsed.domains;
}

export interface PortfolioPostureMetrics {
  domain: string;
  fqdn: string;
  leafZone: string;
  dnssecStatus: ValidationStatus;
  dnssecAlgorithms: number[];
  dnssecAlgorithmLabel: string;
  nsecMode: 'NSEC' | 'NSEC3' | 'NSEC3-OPTOUT' | 'UNSIGNED';
  shortestRrsigRemainingSec: number | null;
  shortestRrsigLabel: string;
  rrsigExpiringSoon: boolean;
  rrsigExpired: boolean;
  nsCount: number;
  nsHostnames: string[];
  nsProviders: string[];
  nsAsns: BgpAsnOrganization[];
  singleNsAsnSpof: boolean;
  dualStackReady: boolean | null;
  nsConsistent: boolean | null;
  mxStatus: MailAnalysisResult['mxStatus'];
  mxCount: number;
  daneStatus: MailAnalysisResult['daneStatus'];
  spfPresent: boolean;
  spfVerdict: SpfPolicyVerdict;
  spfQualifier?: SpfQualifier;
  spfLookups: number;
  dmarcPresent: boolean;
  dmarcPolicy: DmarcPolicyValue | 'invalid' | 'missing';
  dmarcUsedOrgFallback: boolean;
  mtaStsStatus: MtaStsAnalysis['status'];
  hasHttps: boolean;
  httpsStatus: 'ech-enabled' | 'valid' | 'alias-mode' | 'warning' | 'not-deployed' | 'bogus';
  echEnabled: boolean;
  supportsHttp3: boolean;
  caaStatus: WebCaaAnalysis['status'];
  caaIssueCas: string[];
  errorCount: number;
  warningCount: number;
  issueCount: number;
  riskScore: number;
}

export function formatRemainingValidityShort(sec: number | null): string {
  if (sec === null || !Number.isFinite(sec)) return '—';
  if (sec <= 0) return 'EXPIRED';
  if (sec < 3600) return `${Math.max(1, Math.round(sec / 60))}m`;
  if (sec < 86400 * 2) return `${(sec / 3600).toFixed(1)}h`;
  return `${(sec / 86400).toFixed(1)}d`;
}

function summarizeNsProviderLabel(nsFqdn: string): string {
  const clean = displayFqdn(nsFqdn).toLowerCase();
  if (clean.includes('.awsdns-')) return 'awsdns';
  const parts = clean.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return clean;
}

/**
 * Extracts normalized DNSSEC, RRSIG, Authoritative NS/ASN, Mail, and Web posture metrics from any `AnalysisSnapshot`.
 */
export function extractPortfolioPosture(snapshot: AnalysisSnapshot): PortfolioPostureMetrics {
  const targetNorm = normalizeFqdn(snapshot.targetName);
  const leafZoneObj =
    [...snapshot.zones]
      .filter((z) => isSubdomainOrEqual(targetNorm, z.zoneName))
      .sort((a, b) => b.depth - a.depth)[0] ?? snapshot.zones[snapshot.zones.length - 1];

  let dnssecStatus: ValidationStatus =
    snapshot.overallStatus === 'policy-error'
      ? (leafZoneObj?.status ?? 'insecure')
      : snapshot.overallStatus;
  if (leafZoneObj?.status === 'bogus') {
    dnssecStatus = 'bogus';
  } else if (leafZoneObj?.status === 'insecure' && dnssecStatus !== 'bogus') {
    dnssecStatus = 'insecure';
  }

  const algSet = new Set<number>();
  for (const k of leafZoneObj?.dnskeys ?? []) {
    if (k.role !== 'missing' && k.role !== 'revoked') {
      algSet.add(k.algorithm);
    }
  }
  if (algSet.size === 0) {
    for (const d of leafZoneObj?.dsVerifications ?? []) {
      algSet.add(d.ds.algorithm);
    }
  }
  const dnssecAlgorithms = Array.from(algSet).sort((a, b) => a - b);
  const dnssecAlgorithmLabel =
    dnssecStatus === 'insecure' || dnssecAlgorithms.length === 0
      ? 'UNSIGNED'
      : dnssecAlgorithms
          .map((alg) => DNSSEC_ALGORITHMS[alg]?.mnemonic ?? formatAlgorithm(alg))
          .join(' + ');

  // Compute shortest RRSIG remaining validity across the target domain's own authoritative zone(s)
  let shortestRrsigRemainingSec: number | null = null;
  if (dnssecStatus !== 'insecure') {
    for (const z of snapshot.zones) {
      if (!isSubdomainOrEqual(targetNorm, z.zoneName)) {
        continue;
      }
      if (z.depth < 2 && z.zoneName !== targetNorm && z.zoneName !== leafZoneObj?.zoneName) {
        continue;
      }
      for (const rr of z.rrsets) {
        for (const sig of rr.rrsigs) {
          if (
            shortestRrsigRemainingSec === null ||
            sig.remainingSeconds < shortestRrsigRemainingSec
          ) {
            shortestRrsigRemainingSec = sig.remainingSeconds;
          }
        }
      }
    }
  }

  const rrsigExpired = shortestRrsigRemainingSec !== null && shortestRrsigRemainingSec <= 0;
  const rrsigExpiringSoon =
    shortestRrsigRemainingSec !== null && shortestRrsigRemainingSec < 72 * 3600;

  const nsHostnames = (leafZoneObj?.nameservers ?? []).map((n) => displayFqdn(n.hostname));
  const nsProviders = Array.from(
    new Set((leafZoneObj?.nameservers ?? []).map((n) => summarizeNsProviderLabel(n.hostname)))
  );
  const nsAsns = leafZoneObj?.nsDiversity?.uniqueAsns ?? [];
  const nsCount = leafZoneObj?.nameservers.length ?? 0;
  const singleNsAsnSpof = Boolean(
    leafZoneObj?.nsDiversity?.singleAsn || (nsAsns.length === 1 && nsCount >= 1)
  );
  const dualStackReady =
    leafZoneObj?.nsDiversity?.dualStackReady !== undefined
      ? leafZoneObj.nsDiversity.dualStackReady
      : null;
  const nsConsistent =
    leafZoneObj?.nsConsistency !== undefined ? leafZoneObj.nsConsistency.consistent : null;

  const mail = snapshot.mailAnalysis;
  const mxStatus: MailAnalysisResult['mxStatus'] = mail?.mxStatus ?? 'none';
  const mxCount = (mail?.mxHosts ?? []).filter((h) => !h.isNullMx).length;
  const daneStatus: MailAnalysisResult['daneStatus'] = mail?.daneStatus ?? 'not-deployed';
  const spfPresent = Boolean(mail?.spf.present);
  const spfVerdict: SpfPolicyVerdict = mail?.spf.verdict ?? 'none';
  const spfQualifier = mail?.spf.effectiveAllQualifier;
  const spfLookups = mail?.spf.dnsLookupCount ?? 0;
  const dmarcPresent = Boolean(mail?.dmarc.present);
  const dmarcPolicy: PortfolioPostureMetrics['dmarcPolicy'] = !mail?.dmarc.present
    ? 'missing'
    : mail.dmarc.verdict === 'invalid'
      ? 'invalid'
      : (mail.dmarc.policy ?? 'none');
  const dmarcUsedOrgFallback = Boolean(mail?.dmarc.usedOrgFallback);
  const mtaStsStatus: MtaStsAnalysis['status'] = mail?.mtaSts.status ?? 'not-deployed';

  const web = snapshot.webAnalysis;
  const hasHttps = (web?.httpsRecords.length ?? 0) > 0;
  const httpsStatus = web?.httpsStatus ?? 'not-deployed';
  const echEnabled = Boolean(web?.echEnabled);
  const supportsHttp3 = Boolean(web?.supportsHttp3);
  const caaStatus: WebCaaAnalysis['status'] = web?.caa.status ?? 'unprotected';
  const caaIssueCas = web?.caa.issueCas ?? [];

  const errorCount = snapshot.findings.filter((f) => f.severity === 'error').length;
  const warningCount = snapshot.findings.filter((f) => f.severity === 'warning').length;
  const issueCount = errorCount + warningCount;

  // Compute deterministic triage priority score (higher = needs attention first)
  let riskScore = 0;
  if (dnssecStatus === 'bogus') riskScore += 100;
  else if (dnssecStatus === 'insecure') riskScore += 20;
  if (rrsigExpired) riskScore += 90;
  else if (rrsigExpiringSoon) riskScore += 45;
  if (daneStatus === 'bogus') riskScore += 60;
  else if (daneStatus === 'unsigned-ignored') riskScore += 35;
  if (spfVerdict === 'permerror' || spfVerdict === 'pass-all') riskScore += 50;
  else if (spfVerdict === 'none' && mxStatus !== 'null-mx') riskScore += 20;
  if (dmarcPolicy === 'invalid') riskScore += 45;
  else if (dmarcPolicy === 'missing') riskScore += 28;
  else if (dmarcPolicy === 'none') riskScore += 18;
  if (singleNsAsnSpof) riskScore += 12;
  if (dualStackReady === false) riskScore += 10;
  if (nsConsistent === false) riskScore += 22;
  if (caaStatus === 'unprotected' || caaStatus === 'permissive') riskScore += 8;
  riskScore += errorCount * 15 + warningCount * 4;

  return {
    domain: snapshot.displayDomain,
    fqdn: targetNorm,
    leafZone: leafZoneObj ? displayFqdn(leafZoneObj.zoneName) : snapshot.displayDomain,
    dnssecStatus,
    dnssecAlgorithms,
    dnssecAlgorithmLabel,
    nsecMode: leafZoneObj?.nsecMode ?? 'UNSIGNED',
    shortestRrsigRemainingSec,
    shortestRrsigLabel: formatRemainingValidityShort(shortestRrsigRemainingSec),
    rrsigExpiringSoon,
    rrsigExpired,
    nsCount,
    nsHostnames,
    nsProviders,
    nsAsns,
    singleNsAsnSpof,
    dualStackReady,
    nsConsistent,
    mxStatus,
    mxCount,
    daneStatus,
    spfPresent,
    spfVerdict,
    spfQualifier,
    spfLookups,
    dmarcPresent,
    dmarcPolicy,
    dmarcUsedOrgFallback,
    mtaStsStatus,
    hasHttps,
    httpsStatus,
    echEnabled,
    supportsHttp3,
    caaStatus,
    caaIssueCas,
    errorCount,
    warningCount,
    issueCount,
    riskScore,
  };
}

export type PortfolioRowStatus = 'queued' | 'running' | 'done' | 'error' | 'canceled';

export interface PortfolioDomainRow {
  index: number;
  domain: string;
  status: PortfolioRowStatus;
  completedQueries: number;
  phaseMessage?: string;
  startedAt?: number;
  durationMs?: number;
  error?: string;
  snapshot?: AnalysisSnapshot;
  posture?: PortfolioPostureMetrics;
}

export interface PortfolioAsnConcentrationEntry {
  asn: number;
  asName?: string;
  country?: string;
  domainCount: number;
  soleSpofDomainCount: number;
  completedPortfolioCount: number;
  shareRatio: number;
  sharePercent: number;
  domains: string[];
  soleSpofDomains: string[];
  concentrationRisk: 'critical' | 'elevated' | 'diversified';
}

export function computePortfolioAsnConcentration(
  rows: readonly PortfolioDomainRow[]
): PortfolioAsnConcentrationEntry[] {
  const doneRows = rows.filter((r) => r.status === 'done' && r.posture);
  const totalDone = doneRows.length;
  if (totalDone === 0) return [];

  const map = new Map<
    number,
    {
      asn: number;
      asName?: string;
      country?: string;
      domains: string[];
      soleSpofDomains: string[];
    }
  >();

  for (const row of doneRows) {
    const p = row.posture!;
    const uniqueRowAsns = new Map<number, BgpAsnOrganization>();
    for (const a of p.nsAsns) {
      if (!uniqueRowAsns.has(a.asn)) uniqueRowAsns.set(a.asn, a);
    }
    const isSoleAsn = uniqueRowAsns.size === 1;
    for (const a of uniqueRowAsns.values()) {
      const entry = map.get(a.asn) ?? {
        asn: a.asn,
        asName: a.asName,
        country: a.country,
        domains: [],
        soleSpofDomains: [],
      };
      if (!entry.asName && a.asName) entry.asName = a.asName;
      if (!entry.country && a.country) entry.country = a.country;
      entry.domains.push(p.domain);
      if (isSoleAsn) {
        entry.soleSpofDomains.push(p.domain);
      }
      map.set(a.asn, entry);
    }
  }

  return Array.from(map.values())
    .map((e) => {
      const shareRatio = e.domains.length / totalDone;
      const sharePercent = Math.round(shareRatio * 100);
      let concentrationRisk: PortfolioAsnConcentrationEntry['concentrationRisk'] = 'diversified';
      if (e.soleSpofDomains.length >= 2 && shareRatio >= 0.5) {
        concentrationRisk = 'critical';
      } else if (e.domains.length >= 2 && shareRatio >= 0.35) {
        concentrationRisk = 'elevated';
      }
      return {
        asn: e.asn,
        asName: e.asName,
        country: e.country,
        domainCount: e.domains.length,
        soleSpofDomainCount: e.soleSpofDomains.length,
        completedPortfolioCount: totalDone,
        shareRatio,
        sharePercent,
        domains: e.domains,
        soleSpofDomains: e.soleSpofDomains,
        concentrationRisk,
      };
    })
    .sort(
      (a, b) =>
        b.domainCount - a.domainCount ||
        b.soleSpofDomainCount - a.soleSpofDomainCount ||
        a.asn - b.asn
    );
}

export interface PortfolioProbeOptions {
  endpoint?: string;
  timeoutMs?: number;
  trustAnchors?: TrustAnchor[];
  validationTimeMs?: number;
  fetchImpl?: typeof fetch;
  sharedQueryCache?: Map<string, Promise<DohQueryLog>>;
  signal?: AbortSignal;
  skipExternalHttp?: boolean;
  onQueryProgress?: (completedQueries: number, message: string) => void;
}

function resolveSimpleCnameInLogs(
  logs: readonly DohQueryLog[],
  startName: string,
  qtype: number
): { finalOwner: string; cnameChain: string[] } {
  let cur = normalizeFqdn(startName);
  const visited = new Set<string>([cur]);
  const chain: string[] = [];

  for (let hop = 0; hop < 8; hop++) {
    const log =
      logs.find((l) => l.qname === cur && l.qtype === qtype && l.cd) ??
      logs.find((l) => l.qname === cur && l.cd) ??
      logs.find(
        (l) =>
          l.cd &&
          l.packet.answers.some((r) => normalizeFqdn(r.name) === cur && r.type === RR_TYPES.CNAME)
      ) ??
      logs.find((l) => l.qname === cur && l.qtype === qtype);
    const cnameAns = log?.packet.answers.find(
      (r) => normalizeFqdn(r.name) === cur && r.type === RR_TYPES.CNAME
    );
    if (!cnameAns || cnameAns.parsed.kind !== 'GENERIC' || !cnameAns.parsed.target) {
      break;
    }
    const next = normalizeFqdn(cnameAns.parsed.target);
    if (visited.has(next)) break;
    visited.add(next);
    chain.push(next);
    cur = next;
  }
  return { finalOwner: cur, cnameChain: chain };
}

/**
 * Executes a unified client-side DoH probe for a single portfolio domain, collecting:
 * - Full DNSSEC chain of trust (`DNSKEY`, `DS`, `RRSIG`, `NSEC`/`NSEC3`, `SOA`, `NS`)
 * - Authoritative NS `A`/`AAAA` hygiene, RFC 3901 dual-stack readiness & Team Cymru BGP ASNs
 * - Mail posture (`MX`, SMTP DANE `_25._tcp` `TLSA`, recursive `SPF`, `_dmarc` + org fallback, `_mta-sts`, `_smtp._tls`)
 * - Web posture (`HTTPS`/`SVCB` + `ECHConfigList`, RFC 8659 tree-walking `CAA`, `_443._tcp` `TLSA`)
 */
export async function runPortfolioDomainProbe(
  rawDomain: string,
  options: PortfolioProbeOptions = {}
): Promise<AnalysisSnapshot> {
  const endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;
  const trustAnchors = options.trustAnchors ?? IANA_ROOT_TRUST_ANCHORS;
  const targetName = normalizeFqdn(rawDomain);
  const displayDomain = displayFqdn(targetName);
  const startedAt = Date.now();

  const session = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs ?? 8000,
    fetchImpl: options.fetchImpl,
    sharedQueryCache: options.sharedQueryCache,
    signal: options.signal,
  });

  let phaseLabel = `Probing ${displayDomain}…`;
  session.onQueryCompleted = (count) => {
    options.onQueryProgress?.(count, phaseLabel);
  };

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);

  // Step 1: Target RRsets + zone cuts + CD=0 validating check
  phaseLabel = `Querying target records & zone cuts for ${displayDomain}…`;
  options.onQueryProgress?.(0, phaseLabel);

  const coreTypes = [
    RR_TYPES.A,
    RR_TYPES.AAAA,
    RR_TYPES.MX,
    RR_TYPES.TXT,
    RR_TYPES.HTTPS,
    RR_TYPES.CAA,
  ];
  await Promise.all([
    discoverZoneCutsForName(session, targetName, discoveredZones, checkedCandidates),
    ...coreTypes.map((qt) =>
      session.query(targetName, qt, {
        cd: true,
        doBit: true,
        purpose: `Target RRset (${targetName} ${rrTypeToString(qt)})`,
      })
    ),
    session
      .query(targetName, RR_TYPES.A, {
        cd: false,
        doBit: true,
        purpose: `Resolver validating check (${targetName} A, CD=0)`,
      })
      .catch(() => undefined),
  ]);

  // Follow CNAME hops on targetName if aliased
  let effectiveDomain = targetName;
  const visitedTargetCnames = new Set<string>([targetName]);
  for (let hop = 0; hop < 5; hop++) {
    const logsNow = session.getLogs();
    const aChain = resolveSimpleCnameInLogs(logsNow, targetName, RR_TYPES.A);
    const httpsChain = resolveSimpleCnameInLogs(logsNow, targetName, RR_TYPES.HTTPS);
    const mxChain = resolveSimpleCnameInLogs(logsNow, targetName, RR_TYPES.MX);
    const longest =
      aChain.cnameChain.length >= httpsChain.cnameChain.length &&
      aChain.cnameChain.length >= mxChain.cnameChain.length
        ? aChain
        : httpsChain.cnameChain.length >= mxChain.cnameChain.length
          ? httpsChain
          : mxChain;
    effectiveDomain = longest.finalOwner;
    const unvisited = Array.from(
      new Set([...aChain.cnameChain, ...httpsChain.cnameChain, ...mxChain.cnameChain])
    ).filter((c) => !visitedTargetCnames.has(c));
    if (unvisited.length === 0) break;
    for (const c of unvisited) visitedTargetCnames.add(c);
    await Promise.all(
      unvisited.flatMap((cTarget) => [
        discoverZoneCutsForName(session, cTarget, discoveredZones, checkedCandidates),
        session
          .query(cTarget, RR_TYPES.A, {
            cd: true,
            doBit: true,
            purpose: `CNAME target (${cTarget} A)`,
          })
          .catch(() => undefined),
        session
          .query(cTarget, RR_TYPES.AAAA, {
            cd: true,
            doBit: true,
            purpose: `CNAME target (${cTarget} AAAA)`,
          })
          .catch(() => undefined),
        session
          .query(cTarget, RR_TYPES.HTTPS, {
            cd: true,
            doBit: true,
            purpose: `CNAME target (${cTarget} HTTPS)`,
          })
          .catch(() => undefined),
        session
          .query(cTarget, RR_TYPES.MX, {
            cd: true,
            doBit: true,
            purpose: `CNAME target (${cTarget} MX)`,
          })
          .catch(() => undefined),
        session
          .query(cTarget, RR_TYPES.TXT, {
            cd: true,
            doBit: true,
            purpose: `CNAME target (${cTarget} TXT)`,
          })
          .catch(() => undefined),
      ])
    );
  }

  // Step 2: Mail (MX + _25._tcp DANE TLSA + SPF + _dmarc + _mta-sts) & Web (CAA climb + _443._tcp TLSA)
  phaseLabel = `Checking Mail (MX/DANE/SPF/DMARC/MTA-STS) & Web (HTTPS/ECH/CAA) for ${displayDomain}…`;
  options.onQueryProgress?.(session.getLogs().length, phaseLabel);

  const mxLog =
    findLog(session.getLogs(), effectiveDomain, RR_TYPES.MX, true) ??
    findLog(session.getLogs(), targetName, RR_TYPES.MX, true);
  const mxExchanges = Array.from(
    new Set(
      (mxLog?.packet.answers ?? [])
        .filter(
          (r) =>
            (normalizeFqdn(r.name) === effectiveDomain || normalizeFqdn(r.name) === targetName) &&
            r.type === RR_TYPES.MX &&
            r.parsed.kind === 'MX' &&
            r.parsed.exchange !== '.'
        )
        .sort((a, b) =>
          a.parsed.kind === 'MX' && b.parsed.kind === 'MX'
            ? a.parsed.preference - b.parsed.preference
            : 0
        )
        .map((r) => normalizeFqdn((r.parsed as { exchange: string }).exchange))
    )
  ).slice(0, 3);

  const dmarcOwner = normalizeFqdn(`_dmarc.${effectiveDomain}`);
  const mtaStsOwner = normalizeFqdn(`_mta-sts.${effectiveDomain}`);
  const tlsRptOwner = normalizeFqdn(`_smtp._tls.${effectiveDomain}`);
  const webTlsaOwner = normalizeFqdn(`_443._tcp.${effectiveDomain}`);
  const caaClimbAncestors = Array.from(
    new Set([
      ...getDomainHierarchy(targetName).slice(1),
      ...getDomainHierarchy(effectiveDomain).slice(1),
    ])
  ).filter((anc) => anc !== '.' && countDnsLabels(anc) >= 2);

  // Check if HTTPS record is in AliasMode (priority 0) pointing to another target
  const httpsLogStep1 =
    findLog(session.getLogs(), effectiveDomain, RR_TYPES.HTTPS, true) ??
    findLog(session.getLogs(), targetName, RR_TYPES.HTTPS, true);
  const httpsAliasTargets = Array.from(
    new Set(
      (httpsLogStep1?.packet.answers ?? [])
        .filter(
          (r) =>
            r.type === RR_TYPES.HTTPS &&
            r.parsed.kind === 'SVCB' &&
            r.parsed.priority === 0 &&
            r.parsed.target !== '.'
        )
        .map((r) => normalizeFqdn((r.parsed as { target: string }).target))
        .filter((t) => t !== '.' && t !== effectiveDomain)
    )
  ).slice(0, 2);

  const [, , , mtaStsProbeLog, tlsRptProbeLog] = await Promise.all([
    prefetchSpfTree(session, effectiveDomain).catch(() => undefined),
    discoverZoneCutsForName(session, dmarcOwner, discoveredZones, checkedCandidates),
    session
      .query(dmarcOwner, RR_TYPES.TXT, {
        cd: true,
        doBit: true,
        purpose: `Mail target (${dmarcOwner} TXT)`,
      })
      .catch(() => undefined),
    session
      .query(mtaStsOwner, RR_TYPES.TXT, {
        cd: false,
        doBit: true,
        purpose: `Mail probe (${mtaStsOwner} TXT)`,
      })
      .catch(() => undefined),
    session
      .query(tlsRptOwner, RR_TYPES.TXT, {
        cd: false,
        doBit: true,
        purpose: `Mail probe (${tlsRptOwner} TXT)`,
      })
      .catch(() => undefined),
    discoverZoneCutsForName(session, webTlsaOwner, discoveredZones, checkedCandidates),
    session
      .query(webTlsaOwner, RR_TYPES.TLSA, {
        cd: true,
        doBit: true,
        purpose: `Web target (${webTlsaOwner} TLSA)`,
      })
      .catch(() => undefined),
    ...caaClimbAncestors.flatMap((anc) => [
      discoverZoneCutsForName(session, anc, discoveredZones, checkedCandidates),
      session
        .query(anc, RR_TYPES.CAA, {
          cd: true,
          doBit: true,
          purpose: `Web target (${anc} CAA)`,
        })
        .catch(() => undefined),
    ]),
    ...httpsAliasTargets.flatMap((aliasTarget) => [
      discoverZoneCutsForName(session, aliasTarget, discoveredZones, checkedCandidates),
      session
        .query(aliasTarget, RR_TYPES.HTTPS, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} HTTPS)`,
        })
        .catch(() => undefined),
      session
        .query(aliasTarget, RR_TYPES.A, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} A)`,
        })
        .catch(() => undefined),
      session
        .query(aliasTarget, RR_TYPES.AAAA, {
          cd: true,
          doBit: true,
          purpose: `Web target (${aliasTarget} AAAA)`,
        })
        .catch(() => undefined),
    ]),
    ...mxExchanges.flatMap((exch) => {
      const smtpTlsaOwner = normalizeFqdn(`_25._tcp.${exch}`);
      return [
        discoverZoneCutsForName(session, exch, discoveredZones, checkedCandidates),
        discoverZoneCutsForName(session, smtpTlsaOwner, discoveredZones, checkedCandidates),
        session
          .query(exch, RR_TYPES.A, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${exch} A)`,
          })
          .catch(() => undefined),
        session
          .query(exch, RR_TYPES.AAAA, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${exch} AAAA)`,
          })
          .catch(() => undefined),
        session
          .query(smtpTlsaOwner, RR_TYPES.TLSA, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${smtpTlsaOwner} TLSA)`,
          })
          .catch(() => undefined),
      ];
    }),
  ]);

  // Upgrade _mta-sts / _smtp._tls probes that returned TXT/CNAME answers or SERVFAIL to CD=1 Mail targets
  const matchedTransportOwners: string[] = [];
  for (const [qn, pLog] of [
    [mtaStsOwner, mtaStsProbeLog],
    [tlsRptOwner, tlsRptProbeLog],
  ] as const) {
    if (
      pLog &&
      (pLog.packet.answers.some((r) => r.type === RR_TYPES.TXT || r.type === RR_TYPES.CNAME) ||
        pLog.packet.flags.rcode === 2)
    ) {
      matchedTransportOwners.push(qn);
    }
  }
  if (matchedTransportOwners.length > 0) {
    await Promise.all(
      matchedTransportOwners.flatMap((qn) => [
        discoverZoneCutsForName(session, qn, discoveredZones, checkedCandidates),
        session
          .query(qn, RR_TYPES.TXT, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${qn} TXT)`,
          })
          .catch(() => undefined),
      ])
    );
  }

  // Follow CNAME chains across MX exchanges, _25._tcp.<mx> TLSA, _dmarc, _mta-sts/_smtp._tls, and _443._tcp TLSA
  const visitedStep2Followups = new Set<string>();
  for (let hop = 0; hop < 5; hop++) {
    const logsNow = session.getLogs();
    const followTasks: Promise<unknown>[] = [];

    for (const txtStart of [dmarcOwner, ...matchedTransportOwners]) {
      const cRes = resolveSimpleCnameInLogs(logsNow, txtStart, RR_TYPES.TXT);
      for (const cTarget of cRes.cnameChain) {
        const key = `txt|${cTarget}`;
        if (!visitedStep2Followups.has(key)) {
          visitedStep2Followups.add(key);
          followTasks.push(
            discoverZoneCutsForName(session, cTarget, discoveredZones, checkedCandidates),
            session
              .query(cTarget, RR_TYPES.TXT, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cTarget} TXT)`,
              })
              .catch(() => undefined)
          );
        }
      }
    }

    const webTlsaCname = resolveSimpleCnameInLogs(logsNow, webTlsaOwner, RR_TYPES.TLSA);
    for (const cTarget of webTlsaCname.cnameChain) {
      const key = `webtlsa|${cTarget}`;
      if (!visitedStep2Followups.has(key)) {
        visitedStep2Followups.add(key);
        followTasks.push(
          discoverZoneCutsForName(session, cTarget, discoveredZones, checkedCandidates),
          session
            .query(cTarget, RR_TYPES.TLSA, {
              cd: true,
              doBit: true,
              purpose: `CNAME target (${cTarget} TLSA)`,
            })
            .catch(() => undefined)
        );
      }
    }

    for (const exch of mxExchanges) {
      const aRes = resolveSimpleCnameInLogs(logsNow, exch, RR_TYPES.A);
      const aaaaRes = resolveSimpleCnameInLogs(logsNow, exch, RR_TYPES.AAAA);
      const mxHostCnames = Array.from(new Set([...aRes.cnameChain, ...aaaaRes.cnameChain]));
      for (const cnameTarget of mxHostCnames) {
        const key = `mx|${cnameTarget}`;
        if (!visitedStep2Followups.has(key)) {
          visitedStep2Followups.add(key);
          const fallbackTlsa = normalizeFqdn(`_25._tcp.${cnameTarget}`);
          followTasks.push(
            discoverZoneCutsForName(session, cnameTarget, discoveredZones, checkedCandidates),
            discoverZoneCutsForName(session, fallbackTlsa, discoveredZones, checkedCandidates),
            session
              .query(cnameTarget, RR_TYPES.A, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cnameTarget} A)`,
              })
              .catch(() => undefined),
            session
              .query(cnameTarget, RR_TYPES.AAAA, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cnameTarget} AAAA)`,
              })
              .catch(() => undefined),
            session
              .query(fallbackTlsa, RR_TYPES.TLSA, {
                cd: true,
                doBit: true,
                purpose: `Mail target (${fallbackTlsa} TLSA)`,
              })
              .catch(() => undefined)
          );
        }
      }

      const smtpTlsa = normalizeFqdn(`_25._tcp.${exch}`);
      const tCname = resolveSimpleCnameInLogs(logsNow, smtpTlsa, RR_TYPES.TLSA);
      for (const cTarget of tCname.cnameChain) {
        const key = `tlsa|${cTarget}`;
        if (!visitedStep2Followups.has(key)) {
          visitedStep2Followups.add(key);
          followTasks.push(
            discoverZoneCutsForName(session, cTarget, discoveredZones, checkedCandidates),
            session
              .query(cTarget, RR_TYPES.TLSA, {
                cd: true,
                doBit: true,
                purpose: `CNAME target (${cTarget} TLSA)`,
              })
              .catch(() => undefined)
          );
        }
      }
    }

    if (followTasks.length === 0) break;
    await Promise.all(followTasks);
  }

  // Organizational DMARC fallback when querying a subdomain without its own _dmarc TXT
  const dmarcCname = resolveSimpleCnameInLogs(session.getLogs(), dmarcOwner, RR_TYPES.TXT);
  const finalDmarcLog = findLog(session.getLogs(), dmarcCname.finalOwner, RR_TYPES.TXT, true);
  const hasDirectDmarc = (finalDmarcLog?.packet.answers ?? []).some(
    (r) =>
      r.type === RR_TYPES.TXT &&
      r.parsed.kind === 'TXT' &&
      /^v\s*=\s*DMARC1\b/i.test(r.parsed.joinedText.trim())
  );
  if (!hasDirectDmarc) {
    const orgDomain = estimateOrganizationalDomain(effectiveDomain, session.getLogs());
    if (orgDomain !== effectiveDomain && orgDomain !== '.') {
      const orgDmarcOwner = normalizeFqdn(`_dmarc.${orgDomain}`);
      await Promise.all([
        discoverZoneCutsForName(session, orgDmarcOwner, discoveredZones, checkedCandidates),
        session
          .query(orgDmarcOwner, RR_TYPES.TXT, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${orgDmarcOwner} TXT)`,
          })
          .catch(() => undefined),
      ]);
      const visitedOrgCnames = new Set<string>([orgDmarcOwner]);
      for (let hop = 0; hop < 4; hop++) {
        const oRes = resolveSimpleCnameInLogs(session.getLogs(), orgDmarcOwner, RR_TYPES.TXT);
        const nextC = oRes.cnameChain.find((c) => !visitedOrgCnames.has(c));
        if (!nextC) break;
        visitedOrgCnames.add(nextC);
        await Promise.all([
          discoverZoneCutsForName(session, nextC, discoveredZones, checkedCandidates),
          session
            .query(nextC, RR_TYPES.TXT, {
              cd: true,
              doBit: true,
              purpose: `CNAME target (${nextC} TXT)`,
            })
            .catch(() => undefined),
        ]);
      }
    }
  }

  // Optional fast MTA-STS HTTPS policy check when _mta-sts TXT is published
  let mtaStsPolicyFetch: MtaStsPolicyFetchResult | undefined;
  const mtaStsCname = resolveSimpleCnameInLogs(session.getLogs(), mtaStsOwner, RR_TYPES.TXT);
  const mtaStsLog =
    findLog(session.getLogs(), mtaStsCname.finalOwner, RR_TYPES.TXT, true) ??
    findLog(session.getLogs(), mtaStsOwner, RR_TYPES.TXT, false);
  const hasMtaStsDns = (mtaStsLog?.packet.answers ?? []).some(
    (r) =>
      r.type === RR_TYPES.TXT &&
      r.parsed.kind === 'TXT' &&
      /^v\s*=\s*STSv1\b/i.test(r.parsed.joinedText.trim())
  );
  if (hasMtaStsDns && !options.skipExternalHttp && !options.fetchImpl) {
    const policyUrl = `https://mta-sts.${displayDomain}/.well-known/mta-sts.txt`;
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    options.signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const res = await fetch(policyUrl, {
        method: 'GET',
        headers: { Accept: 'text/plain' },
        signal: controller.signal,
      });
      const text = await res.text();
      mtaStsPolicyFetch = {
        url: policyUrl,
        fetchedAt: Date.now(),
        ok: res.ok,
        httpStatus: res.status,
        contentType: res.headers.get('content-type') ?? undefined,
        rawBody: text.slice(0, 16384),
      };
    } catch (err) {
      mtaStsPolicyFetch = {
        url: policyUrl,
        fetchedAt: Date.now(),
        ok: false,
        corsOrNetworkError:
          err instanceof Error ? err.message : 'CORS or network error fetching mta-sts.txt',
      };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
    }
  }

  // Include authoritative SOA zones & any RRSIG signer zones discovered in CD=1 responses
  const missingSignerZones = new Set<string>();
  for (const log of session.getLogs()) {
    if (
      !log.cd ||
      log.purpose.startsWith('SPF lookup') ||
      log.purpose.startsWith('Nameserver IP') ||
      log.purpose.startsWith('Zone-cut probe') ||
      log.purpose.startsWith('Delegation probe')
    ) {
      continue;
    }
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
      if (auth.type === RR_TYPES.RRSIG && auth.parsed.kind === 'RRSIG') {
        const signer = normalizeFqdn(auth.parsed.signerName);
        if (!discoveredZones.has(signer)) missingSignerZones.add(signer);
      }
    }
    for (const ans of log.packet.answers) {
      if (ans.type === RR_TYPES.RRSIG && ans.parsed.kind === 'RRSIG') {
        const signer = normalizeFqdn(ans.parsed.signerName);
        if (!discoveredZones.has(signer)) missingSignerZones.add(signer);
      }
    }
  }
  if (missingSignerZones.size > 0) {
    await Promise.all(
      Array.from(missingSignerZones).map((signer) =>
        discoverZoneCutsForName(session, signer, discoveredZones, checkedCandidates)
      )
    );
  }

  // Step 3: Fetch DNSKEY, DS, SOA & NS across all discovered zones + probe NS IPs & BGP ASNs
  phaseLabel = `Verifying DNSSEC keys, NS dual-stack IPs & BGP ASNs for ${displayDomain}…`;
  options.onQueryProgress?.(session.getLogs().length, phaseLabel);

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

  await probeLeafNameserverAddresses(session, zoneList, targetName);

  // Team Cymru BGP ASN lookup for resolved leaf/target zone nameserver IPs (deduplicated across portfolio!)
  const nsOriginQnames = new Set<string>(
    collectPrioritizedNsOriginQnames(zoneList, session.getLogs(), targetName, 14)
  );

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
    for (const oLog of originLogs) {
      if (!oLog) continue;
      const txts: string[] = [];
      for (const ans of oLog.packet.answers) {
        if (ans.type === RR_TYPES.TXT && ans.parsed.kind === 'TXT') {
          txts.push(ans.parsed.joinedText);
        }
      }
      for (const parsed of parseCymruOriginTxt(txts)) {
        for (const asn of parsed.asns) nsUniqueAsns.add(asn);
      }
    }
    if (nsUniqueAsns.size > 0) {
      await Promise.all(
        Array.from(nsUniqueAsns)
          .slice(0, 6)
          .map((asn) => {
            const asnQname = `as${asn}.asn.cymru.com.`;
            return session
              .query(asnQname, RR_TYPES.TXT, {
                cd: false,
                doBit: false,
                purpose: `BGP ASN lookup (${asnQname} TXT)`,
              })
              .catch(() => undefined);
          })
      );
    }
  }

  // Step 4: Cryptographic WebCrypto evaluation + Mail & Web synthesis
  phaseLabel = `Validating WebCrypto DNSSEC chain for ${displayDomain}…`;
  options.onQueryProgress?.(session.getLogs().length, phaseLabel);

  const capturedAt = Date.now();
  const validatedAt = options.validationTimeMs ?? capturedAt;
  const durationMs = Math.max(1, capturedAt - startedAt);

  const baseSnap = await evaluateSnapshotFromLogs({
    id: `snap-${capturedAt}-${Math.random().toString(36).slice(2, 8)}`,
    mode: 'dnssec',
    targetName,
    queryTypes: ['A', 'AAAA', 'MX', 'TXT', 'HTTPS', 'CAA'],
    mtaStsPolicyFetch,
    dohEndpoint: endpoint,
    capturedAt,
    validatedAt,
    durationMs,
    queries: session.getLogs(),
    trustAnchors,
  });

  const dnssecTargetStatus: ValidationStatus =
    baseSnap.overallStatus === 'policy-error' ? 'secure' : baseSnap.overallStatus;

  const mailEval = evaluateMailFromSnapshotData({
    targetName: baseSnap.targetName,
    queries: baseSnap.queries,
    zones: baseSnap.zones,
    cnameEdges: baseSnap.cnameEdges,
    targetDomainStatus: dnssecTargetStatus,
    mtaStsPolicyFetch,
  });

  const webEval = evaluateWebFromSnapshotData({
    targetName: baseSnap.targetName,
    queries: baseSnap.queries,
    zones: baseSnap.zones,
    cnameEdges: baseSnap.cnameEdges,
    targetDomainStatus: dnssecTargetStatus,
    validatedAt: baseSnap.validatedAt,
  });

  const mergedFindings = [...baseSnap.findings];
  for (const mf of mailEval.mailFindings) {
    if (mf.code === 'DKIM_NO_COMMON_SELECTOR_MATCH') continue;
    if (!mergedFindings.some((f) => f.id === mf.id)) {
      mergedFindings.push(mf);
    }
  }
  for (const wf of webEval.webFindings) {
    if (!mergedFindings.some((f) => f.id === wf.id)) {
      mergedFindings.push(wf);
    }
  }

  return {
    ...baseSnap,
    mailAnalysis: mailEval.mailAnalysis,
    webAnalysis: webEval.webAnalysis,
    findings: mergedFindings,
  };
}

export type PortfolioBatchStatus = 'idle' | 'running' | 'paused' | 'completed' | 'canceled';

export interface PortfolioBatchState {
  id: string;
  status: PortfolioBatchStatus;
  concurrency: number;
  dohEndpoint: string;
  sourceLabel?: string;
  startedAt: number;
  finishedAt?: number;
  totalDomains: number;
  completedDomains: number;
  failedDomains: number;
  runningDomains: number;
  totalQueries: number;
  rows: PortfolioDomainRow[];
  asnConcentration: PortfolioAsnConcentrationEntry[];
}

export interface PortfolioBatchRunnerOptions {
  domains: string[];
  concurrency?: number;
  dohEndpoint?: string;
  trustAnchors?: TrustAnchor[];
  sourceLabel?: string;
  fetchImpl?: typeof fetch;
  skipExternalHttp?: boolean;
  probeFn?: (domain: string, opts: PortfolioProbeOptions) => Promise<AnalysisSnapshot>;
  onUpdate?: (state: PortfolioBatchState) => void;
  onSnapshotReady?: (snapshot: AnalysisSnapshot, row: PortfolioDomainRow) => void;
}

export interface PortfolioBatchRunner {
  start: () => Promise<PortfolioBatchState>;
  pause: () => void;
  resume: () => void;
  cancel: () => void;
  getState: () => PortfolioBatchState;
}

/**
 * Creates a bounded-concurrency client-side Portfolio Batch Runner with live per-row progress,
 * Pause/Resume gating, and immediate AbortController cancellation.
 */
export function createPortfolioBatchRunner(
  options: PortfolioBatchRunnerOptions
): PortfolioBatchRunner {
  const cleanDomains = Array.from(
    new Set(
      options.domains
        .map((d) => d.trim())
        .filter(Boolean)
        .map((d) => displayFqdn(normalizeFqdn(d)))
    )
  ).slice(0, MAX_PORTFOLIO_DOMAINS);

  const concurrency = Math.max(1, Math.min(8, Math.floor(options.concurrency ?? DEFAULT_PORTFOLIO_CONCURRENCY)));
  const dohEndpoint = options.dohEndpoint ?? DEFAULT_DOH_ENDPOINT;
  const probeImpl = options.probeFn ?? runPortfolioDomainProbe;
  const sharedQueryCache = new Map<string, Promise<DohQueryLog>>();
  const abortController = new AbortController();

  const rows: PortfolioDomainRow[] = cleanDomains.map((domain, index) => ({
    index,
    domain,
    status: 'queued',
    completedQueries: 0,
  }));

  let status: PortfolioBatchStatus = 'idle';
  const startedAt = Date.now();
  let finishedAt: number | undefined;
  let nextIdx = 0;
  let resumeResolvers: Array<() => void> = [];
  let startPromise: Promise<PortfolioBatchState> | null = null;

  const buildSnapshotState = (): PortfolioBatchState => {
    const completedDomains = rows.filter((r) => r.status === 'done').length;
    const failedDomains = rows.filter((r) => r.status === 'error').length;
    const runningDomains = rows.filter((r) => r.status === 'running').length;
    const totalQueries = rows.reduce((acc, r) => acc + r.completedQueries, 0);
    return {
      id: `portfolio-${startedAt}`,
      status,
      concurrency,
      dohEndpoint,
      sourceLabel: options.sourceLabel,
      startedAt,
      finishedAt,
      totalDomains: rows.length,
      completedDomains,
      failedDomains,
      runningDomains,
      totalQueries,
      rows: rows.map((r) => ({ ...r })),
      asnConcentration: computePortfolioAsnConcentration(rows),
    };
  };

  const emit = () => {
    options.onUpdate?.(buildSnapshotState());
  };

  const waitWhilePaused = async (): Promise<void> => {
    while (status === 'paused') {
      await new Promise<void>((resolve) => {
        resumeResolvers.push(resolve);
      });
    }
  };

  const wakePausedWorkers = () => {
    const pending = resumeResolvers;
    resumeResolvers = [];
    for (const resolve of pending) resolve();
  };

  const workerLoop = async (): Promise<void> => {
    while (true) {
      await waitWhilePaused();
      if (status === 'canceled' || abortController.signal.aborted) {
        return;
      }
      const idx = nextIdx++;
      if (idx >= rows.length) {
        return;
      }
      const row = rows[idx]!;
      if (row.status !== 'queued') continue;

      const rowStart = Date.now();
      row.status = 'running';
      row.startedAt = rowStart;
      row.phaseMessage = `Starting DoH probe…`;
      emit();

      try {
        const snap = await probeImpl(row.domain, {
          endpoint: dohEndpoint,
          trustAnchors: options.trustAnchors,
          fetchImpl: options.fetchImpl,
          sharedQueryCache,
          signal: abortController.signal,
          skipExternalHttp: options.skipExternalHttp,
          onQueryProgress: (qCount, msg) => {
            if (row.status !== 'running') return;
            row.completedQueries = qCount;
            row.phaseMessage = msg;
            emit();
          },
        });

        if (abortController.signal.aborted || (status as PortfolioBatchStatus) === 'canceled') {
          row.status = 'canceled';
          row.phaseMessage = undefined;
          row.durationMs = Math.max(1, Date.now() - rowStart);
          emit();
          return;
        }

        row.status = 'done';
        row.snapshot = snap;
        row.posture = extractPortfolioPosture(snap);
        row.completedQueries = snap.queries.length;
        row.durationMs = snap.durationMs;
        row.phaseMessage = undefined;
        options.onSnapshotReady?.(snap, { ...row });
        emit();
      } catch (err) {
        row.durationMs = Math.max(1, Date.now() - rowStart);
        row.phaseMessage = undefined;
        if (abortController.signal.aborted || (status as PortfolioBatchStatus) === 'canceled') {
          row.status = 'canceled';
        } else {
          row.status = 'error';
          row.error = err instanceof Error ? err.message : 'DoH probe failed';
        }
        emit();
      }
    }
  };

  return {
    start() {
      if (startPromise) return startPromise;
      if (rows.length === 0) {
        status = 'completed';
        finishedAt = Date.now();
        const empty = buildSnapshotState();
        options.onUpdate?.(empty);
        return Promise.resolve(empty);
      }

      status = 'running';
      emit();

      const workerCount = Math.min(concurrency, rows.length);
      startPromise = Promise.all(
        Array.from({ length: workerCount }, () => workerLoop())
      ).then(() => {
        if (status !== 'canceled') {
          status = 'completed';
        }
        finishedAt = Date.now();
        const finalState = buildSnapshotState();
        options.onUpdate?.(finalState);
        return finalState;
      });

      return startPromise;
    },

    pause() {
      if (status !== 'running') return;
      status = 'paused';
      emit();
    },

    resume() {
      if (status !== 'paused') return;
      status = 'running';
      wakePausedWorkers();
      emit();
    },

    cancel() {
      if (status === 'completed' || status === 'canceled') return;
      status = 'canceled';
      abortController.abort();
      for (const r of rows) {
        if (r.status === 'queued') {
          r.status = 'canceled';
        }
      }
      finishedAt = Date.now();
      wakePausedWorkers();
      emit();
    },

    getState() {
      return buildSnapshotState();
    },
  };
}

export type PortfolioSortField =
  | 'order'
  | 'domain'
  | 'risk'
  | 'dnssec'
  | 'rrsig'
  | 'nsAsn'
  | 'dmarc'
  | 'mail'
  | 'web'
  | 'issues';

export type PortfolioSortDirection = 'asc' | 'desc';

const DNSSEC_RANK: Record<ValidationStatus, number> = {
  bogus: 0,
  indeterminate: 1,
  insecure: 2,
  warning: 3,
  secure: 4,
};

const DMARC_RANK: Record<PortfolioPostureMetrics['dmarcPolicy'], number> = {
  invalid: 0,
  missing: 1,
  none: 2,
  quarantine: 3,
  reject: 4,
};

function computeMailPostureRank(p: PortfolioPostureMetrics): number {
  let score = 0;
  if (p.mxStatus === 'valid' || p.mxStatus === 'null-mx') score += 2;
  if (p.daneStatus === 'all-valid') score += 3;
  else if (p.daneStatus === 'bogus') score -= 3;
  if (p.spfVerdict === 'strict-fail') score += 2;
  else if (p.spfVerdict === 'soft-fail') score += 1;
  else if (p.spfVerdict === 'permerror' || p.spfVerdict === 'pass-all') score -= 2;
  score += DMARC_RANK[p.dmarcPolicy] - 1;
  if (p.mtaStsStatus === 'enforce') score += 2;
  else if (p.mtaStsStatus === 'testing' || p.mtaStsStatus === 'dns-only') score += 1;
  return score;
}

function computeWebPostureRank(p: PortfolioPostureMetrics): number {
  let score = 0;
  if (p.echEnabled) score += 4;
  else if (p.hasHttps) score += 2;
  if (p.caaStatus === 'enforced' || p.caaStatus === 'inherited') score += 3;
  return score;
}

export function sortPortfolioRows(
  rows: readonly PortfolioDomainRow[],
  field: PortfolioSortField,
  direction: PortfolioSortDirection,
  asnShareByAsn?: ReadonlyMap<number, number>
): PortfolioDomainRow[] {
  const mult = direction === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    if (field === 'order') {
      return (a.index - b.index) * mult;
    }
    if (field === 'domain') {
      return a.domain.localeCompare(b.domain) * mult;
    }

    // Keep incomplete rows below completed rows when sorting by posture metrics
    const aDone = Boolean(a.posture);
    const bDone = Boolean(b.posture);
    if (aDone !== bDone) return aDone ? -1 : 1;
    if (!a.posture || !b.posture) return a.index - b.index;

    const pa = a.posture;
    const pb = b.posture;

    switch (field) {
      case 'risk':
        return (pa.riskScore - pb.riskScore) * mult || a.domain.localeCompare(b.domain);
      case 'dnssec':
        return (
          (DNSSEC_RANK[pa.dnssecStatus] - DNSSEC_RANK[pb.dnssecStatus]) * mult ||
          a.domain.localeCompare(b.domain)
        );
      case 'rrsig': {
        const ra = pa.shortestRrsigRemainingSec ?? Number.POSITIVE_INFINITY;
        const rb = pb.shortestRrsigRemainingSec ?? Number.POSITIVE_INFINITY;
        return (ra - rb) * mult || a.domain.localeCompare(b.domain);
      }
      case 'nsAsn': {
        const maxShareA = Math.max(
          0,
          ...pa.nsAsns.map((x) => asnShareByAsn?.get(x.asn) ?? 0)
        );
        const maxShareB = Math.max(
          0,
          ...pb.nsAsns.map((x) => asnShareByAsn?.get(x.asn) ?? 0)
        );
        return (
          (maxShareA - maxShareB) * mult ||
          ((pa.nsAsns[0]?.asn ?? 0) - (pb.nsAsns[0]?.asn ?? 0)) * mult ||
          a.domain.localeCompare(b.domain)
        );
      }
      case 'dmarc':
        return (
          (DMARC_RANK[pa.dmarcPolicy] - DMARC_RANK[pb.dmarcPolicy]) * mult ||
          a.domain.localeCompare(b.domain)
        );
      case 'mail':
        return (
          (computeMailPostureRank(pa) - computeMailPostureRank(pb)) * mult ||
          a.domain.localeCompare(b.domain)
        );
      case 'web':
        return (
          (computeWebPostureRank(pa) - computeWebPostureRank(pb)) * mult ||
          a.domain.localeCompare(b.domain)
        );
      case 'issues':
        return (
          (pa.issueCount - pb.issueCount) * mult ||
          (pa.errorCount - pb.errorCount) * mult ||
          a.domain.localeCompare(b.domain)
        );
    }
  });
}

function escapeCsvField(raw: string | number | boolean | null | undefined): string {
  if (raw === null || raw === undefined) return '';
  let str = String(raw);
  // Guard against spreadsheet formula injection (=, +, -, @) while keeping numbers intact
  if (/^[=+\-@]/.test(str) && !/^-\d+(\.\d+)?$/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Formats the Portfolio Posture Matrix as an RFC 4180 CSV document.
 */
export function formatPortfolioCsv(
  rows: readonly PortfolioDomainRow[],
  asnConcentration: readonly PortfolioAsnConcentrationEntry[] = computePortfolioAsnConcentration(rows)
): string {
  const asnShareMap = new Map<number, number>(
    asnConcentration.map((a) => [a.asn, a.sharePercent])
  );

  const headers = [
    'domain',
    'status',
    'leaf_zone',
    'dnssec_status',
    'dnssec_algorithm',
    'nsec_mode',
    'shortest_rrsig_remaining_sec',
    'shortest_rrsig_human',
    'ns_count',
    'ns_dual_stack_ready',
    'ns_asns',
    'ns_max_portfolio_asn_share_pct',
    'ns_single_asn_spof',
    'ns_providers',
    'mx_status',
    'mx_count',
    'smtp_dane_status',
    'spf_verdict',
    'spf_lookups',
    'dmarc_policy',
    'mta_sts_status',
    'https_svcb_status',
    'tls_ech_enabled',
    'caa_status',
    'caa_issue_cas',
    'errors',
    'warnings',
    'risk_score',
  ];

  const lines = [headers.join(',')];

  for (const row of rows) {
    const p = row.posture;
    if (!p) {
      lines.push(
        [
          escapeCsvField(row.domain),
          escapeCsvField(row.status),
          ...Array.from({ length: headers.length - 2 }, () => ''),
        ].join(',')
      );
      continue;
    }

    const asnLabel = p.nsAsns
      .map((a) => `AS${a.asn}${a.asName ? ` (${a.asName})` : ''}`)
      .join('; ');
    const maxAsnShare =
      p.nsAsns.length > 0
        ? Math.max(...p.nsAsns.map((a) => asnShareMap.get(a.asn) ?? 0))
        : '';
    const spfText = p.spfPresent
      ? `${p.spfVerdict}${p.spfQualifier ? ` (${p.spfQualifier}all)` : ''}`
      : 'missing';

    lines.push(
      [
        p.domain,
        row.status,
        p.leafZone,
        p.dnssecStatus,
        p.dnssecAlgorithmLabel,
        p.nsecMode,
        p.shortestRrsigRemainingSec ?? '',
        p.shortestRrsigLabel,
        p.nsCount,
        p.dualStackReady === null ? '' : p.dualStackReady,
        asnLabel,
        maxAsnShare,
        p.singleNsAsnSpof,
        p.nsProviders.join('; '),
        p.mxStatus,
        p.mxCount,
        p.daneStatus,
        spfText,
        p.spfLookups,
        p.dmarcPolicy,
        p.mtaStsStatus,
        p.httpsStatus,
        p.echEnabled,
        p.caaStatus,
        p.caaIssueCas.join('; '),
        p.errorCount,
        p.warningCount,
        p.riskScore,
      ]
        .map(escapeCsvField)
        .join(',')
    );
  }

  return lines.join('\n');
}

function escapeMdCell(val: string): string {
  return val.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/**
 * Formats the Portfolio Posture & BGP ASN Concentration report as GitHub-Flavored Markdown.
 */
export function formatPortfolioMarkdown(
  rows: readonly PortfolioDomainRow[],
  asnConcentration: readonly PortfolioAsnConcentrationEntry[] = computePortfolioAsnConcentration(rows),
  meta: { dohEndpoint?: string; exportedAt?: number; sourceLabel?: string } = {}
): string {
  const doneRows = rows.filter((r) => r.status === 'done' && r.posture);
  const total = doneRows.length;
  const exportedIso = new Date(meta.exportedAt ?? Date.now()).toISOString();
  const resolverLabel = formatDohShortLabel(meta.dohEndpoint ?? DEFAULT_DOH_ENDPOINT);

  const signedCount = doneRows.filter(
    (r) => r.posture!.dnssecStatus === 'secure' || r.posture!.dnssecStatus === 'warning'
  ).length;
  const bogusCount = doneRows.filter((r) => r.posture!.dnssecStatus === 'bogus').length;
  const dmarcEnforcedCount = doneRows.filter(
    (r) => r.posture!.dmarcPolicy === 'reject' || r.posture!.dmarcPolicy === 'quarantine'
  ).length;
  const daneValidCount = doneRows.filter((r) => r.posture!.daneStatus === 'all-valid').length;
  const echCount = doneRows.filter((r) => r.posture!.echEnabled).length;
  const caaCount = doneRows.filter(
    (r) => r.posture!.caaStatus === 'enforced' || r.posture!.caaStatus === 'inherited'
  ).length;

  const out: string[] = [];
  out.push(`# DigDeep Portfolio DNS Security & Resilience Triage Report`);
  out.push('');
  out.push(
    `- **Audited Domains**: ${total} completed${rows.length > total ? ` (${rows.length} total)` : ''}${meta.sourceLabel ? ` · Source: ${meta.sourceLabel}` : ''}`
  );
  out.push(`- **DoH Resolver**: \`${resolverLabel}\` · **Generated**: \`${exportedIso}\``);
  if (total > 0) {
    out.push(
      `- **Posture Summary**: DNSSEC Valid **${signedCount}/${total}**${bogusCount > 0 ? ` (**${bogusCount} BOGUS**)` : ''} · DMARC Enforced **${dmarcEnforcedCount}/${total}** · SMTP DANE **${daneValidCount}/${total}** · TLS ECH **${echCount}/${total}** · CAA Protected **${caaCount}/${total}**`
    );
  }
  out.push('');

  if (asnConcentration.length > 0) {
    out.push(`## Cross-Portfolio Authoritative NS BGP ASN Concentration`);
    out.push('');
    out.push(`| BGP ASN | Network / Organization | Portfolio Coverage | Single-ASN SPOF Domains | Risk |`);
    out.push(`| :--- | :--- | :--- | :--- | :--- |`);
    for (const a of asnConcentration) {
      const riskBadge =
        a.concentrationRisk === 'critical'
          ? 'CRITICAL SPOF'
          : a.concentrationRisk === 'elevated'
            ? 'ELEVATED'
            : 'DIVERSIFIED';
      out.push(
        `| \`AS${a.asn}\` | ${escapeMdCell(a.asName ?? 'Unknown')} | **${a.domainCount}/${a.completedPortfolioCount}** (${a.sharePercent}%) | ${a.soleSpofDomainCount} (${escapeMdCell(a.soleSpofDomains.slice(0, 4).join(', '))}${a.soleSpofDomains.length > 4 ? '…' : ''}) | ${riskBadge} |`
      );
    }
    out.push('');
  }

  out.push(`## Domain Security & Resilience Matrix`);
  out.push('');
  out.push(
    `| Domain | DNSSEC & Alg | Min RRSIG | Authoritative NS ASNs | MX / DANE | SPF | DMARC | MTA-STS | HTTPS / ECH | CAA | Issues |`
  );
  out.push(
    `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |`
  );

  for (const row of rows) {
    const p = row.posture;
    if (!p) {
      out.push(
        `| \`${escapeMdCell(row.domain)}\` | ${escapeMdCell(row.status.toUpperCase())} | — | — | — | — | — | — | — | — | ${escapeMdCell(row.error ?? '—')} |`
      );
      continue;
    }

    const dnssecCell = `**${p.dnssecStatus.toUpperCase()}** (${p.dnssecAlgorithmLabel})`;
    const asnCell =
      p.nsAsns.length > 0
        ? `${p.nsAsns.map((a) => `\`AS${a.asn}\``).join(', ')}${p.singleNsAsnSpof ? ' *(1-ASN)*' : ''}`
        : p.nsProviders.join(', ') || '—';
    const mxDaneCell =
      p.mxStatus === 'null-mx'
        ? 'Null MX (`.`)'
        : p.mxStatus === 'none'
          ? 'No MX'
          : `${p.mxCount} MX · ${p.daneStatus === 'all-valid' ? 'DANE ✓' : p.daneStatus}`;
    const spfCell = p.spfPresent
      ? `${p.spfVerdict}${p.spfQualifier ? ` \`${p.spfQualifier}all\`` : ''} (${p.spfLookups}/10)`
      : 'missing';
    const dmarcCell =
      p.dmarcPolicy === 'missing'
        ? 'missing'
        : p.dmarcPolicy === 'invalid'
          ? 'INVALID'
          : `\`p=${p.dmarcPolicy}\``;
    const httpsCell = p.echEnabled
      ? 'HTTPS + ECH ✓'
      : p.hasHttps
        ? 'HTTPS'
        : '—';
    const caaCell =
      p.caaStatus === 'enforced' || p.caaStatus === 'inherited'
        ? `${p.caaStatus} (${p.caaIssueCas.slice(0, 2).join(', ')})`
        : p.caaStatus;
    const issuesCell =
      p.errorCount > 0 || p.warningCount > 0
        ? `${p.errorCount}E / ${p.warningCount}W`
        : '0';

    out.push(
      `| \`${escapeMdCell(p.domain)}\` | ${escapeMdCell(dnssecCell)} | ${escapeMdCell(p.shortestRrsigLabel)} | ${escapeMdCell(asnCell)} | ${escapeMdCell(mxDaneCell)} | ${escapeMdCell(spfCell)} | ${escapeMdCell(dmarcCell)} | ${escapeMdCell(p.mtaStsStatus)} | ${escapeMdCell(httpsCell)} | ${escapeMdCell(caaCell)} | ${issuesCell} |`
    );
  }

  return out.join('\n');
}

export interface PortfolioJsonBundle {
  kind: 'digdeep-portfolio-bundle';
  version: 1;
  exportedAt: string;
  dohEndpoint: string;
  sourceLabel?: string;
  totalDomains: number;
  completedDomains: number;
  asnConcentration: PortfolioAsnConcentrationEntry[];
  matrix: Array<{
    domain: string;
    status: PortfolioRowStatus;
    error?: string;
    posture?: PortfolioPostureMetrics;
  }>;
  snapshots: AnalysisSnapshot[];
}

/**
 * Formats the Portfolio Matrix + full underlying `AnalysisSnapshot` array as a structured JSON bundle
 * (directly re-importable via DigDeep's History JSON importer).
 */
export function formatPortfolioJsonBundle(
  rows: readonly PortfolioDomainRow[],
  asnConcentration: readonly PortfolioAsnConcentrationEntry[] = computePortfolioAsnConcentration(rows),
  meta: { dohEndpoint?: string; exportedAt?: number; sourceLabel?: string } = {}
): string {
  const bundle: PortfolioJsonBundle = {
    kind: 'digdeep-portfolio-bundle',
    version: 1,
    exportedAt: new Date(meta.exportedAt ?? Date.now()).toISOString(),
    dohEndpoint: meta.dohEndpoint ?? DEFAULT_DOH_ENDPOINT,
    ...(meta.sourceLabel ? { sourceLabel: meta.sourceLabel } : {}),
    totalDomains: rows.length,
    completedDomains: rows.filter((r) => r.status === 'done').length,
    asnConcentration: [...asnConcentration],
    matrix: rows.map((r) => ({
      domain: r.domain,
      status: r.status,
      ...(r.error ? { error: r.error } : {}),
      ...(r.posture ? { posture: r.posture } : {}),
    })),
    snapshots: rows.flatMap((r) => (r.snapshot ? [r.snapshot] : [])),
  };
  return JSON.stringify(bundle, null, 2);
}
