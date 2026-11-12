import { STATUS_META } from '../components/StatusBadge';
import { type ActiveTab, buildShareUrl } from '../urlState';
import {
  formatAlgorithm,
  formatDigestType,
  formatDohShortLabel,
  RR_TYPES,
} from './constants';
import { formatPacketAsDig, generateCliReproducerCommands } from './digFormat';
import { displayFqdn, normalizeFqdn } from './encoding';
import type {
  AnalysisMode,
  AnalysisSnapshot,
  AuditFinding,
  DohQueryLog,
  SnapshotStatus,
  ZoneAnalysis,
} from './types';

export type WireTranscriptMode = 'key' | 'all' | 'none';

export interface MarkdownReportOptions {
  /** Base URL for the interactive DigDeep permalink (defaults to `https://digdeep.fyi/`). */
  baseHref?: string;
  /** Focused graph element ID to preserve in the permalink if applicable. */
  focus?: string | null;
  /** Which wire transcripts to embed inside collapsible `<details>` sections (default `'key'`). */
  wireTranscriptMode?: WireTranscriptMode;
  /** Maximum number of key wire transcripts when `wireTranscriptMode === 'key'` (default `8`). */
  maxKeyWireTranscripts?: number;
  /** Whether to include `info`-level audit notices in the Audit Findings section (default `true`). */
  includeInfoFindings?: boolean;
}

export interface CiCheckGeneratorOptions {
  /** Base URL for DigDeep attribution/permalink comments (defaults to `https://digdeep.fyi/`). */
  baseHref?: string;
  /** Override minimum remaining RRSIG validity in hours (defaults to snapshot-tailored value). */
  minRrsigHours?: number;
  /** Override default DNS resolver IP/host for `dig` / `delv` (defaults to snapshot resolver or `1.1.1.1`). */
  resolver?: string;
  // Cron expression for `.github/workflows/dns-check.yml` (defaults to '17 */6 * * *').
  cronSchedule?: string;
}

export interface CiTlsaInvariant {
  owner: string;
  rrtype: 'TLSA' | 'OPENPGPKEY' | 'SMIMEA';
  requireDnssecAd: boolean;
  label: string;
}

export interface CiInvariantBadge {
  id: string;
  label: string;
  detail: string;
}

export interface SnapshotCiInvariants {
  targetDomain: string;
  targetFqdn: string;
  primaryQueryType: string;
  defaultResolver: string;
  permalink: string;
  expectDnssecAd: boolean;
  signedZone: string | null;
  expectedDsKeyTags: number[];
  minObservedRrsigHours: number | null;
  recommendedMinRrsigHours: number;
  caaCheck: {
    owner: string;
    expectedIssueCas: string[];
    explicitDenyAll: boolean;
  } | null;
  spfCheck: {
    owner: string;
    maxDnsLookups: number;
    observedLookups?: number;
    expectedAllToken: '-all' | '~all' | null;
  } | null;
  dmarcCheck: {
    owner: string;
    expectedPolicy: 'reject' | 'quarantine' | 'none';
  } | null;
  tlsaChecks: CiTlsaInvariant[];
  badges: CiInvariantBadge[];
}

const KNOWN_UDP_DNS_HOSTS = new Set([
  '1.1.1.1',
  '1.0.0.1',
  '1.1.1.2',
  '1.1.1.3',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '9.9.9.10',
  '9.9.9.11',
  '94.140.14.14',
  '94.140.14.140',
  '208.67.222.222',
  '194.242.2.2',
  '185.228.168.9',
  'dns.google',
  'dns.quad9.net',
  'one.one.one.one',
]);

function statusEmoji(status: SnapshotStatus): string {
  switch (status) {
    case 'secure':
      return '✅';
    case 'warning':
      return '⚠️';
    case 'insecure':
      return '🔓';
    case 'bogus':
      return '❌';
    case 'policy-error':
      return '🛑';
    case 'indeterminate':
      return '❔';
  }
}

function modeDescription(snapshot: AnalysisSnapshot): string {
  const mode: AnalysisMode = snapshot.mode ?? 'dnssec';
  if (mode === 'mail') {
    const dkimNote =
      snapshot.customDkimSelectors && snapshot.customDkimSelectors.length > 0
        ? ` (custom DKIM: ${snapshot.customDkimSelectors.join(', ')})`
        : '';
    return `Mail · MX · SMTP DANE · SPF · DKIM · DMARC${dkimNote}`;
  }
  if (mode === 'web') {
    return 'Web · HTTPS/SVCB · TLS ECH · CAA · DANE · CT';
  }
  if (mode === 'consensus') {
    return 'Multi-Resolver DoH Consensus · RFC 8914 EDE · RFC 7871 ECS';
  }
  return `DNSSEC Chain & RDATA [${snapshot.queryTypes.join(', ')}]`;
}

function escapeMdCell(raw: string): string {
  return raw
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|')
    .trim();
}

function escapeHtmlText(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeInlineCode(raw: string): string {
  const clean = raw.replace(/[\r\n]+/g, ' ').trim();
  if (!clean.includes('`')) return `\`${clean}\``;
  return `\`\` ${clean} \`\``;
}

function formatCodeFence(content: string, lang: string): string {
  let fence = '```';
  while (content.includes(fence)) {
    fence += '`';
  }
  return `${fence}${lang}\n${content.replace(/\n+$/, '')}\n${fence}`;
}

function formatDurationShort(seconds: number): string {
  const abs = Math.abs(Math.round(seconds));
  const days = Math.floor(abs / 86400);
  const hours = Math.floor((abs % 86400) / 3600);
  const mins = Math.floor((abs % 3600) / 60);
  const core =
    days > 0
      ? `${days}d ${hours}h`
      : hours > 0
        ? `${hours}h ${mins}m`
        : `${mins}m`;
  return seconds < 0 ? `EXPIRED (${core} ago)` : core;
}

/**
 * Safely quotes an arbitrary string as a single-quoted POSIX `sh` literal,
 * stripping ASCII control characters so untrusted DNS RDATA can never inject commands.
 */
export function shellSingleQuote(raw: string): string {
  let sanitized = '';
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code >= 0x20 && code !== 0x7f) {
      sanitized += raw[i];
    }
  }
  return `'${sanitized.replace(/'/g, `'\\''`)}'`;
}

/**
 * Builds a canonical `https://digdeep.fyi/?...` share permalink for an `AnalysisSnapshot`.
 */
export function buildSnapshotPermalink(
  snapshot: AnalysisSnapshot,
  options: { baseHref?: string; tab?: ActiveTab; focus?: string | null } = {}
): string {
  const mode: AnalysisMode = snapshot.mode ?? 'dnssec';
  const defaultTab: ActiveTab =
    mode === 'mail'
      ? 'mail'
      : mode === 'web'
        ? 'web'
        : mode === 'consensus'
          ? 'consensus'
          : 'graph';
  const base = options.baseHref ?? 'https://digdeep.fyi/';
  return buildShareUrl(base, {
    name: snapshot.queriedEmail ?? snapshot.queriedIp ?? snapshot.displayDomain,
    mode: snapshot.mode,
    types: snapshot.queryTypes,
    dkimSelectors: snapshot.customDkimSelectors,
    dohEndpoint: snapshot.dohEndpoint,
    tab: options.tab ?? defaultTab,
    focus: options.focus ?? null,
  });
}

/**
 * Builds a clean download filename for a snapshot export artifact.
 */
export function buildReportFilename(
  snapshot: AnalysisSnapshot,
  kind: 'markdown' | 'shell' | 'workflow'
): string {
  if (kind === 'workflow') {
    return 'dns-check.yml';
  }
  const rawSlug =
    snapshot.displayDomain === '.'
      ? 'root-zone'
      : (snapshot.queriedEmail ?? snapshot.queriedIp ?? snapshot.displayDomain)
          .toLowerCase()
          .replace(/[^a-z0-9.-]+/g, '-')
          .replace(/^-+|-+$/g, '');
  const slug = rawSlug || 'domain';
  const datePart = new Date(snapshot.capturedAt).toISOString().slice(0, 10);
  if (kind === 'markdown') {
    return `digdeep-${slug}-${datePart}.md`;
  }
  return `dns-check-${slug}.sh`;
}

function selectRepresentativeWireQueries(
  snapshot: AnalysisSnapshot,
  mode: WireTranscriptMode,
  maxKeyCount: number
): DohQueryLog[] {
  if (mode === 'none' || snapshot.queries.length === 0) return [];
  if (mode === 'all') return snapshot.queries;

  const picked: DohQueryLog[] = [];
  const seen = new Set<string>();
  const add = (q: DohQueryLog | undefined) => {
    if (!q || seen.has(q.id) || picked.length >= maxKeyCount) return;
    seen.add(q.id);
    picked.push(q);
  };

  // 1. Primary CD=0 validating resolver verdict query
  add(
    snapshot.queries.find(
      (q) => !q.cd && !q.ecsSubnet && !q.purpose.startsWith('Consensus probe')
    )
  );

  // 2. Any queries with SERVFAIL, NXDOMAIN on primary target, or RFC 8914 EDE codes
  for (const q of snapshot.queries) {
    if (
      q.packet.flags.rcode === 2 ||
      (q.packet.edns?.ede.length ?? 0) > 0
    ) {
      add(q);
    }
  }

  // 3. Leaf zone DS & DNSKEY queries
  const sortedZones = [...snapshot.zones].sort((a, b) => b.depth - a.depth);
  const leafZone = sortedZones[0];
  if (leafZone) {
    add(
      snapshot.queries.find(
        (q) =>
          normalizeFqdn(q.qname) === leafZone.zoneName &&
          q.qtype === RR_TYPES.DS &&
          q.cd
      )
    );
    add(
      snapshot.queries.find(
        (q) =>
          normalizeFqdn(q.qname) === leafZone.zoneName &&
          q.qtype === RR_TYPES.DNSKEY &&
          q.cd
      )
    );
  }

  // 4. Target domain primary queries (A, AAAA, MX, TXT, HTTPS, CAA, TLSA, PTR, OPENPGPKEY, SMIMEA)
  const targetNorm = normalizeFqdn(snapshot.targetName);
  for (const q of snapshot.queries) {
    if (
      normalizeFqdn(q.qname) === targetNorm ||
      q.purpose.startsWith('Target ') ||
      q.purpose.startsWith('Mail ') ||
      q.purpose.startsWith('Web ') ||
      q.purpose.startsWith('DMARC ')
    ) {
      add(q);
    }
  }

  // 5. Fill remaining slots in chronological order
  for (const q of snapshot.queries) {
    add(q);
  }

  return picked;
}

function minZoneRrsigRemainingSec(zone: ZoneAnalysis): number | null {
  let minSec: number | null = null;
  for (const rrset of zone.rrsets) {
    for (const rv of rrset.rrsigs) {
      if (minSec === null || rv.remainingSeconds < minSec) {
        minSec = rv.remainingSeconds;
      }
    }
  }
  return minSec;
}

/**
 * Generates a self-contained GitHub-Flavored Markdown (GFM) diagnostic / incident report
 * from any `AnalysisSnapshot`, ready to paste into GitHub Issues, PRs, or postmortems.
 */
export function formatSnapshotMarkdownReport(
  snapshot: AnalysisSnapshot,
  options: MarkdownReportOptions = {}
): string {
  const wireMode = options.wireTranscriptMode ?? 'key';
  const maxKeyWire = Math.max(1, options.maxKeyWireTranscripts ?? 8);
  const includeInfo = options.includeInfoFindings ?? true;
  const permalink = buildSnapshotPermalink(snapshot, {
    baseHref: options.baseHref,
    focus: options.focus,
  });

  const statusMeta = STATUS_META[snapshot.overallStatus];
  const emoji = statusEmoji(snapshot.overallStatus);
  const primaryLabel =
    snapshot.queriedEmail ?? snapshot.queriedIp ?? snapshot.displayDomain;

  const lines: string[] = [];
  lines.push(
    `# ${emoji} DNS Diagnostic Report: ${escapeInlineCode(primaryLabel)} (${statusMeta.label})`
  );
  lines.push('');
  lines.push(`> **Summary:** ${snapshot.overallSummary}`);
  lines.push('');

  // 1. Status Summary Table
  const targetCell =
    snapshot.queriedEmail || snapshot.queriedIp
      ? `${escapeInlineCode(primaryLabel)} → ${escapeInlineCode(snapshot.displayDomain)} (${escapeInlineCode(snapshot.targetName)})`
      : `${escapeInlineCode(snapshot.displayDomain)} (${escapeInlineCode(snapshot.targetName)})`;

  let resolverCell = `${escapeMdCell(formatDohShortLabel(snapshot.dohEndpoint))} (${escapeInlineCode(snapshot.dohEndpoint)})`;
  if (snapshot.resolverVerdict) {
    const rv = snapshot.resolverVerdict;
    const edePart =
      rv.ede.length > 0
        ? ` · ${rv.ede
            .map(
              (e) =>
                `EDE(${e.infoCode} ${e.name}${e.extraText ? `: ${e.extraText}` : ''})`
            )
            .join(', ')}`
        : '';
    resolverCell += ` — \`${rv.rcodeName}\` · \`AD=${rv.adBit ? '1' : '0'}\`${escapeMdCell(edePart)}`;
  }

  const capturedIso = new Date(snapshot.capturedAt).toISOString();
  const validatedIso = new Date(snapshot.validatedAt).toISOString();
  const timeNote =
    Math.abs(snapshot.validatedAt - snapshot.capturedAt) > 1000
      ? `${capturedIso} (clock override @ ${validatedIso})`
      : capturedIso;

  lines.push('| Property | Value |');
  lines.push('| :--- | :--- |');
  lines.push(`| **Target** | ${escapeMdCell(targetCell)} |`);
  lines.push(`| **Analysis Mode** | ${escapeMdCell(modeDescription(snapshot))} |`);
  lines.push(
    `| **Client WebCrypto Verdict** | **${emoji} ${escapeMdCell(statusMeta.label)}** |`
  );
  lines.push(`| **Upstream Resolver (\`CD=0\`)** | ${resolverCell} |`);
  lines.push(
    `| **Captured (UTC)** | \`${timeNote}\` (${snapshot.queries.length} DoH queries, ${snapshot.durationMs} ms) |`
  );
  if (snapshot.note) {
    lines.push(`| **Note** | ${escapeMdCell(snapshot.note)} |`);
  }
  lines.push(
    `| **Interactive Trace** | [Open live trace in DigDeep (\`digdeep.fyi\`)](${permalink}) |`
  );
  lines.push('');

  // 2. Key Audit Findings
  const severityOrder: Record<AuditFinding['severity'], number> = {
    error: 0,
    warning: 1,
    info: 2,
  };
  const visibleFindings = snapshot.findings
    .filter((f) => includeInfo || f.severity !== 'info')
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const errorCount = snapshot.findings.filter((f) => f.severity === 'error').length;
  const warnCount = snapshot.findings.filter((f) => f.severity === 'warning').length;
  const infoCount = snapshot.findings.filter((f) => f.severity === 'info').length;

  lines.push(
    `## Audit Findings (${errorCount} error${errorCount === 1 ? '' : 's'}, ${warnCount} warning${warnCount === 1 ? '' : 's'}, ${infoCount} notice${infoCount === 1 ? '' : 's'})`
  );
  lines.push('');

  if (visibleFindings.length === 0) {
    lines.push(
      '✅ **No errors or warnings detected.** All cryptographic signatures, delegation digests, and RFC best-practice checks passed.'
    );
    lines.push('');
  } else {
    lines.push('| Severity | Code & RFC | Zone | Finding |');
    lines.push('| :--- | :--- | :--- | :--- |');
    for (const f of visibleFindings) {
      const sevBadge =
        f.severity === 'error'
          ? '🔴 **ERROR**'
          : f.severity === 'warning'
            ? '🟡 **WARN**'
            : '🔵 **INFO**';
      const codeCell = f.rfc
        ? `${escapeInlineCode(f.code)} (${escapeMdCell(f.rfc)})`
        : escapeInlineCode(f.code);
      const zoneCell = f.zone ? escapeInlineCode(f.zone) : '—';
      const detailCell = `**${escapeMdCell(f.title)}** — ${escapeMdCell(f.detail)}`;
      lines.push(`| ${sevBadge} | ${codeCell} | ${zoneCell} | ${detailCell} |`);
    }
    lines.push('');
  }

  // 3. DNSSEC Zone / DS / DNSKEY Chain Table
  if (snapshot.zones.length > 0) {
    lines.push('## DNSSEC Chain of Trust');
    lines.push('');
    lines.push(
      '| Zone | Status | NSEC Mode | Delegation / Trust Anchor | Active `DNSKEY`s | Min `RRSIG` Lifetime | Detail |'
    );
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |');

    const orderedZones = [...snapshot.zones].sort((a, b) => a.depth - b.depth);
    for (const z of orderedZones) {
      const zMeta = STATUS_META[z.status];
      let dsOrTa = '—';
      if (z.trustAnchorMatches.length > 0) {
        dsOrTa = z.trustAnchorMatches
          .map(
            (ta) =>
              `TA \`#${ta.keyTag}\` (${ta.matched ? '✓ matched' : '✗ mismatch'})`
          )
          .join(', ');
      } else if (z.dsVerifications.length > 0) {
        dsOrTa = z.dsVerifications
          .map(
            (d) =>
              `DS \`#${d.ds.keyTag}\` ${formatDigestType(d.ds.digestType)} (${d.digestValid && d.targetKeyFound ? '✓' : '✗'})`
          )
          .join(', ');
      } else if (z.insecureDelegationProof) {
        dsOrTa = `No DS (${z.insecureDelegationProof.protocol} ${z.insecureDelegationProof.valid ? '✓ proven unsigned' : '✗ unverified'})`;
      }

      const activeKeys = z.dnskeys.filter(
        (k) => k.role !== 'standby' && !k.isRevoked
      );
      const keysCell =
        activeKeys.length > 0
          ? activeKeys
              .map(
                (k) =>
                  `\`#${k.keyTag}\` ${k.role.toUpperCase()} (${formatAlgorithm(k.algorithm)})`
              )
              .join(', ')
          : z.dnskeys.length > 0
            ? `${z.dnskeys.length} key(s)`
            : '—';

      const minRemSec = minZoneRrsigRemainingSec(z);
      const rrsigCell =
        minRemSec !== null ? `\`${formatDurationShort(minRemSec)}\`` : '—';

      lines.push(
        `| ${escapeInlineCode(z.zoneName)} | **${escapeMdCell(zMeta.label)}** | \`${z.nsecMode}\` | ${escapeMdCell(dsOrTa)} | ${escapeMdCell(keysCell)} | ${rrsigCell} | ${escapeMdCell(z.statusReason)} |`
      );
    }
    lines.push('');

    if (snapshot.cnameEdges.length > 0) {
      const chainText = snapshot.cnameEdges
        .map((e) => `${escapeInlineCode(e.fromName)} → ${escapeInlineCode(e.toName)}`)
        .join(', ');
      lines.push(`**CNAME Chain:** ${chainText}`);
      lines.push('');
    }
  }

  // 4a. Mail, SMTP DANE, SPF, DKIM & DMARC Highlights
  if (snapshot.mailAnalysis) {
    const m = snapshot.mailAnalysis;
    lines.push('## Mail, SMTP DANE, SPF, DKIM & DMARC Summary');
    lines.push('');
    lines.push('| Control | Status / Verdict | Details |');
    lines.push('| :--- | :--- | :--- |');
    lines.push(
      `| **MX & Transport** | \`${m.mxStatus.toUpperCase()}\` (DNSSEC: \`${m.mxDnssecStatus.toUpperCase()}\`) | ${
        m.mxHosts.length > 0
          ? escapeMdCell(
              m.mxHosts
                .map((mx) =>
                  mx.isNullMx
                    ? '0 . (Null MX — RFC 7505)'
                    : `${mx.preference} ${mx.displayExchange} [DANE: ${mx.dane.status}]`
                )
                .join('; ')
            )
          : 'No MX records'
      } |`
    );
    lines.push(
      `| **SMTP DANE (\`_25._tcp\`)** | \`${m.daneStatus.toUpperCase()}\` | ${escapeMdCell(m.daneSummary)} |`
    );
    lines.push(
      `| **SPF (RFC 7208)** | \`${m.spf.verdict.toUpperCase()}\` (\`${m.spf.dnsLookupCount}/${m.spf.dnsLookupLimit}\` lookups) | ${escapeMdCell(m.spf.summary)}${m.spf.rawRecord ? ` — ${escapeInlineCode(m.spf.rawRecord)}` : ''} |`
    );
    lines.push(
      `| **DMARC (RFC 7489)** | \`${m.dmarc.verdict.toUpperCase()}\`${m.dmarc.policy ? ` (\`p=${m.dmarc.policy}\`)` : ''} | ${escapeMdCell(m.dmarc.summary)} |`
    );
    lines.push(
      `| **DKIM (RFC 6376)** | \`${m.dkim.status.toUpperCase()}\` | ${escapeMdCell(m.dkim.summary)} |`
    );
    lines.push(
      `| **MTA-STS & TLS-RPT** | STS: \`${m.mtaSts.status.toUpperCase()}\` · TLS-RPT: \`${m.tlsRpt.status.toUpperCase()}\` | ${escapeMdCell(m.mtaSts.summary)} |`
    );
    lines.push('');
  }

  // 4b. Web, HTTPS/SVCB, TLS ECH, CAA & DANE Highlights
  if (snapshot.webAnalysis) {
    const w = snapshot.webAnalysis;
    lines.push('## Web, HTTPS/SVCB, ECH, CAA & DANE Summary');
    lines.push('');
    lines.push('| Control | Status / Verdict | Details |');
    lines.push('| :--- | :--- | :--- |');
    lines.push(
      `| **A / AAAA Addresses** | DNSSEC: \`${w.addressDnssecStatus.toUpperCase()}\` | IPv4: ${w.ipv4Addresses.length > 0 ? w.ipv4Addresses.map((ip) => `\`${ip}\``).join(', ') : 'none'} · IPv6: ${w.ipv6Addresses.length > 0 ? w.ipv6Addresses.map((ip) => `\`${ip}\``).join(', ') : 'none'} |`
    );
    lines.push(
      `| **HTTPS / SVCB & ECH** | \`${w.httpsStatus.toUpperCase()}\` (H3: \`${w.supportsHttp3 ? 'yes' : 'no'}\`, ECH: \`${w.echEnabled ? 'enabled' : 'no'}\`) | ${escapeMdCell(w.httpsSummary)} |`
    );
    lines.push(
      `| **CAA Policy (RFC 8659)** | \`${w.caa.status.toUpperCase()}\` | ${escapeMdCell(w.caa.summary)} |`
    );
    lines.push(
      `| **Web DANE (\`_443._tcp\`)** | \`${w.webDane.status.toUpperCase()}\` | ${escapeMdCell(w.webDane.summary)} |`
    );
    if (w.ctAnalysis && w.ctAnalysis.status !== 'unavailable') {
      lines.push(
        `| **CT Log Cross-Check** | \`${w.ctAnalysis.status.toUpperCase()}\` | ${escapeMdCell(w.ctAnalysis.summary)} |`
      );
    }
    lines.push('');
  }

  // 4c. Multi-Resolver DoH Consensus, RFC 8914 EDE & RFC 7871 ECS Highlights
  if (snapshot.consensusAnalysis) {
    const c = snapshot.consensusAnalysis;
    lines.push('## Multi-Resolver DoH Consensus, EDE & ECS GeoDNS');
    lines.push('');
    lines.push(
      `**Consensus Verdict:** \`${c.overallVerdict.toUpperCase()}\` — ${c.summary}`
    );
    lines.push('');
    lines.push(
      '| Resolver | Role | RCODE | AD | Classification | SOA Serial | DS Tags | EDE / Answers |'
    );
    lines.push('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |');
    for (const r of c.resolvers) {
      const edeOrAns =
        r.ede.length > 0
          ? r.ede
              .map(
                (e) =>
                  `EDE(${e.infoCode} ${e.name}${e.extraText ? `: ${e.extraText}` : ''})`
              )
              .join('; ')
          : !r.reachable
            ? r.error ?? 'unreachable'
            : [...r.ipv4Answers, ...r.ipv6Answers].slice(0, 3).join(', ') || r.summary;
      const dsTags =
        r.dsKeyTags.length > 0 ? r.dsKeyTags.map((t) => `#${t}`).join(', ') : '—';
      lines.push(
        `| **${escapeMdCell(r.shortLabel)}** | \`${r.role}\` | \`${r.reachable ? r.rcodeName : 'ERR'}\` | \`${r.adBit ? '1' : '0'}\` | \`${r.classification}\` | ${r.soaSerial !== undefined ? `\`${r.soaSerial}\`` : '—'} | ${escapeMdCell(dsTags)} | ${escapeMdCell(edeOrAns)} |`
      );
    }
    lines.push('');

    if (c.edeHighlights.length > 0) {
      lines.push('### RFC 8914 Extended DNS Error (EDE) Highlights');
      lines.push('');
      for (const h of c.edeHighlights) {
        lines.push(
          `- **${escapeMdCell(h.resolverLabel)}**: \`EDE(${h.infoCode} ${h.name})\` [${h.category}]${h.extraText ? ` — ${escapeMdCell(h.extraText)}` : ''}`
        );
      }
      lines.push('');
    }

    if (c.ecsGeo) {
      const eg = c.ecsGeo;
      lines.push('### RFC 7871 EDNS Client Subnet (ECS) Geo-Steering');
      lines.push('');
      lines.push(
        `- **Steering Model:** \`${eg.steeringModel}\` via ${escapeMdCell(eg.ecsEndpointLabel)} (${eg.uniqueIpv4PoolCount} IPv4 pool(s), ${eg.uniqueIpv6PoolCount} IPv6 pool(s), opt-out \`/0\` honored: \`${eg.optOutHonored ? 'yes' : 'no'}\`)`
      );
      lines.push(`- **Summary:** ${eg.summary}`);
      lines.push('');
    }
  }

  // 4d. Reverse DNS / BGP RPKI & Email DANE Highlights
  if (snapshot.reverseDns) {
    const rd = snapshot.reverseDns;
    lines.push('## Reverse DNS, FCrDNS & BGP RPKI');
    lines.push('');
    lines.push(
      `- **IP / Reverse Zone:** \`${rd.ip}\` → \`${rd.arpaFqdn}\` (\`${rd.ptrStatus.toUpperCase()}\`, DNSSEC: \`${rd.ptrDnssecStatus.toUpperCase()}\`)`
    );
    lines.push(`- **FCrDNS:** \`${rd.fcrdnsStatus.toUpperCase()}\` — ${rd.fcrdnsSummary}`);
    if (rd.bgp) {
      const asnStr = rd.bgp.asns
        .map((a) => `AS${a.asn}${a.asName ? ` (${a.asName})` : ''}`)
        .join(', ');
      const rpkiStr = rd.bgp.rpki ? ` · RPKI: \`${rd.bgp.rpki.status.toUpperCase()}\`` : '';
      lines.push(
        `- **BGP Origin:** ${asnStr || 'unknown'}${rd.bgp.bgpPrefix ? ` (${rd.bgp.bgpPrefix})` : ''}${rpkiStr}`
      );
    }
    lines.push('');
  }

  if (snapshot.emailDane) {
    const ed = snapshot.emailDane;
    lines.push('## Email DANE Identity (RFC 7929 OPENPGPKEY / RFC 8162 SMIMEA)');
    lines.push('');
    lines.push(`- **Summary:** ${ed.summary}`);
    if (ed.openpgpkey) {
      lines.push(
        `- **OPENPGPKEY:** \`${ed.openpgpkey.status.toUpperCase()}\` (DNSSEC: \`${ed.openpgpkey.dnssecStatus.toUpperCase()}\`, DANE usable: \`${ed.openpgpkey.daneUsable ? 'yes' : 'no'}\`) at ${escapeInlineCode(ed.openpgpkey.queriedOwner)}`
      );
    }
    if (ed.smimea) {
      lines.push(
        `- **SMIMEA:** \`${ed.smimea.status.toUpperCase()}\` (DNSSEC: \`${ed.smimea.dnssecStatus.toUpperCase()}\`, DANE usable: \`${ed.smimea.daneUsable ? 'yes' : 'no'}\`) at ${escapeInlineCode(ed.smimea.queriedOwner)}`
      );
    }
    lines.push('');
  }

  // 5. CLI Reproducer Commands
  const primaryQtype = snapshot.queryTypes[0] ?? 'A';
  const cli = generateCliReproducerCommands({
    qname: snapshot.targetName,
    qtypeName: primaryQtype,
    dohEndpoint: snapshot.dohEndpoint,
    validatedAt: snapshot.validatedAt,
    capturedAt: snapshot.capturedAt,
  });
  lines.push('## CLI Reproducer Commands');
  lines.push('');
  lines.push(formatCodeFence(`${cli.delv}\n${cli.dig}`, 'sh'));
  lines.push('');

  // 6. Collapsible <details> dig Wire Transcripts
  const selectedQueries = selectRepresentativeWireQueries(
    snapshot,
    wireMode,
    maxKeyWire
  );
  if (selectedQueries.length > 0) {
    const headerCountNote =
      selectedQueries.length < snapshot.queries.length
        ? `${selectedQueries.length} of ${snapshot.queries.length} DoH packets`
        : `${selectedQueries.length} DoH packet${selectedQueries.length === 1 ? '' : 's'}`;
    lines.push(`## DoH Wire Transcripts (${headerCountNote})`);
    lines.push('');

    for (const q of selectedQueries) {
      const rcodeStr =
        q.packet.flags.rcode === 0
          ? 'NOERROR'
          : q.packet.flags.rcode === 2
            ? 'SERVFAIL'
            : q.packet.flags.rcode === 3
              ? 'NXDOMAIN'
              : `RCODE=${q.packet.flags.rcode}`;
      const flagTags = [
        rcodeStr,
        q.packet.flags.ad ? 'AD=1' : 'AD=0',
        q.cd ? 'CD=1' : 'CD=0',
        `${q.packet.answers.length} ans`,
        `${q.latencyMs}ms`,
      ];
      if (q.ecsSubnet) {
        flagTags.push(`ECS=${q.ecsSubnet}`);
      }
      for (const ede of q.packet.edns?.ede ?? []) {
        flagTags.push(`EDE=${ede.infoCode}`);
      }
      const summaryLabel = `${q.qname} ${q.qtypeName} (${flagTags.join(' · ')}) — ${q.purpose}`;
      lines.push('<details>');
      lines.push(`<summary><code>${escapeHtmlText(summaryLabel)}</code></summary>`);
      lines.push('');
      lines.push(formatCodeFence(formatPacketAsDig(q), 'dns'));
      lines.push('</details>');
      lines.push('');
    }
  }

  lines.push('---');
  lines.push(
    `*Generated client-side by [DigDeep](${permalink}) — WebCrypto DNSSEC, DANE, SPF, DKIM, DMARC & DoH Wire Analyzer.*`
  );
  return `${lines.join('\n')}\n`;
}

/**
 * Extracts snapshot-tailored DNSSEC, DS, RRSIG, CAA, SPF, DMARC, and DANE TLSA invariants
 * for CI regression check generation.
 */
export function extractSnapshotCiInvariants(
  snapshot: AnalysisSnapshot,
  options: CiCheckGeneratorOptions = {}
): SnapshotCiInvariants {
  const targetFqdn = normalizeFqdn(snapshot.targetName);
  const targetDomain =
    targetFqdn === '.' ? '.' : displayFqdn(targetFqdn);

  // Determine primary query type
  let primaryQueryType = snapshot.queryTypes[0] ?? 'A';
  if (snapshot.reverseDns || snapshot.queryTypes.includes('PTR')) {
    primaryQueryType = 'PTR';
  } else if (snapshot.mode === 'mail') {
    primaryQueryType = 'MX';
  } else if (snapshot.emailDane) {
    if (snapshot.emailDane.openpgpkey?.status === 'present') {
      primaryQueryType = 'OPENPGPKEY';
    } else if (snapshot.emailDane.smimea?.status === 'present') {
      primaryQueryType = 'SMIMEA';
    }
  } else {
    const answeredType = snapshot.queryTypes.find((qt) =>
      snapshot.queries.some(
        (q) =>
          normalizeFqdn(q.qname) === targetFqdn &&
          q.qtypeName.toUpperCase() === qt.toUpperCase() &&
          q.packet.flags.rcode === 0 &&
          q.packet.answers.length > 0
      )
    );
    if (answeredType) {
      primaryQueryType = answeredType.toUpperCase();
    }
  }

  const cli = generateCliReproducerCommands({
    qname: targetFqdn,
    qtypeName: primaryQueryType,
    dohEndpoint: snapshot.dohEndpoint,
  });
  const defaultResolver =
    options.resolver?.trim() ||
    (KNOWN_UDP_DNS_HOSTS.has(cli.resolverIpOrHost)
      ? cli.resolverIpOrHost
      : '1.1.1.1');

  const permalink = buildSnapshotPermalink(snapshot, {
    baseHref: options.baseHref,
  });

  // Leaf zone & DNSSEC state
  const sortedZones = [...snapshot.zones].sort((a, b) => b.depth - a.depth);
  const leafZone = sortedZones[0] ?? null;

  const expectDnssecAd = Boolean(
    leafZone
      ? leafZone.status === 'secure' ||
          leafZone.status === 'warning' ||
          leafZone.status === 'bogus'
      : snapshot.resolverVerdict?.adBit
  );

  const signedZone =
    expectDnssecAd && leafZone
      ? leafZone.zoneName === '.'
        ? '.'
        : displayFqdn(leafZone.zoneName)
      : expectDnssecAd
        ? targetDomain
        : null;

  // Parent DS key tags
  let expectedDsKeyTags: number[] = [];
  if (leafZone && leafZone.zoneName !== '.') {
    const validTags = leafZone.dsVerifications
      .filter((d) => d.digestValid && d.targetKeyFound)
      .map((d) => d.ds.keyTag);
    const rawTags =
      validTags.length > 0
        ? validTags
        : leafZone.dsVerifications.map((d) => d.ds.keyTag);
    expectedDsKeyTags = Array.from(new Set(rawTags)).sort((a, b) => a - b);
  }

  // Minimum observed RRSIG remaining lifetime across leaf/signed zones
  let minPositiveRrsigSec: number | null = null;
  for (const z of sortedZones) {
    if (z.zoneName === '.' && sortedZones.length > 1) continue;
    for (const rrset of z.rrsets) {
      for (const rv of rrset.rrsigs) {
        if (rv.cryptoValid && rv.timeValid && rv.remainingSeconds > 0) {
          if (
            minPositiveRrsigSec === null ||
            rv.remainingSeconds < minPositiveRrsigSec
          ) {
            minPositiveRrsigSec = rv.remainingSeconds;
          }
        }
      }
    }
    if (minPositiveRrsigSec !== null) break;
  }

  const minObservedRrsigHours =
    minPositiveRrsigSec !== null ? Math.floor(minPositiveRrsigSec / 3600) : null;

  let recommendedMinRrsigHours = 24;
  if (options.minRrsigHours !== undefined && Number.isFinite(options.minRrsigHours)) {
    recommendedMinRrsigHours = Math.max(1, Math.round(options.minRrsigHours));
  } else if (minObservedRrsigHours !== null) {
    if (minObservedRrsigHours >= 168) {
      recommendedMinRrsigHours = 72;
    } else if (minObservedRrsigHours >= 48) {
      recommendedMinRrsigHours = 24;
    } else if (minObservedRrsigHours >= 16) {
      recommendedMinRrsigHours = 12;
    } else if (minObservedRrsigHours >= 4) {
      recommendedMinRrsigHours = 2;
    } else {
      recommendedMinRrsigHours = 1;
    }
  }

  // CAA invariant
  let caaCheck: SnapshotCiInvariants['caaCheck'] = null;
  if (
    snapshot.webAnalysis &&
    (snapshot.webAnalysis.caa.status === 'enforced' ||
      snapshot.webAnalysis.caa.status === 'inherited')
  ) {
    const rawIssues = snapshot.webAnalysis.caa.issueCas
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
    const nonDeny = Array.from(new Set(rawIssues.filter((s) => s !== ';')));
    const explicitDenyAll = nonDeny.length === 0 && rawIssues.includes(';');
    if (nonDeny.length > 0 || explicitDenyAll) {
      caaCheck = {
        owner: displayFqdn(
          snapshot.webAnalysis.caa.effectiveOwner ?? snapshot.targetName
        ),
        expectedIssueCas: nonDeny,
        explicitDenyAll,
      };
    }
  } else {
    // Fallback: inspect CAA RRsets in snapshot.zones
    for (const z of sortedZones) {
      const caaRrset = z.rrsets.find(
        (rr) => rr.type === RR_TYPES.CAA && rr.records.length > 0
      );
      if (caaRrset) {
        const cas: string[] = [];
        let sawEmptyDeny = false;
        for (const rec of caaRrset.records) {
          if (rec.parsed.kind === 'CAA' && rec.parsed.tag.toLowerCase() === 'issue') {
            const caDom = rec.parsed.value.split(';')[0].trim().toLowerCase();
            if (caDom) cas.push(caDom);
            else sawEmptyDeny = true;
          }
        }
        const uniqueCas = Array.from(new Set(cas));
        if (uniqueCas.length > 0 || sawEmptyDeny) {
          caaCheck = {
            owner: displayFqdn(caaRrset.name),
            expectedIssueCas: uniqueCas,
            explicitDenyAll: uniqueCas.length === 0 && sawEmptyDeny,
          };
        }
        break;
      }
    }
  }

  // SPF invariant
  let spfCheck: SnapshotCiInvariants['spfCheck'] = null;
  if (snapshot.mailAnalysis?.spf.present) {
    const q = snapshot.mailAnalysis.spf.effectiveAllQualifier;
    spfCheck = {
      owner: targetDomain,
      maxDnsLookups: snapshot.mailAnalysis.spf.dnsLookupLimit || 10,
      observedLookups: snapshot.mailAnalysis.spf.dnsLookupCount,
      expectedAllToken: q === '-' ? '-all' : q === '~' ? '~all' : null,
    };
  } else {
    // Fallback: inspect apex TXT records for v=spf1
    for (const z of sortedZones) {
      for (const rr of z.rrsets) {
        if (normalizeFqdn(rr.name) === targetFqdn && rr.type === RR_TYPES.TXT) {
          for (const rec of rr.records) {
            if (
              rec.parsed.kind === 'TXT' &&
              /^v=spf1(\s|$)/i.test(rec.parsed.joinedText.trim())
            ) {
              const txt = rec.parsed.joinedText.trim();
              const allMatch = /(?:^|\s)([-~])all(?:\s|$)/i.exec(txt);
              spfCheck = {
                owner: targetDomain,
                maxDnsLookups: 10,
                expectedAllToken: allMatch
                  ? (`${allMatch[1]}all`.toLowerCase() as '-all' | '~all')
                  : null,
              };
              break;
            }
          }
        }
      }
      if (spfCheck) break;
    }
  }

  // DMARC invariant
  let dmarcCheck: SnapshotCiInvariants['dmarcCheck'] = null;
  if (snapshot.mailAnalysis?.dmarc.present && snapshot.mailAnalysis.dmarc.policy) {
    dmarcCheck = {
      owner: displayFqdn(snapshot.mailAnalysis.dmarc.effectiveOwner),
      expectedPolicy: snapshot.mailAnalysis.dmarc.policy,
    };
  } else if (targetFqdn !== '.') {
    const dmarcQname = `_dmarc.${targetFqdn}`;
    for (const q of snapshot.queries) {
      if (normalizeFqdn(q.qname) === dmarcQname && q.qtype === RR_TYPES.TXT) {
        for (const ans of q.packet.answers) {
          if (
            ans.parsed.kind === 'TXT' &&
            /^v=DMARC1\s*;/i.test(ans.parsed.joinedText.trim())
          ) {
            const pMatch = /;\s*p\s*=\s*(reject|quarantine|none)\b/i.exec(
              ans.parsed.joinedText
            );
            if (pMatch) {
              dmarcCheck = {
                owner: displayFqdn(dmarcQname),
                expectedPolicy: pMatch[1].toLowerCase() as
                  | 'reject'
                  | 'quarantine'
                  | 'none',
              };
              break;
            }
          }
        }
      }
      if (dmarcCheck) break;
    }
  }

  // DANE TLSA / OPENPGPKEY / SMIMEA invariants
  const tlsaChecks: CiTlsaInvariant[] = [];
  const seenTlsa = new Set<string>();
  const addTlsa = (entry: CiTlsaInvariant) => {
    const key = `${entry.owner.toLowerCase()}|${entry.rrtype}`;
    if (seenTlsa.has(key)) return;
    seenTlsa.add(key);
    tlsaChecks.push(entry);
  };

  if (snapshot.mailAnalysis) {
    for (const mx of snapshot.mailAnalysis.mxHosts) {
      if (mx.dane.records.length > 0) {
        addTlsa({
          owner: displayFqdn(mx.dane.resolvedOwner || mx.dane.qname),
          rrtype: 'TLSA',
          requireDnssecAd:
            mx.dane.dnssecStatus === 'secure' ||
            mx.dane.dnssecStatus === 'warning' ||
            mx.dane.dnssecStatus === 'bogus',
          label: `SMTP DANE (${mx.displayExchange})`,
        });
      }
    }
  }

  if (snapshot.webAnalysis && snapshot.webAnalysis.webDane.records.length > 0) {
    addTlsa({
      owner: displayFqdn(
        snapshot.webAnalysis.webDane.resolvedOwner ||
          snapshot.webAnalysis.webDane.qname
      ),
      rrtype: 'TLSA',
      requireDnssecAd:
        snapshot.webAnalysis.webDane.dnssecStatus !== 'insecure',
      label: 'HTTPS/443 DANE',
    });
  }

  if (snapshot.emailDane) {
    if (snapshot.emailDane.openpgpkey?.status === 'present') {
      addTlsa({
        owner: displayFqdn(
          snapshot.emailDane.openpgpkey.resolvedOwner ||
            snapshot.emailDane.openpgpkey.queriedOwner
        ),
        rrtype: 'OPENPGPKEY',
        requireDnssecAd: snapshot.emailDane.openpgpkey.daneUsable,
        label: 'RFC 7929 OPENPGPKEY',
      });
    }
    if (snapshot.emailDane.smimea?.status === 'present') {
      addTlsa({
        owner: displayFqdn(
          snapshot.emailDane.smimea.resolvedOwner ||
            snapshot.emailDane.smimea.queriedOwner
        ),
        rrtype: 'SMIMEA',
        requireDnssecAd: snapshot.emailDane.smimea.daneUsable,
        label: 'RFC 8162 SMIMEA',
      });
    }
  }

  for (const z of sortedZones) {
    for (const rr of z.rrsets) {
      if (rr.type === RR_TYPES.TLSA && rr.records.length > 0) {
        addTlsa({
          owner: displayFqdn(rr.name),
          rrtype: 'TLSA',
          requireDnssecAd: rr.status !== 'insecure',
          label: `DANE TLSA (${displayFqdn(rr.name)})`,
        });
      }
    }
  }

  // Build concise UI summary badges
  const badges: CiInvariantBadge[] = [];
  if (expectDnssecAd) {
    badges.push({
      id: 'dnssec-ad',
      label: 'DNSSEC AD=1 & delv',
      detail: `Asserts NOERROR + AD=1 and delv cryptographic validation for ${targetDomain} ${primaryQueryType}`,
    });
  } else {
    badges.push({
      id: 'dns-noerror',
      label: `${primaryQueryType} Resolution`,
      detail: `Asserts NOERROR resolution for ${targetDomain} ${primaryQueryType} (DNSSEC currently unsigned)`,
    });
  }

  if (expectedDsKeyTags.length > 0 && signedZone && signedZone !== '.') {
    badges.push({
      id: 'ds-tags',
      label: `DS Key Tags (${expectedDsKeyTags.map((t) => `#${t}`).join(', ')})`,
      detail: `Asserts parent DS RRset for ${signedZone} publishes key tag(s) ${expectedDsKeyTags.join(', ')}`,
    });
  }

  if (expectDnssecAd && signedZone) {
    badges.push({
      id: 'rrsig-lifetime',
      label: `RRSIG >= ${recommendedMinRrsigHours}h`,
      detail: `Asserts ${signedZone} SOA & DNSKEY RRSIG remaining validity >= ${recommendedMinRrsigHours} hours`,
    });
  }

  if (caaCheck) {
    badges.push({
      id: 'caa',
      label: caaCheck.explicitDenyAll
        ? 'CAA (Deny All)'
        : `CAA (${caaCheck.expectedIssueCas.length} issuer${caaCheck.expectedIssueCas.length === 1 ? '' : 's'})`,
      detail: caaCheck.explicitDenyAll
        ? `Asserts CAA at ${caaCheck.owner} enforces explicit ";" deny-all`
        : `Asserts CAA at ${caaCheck.owner} authorizes ${caaCheck.expectedIssueCas.join(', ')}`,
    });
  }

  if (spfCheck) {
    badges.push({
      id: 'spf',
      label: `SPF <= ${spfCheck.maxDnsLookups} Lookups${spfCheck.expectedAllToken ? ` (${spfCheck.expectedAllToken})` : ''}`,
      detail: `Walks include/redirect mechanisms live and enforces RFC 7208 <= ${spfCheck.maxDnsLookups} DNS lookups`,
    });
  }

  if (dmarcCheck) {
    badges.push({
      id: 'dmarc',
      label: `DMARC (p=${dmarcCheck.expectedPolicy})`,
      detail: `Asserts ${dmarcCheck.owner} publishes v=DMARC1 with p=${dmarcCheck.expectedPolicy}`,
    });
  }

  if (tlsaChecks.length > 0) {
    badges.push({
      id: 'dane-tlsa',
      label: `DANE (${tlsaChecks.length} endpoint${tlsaChecks.length === 1 ? '' : 's'})`,
      detail: tlsaChecks.map((t) => `${t.label}: ${t.owner} ${t.rrtype}`).join('; '),
    });
  }

  return {
    targetDomain,
    targetFqdn,
    primaryQueryType,
    defaultResolver,
    permalink,
    expectDnssecAd,
    signedZone,
    expectedDsKeyTags,
    minObservedRrsigHours,
    recommendedMinRrsigHours,
    caaCheck,
    spfCheck,
    dmarcCheck,
    tlsaChecks,
    badges,
  };
}

/**
 * Generates a zero-dependency POSIX `sh` DNSSEC / DANE / CAA / SPF / DMARC regression check
 * script tailored to the security invariants observed in an `AnalysisSnapshot`.
 */
export function generateSnapshotCiScript(
  snapshot: AnalysisSnapshot,
  options: CiCheckGeneratorOptions = {}
): string {
  const inv = extractSnapshotCiInvariants(snapshot, options);
  const capturedIso = new Date(snapshot.capturedAt).toISOString();

  const lines: string[] = [];
  lines.push('#!/usr/bin/env sh');
  lines.push('# ==============================================================================');
  lines.push(`# DigDeep DNSSEC / DANE / Policy CI Regression Check — ${inv.targetDomain}`);
  lines.push(`# Baseline captured: ${capturedIso}`);
  lines.push(`# Interactive trace: ${inv.permalink}`);
  lines.push('# Dependencies: POSIX sh, dig (bind9-dnsutils), awk, grep, tr, date; optional delv');
  lines.push('# ==============================================================================');
  lines.push('set -eu');
  lines.push('');
  lines.push(`DOMAIN=${shellSingleQuote(inv.targetDomain)}`);
  lines.push(`PRIMARY_QTYPE=${shellSingleQuote(inv.primaryQueryType)}`);
  lines.push(`RESOLVER="\${RESOLVER:-${inv.defaultResolver.replace(/[^a-zA-Z0-9.:_-]/g, '') || '1.1.1.1'}}"`);
  lines.push(`MIN_RRSIG_HOURS="\${MIN_RRSIG_HOURS:-${inv.recommendedMinRrsigHours}}"`);
  lines.push(`SKIP_DELV="\${SKIP_DELV:-0}"`);
  lines.push(`DIGDEEP_URL=${shellSingleQuote(inv.permalink)}`);
  lines.push('');
  lines.push('PASS_COUNT=0');
  lines.push('FAIL_COUNT=0');
  lines.push('');
  lines.push('if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then');
  lines.push('  {');
  lines.push('    printf \'### DNS Security Regression Check: `%s`\\n\\n\' "$DOMAIN"');
  lines.push('    printf \'| Result | Invariant | Detail |\\n\'');
  lines.push('    printf \'| :--- | :--- | :--- |\\n\'');
  lines.push('  } >> "$GITHUB_STEP_SUMMARY"');
  lines.push('fi');
  lines.push('');
  lines.push('record_pass() {');
  lines.push('  PASS_COUNT=$((PASS_COUNT + 1))');
  lines.push('  printf \'[PASS] %s — %s\\n\' "$1" "$2"');
  lines.push('  [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf \'| ✅ PASS | %s | %s |\\n\' "$1" "$2" >> "$GITHUB_STEP_SUMMARY"');
  lines.push('}');
  lines.push('');
  lines.push('record_fail() {');
  lines.push('  FAIL_COUNT=$((FAIL_COUNT + 1))');
  lines.push('  printf \'[FAIL] %s — %s\\n\' "$1" "$2" >&2');
  lines.push('  [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf \'| ❌ FAIL | %s | %s |\\n\' "$1" "$2" >> "$GITHUB_STEP_SUMMARY"');
  lines.push('}');
  lines.push('');
  lines.push('if ! command -v dig >/dev/null 2>&1; then');
  lines.push('  echo "Error: \'dig\' is required (install bind9-dnsutils / dnsutils)." >&2');
  lines.push('  exit 2');
  lines.push('fi');
  lines.push('');

  // Core helpers
  lines.push('# Assert NOERROR resolution (and AD=1 authenticated data bit when expected)');
  lines.push('check_resolution() {');
  lines.push('  _qname="$1"');
  lines.push('  _qtype="$2"');
  lines.push('  _require_ad="$3"');
  lines.push('  _out=$(dig +dnssec +noall +comments +answer @"$RESOLVER" "$_qname" "$_qtype" 2>&1) || {');
  lines.push('    record_fail "DNS Resolution ($_qname $_qtype)" "dig query to @$RESOLVER failed"');
  lines.push('    return');
  lines.push('  }');
  lines.push('  if ! printf \'%s\\n\' "$_out" | grep -q "status: NOERROR"; then');
  lines.push('    _st=$(printf \'%s\\n\' "$_out" | sed -n \'s/.*status: \\([A-Z0-9_]*\\).*/\\1/p\' | head -n 1)');
  lines.push('    record_fail "DNS Resolution ($_qname $_qtype)" "Expected status NOERROR, got ${_st:-UNKNOWN}"');
  lines.push('    return');
  lines.push('  fi');
  lines.push('  if [ "$_require_ad" = "1" ]; then');
  lines.push('    if printf \'%s\\n\' "$_out" | grep -Eq "^;; flags:.* ad[ ;]"; then');
  lines.push('      record_pass "DNSSEC AD=1 ($_qname $_qtype)" "Validated NOERROR with AD=1 via @$RESOLVER"');
  lines.push('    else');
  lines.push('      record_fail "DNSSEC AD=1 ($_qname $_qtype)" "Missing Authenticated Data (ad) flag from @$RESOLVER"');
  lines.push('    fi');
  lines.push('  else');
  lines.push('    record_pass "DNS Resolution ($_qname $_qtype)" "Resolved NOERROR via @$RESOLVER"');
  lines.push('  fi');
  lines.push('}');
  lines.push('');

  if (inv.expectDnssecAd) {
    lines.push('# Cryptographic chain-of-trust verification via ISC delv (when installed)');
    lines.push('check_delv_validation() {');
    lines.push('  _qname="$1"');
    lines.push('  _qtype="$2"');
    lines.push('  if [ "$SKIP_DELV" = "1" ] || ! command -v delv >/dev/null 2>&1; then');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  _delv_out=$(delv @"$RESOLVER" "$_qname" "$_qtype" 2>&1 || true)');
    lines.push('  if printf \'%s\\n\' "$_delv_out" | grep -q "^; fully validated"; then');
    lines.push('    record_pass "ISC delv Chain ($_qname $_qtype)" "delv confirmed full DNSSEC chain of trust"');
    lines.push('  else');
    lines.push('    _reason=$(printf \'%s\\n\' "$_delv_out" | grep -E "^;; resolution failed|^; unsigned" | head -n 1)');
    lines.push('    record_fail "ISC delv Chain ($_qname $_qtype)" "delv did not report fully validated (${_reason:-check output})"');
    lines.push('  fi');
    lines.push('}');
    lines.push('');
  }

  if (inv.expectedDsKeyTags.length > 0 && inv.signedZone && inv.signedZone !== '.') {
    lines.push('# Verify expected parent DS key tag(s) exist at delegation cut');
    lines.push('check_ds_key_tags() {');
    lines.push('  _zone="$1"');
    lines.push('  shift');
    lines.push('  _ds_ans=$(dig +noall +answer @"$RESOLVER" "$_zone" DS 2>/dev/null || true)');
    lines.push('  for _tag in "$@"; do');
    lines.push('    if printf \'%s\\n\' "$_ds_ans" | awk -v t="$_tag" \'$4 == "DS" && $5 == t { found=1 } END { exit !found }\'; then');
    lines.push('      record_pass "Parent DS #$_tag ($_zone)" "Parent delegation publishes DS key tag #$_tag"');
    lines.push('    else');
    lines.push('      record_fail "Parent DS #$_tag ($_zone)" "Expected DS key tag #$_tag missing from $_zone DS RRset"');
    lines.push('    fi');
    lines.push('  done');
    lines.push('}');
    lines.push('');
  }

  if (inv.expectDnssecAd && inv.signedZone) {
    lines.push('# Verify minimum RRSIG remaining validity (portable POSIX awk UTC civil-to-epoch math)');
    lines.push('check_rrsig_lifetime() {');
    lines.push('  _qname="$1"');
    lines.push('  _qtype="$2"');
    lines.push('  _min_hours="$3"');
    lines.push('  _now_epoch=$(date -u +%s)');
    lines.push('  _ans=$(dig +dnssec +noall +answer @"$RESOLVER" "$_qname" "$_qtype" 2>/dev/null || true)');
    lines.push('  _min_rem_hrs=$(printf \'%s\\n\' "$_ans" | awk -v qt="$_qtype" -v now="$_now_epoch" \'');
    lines.push('    function utc_to_epoch(ts,    y, m, d, hh, mm, ss, era, yoe, doy, doe, days) {');
    lines.push('      y  = int(substr(ts, 1, 4))');
    lines.push('      m  = int(substr(ts, 5, 2))');
    lines.push('      d  = int(substr(ts, 7, 2))');
    lines.push('      hh = int(substr(ts, 9, 2))');
    lines.push('      mm = int(substr(ts, 11, 2))');
    lines.push('      ss = int(substr(ts, 13, 2))');
    lines.push('      if (m <= 2) y -= 1');
    lines.push('      era = int((y >= 0 ? y : y - 399) / 400)');
    lines.push('      yoe = y - era * 400');
    lines.push('      doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1');
    lines.push('      doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy');
    lines.push('      days = era * 146097 + doe - 719468');
    lines.push('      return days * 86400 + hh * 3600 + mm * 60 + ss');
    lines.push('    }');
    lines.push('    $4 == "RRSIG" && toupper($5) == toupper(qt) && length($9) == 14 {');
    lines.push('      rem = int((utc_to_epoch($9) - now) / 3600)');
    lines.push('      if (!seen || rem < min_rem) { min_rem = rem; seen = 1 }');
    lines.push('    }');
    lines.push('    END { if (seen) print min_rem; else print "MISSING" }');
    lines.push('  \')');
    lines.push('  if [ "$_min_rem_hrs" = "MISSING" ]; then');
    lines.push('    record_fail "RRSIG Lifetime ($_qname $_qtype)" "No covering RRSIG returned for $_qname $_qtype"');
    lines.push('  elif [ "$_min_rem_hrs" -lt "$_min_hours" ]; then');
    lines.push('    record_fail "RRSIG Lifetime ($_qname $_qtype)" "Remaining RRSIG validity ${_min_rem_hrs}h is below threshold ${_min_hours}h"');
    lines.push('  else');
    lines.push('    record_pass "RRSIG Lifetime ($_qname $_qtype)" "Remaining RRSIG validity ${_min_rem_hrs}h >= ${_min_hours}h threshold"');
    lines.push('  fi');
    lines.push('}');
    lines.push('');
  }

  if (inv.caaCheck) {
    lines.push('# Verify RFC 8659 CAA authorized certificate authority presence');
    lines.push('check_caa_issuer() {');
    lines.push('  _owner="$1"');
    lines.push('  _expected_ca="$2"');
    lines.push('  _caa_ans=$(dig +noall +answer @"$RESOLVER" "$_owner" CAA 2>/dev/null || true)');
    lines.push('  if printf \'%s\\n\' "$_caa_ans" | awk -v want="$_expected_ca" \'');
    lines.push('    $4 == "CAA" && tolower($6) == "issue" {');
    lines.push('      line = $0');
    lines.push('      sub(/^[^"]*"/, "", line)');
    lines.push('      sub(/".*$/, "", line)');
    lines.push('      split(line, parts, ";")');
    lines.push('      ca = tolower(parts[1])');
    lines.push('      gsub(/^[[:space:]]+|[[:space:]]+$/, "", ca)');
    lines.push('      if (ca == tolower(want)) found = 1');
    lines.push('    }');
    lines.push('    END { exit !found }');
    lines.push('  \'; then');
    lines.push(
      '    record_pass "CAA Issuer ($_owner)" "Authorized CA \'${_expected_ca:-; (deny-all)}\' present in CAA issue RRset"'
    );
    lines.push('  else');
    lines.push(
      '    record_fail "CAA Issuer ($_owner)" "Authorized CA \'${_expected_ca:-; (deny-all)}\' missing from $_owner CAA RRset"'
    );
    lines.push('  fi');
    lines.push('}');
    lines.push('');
  }

  if (inv.spfCheck) {
    lines.push('# Verify RFC 7208 SPF record uniqueness, all-qualifier, and <= 10 DNS-interactive lookup budget');
    lines.push('SPF_LOOKUPS=0');
    lines.push('SPF_VISITED=" "');
    lines.push('walk_spf_domain() {');
    lines.push('  _spf_dom=$(printf \'%s\' "$1" | tr \'A-Z\' \'a-z\' | sed \'s/\\.$//\')');
    lines.push('  case "$SPF_VISITED" in');
    lines.push('    *" $_spf_dom "*) return ;;');
    lines.push('  esac');
    lines.push('  SPF_VISITED="${SPF_VISITED}${_spf_dom} "');
    lines.push('  if [ "$SPF_LOOKUPS" -gt 20 ]; then return; fi');
    lines.push('  _spf_line=$(dig +noall +answer @"$RESOLVER" "$_spf_dom" TXT 2>/dev/null | awk \'');
    lines.push('    $4 == "TXT" {');
    lines.push('      line = $0');
    lines.push('      sub(/^[^"]*"/, "", line)');
    lines.push('      sub(/"[[:space:]]*$/, "", line)');
    lines.push('      gsub(/"[[:space:]]+"/, "", line)');
    lines.push('      if (tolower(line) ~ /^v=spf1([[:space:]]|$)/) { print line; exit }');
    lines.push('    }');
    lines.push('  \')');
    lines.push('  [ -n "$_spf_line" ] || return');
    lines.push('  _redirect_target=""');
    lines.push('  _saw_all=0');
    lines.push('  for _tok in $_spf_line; do');
    lines.push('    _low=$(printf \'%s\' "$_tok" | tr \'A-Z\' \'a-z\')');
    lines.push('    _mech="${_low#[+~?-]}"');
    lines.push('    case "$_mech" in');
    lines.push('      v=spf1|ip4:*|ip6:*|exp=*) ;;');
    lines.push('      all) _saw_all=1 ;;');
    lines.push('      include:*)');
    lines.push('        SPF_LOOKUPS=$((SPF_LOOKUPS + 1))');
    lines.push('        _inc="${_mech#include:}"');
    lines.push('        case "$_inc" in *%*) ;; *) [ -n "$_inc" ] && walk_spf_domain "$_inc" ;; esac');
    lines.push('        ;;');
    lines.push('      redirect=*)');
    lines.push('        _redirect_target="${_mech#redirect=}"');
    lines.push('        ;;');
    lines.push('      a|a:*|a/*|mx|mx:*|mx/*|ptr|ptr:*|exists:*)');
    lines.push('        SPF_LOOKUPS=$((SPF_LOOKUPS + 1))');
    lines.push('        ;;');
    lines.push('    esac');
    lines.push('  done');
    lines.push('  if [ "$_saw_all" -eq 0 ] && [ -n "$_redirect_target" ]; then');
    lines.push('    SPF_LOOKUPS=$((SPF_LOOKUPS + 1))');
    lines.push('    case "$_redirect_target" in *%*) ;; *) walk_spf_domain "$_redirect_target" ;; esac');
    lines.push('  fi');
    lines.push('}');
    lines.push('');
    lines.push('check_spf_policy() {');
    lines.push('  _owner="$1"');
    lines.push('  _max_lookups="$2"');
    lines.push('  _want_all="$3"');
    lines.push('  _spf_records=$(dig +noall +answer @"$RESOLVER" "$_owner" TXT 2>/dev/null | awk \'');
    lines.push('    $4 == "TXT" {');
    lines.push('      line = $0');
    lines.push('      sub(/^[^"]*"/, "", line)');
    lines.push('      sub(/"[[:space:]]*$/, "", line)');
    lines.push('      gsub(/"[[:space:]]+"/, "", line)');
    lines.push('      if (tolower(line) ~ /^v=spf1([[:space:]]|$)/) print line');
    lines.push('    }');
    lines.push('  \')');
    lines.push('  _spf_count=$(printf \'%s\\n\' "$_spf_records" | grep -ci "^v=spf1" || true)');
    lines.push('  if [ "$_spf_count" -ne 1 ]; then');
    lines.push('    record_fail "SPF Record ($_owner)" "Expected exactly 1 v=spf1 TXT record, found $_spf_count"');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  if printf \'%s\\n\' "$_spf_records" | grep -Eiq "(^|[[:space:]])\\+?all([[:space:]]|$)"; then');
    lines.push('    record_fail "SPF Policy ($_owner)" "Insecure +all / pass-all mechanism detected"');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  if [ -n "$_want_all" ] && ! printf \'%s\\n\' "$_spf_records" | grep -Fqi "$_want_all"; then');
    lines.push('    record_fail "SPF Qualifier ($_owner)" "Expected $_want_all qualifier in SPF record"');
    lines.push('  fi');
    lines.push('  SPF_LOOKUPS=0');
    lines.push('  SPF_VISITED=" "');
    lines.push('  walk_spf_domain "$_owner"');
    lines.push('  if [ "$SPF_LOOKUPS" -le "$_max_lookups" ]; then');
    lines.push('    record_pass "SPF Lookup Budget ($_owner)" "SPF uses ${SPF_LOOKUPS}/${_max_lookups} DNS-interactive lookups"');
    lines.push('  else');
    lines.push('    record_fail "SPF Lookup Budget ($_owner)" "SPF exceeds RFC 7208 cap (${SPF_LOOKUPS}/${_max_lookups} DNS lookups -> permerror)"');
    lines.push('  fi');
    lines.push('}');
    lines.push('');
  }

  if (inv.dmarcCheck) {
    lines.push('# Verify RFC 7489 DMARC record presence and p= enforcement policy');
    lines.push('check_dmarc_policy() {');
    lines.push('  _owner="$1"');
    lines.push('  _want_p="$2"');
    lines.push('  _dmarc=$(dig +noall +answer @"$RESOLVER" "$_owner" TXT 2>/dev/null | awk \'');
    lines.push('    $4 == "TXT" {');
    lines.push('      line = $0');
    lines.push('      sub(/^[^"]*"/, "", line)');
    lines.push('      sub(/"[[:space:]]*$/, "", line)');
    lines.push('      gsub(/"[[:space:]]+"/, "", line)');
    lines.push('      if (tolower(line) ~ /^v=dmarc1[[:space:]]*;/) { print line; exit }');
    lines.push('    }');
    lines.push('  \')');
    lines.push('  if [ -z "$_dmarc" ]; then');
    lines.push('    record_fail "DMARC ($_owner)" "Missing v=DMARC1 TXT record at $_owner"');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  if printf \'%s\\n\' "$_dmarc" | grep -Eiq ";[[:space:]]*p[[:space:]]*=[[:space:]]*${_want_p}([[:space:];]|$)"; then');
    lines.push('    record_pass "DMARC Policy ($_owner)" "Verified v=DMARC1 with p=$_want_p"');
    lines.push('  else');
    lines.push('    record_fail "DMARC Policy ($_owner)" "Expected p=$_want_p in $_dmarc"');
    lines.push('  fi');
    lines.push('}');
    lines.push('');
  }

  if (inv.tlsaChecks.length > 0) {
    lines.push('# Verify DANE TLSA / OPENPGPKEY / SMIMEA record presence and DNSSEC authentication');
    lines.push('check_dane_record() {');
    lines.push('  _owner="$1"');
    lines.push('  _rrtype="$2"');
    lines.push('  _require_ad="$3"');
    lines.push('  _label="$4"');
    lines.push('  _out=$(dig +dnssec +noall +comments +answer @"$RESOLVER" "$_owner" "$_rrtype" 2>/dev/null || true)');
    lines.push('  if ! printf \'%s\\n\' "$_out" | awk -v rt="$_rrtype" \'$4 == rt { found=1 } END { exit !found }\'; then');
    lines.push('    record_fail "$_label ($_owner)" "No $_rrtype record returned at $_owner"');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  if [ "$_require_ad" = "1" ] && ! printf \'%s\\n\' "$_out" | grep -Eq "^;; flags:.* ad[ ;]"; then');
    lines.push('    record_fail "$_label ($_owner)" "$_rrtype present at $_owner, but AD=1 DNSSEC authentication is missing"');
    lines.push('    return');
    lines.push('  fi');
    lines.push('  record_pass "$_label ($_owner)" "Verified $_rrtype record${_require_ad:+ (AD=$_require_ad)}"');
    lines.push('}');
    lines.push('');
  }

  // Execute tailored invariant checks
  lines.push('printf \'=== DigDeep DNS Regression Check: %s (resolver @%s) ===\\n\' "$DOMAIN" "$RESOLVER"');
  lines.push(`check_resolution "$DOMAIN" "$PRIMARY_QTYPE" ${inv.expectDnssecAd ? '1' : '0'}`);
  if (inv.expectDnssecAd) {
    lines.push('check_delv_validation "$DOMAIN" "$PRIMARY_QTYPE"');
  }
  if (inv.expectedDsKeyTags.length > 0 && inv.signedZone && inv.signedZone !== '.') {
    const quotedTags = inv.expectedDsKeyTags
      .map((t) => shellSingleQuote(String(t)))
      .join(' ');
    lines.push(`check_ds_key_tags ${shellSingleQuote(inv.signedZone)} ${quotedTags}`);
  }
  if (inv.expectDnssecAd && inv.signedZone) {
    lines.push(
      `check_rrsig_lifetime ${shellSingleQuote(inv.signedZone)} 'SOA' "$MIN_RRSIG_HOURS"`
    );
    lines.push(
      `check_rrsig_lifetime ${shellSingleQuote(inv.signedZone)} 'DNSKEY' "$MIN_RRSIG_HOURS"`
    );
  }
  if (inv.caaCheck) {
    if (inv.caaCheck.explicitDenyAll) {
      lines.push(`check_caa_issuer ${shellSingleQuote(inv.caaCheck.owner)} ''`);
    } else {
      for (const ca of inv.caaCheck.expectedIssueCas) {
        lines.push(
          `check_caa_issuer ${shellSingleQuote(inv.caaCheck.owner)} ${shellSingleQuote(ca)}`
        );
      }
    }
  }
  if (inv.spfCheck) {
    lines.push(
      `check_spf_policy ${shellSingleQuote(inv.spfCheck.owner)} ${shellSingleQuote(String(inv.spfCheck.maxDnsLookups))} ${shellSingleQuote(inv.spfCheck.expectedAllToken ?? '')}`
    );
  }
  if (inv.dmarcCheck) {
    lines.push(
      `check_dmarc_policy ${shellSingleQuote(inv.dmarcCheck.owner)} ${shellSingleQuote(inv.dmarcCheck.expectedPolicy)}`
    );
  }
  for (const tlsa of inv.tlsaChecks) {
    lines.push(
      `check_dane_record ${shellSingleQuote(tlsa.owner)} ${shellSingleQuote(tlsa.rrtype)} ${tlsa.requireDnssecAd ? '1' : '0'} ${shellSingleQuote(tlsa.label)}`
    );
  }

  lines.push('');
  lines.push('# Finalize GitHub Actions Job Summary footer when $GITHUB_STEP_SUMMARY is set');
  lines.push('if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then');
  lines.push('  printf \'\\n**Summary:** %d passed, %d failed · [Inspect interactive DNSSEC/DANE trace in DigDeep](%s)\\n\' "$PASS_COUNT" "$FAIL_COUNT" "$DIGDEEP_URL" >> "$GITHUB_STEP_SUMMARY"');
  lines.push('fi');
  lines.push('');
  lines.push('printf \'=== Result: %d passed, %d failed ===\\n\' "$PASS_COUNT" "$FAIL_COUNT"');
  lines.push('[ "$FAIL_COUNT" -eq 0 ]');
  return `${lines.join('\n')}\n`;
}

/**
 * Generates a self-contained `.github/workflows/dns-check.yml` GitHub Actions workflow
 * that runs on cron schedule + manual `workflow_dispatch` and embeds the snapshot-tailored
 * POSIX regression script (so dropping the single YAML file into `.github/workflows/` works out of the box).
 */
export function generateSnapshotGitHubWorkflow(
  snapshot: AnalysisSnapshot,
  options: CiCheckGeneratorOptions = {}
): string {
  const inv = extractSnapshotCiInvariants(snapshot, options);
  const cron = (options.cronSchedule?.trim() || '17 */6 * * *').replace(/'/g, '');
  const scriptBody = generateSnapshotCiScript(snapshot, options);

  const indentedScript = scriptBody
    .trimEnd()
    .split('\n')
    .map((line) => (line.length > 0 ? `          ${line}` : ''))
    .join('\n');

  const safeTitleDomain = inv.targetDomain.replace(/["\\\r\n]/g, '');

  const lines: string[] = [
    `# DigDeep CI DNSSEC / DANE / Policy Regression Workflow — ${safeTitleDomain}`,
    `# Save as: .github/workflows/dns-check.yml`,
    `# Live trace: ${inv.permalink}`,
    `name: "DNS Security Check (${safeTitleDomain})"`,
    '',
    'on:',
    '  schedule:',
    `    - cron: '${cron}'`,
    '  workflow_dispatch:',
    '    inputs:',
    '      resolver:',
    '        description: "Recursive DNS resolver IP/host for dig & delv"',
    '        required: false',
    `        default: "${inv.defaultResolver.replace(/["\\\r\n]/g, '')}"`,
    '      min_rrsig_hours:',
    '        description: "Minimum remaining RRSIG validity threshold (hours)"',
    '        required: false',
    `        default: "${inv.recommendedMinRrsigHours}"`,
    '  push:',
    '    paths:',
    "      - '.github/workflows/dns-check.yml'",
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  dns-regression-check:',
    '    name: Verify DNSSEC, DANE & Policy Invariants',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 5',
    '    steps:',
    '      - name: Install DNS CLI tools (dig & delv)',
    '        run: |',
    '          if ! command -v dig >/dev/null 2>&1 || ! command -v delv >/dev/null 2>&1; then',
    '            sudo apt-get update -qq',
    '            sudo apt-get install -y --no-install-recommends bind9-dnsutils',
    '          fi',
    '',
    `      - name: Assert DNS invariants for ${safeTitleDomain}`,
    '        shell: sh -e {0}',
    '        env:',
    `          RESOLVER: \${{ inputs.resolver || '${inv.defaultResolver.replace(/'/g, '')}' }}`,
    `          MIN_RRSIG_HOURS: \${{ inputs.min_rrsig_hours || '${inv.recommendedMinRrsigHours}' }}`,
    '        run: |',
    indentedScript,
  ];

  return `${lines.join('\n')}\n`;
}
