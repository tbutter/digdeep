import {
  ANALYSIS_MODES,
  CONSENSUS_DOH_RESOLVERS,
  DOH_SERVER_PRESETS,
  formatAlgorithm,
  formatDohShortLabel,
  rcodeToString,
  RR_TYPES,
} from './constants';
import { displayFqdn } from './encoding';
import { formatRelativeTime } from './omniboxParse';
import type {
  AnalysisMode,
  AnalysisSnapshot,
  AuditFinding,
  SnapshotStatus,
  ValidationStatus,
} from './types';
import { findAuditFindingWireQuery, type FocusedWireSubMode } from './wireQueryFilter';
import type { ReportExportTab } from '../components/ReportExportModal';
import type { UserSettings } from '../storage/historyStore';
import type { ActiveTab } from '../urlState';

export type CommandPaletteCategory =
  | 'snapshot'
  | 'navigation'
  | 'resolver'
  | 'actions'
  | 'history';

export const COMMAND_CATEGORY_LABELS: Record<CommandPaletteCategory, string> = {
  snapshot: 'Active Snapshot Entities',
  navigation: 'Views & Analysis Modes',
  resolver: 'DoH Resolvers',
  actions: 'Exports, Sharing & Toggles',
  history: 'Saved Local History',
};

export type CommandPaletteAction =
  | {
      type: 'focus-graph';
      targetId: string;
      ensureStandbyVisible?: boolean;
      ensureSoaNsVisible?: boolean;
    }
  | {
      type: 'inspect-wire';
      queryId: string;
      wireMode: FocusedWireSubMode;
    }
  | {
      type: 'switch-tab';
      tab: ActiveTab;
    }
  | {
      type: 'run-mode';
      mode: AnalysisMode;
    }
  | {
      type: 'reprobe';
    }
  | {
      type: 'switch-resolver';
      endpoint: string;
      reprobe: boolean;
    }
  | {
      type: 'copy-share-link';
    }
  | {
      type: 'copy-frozen-link';
    }
  | {
      type: 'download-frozen-gz';
    }
  | {
      type: 'compare-frozen-live';
    }
  | {
      type: 'copy-markdown';
    }
  | {
      type: 'open-report-modal';
      tab: ReportExportTab;
    }
  | {
      type: 'open-settings';
    }
  | {
      type: 'toggle-theme';
    }
  | {
      type: 'toggle-standby-keys';
    }
  | {
      type: 'toggle-soa-ns';
    }
  | {
      type: 'select-history';
      snapshotId: string;
    };

export interface CommandPaletteItem {
  id: string;
  category: CommandPaletteCategory;
  title: string;
  subtitle: string;
  badge?: string;
  status?: SnapshotStatus | ValidationStatus;
  severity?: AuditFinding['severity'];
  isActive?: boolean;
  keywords: string[];
  /** Default priority within its category when query is empty (higher = earlier) */
  defaultPriority: number;
  /** Whether to show when search query is empty (keeps initial view curated & scannable) */
  includeWhenEmpty: boolean;
  action: CommandPaletteAction;
}

export interface BuildCommandPaletteContext {
  activeSnapshot: AnalysisSnapshot | null;
  snapshots: readonly AnalysisSnapshot[];
  activeTab: ActiveTab;
  analysisMode: AnalysisMode;
  domainInput: string;
  settings: UserSettings;
  theme: 'dark' | 'light';
  isOffline: boolean;
  isViewingFrozenSnapshot: boolean;
  nowMs?: number;
}

const WORD_BOUNDARY_RE = /[\s\-_./:#@()[\]]/;

function scoreSingleToken(token: string, haystack: string): number | null {
  if (!token) return 1;
  const idx = haystack.indexOf(token);
  if (idx === 0) {
    return 140 + Math.min(20, token.length * 2);
  }
  if (idx > 0) {
    const prevChar = haystack[idx - 1]!;
    if (WORD_BOUNDARY_RE.test(prevChar)) {
      return 105 + Math.min(16, token.length * 2) - Math.min(20, Math.floor(idx / 4));
    }
    return 70 + Math.min(12, token.length) - Math.min(25, Math.floor(idx / 4));
  }

  // Ordered subsequence fuzzy match
  let tIdx = 0;
  let firstMatch = -1;
  let prevMatch = -1;
  let consecutiveBonus = 0;
  let boundaryBonus = 0;

  for (let hIdx = 0; hIdx < haystack.length && tIdx < token.length; hIdx++) {
    if (haystack[hIdx] === token[tIdx]) {
      if (firstMatch === -1) firstMatch = hIdx;
      if (prevMatch === hIdx - 1) {
        consecutiveBonus += 6;
      }
      if (hIdx === 0 || WORD_BOUNDARY_RE.test(haystack[hIdx - 1]!)) {
        boundaryBonus += 8;
      }
      prevMatch = hIdx;
      tIdx++;
    }
  }

  if (tIdx < token.length) return null;
  const span = prevMatch - firstMatch + 1;
  const gapPenalty = Math.max(0, span - token.length) * 2;
  // Avoid noisy matches when a 2+ char token stretches across huge unrelated spans
  if (token.length >= 2 && span > token.length * 5 + 8 && boundaryBonus === 0) {
    return null;
  }
  return Math.max(5, 28 + consecutiveBonus + boundaryBonus - gapPenalty);
}

/**
 * Multi-token fuzzy & boundary-aware scorer for Command Palette items.
 * Returns `null` if any whitespace-separated token fails to match, or a positive numeric rank.
 */
export function scoreCommandItem(query: string, item: CommandPaletteItem): number | null {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) {
    return item.includeWhenEmpty ? item.defaultPriority : null;
  }

  const tokens = trimmed.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return item.includeWhenEmpty ? item.defaultPriority : null;
  }

  const titleLow = item.title.toLowerCase();
  const badgeLow = (item.badge ?? '').toLowerCase();
  const subtitleLow = item.subtitle.toLowerCase();
  const keywordsLow = item.keywords.join(' ').toLowerCase();
  const combinedLow = `${titleLow} ${badgeLow} ${keywordsLow} ${subtitleLow}`;

  let totalScore = 0;
  for (const rawTok of tokens) {
    const cleanTok = rawTok.startsWith('#') && rawTok.length > 1 ? rawTok.slice(1) : rawTok;
    const titleScore = scoreSingleToken(rawTok, titleLow) ?? scoreSingleToken(cleanTok, titleLow);
    const badgeScore = scoreSingleToken(rawTok, badgeLow) ?? scoreSingleToken(cleanTok, badgeLow);
    const kwScore =
      scoreSingleToken(rawTok, keywordsLow) ?? scoreSingleToken(cleanTok, keywordsLow);
    const subScore =
      scoreSingleToken(rawTok, subtitleLow) ?? scoreSingleToken(cleanTok, subtitleLow);
    const combinedScore =
      scoreSingleToken(rawTok, combinedLow) ?? scoreSingleToken(cleanTok, combinedLow);

    const bestFieldScore = Math.max(
      titleScore !== null ? titleScore * 1.45 : -1,
      badgeScore !== null ? badgeScore * 1.3 : -1,
      kwScore !== null ? kwScore * 1.2 : -1,
      subScore !== null ? subScore * 0.95 : -1,
      combinedScore !== null ? combinedScore * 0.8 : -1
    );

    if (bestFieldScore < 0) {
      return null;
    }
    totalScore += bestFieldScore;
  }

  // Tie-break boost by category relevance & defaultPriority
  return totalScore + item.defaultPriority * 0.05;
}

/**
 * Filters and sorts Command Palette items for a given query and optional category filter.
 */
export function filterCommandPaletteItems(
  items: readonly CommandPaletteItem[],
  query: string,
  categoryFilter: CommandPaletteCategory | 'all' = 'all'
): CommandPaletteItem[] {
  const isSearching = query.trim().length > 0;
  const scored: Array<{ item: CommandPaletteItem; score: number }> = [];

  for (const item of items) {
    if (categoryFilter !== 'all' && item.category !== categoryFilter) continue;
    // If user explicitly clicked a category pill even with empty query, show all items in that category
    if (!isSearching && categoryFilter !== 'all') {
      scored.push({ item, score: item.defaultPriority });
      continue;
    }
    const sc = scoreCommandItem(query, item);
    if (sc !== null) {
      scored.push({ item, score: sc });
    }
  }

  if (!isSearching) {
    // Preserve category grouping order when browsing empty query, sorted by defaultPriority inside each category
    const categoryOrder: Record<CommandPaletteCategory, number> = {
      snapshot: 0,
      navigation: 1,
      resolver: 2,
      actions: 3,
      history: 4,
    };
    scored.sort((a, b) => {
      const catDiff = categoryOrder[a.item.category] - categoryOrder[b.item.category];
      if (catDiff !== 0) return catDiff;
      return b.score - a.score;
    });
  } else {
    scored.sort((a, b) => b.score - a.score);
  }

  return scored.map((entry) => entry.item);
}

/**
 * Dynamically indexes all navigable entities, modes, views, DoH resolvers, exports, settings,
 * and saved local history snapshots for the Global Command Palette (#64).
 */
export function buildCommandPaletteItems(ctx: BuildCommandPaletteContext): CommandPaletteItem[] {
  const items: CommandPaletteItem[] = [];
  const { activeSnapshot, snapshots, activeTab, settings, theme, isOffline } = ctx;
  const nowMs = ctx.nowMs ?? Date.now();
  const targetLabel =
    activeSnapshot?.queriedEmail ??
    activeSnapshot?.queriedIp ??
    activeSnapshot?.displayDomain ??
    (ctx.domainInput.trim() || 'digdeep.butter.eu');

  // ---------------------------------------------------------------------------
  // 1. ACTIVE SNAPSHOT JUMP (Audit Findings, Zones, DNSKEYs, RRsets, Wire Logs)
  // ---------------------------------------------------------------------------
  if (activeSnapshot) {
    // 1a. Audit Findings (errors & warnings shown in default view; all findings searchable)
    const severityWeight: Record<AuditFinding['severity'], number> = {
      error: 98,
      warning: 92,
      info: 60,
    };
    activeSnapshot.findings.forEach((f, idx) => {
      const graphTarget = f.targetId ?? (f.zone ? `zone-${f.zone}` : null);
      const wireQuery = findAuditFindingWireQuery(f, activeSnapshot);
      items.push({
        id: `snap-finding-${f.id}-${idx}`,
        category: 'snapshot',
        title: f.title,
        subtitle: `${f.code}${f.rfc ? ` · ${f.rfc}` : ''} — ${f.detail}`,
        badge: f.severity.toUpperCase(),
        severity: f.severity,
        keywords: [
          'finding',
          'audit',
          'issue',
          f.severity,
          f.code,
          f.rfc ?? '',
          f.zone ? displayFqdn(f.zone) : '',
        ],
        defaultPriority: severityWeight[f.severity] - idx * 0.2,
        includeWhenEmpty: f.severity === 'error' || f.severity === 'warning',
        action: graphTarget
          ? { type: 'focus-graph', targetId: graphTarget }
          : wireQuery
            ? { type: 'inspect-wire', queryId: wireQuery.id, wireMode: 'dig' }
            : { type: 'switch-tab', tab: 'audit' },
      });
    });

    // 1b. Discovered Zones
    activeSnapshot.zones.forEach((z, idx) => {
      const dispZone = z.zoneName === '.' ? '. (Root Zone)' : displayFqdn(z.zoneName);
      items.push({
        id: `snap-zone-${z.zoneName}`,
        category: 'snapshot',
        title: `Zone: ${dispZone}`,
        subtitle: `${z.status.toUpperCase()} · ${z.nsecMode} · ${z.dnskeys.length} DNSKEY(s), ${z.rrsets.length} RRset(s)`,
        badge: z.status.toUpperCase(),
        status: z.status,
        keywords: ['zone', dispZone, z.zoneName, z.status, z.nsecMode],
        defaultPriority: 88 - idx,
        includeWhenEmpty: idx < 5,
        action: {
          type: 'focus-graph',
          targetId: `zone-${z.zoneName}`,
        },
      });
    });

    // 1c. DNSKEYs (#keyTag, KSK/ZSK/CSK/Standby/Trust Anchor)
    for (const z of activeSnapshot.zones) {
      const dispZone = z.zoneName === '.' ? '.' : displayFqdn(z.zoneName);
      for (const k of z.dnskeys) {
        const algText = formatAlgorithm(k.algorithm);
        const roleUpper = k.role.toUpperCase();
        items.push({
          id: `snap-dnskey-${k.id}`,
          category: 'snapshot',
          title: `DNSKEY #${k.keyTag} (${dispZone})`,
          subtitle: `${roleUpper} · ${algText} · ${k.keySizeInfo}`,
          badge: roleUpper,
          status: k.status,
          keywords: [
            'dnskey',
            'key',
            `#${k.keyTag}`,
            String(k.keyTag),
            k.role,
            algText,
            dispZone,
            k.status,
          ],
          defaultPriority: k.role === 'standby' ? 66 : 82,
          includeWhenEmpty: k.role !== 'standby' && z.zoneName === activeSnapshot.zones.at(-1)?.zoneName,
          action: {
            type: 'focus-graph',
            targetId: k.id,
            ensureStandbyVisible: k.role === 'standby',
          },
        });
      }
    }

    // 1d. RRsets across zones
    const auxTypes = new Set<number>([
      RR_TYPES.SOA,
      RR_TYPES.NS,
      RR_TYPES.CDS,
      RR_TYPES.CDNSKEY,
      RR_TYPES.CSYNC,
    ]);
    for (const z of activeSnapshot.zones) {
      const dispZone = z.zoneName === '.' ? '.' : displayFqdn(z.zoneName);
      for (const rr of z.rrsets) {
        if (rr.type === RR_TYPES.DNSKEY && rr.name === z.zoneName) continue;
        const firstRdata = rr.records[0]?.rdataText ?? '';
        const preview = firstRdata.length > 56 ? `${firstRdata.slice(0, 54)}…` : firstRdata;
        const needsSoaNs = !rr.isQueryTarget && auxTypes.has(rr.type);
        items.push({
          id: `snap-rrset-${rr.id}`,
          category: 'snapshot',
          title: `${displayFqdn(rr.name)} ${rr.typeName}`,
          subtitle: `Zone ${dispZone} · TTL ${rr.ttl}s${preview ? ` · ${preview}` : ''}`,
          badge: rr.typeName,
          status: rr.status,
          keywords: [
            'rrset',
            'record',
            displayFqdn(rr.name),
            rr.typeName,
            dispZone,
            rr.status,
            firstRdata.slice(0, 64),
          ],
          defaultPriority: rr.isQueryTarget ? 80 : 58,
          includeWhenEmpty: rr.isQueryTarget,
          action: {
            type: 'focus-graph',
            targetId: rr.id,
            ensureSoaNsVisible: needsSoaNs,
          },
        });
      }
    }

    // 1e. Captured DoH Wire Packets (searchable by "wire", "hex", qname, qtype, or purpose)
    activeSnapshot.queries.slice(0, 48).forEach((q, idx) => {
      const dispQname = q.qname === '.' ? '.' : displayFqdn(q.qname);
      const rcodeName = rcodeToString(q.packet.flags.rcode);
      items.push({
        id: `snap-wire-${q.id}`,
        category: 'snapshot',
        title: `Wire Packet: ${dispQname} ${q.qtypeName}`,
        subtitle: `${q.purpose} · ${rcodeName} · ${Math.round(q.latencyMs)}ms`,
        badge: 'WIRE',
        keywords: [
          'wire',
          'packet',
          'hex',
          'dissect',
          'dig',
          dispQname,
          q.qtypeName,
          q.purpose,
          rcodeName,
          q.ecsSubnet ?? '',
        ],
        defaultPriority: 48 - idx * 0.1,
        includeWhenEmpty: false,
        action: {
          type: 'inspect-wire',
          queryId: q.id,
          wireMode: 'dig',
        },
      });
    });
  }

  // ---------------------------------------------------------------------------
  // 2. SWITCH VIEW & ANALYSIS MODE
  // ---------------------------------------------------------------------------
  if (activeSnapshot && (activeSnapshot.mode === 'mail' || Boolean(activeSnapshot.mailAnalysis))) {
    items.push({
      id: 'nav-tab-mail',
      category: 'navigation',
      title: 'Go to Mail, DANE, SPF, DKIM & DMARC View',
      subtitle: `Inspect MX hosts, SMTP DANE TLSA, SPF lookup tree & DMARC for ${activeSnapshot.displayDomain}`,
      badge: activeTab === 'mail' ? 'ACTIVE VIEW' : 'VIEW',
      isActive: activeTab === 'mail',
      keywords: ['mail', 'mx', 'spf', 'dkim', 'dmarc', 'dane', 'mta-sts', 'bimi', 'tab', 'view'],
      defaultPriority: 90,
      includeWhenEmpty: true,
      action: { type: 'switch-tab', tab: 'mail' },
    });
  }

  if (activeSnapshot && (activeSnapshot.mode === 'web' || Boolean(activeSnapshot.webAnalysis))) {
    items.push({
      id: 'nav-tab-web',
      category: 'navigation',
      title: 'Go to Web, HTTPS/SVCB, ECH, CAA & DANE View',
      subtitle: `Inspect HTTPS/SVCB, TLS ECHConfigList, CAA tree & _443._tcp TLSA for ${activeSnapshot.displayDomain}`,
      badge: activeTab === 'web' ? 'ACTIVE VIEW' : 'VIEW',
      isActive: activeTab === 'web',
      keywords: ['web', 'https', 'svcb', 'ech', 'caa', 'tlsa', 'sshfp', 'ct', 'tab', 'view'],
      defaultPriority: 89,
      includeWhenEmpty: true,
      action: { type: 'switch-tab', tab: 'web' },
    });
  }

  if (activeSnapshot && activeSnapshot.mode === 'consensus') {
    items.push({
      id: 'nav-tab-consensus',
      category: 'navigation',
      title: 'Go to Multi-Resolver DoH Consensus & EDE View',
      subtitle: `Compare 10 DoH resolvers, RFC 8914 EDE codes & RFC 7871 ECS GeoDNS for ${activeSnapshot.displayDomain}`,
      badge: activeTab === 'consensus' ? 'ACTIVE VIEW' : 'VIEW',
      isActive: activeTab === 'consensus',
      keywords: ['consensus', 'ede', 'ecs', 'geodns', 'resolvers', 'matrix', 'tab', 'view'],
      defaultPriority: 89,
      includeWhenEmpty: true,
      action: { type: 'switch-tab', tab: 'consensus' },
    });
  }

  if (activeSnapshot) {
    const snapshotViews: ReadonlyArray<{
      tab: ActiveTab;
      title: string;
      subtitle: string;
      keywords: string[];
      priority: number;
    }> = [
      {
        tab: 'graph',
        title: 'Go to DNSSEC Chain Graph',
        subtitle: 'Interactive top-down cryptographic chain-of-trust diagram',
        keywords: ['graph', 'chain', 'diagram', 'svg', 'dnssec', 'tab', 'view'],
        priority: 88,
      },
      {
        tab: 'audit',
        title: 'Go to Audit & RFC Checks',
        subtitle: `${activeSnapshot.findings.length} cryptographic & RFC compliance check(s)`,
        keywords: ['audit', 'rfc', 'findings', 'errors', 'warnings', 'checks', 'tab', 'view'],
        priority: 87,
      },
      {
        tab: 'responses',
        title: 'Go to DoH Wire Responses & Hex Dissector',
        subtitle: `Inspect ${activeSnapshot.queries.length} captured RFC 8484 wire packets, dig output & byte dissector`,
        keywords: ['wire', 'responses', 'packets', 'hex', 'dissector', 'dig', 'delv', 'kdig', 'tab'],
        priority: 86,
      },
      {
        tab: 'zones',
        title: 'Go to Zones & Nameservers',
        subtitle: `Inspect ${activeSnapshot.zones.length} zone cut(s), glue records, NS compliance & BGP ASNs`,
        keywords: ['zones', 'nameservers', 'ns', 'soa', 'glue', 'asn', 'rpki', 'tab', 'view'],
        priority: 85,
      },
    ];

    for (const v of snapshotViews) {
      items.push({
        id: `nav-tab-${v.tab}`,
        category: 'navigation',
        title: v.title,
        subtitle: v.subtitle,
        badge: activeTab === v.tab ? 'ACTIVE VIEW' : 'VIEW',
        isActive: activeTab === v.tab,
        keywords: v.keywords,
        defaultPriority: v.priority,
        includeWhenEmpty: true,
        action: { type: 'switch-tab', tab: v.tab },
      });
    }
  }

  const globalViews: ReadonlyArray<{
    tab: ActiveTab;
    title: string;
    subtitle: string;
    keywords: string[];
    priority: number;
  }> = [
    {
      tab: 'watch',
      title: 'Open Live TTL Countdown & Serve-Stale Watch Mode',
      subtitle: 'Real-time TTL countdown, resolver cache-decay tracking & RFC 8767 Serve-Stale monitor',
      keywords: ['watch', 'ttl', 'countdown', 'cache', 'decay', 'serve-stale', 'rfc 8767', 'live'],
      priority: 84,
    },
    {
      tab: 'portfolio',
      title: 'Open Multi-Domain Portfolio Security Triage Matrix',
      subtitle: 'Batch audit up to 50 domains across DNSSEC, Mail, Web & NS ASN concentration',
      keywords: ['portfolio', 'batch', 'multi-domain', 'matrix', 'csv', 'triage'],
      priority: 83,
    },
    {
      tab: 'history',
      title: 'Open Local History & Snapshot Diff',
      subtitle: `Browse, pin, import/export, or diff ${snapshots.length} saved snapshot(s)`,
      keywords: ['history', 'diff', 'compare', 'snapshots', 'import', 'export', 'local'],
      priority: 82,
    },
  ];

  for (const gv of globalViews) {
    items.push({
      id: `nav-tab-${gv.tab}`,
      category: 'navigation',
      title: gv.title,
      subtitle: gv.subtitle,
      badge: activeTab === gv.tab ? 'ACTIVE VIEW' : 'VIEW',
      isActive: activeTab === gv.tab,
      keywords: gv.keywords,
      defaultPriority: gv.priority,
      includeWhenEmpty: true,
      action: { type: 'switch-tab', tab: gv.tab },
    });
  }

  // Analysis Mode runners
  for (const m of ANALYSIS_MODES) {
    items.push({
      id: `mode-run-${m.id}`,
      category: 'navigation',
      title: `${m.actionLabel} for ${targetLabel}`,
      subtitle: m.description,
      badge: ctx.analysisMode === m.id ? 'ACTIVE MODE' : 'MODE',
      isActive: ctx.analysisMode === m.id,
      keywords: ['mode', 'analyze', 'probe', 'run', m.id, m.shortLabel, targetLabel],
      defaultPriority: 78,
      includeWhenEmpty: true,
      action: { type: 'run-mode', mode: m.id },
    });
  }

  if (!isOffline) {
    items.push({
      id: 'mode-reprobe-now',
      category: 'navigation',
      title: `Re-probe ${targetLabel} Now`,
      subtitle: `Run a fresh live ${formatDohShortLabel(settings.dohEndpoint)} DoH trace`,
      badge: 'LIVE TRACE',
      keywords: ['reprobe', 'refresh', 'rerun', 'reload', 'trace', targetLabel],
      defaultPriority: 76,
      includeWhenEmpty: false,
      action: { type: 'reprobe' },
    });
  }

  // ---------------------------------------------------------------------------
  // 3. SWITCH DoH RESOLVER & RE-PROBE
  // ---------------------------------------------------------------------------
  const seenEndpoints = new Set<string>();
  const resolverPresets = [
    ...CONSENSUS_DOH_RESOLVERS,
    ...DOH_SERVER_PRESETS.filter((p) => p.isAlias && p.url === settings.dohEndpoint),
  ];

  resolverPresets.forEach((preset, idx) => {
    seenEndpoints.add(preset.url);
    const active = settings.dohEndpoint === preset.url;
    items.push({
      id: `resolver-preset-${preset.shortLabel}`,
      category: 'resolver',
      title: `Use DoH Resolver: ${preset.provider} (${preset.shortLabel})`,
      subtitle: `${preset.description} · ${preset.url}`,
      badge: active ? 'ACTIVE DoH' : preset.role.toUpperCase(),
      isActive: active,
      keywords: [
        'doh',
        'resolver',
        'server',
        'switch',
        preset.shortLabel,
        preset.provider,
        preset.role,
        preset.url,
      ],
      defaultPriority: active ? 75 : 74 - idx * 0.5,
      includeWhenEmpty: idx < 6 || active,
      action: {
        type: 'switch-resolver',
        endpoint: preset.url,
        reprobe: !isOffline,
      },
    });
  });

  for (const customUrl of settings.customDohEndpoints) {
    if (seenEndpoints.has(customUrl)) continue;
    seenEndpoints.add(customUrl);
    const active = settings.dohEndpoint === customUrl;
    const short = formatDohShortLabel(customUrl);
    items.push({
      id: `resolver-custom-${customUrl}`,
      category: 'resolver',
      title: `Use Custom DoH Resolver: ${short}`,
      subtitle: customUrl,
      badge: active ? 'ACTIVE DoH' : 'CUSTOM DoH',
      isActive: active,
      keywords: ['doh', 'resolver', 'custom', short, customUrl],
      defaultPriority: active ? 75 : 68,
      includeWhenEmpty: true,
      action: {
        type: 'switch-resolver',
        endpoint: customUrl,
        reprobe: !isOffline,
      },
    });
  }

  // ---------------------------------------------------------------------------
  // 4. EXPORTS, SHARING & UI TOGGLES
  // ---------------------------------------------------------------------------
  if (activeSnapshot) {
    if (ctx.isViewingFrozenSnapshot && !isOffline) {
      items.push({
        id: 'action-compare-frozen-live',
        category: 'actions',
        title: 'Compare Frozen Incident Snapshot Against Live DNS',
        subtitle: `Probe live ${formatDohShortLabel(settings.dohEndpoint)} DoH and open side-by-side Snapshot Diff`,
        badge: 'INCIDENT DIFF',
        keywords: ['compare', 'frozen', 'live', 'diff', 'incident', 'snap'],
        defaultPriority: 95,
        includeWhenEmpty: true,
        action: { type: 'compare-frozen-live' },
      });
    }

    items.push(
      {
        id: 'action-copy-frozen-link',
        category: 'actions',
        title: 'Copy Frozen Incident Permalink (#snap=)',
        subtitle:
          'Compress raw RFC 8484 wire packets via gzip into a zero-server #snap= URL fragment',
        badge: 'FREEZE LINK',
        keywords: ['freeze', 'frozen', 'snap', 'permalink', 'share', 'gzip', 'incident', 'url'],
        defaultPriority: 73,
        includeWhenEmpty: true,
        action: { type: 'copy-frozen-link' },
      },
      {
        id: 'action-download-frozen-gz',
        category: 'actions',
        title: 'Download Compressed Wire Snapshot (.digdeep.gz)',
        subtitle: 'Save portable DDP1 gzipped binary wire-packet bundle for offline archival',
        badge: '.DIGDEEP.GZ',
        keywords: ['download', 'export', 'gz', 'gzip', 'digdeep.gz', 'wire', 'bundle', 'archive'],
        defaultPriority: 71,
        includeWhenEmpty: false,
        action: { type: 'download-frozen-gz' },
      },
      {
        id: 'action-copy-share-link',
        category: 'actions',
        title: 'Copy Live Share Deep Link',
        subtitle: 'Copy URL with domain, mode, RR types, DoH resolver, active tab & focused node',
        badge: 'COPY URL',
        keywords: ['copy', 'link', 'url', 'share', 'deeplink'],
        defaultPriority: 72,
        includeWhenEmpty: true,
        action: { type: 'copy-share-link' },
      },
      {
        id: 'action-copy-markdown',
        category: 'actions',
        title: 'Copy GitHub-Flavored Markdown Incident Report',
        subtitle: 'Copy structured diagnostic summary, chain of trust & CLI reproducer commands',
        badge: 'MARKDOWN',
        keywords: ['copy', 'markdown', 'md', 'report', 'incident', 'gfm'],
        defaultPriority: 70,
        includeWhenEmpty: true,
        action: { type: 'copy-markdown' },
      },
      {
        id: 'action-open-ci-shell',
        category: 'actions',
        title: 'Generate POSIX Shell DNSSEC / DANE Regression Script (.sh)',
        subtitle: 'Open CI regression check generator using dig & delv',
        badge: 'CI .SH',
        keywords: ['ci', 'script', 'shell', 'bash', 'sh', 'dig', 'delv', 'regression', 'export'],
        defaultPriority: 69,
        includeWhenEmpty: true,
        action: { type: 'open-report-modal', tab: 'shell' },
      },
      {
        id: 'action-open-ci-workflow',
        category: 'actions',
        title: 'Generate GitHub Actions Scheduled DNS Check (.yml)',
        subtitle: 'Open ready-to-commit .github/workflows/dns-check.yml cron workflow',
        badge: 'GITHUB ACTIONS',
        keywords: ['github', 'actions', 'workflow', 'yaml', 'yml', 'cron', 'ci'],
        defaultPriority: 68,
        includeWhenEmpty: false,
        action: { type: 'open-report-modal', tab: 'workflow' },
      }
    );
  }

  items.push(
    {
      id: 'action-open-settings',
      category: 'actions',
      title: 'Open Trust Anchors & Time-Travel Validation Clock',
      subtitle: 'Configure root DS trust anchors, custom DoH endpoints & historical RRSIG clock',
      badge: 'SETTINGS',
      keywords: ['settings', 'trust', 'anchor', 'ksk', 'clock', 'time-travel', 'reverify'],
      defaultPriority: 67,
      includeWhenEmpty: true,
      action: { type: 'open-settings' },
    },
    {
      id: 'action-toggle-theme',
      category: 'actions',
      title: `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Theme`,
      subtitle: `Current color theme: ${theme === 'dark' ? 'Dark' : 'Light'}`,
      badge: theme === 'dark' ? 'DARK → LIGHT' : 'LIGHT → DARK',
      keywords: ['theme', 'dark', 'light', 'mode', 'color', 'appearance', 'toggle'],
      defaultPriority: 66,
      includeWhenEmpty: true,
      action: { type: 'toggle-theme' },
    },
    {
      id: 'action-toggle-standby-keys',
      category: 'actions',
      title: `${settings.showStandbyKeys ? 'Hide' : 'Show'} Standby DNSKEYs in Chain Graph`,
      subtitle: 'Toggle visibility of non-signing standby / pre-published rollover keys',
      badge: settings.showStandbyKeys ? 'ON' : 'OFF',
      isActive: settings.showStandbyKeys,
      keywords: ['toggle', 'standby', 'keys', 'dnskey', 'rollover', 'filter', 'graph'],
      defaultPriority: 65,
      includeWhenEmpty: true,
      action: { type: 'toggle-standby-keys' },
    },
    {
      id: 'action-toggle-soa-ns',
      category: 'actions',
      title: `${settings.showSoaAndNs ? 'Hide' : 'Show'} SOA, NS & Rollover Records in Graph`,
      subtitle: 'Toggle visibility of non-target SOA, NS, CDS, CDNSKEY & CSYNC RRset nodes',
      badge: settings.showSoaAndNs ? 'ON' : 'OFF',
      isActive: settings.showSoaAndNs,
      keywords: ['toggle', 'soa', 'ns', 'cds', 'cdnskey', 'csync', 'filter', 'graph'],
      defaultPriority: 64,
      includeWhenEmpty: true,
      action: { type: 'toggle-soa-ns' },
    }
  );

  // ---------------------------------------------------------------------------
  // 5. RECENT HISTORY SNAPSHOTS
  // ---------------------------------------------------------------------------
  snapshots.slice(0, 30).forEach((s, idx) => {
    const isCurrent = activeSnapshot?.id === s.id;
    const subject = s.queriedEmail ?? s.queriedIp ?? s.displayDomain;
    const modeTag = (s.mode ?? 'dnssec').toUpperCase();
    const relTime = formatRelativeTime(s.capturedAt, nowMs);
    items.push({
      id: `history-snap-${s.id}`,
      category: 'history',
      title: `History: ${subject}`,
      subtitle: `${modeTag} · ${s.overallStatus.toUpperCase()} · ${formatDohShortLabel(s.dohEndpoint)} · ${relTime}${s.note ? ` · "${s.note}"` : ''}`,
      badge: isCurrent ? 'CURRENT' : modeTag,
      status: s.overallStatus,
      isActive: isCurrent,
      keywords: [
        'history',
        'snapshot',
        'saved',
        subject,
        s.displayDomain,
        s.mode ?? 'dnssec',
        s.overallStatus,
        s.note ?? '',
      ],
      defaultPriority: 60 - idx * 0.5,
      includeWhenEmpty: idx < 5,
      action: {
        type: 'select-history',
        snapshotId: s.id,
      },
    });
  });

  return items;
}
