import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  FileCode2,
  FileText,
  Fingerprint,
  Globe,
  KeyRound,
  RefreshCw,
  Server,
  Sparkles,
} from 'lucide-react';
import { formatAlgorithm, formatDigestType, formatDohShortLabel } from '../dns/constants';
import {
  downloadTextFile,
  formatSnapshotAsZonefile,
  formatZoneAsZonefile,
} from '../dns/digFormat';
import { displayFqdn, normalizeFqdn } from '../dns/encoding';
import { evaluateIpv6ReadinessAudit } from '../dns/ipv6Readiness';
import type { AnalysisSnapshot, Ipv6DelegationHopAudit, ZoneAnalysis } from '../dns/types';
import { IpHoverBadge, RpkiStatusBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { HostnameBadge } from './HostnameBadge';
import { CryptoBlob } from './CryptoBlob';
import { StatusBadge } from './StatusBadge';

const NARROW_ZONES_MEDIA_QUERY = '(max-width: 639px)';

function detectNarrowZonesViewport(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return Boolean(window.matchMedia(NARROW_ZONES_MEDIA_QUERY)?.matches);
}

export function isHealthyIntermediateParentZone(
  zone: ZoneAnalysis,
  snapshot: AnalysisSnapshot
): boolean {
  const queriedFqdn = normalizeFqdn(snapshot.targetName);
  if (zone.zoneName === queriedFqdn) return false;
  const hasDelegatedChild = snapshot.zones.some((other) => other.parentZone === zone.zoneName);
  if (!hasDelegatedChild) return false;
  if (zone.status !== 'secure') return false;
  if (zone.soaAudit && !zone.soaAudit.valid) return false;
  if (
    zone.nameservers.some(
      (ns) =>
        ns.status === 'dangling' ||
        (ns.cnameChain?.length ?? 0) > 0 ||
        (ns.bogonIps?.length ?? 0) > 0
    )
  ) {
    return false;
  }
  if (zone.nsDiversity?.dualStackReady === false) return false;
  if (
    snapshot.ipv6Readiness &&
    (snapshot.ipv6Readiness.bottleneckZones.includes(zone.zoneName) ||
      snapshot.ipv6Readiness.singleIpv6NsZones.includes(zone.zoneName))
  ) {
    return false;
  }
  if (zone.nsConsistency && !zone.nsConsistency.consistent) return false;
  if (zone.cdsRollover?.present && zone.cdsRollover.status !== 'in-sync') return false;
  if (zone.zonemd?.present && zone.zonemd.status !== 'valid-sync') return false;
  if (zone.wildcardAudit && zone.wildcardAudit.status !== 'no-wildcard') return false;
  if (zone.txtHygiene && zone.txtHygiene.status === 'warning') return false;
  return true;
}

function zoneDomSlug(zoneName: string): string {
  return zoneName === '.' ? 'root' : displayFqdn(zoneName).replace(/[^a-z0-9.-]/gi, '_');
}

function ipv6HopBadgeClasses(status: Ipv6DelegationHopAudit['status']): string {
  if (status === 'dual-stack') {
    return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
  }
  if (status === 'ipv4-only-bottleneck') {
    return 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35';
  }
  if (status === 'ipv6-single-ns') {
    return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35';
  }
  if (status === 'ipv6-only' || status === 'dual-stack-partial-v4') {
    return 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border-cyan-500/30';
  }
  return 'bg-slate-200/70 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700';
}

export function ZonesPanel({
  snapshot,
  defaultMobileCollapse,
}: {
  snapshot: AnalysisSnapshot;
  defaultMobileCollapse?: boolean;
}) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const [showZonefilePreview, setShowZonefilePreview] = useState(false);
  const [includeDnssecInZonefile, setIncludeDnssecInZonefile] = useState(true);
  const [copiedZoneKey, setCopiedZoneKey] = useState<string | null>(null);
  const [isNarrowViewport, setIsNarrowViewport] = useState<boolean>(detectNarrowZonesViewport);
  const [zoneOverrides, setZoneOverrides] = useState<{
    snapshotId: string;
    byZone: Record<string, boolean>;
  }>({ snapshotId: snapshot.id, byZone: {} });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const mql = window.matchMedia(NARROW_ZONES_MEDIA_QUERY);
    if (!mql) return;
    setIsNarrowViewport(Boolean(mql.matches));
    const onChange = (ev: MediaQueryListEvent) => setIsNarrowViewport(ev.matches);
    if (typeof mql.addEventListener === 'function') {
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    }
    if (typeof mql.addListener === 'function') {
      mql.addListener(onChange);
      return () => mql.removeListener(onChange);
    }
  }, []);

  const effectiveMobileCollapse = defaultMobileCollapse ?? isNarrowViewport;
  const activeOverrides = zoneOverrides.snapshotId === snapshot.id ? zoneOverrides.byZone : {};

  const isZoneCollapsed = (zone: ZoneAnalysis): boolean => {
    if (zone.zoneName in activeOverrides) {
      return Boolean(activeOverrides[zone.zoneName]);
    }
    return effectiveMobileCollapse && isHealthyIntermediateParentZone(zone, snapshot);
  };

  const anyZoneCollapsed = snapshot.zones.some((z) => isZoneCollapsed(z));

  const toggleZone = (zone: ZoneAnalysis) => {
    const nextCollapsed = !isZoneCollapsed(zone);
    setZoneOverrides((prev) => ({
      snapshotId: snapshot.id,
      byZone: {
        ...(prev.snapshotId === snapshot.id ? prev.byZone : {}),
        [zone.zoneName]: nextCollapsed,
      },
    }));
  };

  const setAllZonesCollapsed = (collapsed: boolean) => {
    const nextMap: Record<string, boolean> = {};
    for (const z of snapshot.zones) {
      nextMap[z.zoneName] = collapsed;
    }
    setZoneOverrides({ snapshotId: snapshot.id, byZone: nextMap });
  };

  const jumpToZone = (zone: ZoneAnalysis) => {
    const domId = `zone-card-${zoneDomSlug(zone.zoneName)}`;
    const wasCollapsed = isZoneCollapsed(zone);
    if (wasCollapsed) {
      setZoneOverrides((prev) => ({
        snapshotId: snapshot.id,
        byZone: {
          ...(prev.snapshotId === snapshot.id ? prev.byZone : {}),
          [zone.zoneName]: false,
        },
      }));
      setTimeout(() => {
        const el = typeof document !== 'undefined' ? document.getElementById(domId) : null;
        if (el && typeof el.scrollIntoView === 'function') {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 0);
    } else if (typeof document !== 'undefined') {
      const el = document.getElementById(domId);
      if (el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  };

  const ipv6Audit = useMemo(
    () =>
      snapshot.ipv6Readiness ??
      evaluateIpv6ReadinessAudit({
        targetName: snapshot.targetName,
        queriedIp: snapshot.queriedIp,
        queriedEmail: snapshot.queriedEmail,
        zones: snapshot.zones,
        cnameEdges: snapshot.cnameEdges,
        queries: snapshot.queries,
        mailAnalysis: snapshot.mailAnalysis,
        webAnalysis: snapshot.webAnalysis,
      }).audit,
    [snapshot]
  );

  const ipv6HopByZone = useMemo(() => {
    const map = new Map<string, Ipv6DelegationHopAudit>();
    for (const h of ipv6Audit.hops) {
      map.set(h.zoneName, h);
    }
    return map;
  }, [ipv6Audit]);

  const fullZonefileText = useMemo(
    () =>
      formatSnapshotAsZonefile(snapshot, {
        includeDnssecRecords: includeDnssecInZonefile,
      }),
    [snapshot, includeDnssecInZonefile]
  );

  const snapshotZoneFilename = `${
    snapshot.displayDomain === '.'
      ? 'root'
      : snapshot.displayDomain.replace(/[^a-z0-9.-]/gi, '_')
  }.zone`;

  const handleCopyZoneText = (key: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedZoneKey(key);
    setTimeout(() => setCopiedZoneKey((cur) => (cur === key ? null : cur)), 1500);
  };

  return (
    <div className="space-y-5">
      {/* RFC 1035 Master Zonefile (.zone) Export & Preview Bar */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-3.5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-cyan-500" />
            <span className="font-semibold text-xs text-slate-800 dark:text-slate-100">
              RFC 1035 Master Zonefile Export (<code className="font-mono">{snapshotZoneFilename}</code>)
            </span>
            <span className="text-xs text-slate-500 hidden sm:inline">
              · BIND / NSD / Knot compatible master file across {snapshot.zones.length} discovered zone
              {snapshot.zones.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeDnssecInZonefile}
                onChange={(e) => setIncludeDnssecInZonefile(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-700 text-cyan-500 focus:ring-cyan-500"
              />
              <span>Include DNSSEC RRs (DNSKEY/DS/RRSIG/NSEC)</span>
            </label>

            <button
              type="button"
              onClick={() => setShowZonefilePreview((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
            >
              <FileCode2 className="w-3.5 h-3.5 text-cyan-500" />
              <span>{showZonefilePreview ? 'Hide Zonefile' : 'Preview Zonefile'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleCopyZoneText('all', fullZonefileText)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
            >
              {copiedZoneKey === 'all' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy .zone</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => downloadTextFile(fullZonefileText, snapshotZoneFilename)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2.5 py-1 text-xs font-semibold cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Zonefile (.zone)</span>
            </button>
          </div>
        </div>

        {showZonefilePreview && (
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3.5 max-h-80 overflow-auto">
            <pre className="font-mono text-xs text-slate-200 whitespace-pre leading-relaxed">
              {fullZonefileText}
            </pre>
          </div>
        )}
      </div>

      {/* #58 End-to-End IPv6-Only Iterative Resolution & Delegation Glue Readiness Matrix */}
      {(ipv6Audit.probedHopCount > 0 || ipv6Audit.dns64Detections.length > 0) && (
        <div
          data-testid="ipv6-readiness-matrix"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-4 space-y-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-500 shrink-0" />
              <span className="font-semibold text-xs sm:text-sm text-slate-900 dark:text-slate-100">
                End-to-End IPv6-Only Authoritative Resolution &amp; Glue Readiness
              </span>
              <span className="hidden sm:inline rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-mono text-[10px]">
                RFC 3901 · RFC 2182 · RFC 6052
              </span>
            </div>
            <span
              data-testid="ipv6-readiness-verdict-badge"
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                ipv6Audit.overallStatus === 'ipv6-ready'
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                  : ipv6Audit.overallStatus === 'broken-ipv6-path'
                    ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35'
                    : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35'
              }`}
            >
              {ipv6Audit.overallStatus === 'ipv6-ready' ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>IPv6-Only Iterative Ready</span>
                </>
              ) : ipv6Audit.overallStatus === 'broken-ipv6-path' ? (
                <>
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>IPv4-Only Bottleneck</span>
                </>
              ) : ipv6Audit.overallStatus === 'dns64-synthesized' ? (
                <>
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>DNS64 Synthesized (No Native v6)</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Single-v6 NS Redundancy Warning</span>
                </>
              )}
            </span>
          </div>

          <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
            {ipv6Audit.summary}
          </p>

          {/* Delegation Hop Matrix */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {[...ipv6Audit.hops, ...ipv6Audit.oobNsZones].map((hop) => {
              const hopSlug = zoneDomSlug(hop.zoneName);
              const matchingZone = snapshot.zones.find((z) => z.zoneName === hop.zoneName);
              return (
                <div
                  key={`${hop.role}-${hop.zoneName}`}
                  data-testid={`ipv6-matrix-hop-${hop.role}-${hopSlug}`}
                  onClick={matchingZone ? () => jumpToZone(matchingZone) : undefined}
                  className={`rounded-lg border p-2.5 space-y-1.5 transition-colors ${
                    hop.status === 'ipv4-only-bottleneck'
                      ? 'border-rose-500/40 bg-rose-500/5'
                      : hop.status === 'ipv6-single-ns'
                        ? 'border-amber-500/40 bg-amber-500/5'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50'
                  } ${matchingZone ? 'hover:border-cyan-500 cursor-pointer' : ''}`}
                >
                  <div className="flex items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="font-mono font-semibold text-xs text-slate-900 dark:text-slate-100 truncate">
                        {hop.zoneName === '.' ? '. (Root)' : hop.zoneName}
                      </span>
                      {hop.role === 'oob-ns-zone' && (
                        <span
                          className="shrink-0 rounded bg-purple-500/15 border border-purple-500/30 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-purple-700 dark:text-purple-300"
                          title={`Out-of-bailiwick NS parent zone referenced by ${hop.referencedByZones?.map(displayFqdn).join(', ') ?? 'child zone'}`}
                        >
                          OOB NS Zone
                        </span>
                      )}
                      {hop.role === 'cname-chain' && (
                        <span className="shrink-0 rounded bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[9px] text-cyan-700 dark:text-cyan-300">
                          CNAME Hop
                        </span>
                      )}
                    </div>
                    <span
                      className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${ipv6HopBadgeClasses(hop.status)}`}
                    >
                      {hop.badgeLabel}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-slate-600 dark:text-slate-300">
                    <span>
                      {hop.probedNsCount > 0
                        ? `${hop.ipv4NsCount}v4 / ${hop.ipv6NsCount}v6 (${hop.probedNsCount}/${hop.totalNsCount} NS probed)`
                        : `${hop.totalNsCount} NS (unprobed)`}
                    </span>
                    {hop.inBailiwickNsCount > 0 && (
                      <span
                        className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-600 dark:text-slate-300"
                        title={`${hop.inBailiwickNsCount} in-bailiwick NS under ${hop.zoneName} require parent glue`}
                      >
                        {hop.inBailiwickNsCount} in-bailiwick glue
                      </span>
                    )}
                    {hop.ipv6Asns.length > 0 && (
                      <span
                        className={`rounded px-1.5 py-0.5 text-[9px] font-semibold ${
                          hop.singleIpv6Asn && hop.overallAsns.length >= 2
                            ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                            : 'bg-slate-200/80 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                        }`}
                      >
                        {hop.ipv6Asns.length === 1
                          ? `v6 AS${hop.ipv6Asns[0].asn}`
                          : `${hop.ipv6Asns.length} v6 ASNs`}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Leaf Web / HTTPS / Mail IPv6 Parity & DNS64 Alerts */}
          {(ipv6Audit.leaf.evaluated || ipv6Audit.dns64Detections.length > 0) && (
            <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-mono">
              {ipv6Audit.leaf.evaluated && (
                <span className="text-slate-600 dark:text-slate-300">
                  <span className="font-semibold text-slate-800 dark:text-slate-100">
                    Leaf Parity ({displayFqdn(ipv6Audit.leaf.effectiveOwner)}):{' '}
                  </span>
                  {ipv6Audit.leaf.summary}
                </span>
              )}
              {ipv6Audit.dns64Detections.map((det) => (
                <span
                  key={`${det.recordContext}-${det.ownerName}-${det.canonicalIp}`}
                  data-testid="ipv6-dns64-badge"
                  className="inline-flex items-center gap-1 rounded border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300"
                >
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  <span>
                    DNS64 {det.prefixCidr}: {det.canonicalIp}
                    {det.embeddedIpv4 ? ` → ${det.embeddedIpv4}` : ''} ({det.recordContext})
                  </span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {snapshot.zones.length > 1 && (
        <div
          data-testid="zones-jump-bar"
          className="sticky top-2 md:static z-20 rounded-xl border border-slate-200/90 dark:border-slate-800/90 bg-white/95 dark:bg-slate-900/95 backdrop-blur-sm px-3 py-2 shadow-sm flex items-center justify-between gap-2"
        >
          <div className="flex items-center gap-1.5 overflow-x-auto min-w-0">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 shrink-0 mr-0.5 hidden sm:inline">
              Jump:
            </span>
            {snapshot.zones.map((z) => {
              const slug = zoneDomSlug(z.zoneName);
              const dotCls =
                z.status === 'secure'
                  ? 'bg-emerald-500'
                  : z.status === 'bogus'
                    ? 'bg-rose-500'
                    : z.status === 'warning'
                      ? 'bg-amber-500'
                      : 'bg-slate-400';
              return (
                <button
                  key={z.zoneName}
                  type="button"
                  data-testid={`zone-jump-chip-${slug}`}
                  onClick={() => jumpToZone(z)}
                  className="inline-flex items-center gap-1.5 shrink-0 whitespace-nowrap rounded-lg border border-slate-200 dark:border-slate-800 hover:border-cyan-500 bg-slate-50 dark:bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                >
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`} />
                  <span>{z.zoneName === '.' ? 'Root (.)' : z.zoneName}</span>
                </button>
              );
            })}
          </div>

          <button
            type="button"
            data-testid="zones-toggle-all"
            onClick={() => setAllZonesCollapsed(!anyZoneCollapsed)}
            className="inline-flex items-center gap-1 shrink-0 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
          >
            {anyZoneCollapsed ? (
              <>
                <ChevronDown className="w-3.5 h-3.5 text-cyan-500" />
                <span>Expand All</span>
              </>
            ) : (
              <>
                <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                <span>Collapse All</span>
              </>
            )}
          </button>
        </div>
      )}

      {snapshot.zones.map((zone) => {
        const slug = zoneDomSlug(zone.zoneName);
        const singleZoneFilename = `${slug}.zone`;
        const collapsed = isZoneCollapsed(zone);
        const hopAudit = ipv6HopByZone.get(zone.zoneName);
        return (
        <div
          key={zone.zoneName}
          id={`zone-card-${slug}`}
          data-testid={`zone-card-${slug}`}
          data-collapsed={collapsed ? 'true' : 'false'}
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden scroll-mt-16 md:scroll-mt-44"
        >
          {/* Zone Header */}
          <div
            className={`px-4 sm:px-5 py-3.5 ${
              collapsed ? '' : 'border-b border-slate-200 dark:border-slate-800'
            } bg-slate-50/70 dark:bg-slate-900 flex flex-wrap items-center justify-between gap-3`}
          >
            <button
              type="button"
              data-testid={`zone-toggle-${slug}`}
              aria-expanded={!collapsed}
              onClick={() => toggleZone(zone)}
              className="flex flex-wrap items-center gap-2.5 text-left min-w-0 flex-1 cursor-pointer group"
            >
              {collapsed ? (
                <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0 transition-colors" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0 transition-colors" />
              )}
              <Globe className="w-4 h-4 text-cyan-500 shrink-0" />
              <span className="font-mono font-bold text-sm sm:text-base text-slate-900 dark:text-slate-100 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                {zone.zoneName === '.' ? '. (Root Zone)' : zone.zoneName}
              </span>
              <span className="rounded bg-slate-200 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                {zone.nsecMode}
              </span>
              {hopAudit && hopAudit.status !== 'unprobed' && (
                <span
                  data-testid={`zone-ipv6-hop-badge-${slug}`}
                  title={hopAudit.summary}
                  className={`rounded border px-2 py-0.5 font-mono text-[10px] font-semibold ${ipv6HopBadgeClasses(hopAudit.status)}`}
                >
                  {hopAudit.badgeLabel} ({hopAudit.ipv4NsCount}v4 / {hopAudit.ipv6NsCount}v6)
                </span>
              )}
              {collapsed && (
                <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  {zone.nameservers.length} NS · {zone.dnskeys.length} DNSKEY
                  {zone.dsVerifications.length > 0 ? ` · ${zone.dsVerifications.length} DS` : ''}
                </span>
              )}
            </button>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  handleCopyZoneText(
                    zone.zoneName,
                    formatZoneAsZonefile(zone, snapshot, {
                      includeDnssecRecords: includeDnssecInZonefile,
                    })
                  )
                }
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-950 px-2 py-1 text-[11px] font-mono text-slate-600 dark:text-slate-300 cursor-pointer"
                title={`Copy RFC 1035 zonefile for ${zone.zoneName}`}
              >
                {copiedZoneKey === zone.zoneName ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-500" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy .zone</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() =>
                  downloadTextFile(
                    formatZoneAsZonefile(zone, snapshot, {
                      includeDnssecRecords: includeDnssecInZonefile,
                    }),
                    singleZoneFilename
                  )
                }
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-950 px-2 py-1 text-[11px] font-mono text-cyan-700 dark:text-cyan-300 cursor-pointer"
                title={`Download ${singleZoneFilename}`}
              >
                <Download className="w-3 h-3" />
                <span>.zone</span>
              </button>
              <StatusBadge status={zone.status} />
            </div>
          </div>

          {!collapsed && (
          <div className="p-4 sm:p-5 space-y-5">
            <p className="text-xs text-slate-600 dark:text-slate-300">{zone.statusReason}</p>

            {/* SOA + Authoritative Nameservers Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {zone.soa && (
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                      SOA Parameters
                    </div>
                    {zone.soaAudit && (
                      <span
                        className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold ${
                          zone.soaAudit.valid
                            ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-500/25'
                            : 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/25'
                        }`}
                      >
                        {zone.soaAudit.valid ? (
                          <>
                            <CheckCircle2 className="w-3 h-3" />
                            RFC 1912 / 2308 OK
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="w-3 h-3" />
                            {zone.soaAudit.issues.length} Timer Issue
                            {zone.soaAudit.issues.length === 1 ? '' : 's'}
                          </>
                        )}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div>
                      <span className="text-slate-500">MNAME: </span>
                      <span className="text-slate-800 dark:text-slate-200">
                        <HostnameBadge hostname={zone.soa.mname} />
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Serial: </span>
                      <span className="text-cyan-600 dark:text-cyan-400 font-semibold">
                        {zone.soa.serial}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Refresh: </span>
                      <span>{zone.soa.refresh}s</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Retry: </span>
                      <span>{zone.soa.retry}s</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Expire: </span>
                      <span>{zone.soa.expire}s</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Min TTL: </span>
                      <span>{zone.soa.minimum}s</span>
                    </div>
                  </div>
                  {zone.soaAudit && zone.soaAudit.issues.length > 0 && (
                    <div className="space-y-1 pt-1 border-t border-slate-100 dark:border-slate-800/80">
                      {zone.soaAudit.issues.map((issue, idx) => (
                        <div
                          key={`${issue.parameter}-${idx}`}
                          className="text-[11px] text-amber-700 dark:text-amber-300 flex items-start gap-1.5"
                        >
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                          <span>
                            {issue.message}{' '}
                            <span className="font-mono text-[10px] opacity-80">({issue.rfc})</span>
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {zone.nameservers.length > 0 && (
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      <Server className="w-3.5 h-3.5" />
                      Authoritative Nameservers ({zone.nameservers.length})
                    </div>
                    {(zone.nsDiversity || zone.nsConsistency) && (
                      <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                        {zone.nsDiversity && zone.nsDiversity.uniqueAsns.length > 0 && (
                          <span
                            className={`rounded px-1.5 py-0.5 font-semibold border ${
                              zone.nsDiversity.singleAsn
                                ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25'
                                : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                            }`}
                          >
                            {zone.nsDiversity.uniqueAsns.length} BGP ASN
                            {zone.nsDiversity.uniqueAsns.length === 1 ? '' : 's'}
                          </span>
                        )}
                        {zone.nsDiversity && zone.nsDiversity.uniquePrefixes.length > 0 && (
                          <span
                            className={`rounded px-1.5 py-0.5 font-semibold border ${
                              zone.nsDiversity.singlePrefix
                                ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25'
                                : 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border-cyan-500/25'
                            }`}
                          >
                            {zone.nsDiversity.uniquePrefixes.length} Prefix
                            {zone.nsDiversity.uniquePrefixes.length === 1 ? '' : 'es'}
                          </span>
                        )}
                        {zone.nsDiversity &&
                          (zone.nsDiversity.dualStackReady !== undefined ? (
                            <span
                              className={`rounded px-1.5 py-0.5 font-semibold border ${
                                zone.nsDiversity.dualStackReady
                                  ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                                  : 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25'
                              }`}
                              title="RFC 3901 Dual-Stack IPv4 + IPv6 Nameserver Readiness (minimum 2 IPv4 + 2 IPv6 authoritative nameservers)"
                            >
                              {zone.nsDiversity.dualStackReady
                                ? `Dual-Stack Ready (${zone.nsDiversity.ipv4NsCount ?? 0}v4 / ${zone.nsDiversity.ipv6NsCount ?? 0}v6 ✓)`
                                : !zone.nsDiversity.hasIpv6 && zone.nsDiversity.hasIpv4
                                  ? `IPv4 Only (${zone.nsDiversity.ipv4NsCount ?? 0}v4 / 0v6)`
                                  : !zone.nsDiversity.hasIpv4 && zone.nsDiversity.hasIpv6
                                    ? `IPv6 Only (0v4 / ${zone.nsDiversity.ipv6NsCount ?? 0}v6)`
                                    : `Partial Dual-Stack (${zone.nsDiversity.ipv4NsCount ?? 0}v4 / ${zone.nsDiversity.ipv6NsCount ?? 0}v6)`}
                            </span>
                          ) : (
                            <span
                              className={`rounded px-1.5 py-0.5 font-semibold border ${
                                zone.nsDiversity.hasIpv6
                                  ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                                  : 'bg-slate-200/70 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700'
                              }`}
                            >
                              {zone.nsDiversity.hasIpv6 ? 'IPv4 + IPv6' : 'IPv4 Only'}
                            </span>
                          ))}
                        {zone.nsConsistency &&
                          (zone.nsConsistency.checkedObservations > 0 ||
                            !zone.nsConsistency.consistent) && (
                            <span
                              className={`rounded px-1.5 py-0.5 font-semibold border ${
                                zone.nsConsistency.consistent
                                  ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                                  : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'
                              }`}
                              title={zone.nsConsistency.summary}
                            >
                              {zone.nsConsistency.consistent
                                ? `NS Set Consistent (${zone.nsConsistency.checkedObservations} obs ✓)`
                                : `NS Set Skew (${zone.nsConsistency.divergentObservations.length})`}
                            </span>
                          )}
                      </div>
                    )}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs">
                    {zone.nameservers.map((ns) => {
                      const hasHygieneWarning =
                        (ns.cnameChain?.length ?? 0) > 0 || (ns.bogonIps?.length ?? 0) > 0;
                      return (
                        <div
                          key={ns.hostname}
                          className={`rounded border px-2.5 py-1.5 ${
                            ns.status === 'dangling'
                              ? 'border-rose-500/40 bg-rose-500/5'
                              : hasHygieneWarning
                                ? 'border-amber-500/40 bg-amber-500/5'
                                : 'border-slate-100 dark:border-slate-800/90 bg-slate-50 dark:bg-slate-950/50'
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-1.5">
                            <div className="font-mono font-medium text-slate-800 dark:text-slate-200 truncate">
                              <HostnameBadge hostname={ns.hostname} />
                            </div>
                            <div className="flex flex-wrap items-center gap-1">
                              {ns.status === 'dangling' && (
                                <span className="shrink-0 rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-rose-600 dark:text-rose-400">
                                  DANGLING
                                </span>
                              )}
                              {ns.cnameChain && ns.cnameChain.length > 0 && (
                                <span
                                  className="shrink-0 rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-700 dark:text-amber-300"
                                  title="RFC 2181 §10.3: Authoritative NS target must not be a CNAME alias"
                                >
                                  CNAME ALIAS
                                </span>
                              )}
                              {ns.bogonIps && ns.bogonIps.length > 0 && (
                                <span
                                  className="shrink-0 rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-700 dark:text-amber-300"
                                  title="Resolves to private, loopback, link-local, documentation, or CGNAT bogon space"
                                >
                                  BOGON IP
                                </span>
                              )}
                              {ns.addressStack === 'dual-stack' && (
                                <span className="shrink-0 rounded bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-emerald-700 dark:text-emerald-300">
                                  v4+v6
                                </span>
                              )}
                              {ns.addressStack === 'ipv4-only' && (
                                <span className="shrink-0 rounded bg-amber-500/10 border border-amber-500/25 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-amber-700 dark:text-amber-300">
                                  IPv4-only
                                </span>
                              )}
                              {ns.addressStack === 'ipv6-only' && (
                                <span className="shrink-0 rounded bg-amber-500/10 border border-amber-500/25 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-amber-700 dark:text-amber-300">
                                  IPv6-only
                                </span>
                              )}
                            </div>
                          </div>
                          {ns.cnameChain && ns.cnameChain.length > 0 && (
                            <div className="mt-0.5 font-mono text-[10px] text-amber-700 dark:text-amber-300">
                              RFC 2181 §10.3 alias →{' '}
                              {ns.cnameChain.map((c, cIdx) => (
                                <span key={c}>
                                  <HostnameBadge hostname={c} />
                                  {cIdx < ns.cnameChain!.length - 1 ? ' → ' : ''}
                                </span>
                              ))}
                            </div>
                          )}
                          {ns.bogonIps && ns.bogonIps.length > 0 && (
                            <div className="mt-0.5 font-mono text-[10px] text-amber-700 dark:text-amber-300">
                              Non-public:{' '}
                              {ns.bogonIps.map((b) => `${b.ip} (${b.reason})`).join(', ')}
                            </div>
                          )}
                          {(ns.ipv4.length > 0 || ns.ipv6.length > 0) && (
                            <div className="font-mono text-[10px] text-slate-500 flex flex-wrap gap-x-1.5 gap-y-0.5 mt-0.5">
                              {[...ns.ipv4, ...ns.ipv6].map((ip, ipIdx, arr) => (
                                <span key={ip}>
                                  <IpHoverBadge ip={ip} />
                                  {ipIdx < arr.length - 1 ? ',' : ''}
                                </span>
                              ))}
                            </div>
                          )}
                          {((ns.asns && ns.asns.length > 0) ||
                            (ns.bgpPrefixes && ns.bgpPrefixes.length > 0) ||
                            ns.rpkiStatus) && (
                            <div className="flex flex-wrap items-center gap-1 mt-1">
                              {ns.asns?.map((a) => (
                                <span
                                  key={a.asn}
                                  className="inline-flex items-center gap-1 rounded bg-cyan-500/10 border border-cyan-500/25 px-1.5 py-0.5 font-mono text-[10px] text-cyan-700 dark:text-cyan-300"
                                >
                                  <span className="font-bold">AS{a.asn}</span>
                                  {a.asName && (
                                    <span className="truncate max-w-[140px] opacity-85">
                                      · {a.asName}
                                    </span>
                                  )}
                                </span>
                              ))}
                              {ns.bgpPrefixes?.map((pfx) => (
                                <span
                                  key={pfx}
                                  className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300"
                                >
                                  {pfx}
                                </span>
                              ))}
                              {ns.rpkiStatus && ns.rpkiStatus !== 'error' && (
                                <RpkiStatusBadge
                                  status={ns.rpkiStatus}
                                  validation={ns.rpkiValidations?.[0]}
                                  compact
                                />
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  {zone.nsDiversity && (
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {zone.nsDiversity.summary}
                    </div>
                  )}
                  {zone.nsConsistency && !zone.nsConsistency.consistent && (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-2.5 py-2 text-[11px] text-amber-800 dark:text-amber-200 space-y-1">
                      <div className="flex items-center gap-1.5 font-semibold">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-500" />
                        <span>Intra-Zone NS RRset Skew (ANSWER vs. AUTHORITY / Multi-DoH)</span>
                      </div>
                      <div className="text-amber-700/90 dark:text-amber-300/90">
                        {zone.nsConsistency.summary}
                      </div>
                      <div className="space-y-0.5 font-mono text-[10px]">
                        {zone.nsConsistency.divergentObservations.slice(0, 4).map((obs) => (
                          <div
                            key={`${obs.sourceQueryId}-${obs.section}`}
                            className="flex flex-wrap items-center gap-x-2 gap-y-0.5"
                          >
                            <span className="font-semibold">
                              {displayFqdn(obs.qname)} {obs.qtypeName} ({obs.section.toUpperCase()}{' '}
                              via {formatDohShortLabel(obs.endpoint)}):
                            </span>
                            {obs.extraTargets.map((t) => (
                              <span
                                key={`extra-${t}`}
                                className="rounded bg-amber-500/15 px-1 py-0.5 text-amber-800 dark:text-amber-200"
                              >
                                <HostnameBadge hostname={t}>{`+${displayFqdn(t)}`}</HostnameBadge>
                              </span>
                            ))}
                            {obs.missingTargets.map((t) => (
                              <span
                                key={`missing-${t}`}
                                className="rounded bg-rose-500/15 px-1 py-0.5 text-rose-700 dark:text-rose-300"
                              >
                                <HostnameBadge hostname={t}>{`-${displayFqdn(t)}`}</HostnameBadge>
                              </span>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* CDS / CDNSKEY Automated Rollover Sync (RFC 7344 / RFC 8078) */}
            {zone.cdsRollover?.present && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <RefreshCw className="w-3.5 h-3.5 text-cyan-500" />
                    Automated DNSSEC Rollover Sync (CDS / CDNSKEY · RFC 7344 / 8078)
                  </div>
                  <span
                    className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold border ${
                      zone.cdsRollover.status === 'in-sync'
                        ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                        : zone.cdsRollover.status === 'rollover-pending'
                          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25'
                          : 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/25'
                    }`}
                  >
                    {zone.cdsRollover.status === 'in-sync'
                      ? 'IN SYNC WITH PARENT DS ✓'
                      : zone.cdsRollover.status === 'rollover-pending'
                        ? 'ROLLOVER / PARENT DS MISMATCH'
                        : zone.cdsRollover.status === 'delete-signal'
                          ? 'RFC 8078 DELETE SIGNAL'
                          : 'UNSIGNED / INVALID KSK SIG'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {zone.cdsRollover.summary}
                </p>
                <div className="space-y-1.5">
                  {zone.cdsRollover.cdsRecords.map((cds, idx) => (
                    <div
                      key={`cds-${cds.keyTag}-${cds.digestType}-${idx}`}
                      className="rounded border border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 px-2.5 py-1.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0 flex flex-wrap items-center gap-1.5">
                        <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px] font-bold">
                          CDS
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{cds.keyTag}
                        </span>
                        <span>
                          · {formatAlgorithm(cds.algorithm)} · {formatDigestType(cds.digestType)} ·
                        </span>
                        <CryptoBlob
                          value={cds.digestHex}
                          compact
                          headChars={12}
                          tailChars={10}
                          testId={`crypto-cds-${slug}-${cds.keyTag}-${idx}`}
                        />
                      </div>
                      <span
                        className={`text-[10px] font-semibold ${
                          cds.isDeleteSignal
                            ? 'text-rose-600 dark:text-rose-400'
                            : cds.matchesParentDs
                              ? 'text-emerald-600 dark:text-emerald-400'
                              : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        {cds.isDeleteSignal
                          ? 'DELETE DS (RFC 8078)'
                          : cds.matchesParentDs
                            ? 'Matches Parent DS ✓'
                            : 'Not in Parent DS'}
                      </span>
                    </div>
                  ))}
                  {zone.cdsRollover.cdnskeyRecords.map((ck, idx) => (
                    <div
                      key={`cdnskey-${ck.keyTag}-${idx}`}
                      className="rounded border border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 px-2.5 py-1.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0 flex flex-wrap items-center gap-1.5">
                        <span className="rounded bg-purple-500/15 text-purple-700 dark:text-purple-300 px-1.5 py-0.5 text-[10px] font-bold">
                          CDNSKEY
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{ck.keyTag}
                        </span>
                        <span>· flags={ck.flags} · {formatAlgorithm(ck.algorithm)}</span>
                        {!ck.isDeleteSignal && ck.publicKeyBase64 && (
                          <>
                            <span>·</span>
                            <CryptoBlob
                              value={ck.publicKeyBase64}
                              collapseOnDesktop
                              compact
                              headChars={10}
                              tailChars={8}
                              copyLabel="Copy Key"
                              testId={`crypto-cdnskey-${slug}-${ck.keyTag}-${idx}`}
                            />
                          </>
                        )}
                      </div>
                      <span
                        className={`text-[10px] font-semibold ${
                          ck.isDeleteSignal
                            ? 'text-rose-600 dark:text-rose-400'
                            : ck.matchesChildDnskey
                              ? 'text-emerald-600 dark:text-emerald-400'
                              : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        {ck.isDeleteSignal
                          ? 'DELETE DS (RFC 8078)'
                          : ck.matchesChildDnskey
                            ? 'Matches Active DNSKEY ✓'
                            : 'Unmatched Key'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ZONEMD Zone Digest (RFC 8976) */}
            {zone.zonemd?.present && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <Fingerprint className="w-3.5 h-3.5 text-cyan-500" />
                    Message Digest for DNS Zones (ZONEMD · RFC 8976)
                  </div>
                  <div className="flex items-center gap-2">
                    {zone.zonemd.dnssecStatus && (
                      <StatusBadge status={zone.zonemd.dnssecStatus} size="xs" />
                    )}
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold border ${
                        zone.zonemd.status === 'valid-sync'
                          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                          : zone.zonemd.status === 'serial-mismatch' ||
                              zone.zonemd.status === 'unsigned-warning'
                            ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25'
                            : 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/25'
                      }`}
                    >
                      {zone.zonemd.status === 'valid-sync'
                        ? 'SOA SERIAL IN SYNC ✓'
                        : zone.zonemd.status === 'serial-mismatch'
                          ? 'SOA SERIAL MISMATCH'
                          : zone.zonemd.status === 'unsigned-warning'
                            ? 'UNSIGNED ZONEMD'
                            : 'INVALID DIGEST'}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {zone.zonemd.summary}
                </p>
                <div className="space-y-1.5">
                  {zone.zonemd.records.map((zmd, idx) => (
                    <div
                      key={`zonemd-${zmd.serial}-${zmd.scheme}-${zmd.hashAlgorithm}-${idx}`}
                      className="rounded border border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 px-2.5 py-1.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0 flex flex-wrap items-center gap-1.5">
                        <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px] font-bold">
                          ZONEMD
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          serial={zmd.serial}
                        </span>
                        <span>
                          · {zmd.schemeName} ({zmd.scheme}) · {zmd.hashAlgorithmName} (
                          {zmd.hashAlgorithm}, {zmd.digestByteLength}B) ·
                        </span>
                        <CryptoBlob
                          value={zmd.digestHex}
                          compact
                          headChars={12}
                          tailChars={10}
                          testId={`crypto-zonemd-${slug}-${idx}`}
                        />
                      </div>
                      <span
                        className={`text-[10px] font-semibold ${
                          !zmd.digestLengthValid
                            ? 'text-rose-600 dark:text-rose-400'
                            : zmd.serialMatchesSoa
                              ? 'text-emerald-600 dark:text-emerald-400'
                              : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        {!zmd.digestLengthValid
                          ? 'Invalid Digest Length'
                          : zmd.serialMatchesSoa
                            ? 'Matches SOA Serial ✓'
                            : `SOA Serial=${zone.zonemd?.soaSerial ?? '—'}`}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Wildcard DNS (*.zone) Synthesis Probe & RFC 4035 / 5155 Proof */}
            {zone.wildcardAudit && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-500" />
                    Wildcard DNS (*.{displayFqdn(zone.zoneName)}) Synthesis Probe &amp; RFC 4035
                    Proof
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold border ${
                        zone.wildcardAudit.status === 'no-wildcard'
                          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                          : zone.wildcardAudit.status === 'wildcard-bogus'
                            ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/30'
                            : 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30'
                      }`}
                    >
                      {zone.wildcardAudit.status === 'no-wildcard'
                        ? 'NO WILDCARD (NXDOMAIN ✓)'
                        : zone.wildcardAudit.status === 'wildcard-mx-risk'
                          ? `WILDCARD MX RISK (*.${displayFqdn(zone.zoneName)})`
                          : zone.wildcardAudit.status === 'wildcard-bogus'
                            ? 'BOGUS WILDCARD PROOF'
                            : `WILDCARD ACTIVE (${zone.wildcardAudit.wildcardTypes.join(', ')})`}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {zone.wildcardAudit.summary}
                </p>
                {zone.wildcardAudit.wildcardDetected && (
                  <div className="space-y-1.5">
                    {zone.wildcardAudit.probes
                      .filter((p) => p.synthesized)
                      .map((p) => (
                        <div
                          key={`wc-${p.qtype}`}
                          className="rounded border border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 px-2.5 py-2 space-y-1 text-xs font-mono"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 text-[10px] font-bold">
                                {p.qtype}
                              </span>
                              <span className="font-semibold text-slate-800 dark:text-slate-200">
                                {p.wildcardSourceName ?? `*.${zone.zoneName}`}
                              </span>
                              <span className="text-slate-500">→</span>
                              <span className="text-slate-700 dark:text-slate-300">
                                {p.answerValues.length > 0
                                  ? p.qtype === 'A' || p.qtype === 'AAAA'
                                    ? p.answerValues.map((val, vIdx) => (
                                        <span key={val}>
                                          <IpHoverBadge ip={val} />
                                          {vIdx < p.answerValues.length - 1 ? ', ' : ''}
                                        </span>
                                      ))
                                    : p.answerValues.map((val, vIdx) => {
                                        const mxMatch = val.match(/^(\d+\s+)(\S+)$/);
                                        return (
                                          <span key={val}>
                                            {mxMatch ? (
                                              <>
                                                {mxMatch[1]}
                                                {mxMatch[2] === '.' ? (
                                                  '.'
                                                ) : (
                                                  <HostnameBadge hostname={mxMatch[2]!} />
                                                )}
                                              </>
                                            ) : (
                                              <HostnameBadge hostname={val} />
                                            )}
                                            {vIdx < p.answerValues.length - 1 ? ', ' : ''}
                                          </span>
                                        );
                                      })
                                  : p.cnameChain.map((c, cIdx) => (
                                      <span key={c}>
                                        <HostnameBadge hostname={c} />
                                        {cIdx < p.cnameChain.length - 1 ? ' → ' : ''}
                                      </span>
                                    ))}
                              </span>
                            </div>
                            <StatusBadge status={p.dnssecStatus} size="xs" />
                          </div>
                          {p.expansionMode === 'rfc4035-wildcard' && (
                            <div className="text-[11px] text-slate-500 dark:text-slate-400">
                              RFC 4035 §5.3.4 expansion: RRSIG labels={p.rrsigLabels} &lt; QNAME
                              labels={p.qnameLabels} (Closest Encloser:{' '}
                              <span className="text-slate-700 dark:text-slate-300">
                                {p.closestEncloser}
                              </span>
                              ){p.nsecProofSummary ? ` · ${p.nsecProofSummary}` : ''}
                            </div>
                          )}
                          {p.expansionMode === 'online-signed' && p.nsecProofSummary && (
                            <div className="text-[11px] text-slate-500 dark:text-slate-400">
                              {p.nsecProofSummary}
                            </div>
                          )}
                        </div>
                      ))}
                  </div>
                )}
              </div>
            )}

            {/* Apex TXT Records & SaaS Verification Hygiene */}
            {zone.txtHygiene && zone.txtHygiene.recordCount > 0 && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <FileText className="w-3.5 h-3.5 text-cyan-500" />
                    Apex TXT Inventory &amp; SaaS Verification Hygiene ({zone.txtHygiene.recordCount}
                    )
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                    <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-600 dark:text-slate-300">
                      {zone.txtHygiene.totalWireBytes} B RDATA
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold border ${
                        zone.txtHygiene.status === 'warning'
                          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30'
                          : zone.txtHygiene.saasVerificationCount > 0
                            ? 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border-cyan-500/30'
                            : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                      }`}
                    >
                      {zone.txtHygiene.status === 'warning'
                        ? 'HYGIENE WARNING'
                        : zone.txtHygiene.saasVerificationCount > 0
                          ? `${zone.txtHygiene.saasVerificationCount} SAAS / ID TOKENS`
                          : 'CLEAN APEX TXT'}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {zone.txtHygiene.summary}
                </p>
                <div className="space-y-1.5">
                  {zone.txtHygiene.entries.map((entry, idx) => (
                    <div
                      key={`txt-hygiene-${idx}-${entry.rawText.slice(0, 24)}`}
                      className={`rounded border px-2.5 py-1.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs ${
                        entry.status === 'misplaced-at-apex' || entry.status === 'malformed'
                          ? 'border-amber-500/40 bg-amber-500/5'
                          : entry.status === 'duplicate'
                            ? 'border-amber-500/30 bg-amber-500/5'
                            : 'border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50'
                      }`}
                    >
                      <div className="min-w-0 space-y-0.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-slate-700 dark:text-slate-300">
                            {entry.provider}
                          </span>
                          <span className="font-mono text-[10px] text-slate-400">
                            {entry.byteLength}B
                          </span>
                          {entry.status !== 'valid' && (
                            <span className="rounded bg-amber-500/20 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase">
                              {entry.status === 'misplaced-at-apex'
                                ? 'Misplaced at Apex'
                                : entry.status}
                            </span>
                          )}
                        </div>
                        <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 break-all">
                          {entry.rawText}
                        </div>
                        {entry.issue && (
                          <div className="text-[11px] text-amber-700 dark:text-amber-300 font-medium">
                            {entry.issue}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* DNSKEY Inventory Table */}
            {zone.dnskeys.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  <KeyRound className="w-3.5 h-3.5" />
                  DNSKEY Inventory ({zone.dnskeys.length})
                </div>
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-900/80 text-slate-500 font-medium border-b border-slate-200 dark:border-slate-800">
                      <tr>
                        <th className="px-3 py-2">Key Tag</th>
                        <th className="px-3 py-2">Role</th>
                        <th className="px-3 py-2">Flags</th>
                        <th className="px-3 py-2">Algorithm</th>
                        <th className="px-3 py-2">Strength</th>
                        <th className="px-3 py-2">Public Key</th>
                        <th className="px-3 py-2">Signs RRsets</th>
                        <th className="px-3 py-2">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 font-mono">
                      {zone.dnskeys.map((k) => (
                        <tr key={k.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                          <td className="px-3 py-2 font-semibold text-slate-900 dark:text-slate-100">
                            #{k.keyTag}
                          </td>
                          <td className="px-3 py-2 uppercase text-[11px]">{k.role}</td>
                          <td className="px-3 py-2">{k.flags}</td>
                          <td className="px-3 py-2">{formatAlgorithm(k.algorithm)}</td>
                          <td className="px-3 py-2">{k.keySizeInfo}</td>
                          <td className="px-3 py-2">
                            {k.publicKeyBase64 ? (
                              <CryptoBlob
                                value={k.publicKeyBase64}
                                collapseOnDesktop
                                compact
                                headChars={10}
                                tailChars={8}
                                copyLabel="Copy Key"
                                testId={`crypto-dnskey-${slug}-${k.keyTag}`}
                              />
                            ) : (
                              '—'
                            )}
                          </td>
                          <td className="px-3 py-2">
                            {k.signsTypes.length > 0 ? k.signsTypes.join(', ') : '—'}
                          </td>
                          <td className="px-3 py-2">
                            <StatusBadge status={k.status} size="xs" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Parent DS Records */}
            {zone.dsVerifications.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Delegation Signer (DS) Records in {zone.parentZone}
                </div>
                <div className="space-y-1.5">
                  {zone.dsVerifications.map((dsv) => (
                    <div
                      key={dsv.id}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="min-w-0 flex flex-wrap items-center gap-1.5">
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{dsv.ds.keyTag}
                        </span>
                        <span>
                          · {formatAlgorithm(dsv.ds.algorithm)} ·{' '}
                          {formatDigestType(dsv.ds.digestType)} ·
                        </span>
                        <CryptoBlob
                          value={dsv.ds.digestHex}
                          compact
                          headChars={12}
                          tailChars={10}
                          testId={`crypto-ds-${slug}-${dsv.ds.keyTag}`}
                        />
                      </div>
                      <StatusBadge status={dsv.status} size="xs" />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          )}
        </div>
        );
      })}
    </div>
  );
}
