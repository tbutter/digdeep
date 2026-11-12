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
import { formatAlgorithm, formatDigestType } from '../dns/constants';
import {
  downloadTextFile,
  formatSnapshotAsZonefile,
  formatZoneAsZonefile,
} from '../dns/digFormat';
import { displayFqdn, normalizeFqdn } from '../dns/encoding';
import type { AnalysisSnapshot, ZoneAnalysis } from '../dns/types';
import { IpHoverBadge, RpkiStatusBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
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
  if (zone.nameservers.some((ns) => ns.status === 'dangling')) return false;
  if (zone.cdsRollover?.present && zone.cdsRollover.status !== 'in-sync') return false;
  if (zone.zonemd?.present && zone.zonemd.status !== 'valid-sync') return false;
  if (zone.wildcardAudit && zone.wildcardAudit.status !== 'no-wildcard') return false;
  if (zone.txtHygiene && zone.txtHygiene.status === 'warning') return false;
  return true;
}

function zoneDomSlug(zoneName: string): string {
  return zoneName === '.' ? 'root' : displayFqdn(zoneName).replace(/[^a-z0-9.-]/gi, '_');
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
                        {displayFqdn(zone.soa.mname)}
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
                    {zone.nsDiversity && (
                      <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                        {zone.nsDiversity.uniqueAsns.length > 0 && (
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
                        {zone.nsDiversity.uniquePrefixes.length > 0 && (
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
                        <span
                          className={`rounded px-1.5 py-0.5 font-semibold border ${
                            zone.nsDiversity.hasIpv6
                              ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25'
                              : 'bg-slate-200/70 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700'
                          }`}
                        >
                          {zone.nsDiversity.hasIpv6 ? 'IPv4 + IPv6' : 'IPv4 Only'}
                        </span>
                      </div>
                    )}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs">
                    {zone.nameservers.map((ns) => (
                      <div
                        key={ns.hostname}
                        className={`rounded border px-2.5 py-1.5 ${
                          ns.status === 'dangling'
                            ? 'border-rose-500/40 bg-rose-500/5'
                            : 'border-slate-100 dark:border-slate-800/90 bg-slate-50 dark:bg-slate-950/50'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1.5">
                          <div className="font-mono font-medium text-slate-800 dark:text-slate-200 truncate">
                            {displayFqdn(ns.hostname)}
                          </div>
                          {ns.status === 'dangling' && (
                            <span className="shrink-0 rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-rose-600 dark:text-rose-400">
                              DANGLING
                            </span>
                          )}
                        </div>
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
                    ))}
                  </div>
                  {zone.nsDiversity && (
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {zone.nsDiversity.summary}
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
                      <div className="min-w-0 break-all">
                        <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px] font-bold mr-2">
                          CDS
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{cds.keyTag}
                        </span>{' '}
                        · {formatAlgorithm(cds.algorithm)} · {formatDigestType(cds.digestType)} ·{' '}
                        <span className="text-slate-500 text-[11px]">{cds.digestHex}</span>
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
                      <div className="min-w-0 break-all">
                        <span className="rounded bg-purple-500/15 text-purple-700 dark:text-purple-300 px-1.5 py-0.5 text-[10px] font-bold mr-2">
                          CDNSKEY
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{ck.keyTag}
                        </span>{' '}
                        · flags={ck.flags} · {formatAlgorithm(ck.algorithm)}
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
                      <div className="min-w-0 break-all">
                        <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px] font-bold mr-2">
                          ZONEMD
                        </span>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          serial={zmd.serial}
                        </span>{' '}
                        · {zmd.schemeName} ({zmd.scheme}) · {zmd.hashAlgorithmName} (
                        {zmd.hashAlgorithm}, {zmd.digestByteLength}B) ·{' '}
                        <span className="text-slate-500 text-[11px]">{zmd.digestHex}</span>
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
                                    : p.answerValues.join(', ')
                                  : p.cnameChain.join(' → ')}
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
                      <div className="min-w-0 break-all">
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          #{dsv.ds.keyTag}
                        </span>{' '}
                        · {formatAlgorithm(dsv.ds.algorithm)} ·{' '}
                        {formatDigestType(dsv.ds.digestType)} ·{' '}
                        <span className="text-slate-500 text-[11px]">{dsv.ds.digestHex}</span>
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
