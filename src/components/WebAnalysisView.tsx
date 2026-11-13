import { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileCheck2,
  Globe,
  KeyRound,
  Layers,
  Lock,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { displayFqdn } from '../dns/encoding';
import { MAX_PORTFOLIO_DOMAINS } from '../dns/portfolioAnalyzer';
import { fetchCtLogEntries } from '../dns/webAnalyzer';
import type {
  AnalysisSnapshot,
  CtCertificateEntry,
  DaneHostStatus,
  WebAnalysisResult,
  WebCaaAnalysis,
  WebCtAnalysis,
  WebSvcbRecordDetail,
} from '../dns/types';
import {
  type FocusedWireSubMode,
  findWireQueryByGraphTargetId,
  findWireQueryByOwnerAndType,
} from '../dns/wireQueryFilter';
import { IpHoverBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { CryptoBlob } from './CryptoBlob';
import { StatusBadge } from './StatusBadge';

function getHttpsBadgeMeta(status: WebAnalysisResult['httpsStatus']): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'ech-enabled':
      return {
        label: 'HTTPS + ECH ACTIVE',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'valid':
      return {
        label: 'HTTPS SERVICE MODE',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'alias-mode':
      return {
        label: 'HTTPS ALIAS MODE (0)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'warning':
      return {
        label: 'HTTPS · WARNING',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'bogus':
      return {
        label: 'HTTPS · BOGUS',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'not-deployed':
      return {
        label: 'NO HTTPS RR',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
  }
}

function getCaaBadgeMeta(status: WebCaaAnalysis['status']): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'enforced':
      return {
        label: 'CAA ENFORCED',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'inherited':
      return {
        label: 'CAA INHERITED (TREE-WALK)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'permissive':
      return {
        label: 'CAA PERMISSIVE (NO ISSUE)',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'unprotected':
      return {
        label: 'NO CAA POLICY',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
    case 'invalid':
      return {
        label: 'CAA INVALID / CRITICAL BLOCK',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
  }
}

function getDaneBadgeMeta(status: DaneHostStatus): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'dane-valid':
      return {
        label: 'DANE VERIFIED',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'dane-warning':
      return {
        label: 'DANE · WARN',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'dane-unsigned-ignored':
      return {
        label: 'UNSIGNED TLSA (IGNORED)',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'dane-bogus':
      return {
        label: 'DANE BOGUS',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'no-tlsa-secure':
      return {
        label: 'NO TLSA (SIGNED NSEC)',
        cls: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30',
      };
    case 'no-tlsa-unsigned':
      return {
        label: 'NO TLSA (UNSIGNED)',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
  }
}

function getSshfpBadgeMeta(status: WebAnalysisResult['sshfp']['status']): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'secure':
      return {
        label: 'SSHFP VERIFIED (AD=1)',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'insecure-ignored':
      return {
        label: 'UNSIGNED SSHFP (IGNORED)',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'warning':
      return {
        label: 'SSHFP · DEPRECATED',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'bogus':
      return {
        label: 'SSHFP BOGUS',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'not-deployed':
      return {
        label: 'NO SSHFP',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
  }
}

function getCtBadgeMeta(status: WebCtAnalysis['status']): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'caa-compliant':
      return {
        label: 'CT ↔ CAA COMPLIANT',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'caa-mismatch':
      return {
        label: 'CT ↔ CAA MISMATCH',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'unrestricted':
      return {
        label: 'CT ACTIVE · NO CAA',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'no-active-certs':
      return {
        label: 'NO ACTIVE CT CERTS',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
    case 'unavailable':
      return {
        label: 'CT LOGS UNAVAILABLE',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
  }
}

function getCtCertVerdictMeta(verdict: CtCertificateEntry['caaAuthorized']): {
  label: string;
  cls: string;
} {
  switch (verdict) {
    case 'authorized':
      return {
        label: 'CAA AUTHORIZED ✓',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'unauthorized-ca':
      return {
        label: 'UNAUTHORIZED CA',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'unauthorized-wildcard':
      return {
        label: 'WILDCARD NOT IN ISSUEWILD',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'unrestricted':
      return {
        label: 'UNRESTRICTED CAA',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
  }
}

function SvcbRecordCard({
  rec,
  onJumpToGraphTarget,
  onInspectWireQuery,
  rrsetId,
  wireQueryId,
}: {
  rec: WebSvcbRecordDetail;
  onJumpToGraphTarget: (targetId: string) => void;
  onInspectWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
  rrsetId?: string;
  wireQueryId?: string;
}) {
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[11px] font-bold">
            {rec.rrtypeName} Priority {rec.priority}
          </span>
          <span
            className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
              rec.isAliasMode
                ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30'
                : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
            }`}
          >
            {rec.isAliasMode ? 'AliasMode (0)' : 'ServiceMode'}
          </span>
          <span className="font-mono text-xs text-slate-700 dark:text-slate-200">
            Target:{' '}
            <strong>{rec.target === '.' ? '. (owner name)' : displayFqdn(rec.target)}</strong>
          </span>
          <span className="font-mono text-[11px] text-slate-400">TTL {rec.ttl}s</span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {rrsetId && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(rrsetId)}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-0.5 text-[11px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
            >
              <span>Inspect in Graph</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
          {wireQueryId && onInspectWireQuery && (
            <button
              type="button"
              onClick={() => onInspectWireQuery(wireQueryId, 'dig')}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
            >
              <Terminal className="w-3 h-3 text-cyan-500" />
              <span>Wire</span>
            </button>
          )}
        </div>
      </div>

      {/* SvcParams Grid */}
      {rec.params.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
          {rec.alpns.length > 0 && (
            <div className="rounded border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-1.5 flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] text-slate-500">alpn (key 1):</span>
              <div className="flex flex-wrap items-center gap-1">
                {rec.alpns.map((a) => (
                  <span
                    key={a}
                    className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold ${
                      a === 'h3' || a.startsWith('h3-')
                        ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                        : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300'
                    }`}
                  >
                    {a}
                  </span>
                ))}
                {rec.noDefaultAlpn && (
                  <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 font-mono text-[10px]">
                    no-default-alpn
                  </span>
                )}
              </div>
            </div>
          )}

          {rec.port !== undefined && (
            <div className="rounded border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-1.5 flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] text-slate-500">port (key 3):</span>
              <span className="font-mono font-semibold">{rec.port}</span>
            </div>
          )}

          {rec.ipv4Hints.length > 0 && (
            <div className="rounded border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-1.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-slate-500">ipv4hint (key 4):</span>
                <span
                  className={`font-mono text-[10px] font-semibold ${
                    rec.ipv4HintsDrifted.length > 0 ? 'text-amber-500' : 'text-emerald-500'
                  }`}
                >
                  {rec.ipv4HintsDrifted.length > 0
                    ? `${rec.ipv4HintsDrifted.length} drifted from A RRset`
                    : 'Matches A RRset'}
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {rec.ipv4Hints.map((ip) => {
                  const drifted = rec.ipv4HintsDrifted.includes(ip);
                  return (
                    <span
                      key={ip}
                      className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${
                        drifted
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/40'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                      }`}
                    >
                      <IpHoverBadge ip={ip} />
                      {drifted ? ' (drift)' : ''}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {rec.ipv6Hints.length > 0 && (
            <div className="rounded border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-1.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-slate-500">ipv6hint (key 6):</span>
                <span
                  className={`font-mono text-[10px] font-semibold ${
                    rec.ipv6HintsDrifted.length > 0 ? 'text-amber-500' : 'text-emerald-500'
                  }`}
                >
                  {rec.ipv6HintsDrifted.length > 0
                    ? `${rec.ipv6HintsDrifted.length} drifted from AAAA RRset`
                    : 'Matches AAAA RRset'}
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {rec.ipv6Hints.map((ip) => {
                  const drifted = rec.ipv6HintsDrifted.includes(ip);
                  return (
                    <span
                      key={ip}
                      className={`rounded px-1.5 py-0.5 font-mono text-[11px] break-all ${
                        drifted
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/40'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                      }`}
                    >
                      <IpHoverBadge ip={ip} />
                      {drifted ? ' (drift)' : ''}
                    </span>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TLS Encrypted ClientHello (ECHConfigList) */}
      {rec.echConfigs.length > 0 && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2.5 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
            <Lock className="w-3.5 h-3.5" />
            <span>
              TLS Encrypted ClientHello (ECHConfigList · {rec.echConfigs.length} config
              {rec.echConfigs.length === 1 ? '' : 's'})
            </span>
          </div>
          <div className="space-y-1.5">
            {rec.echConfigs.map((cfg, idx) => (
              <div
                key={`${cfg.configId}-${idx}`}
                className="rounded border border-emerald-500/20 bg-white/80 dark:bg-slate-900/80 px-2.5 py-1.5 text-[11px] font-mono flex flex-wrap items-center justify-between gap-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-bold text-emerald-700 dark:text-emerald-300">
                    ECH ({cfg.versionHex})
                  </span>
                  <span>config_id={cfg.configId}</span>
                  <span>
                    public_name=<strong>{cfg.publicName}</strong>
                  </span>
                  <span>KEM={cfg.kemName}</span>
                  <span>pubKey={cfg.publicKeyLength * 8}b</span>
                </div>
                <div className="text-slate-500">
                  Suites:{' '}
                  {cfg.cipherSuites.map((s) => `${s.kdfName}+${s.aeadName}`).join(', ')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {rec.issues.length > 0 && (
        <div className="space-y-1">
          {rec.issues.map((iss, i) => (
            <div
              key={i}
              className="flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-300"
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{iss}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type WebSectionId = 'https' | 'caa' | 'ct' | 'dane' | 'sshfp';

export function WebAnalysisView({
  snapshot,
  onJumpToGraphTarget,
  onOpenChainGraph,
  onInspectWireQuery,
  onTraceDomain,
  onBatchAuditDomains,
}: {
  snapshot: AnalysisSnapshot;
  onJumpToGraphTarget: (targetId: string) => void;
  onOpenChainGraph: () => void;
  onInspectWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
  onTraceDomain?: (domain: string) => void;
  onBatchAuditDomains?: (domains: string[], sourceLabel?: string) => void;
}) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const web = snapshot.webAnalysis;
  const [showAllCtCerts, setShowAllCtCerts] = useState(false);
  const [scanningSubdomains, setScanningSubdomains] = useState(false);
  const [extraSubdomains, setExtraSubdomains] = useState<string[]>([]);
  const [subScanError, setSubScanError] = useState<string | null>(null);
  const [collapsedSections, setCollapsedSections] = useState<
    Partial<Record<WebSectionId, boolean>>
  >({});

  if (!web) return null;

  const httpsMeta = getHttpsBadgeMeta(web.httpsStatus);
  const caaMeta = getCaaBadgeMeta(web.caa.status);
  const daneMeta = getDaneBadgeMeta(web.webDane.status);
  const sshfpMeta = getSshfpBadgeMeta(web.sshfp.status);
  const ct = web.ctAnalysis;
  const ctMeta = ct ? getCtBadgeMeta(ct.status) : null;

  const presentSections: Array<{ id: WebSectionId; label: string }> = [
    { id: 'https', label: 'HTTPS / SVCB' },
    { id: 'caa', label: 'CAA Policy' },
    ...(ct ? [{ id: 'ct' as const, label: `CT Logs (${ct.activeCertCount})` }] : []),
    { id: 'dane', label: 'Web DANE' },
    { id: 'sshfp', label: 'SSHFP' },
  ];
  const anySectionCollapsed = presentSections.some((s) => Boolean(collapsedSections[s.id]));

  const toggleSection = (id: WebSectionId) => {
    setCollapsedSections((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const setAllSectionsCollapsed = (collapsed: boolean) => {
    const next: Partial<Record<WebSectionId, boolean>> = {};
    for (const s of presentSections) {
      next[s.id] = collapsed;
    }
    setCollapsedSections(next);
  };

  const jumpToSection = (id: WebSectionId) => {
    const domId = `web-section-${id}`;
    const wasCollapsed = Boolean(collapsedSections[id]);
    if (wasCollapsed) {
      setCollapsedSections((prev) => ({ ...prev, [id]: false }));
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

  const mergedSubdomains = Array.from(
    new Set([...(ct?.discoveredSubdomains ?? []), ...extraSubdomains])
  );

  const handleScanSubdomainCtLogs = async () => {
    setScanningSubdomains(true);
    setSubScanError(null);
    try {
      const res = await fetchCtLogEntries(web.displayDomain, {
        includeSubdomains: true,
        timeoutMs: 8000,
      });
      if (!res.ok) {
        setSubScanError(res.error ?? 'Subdomain CT log scan timed out');
      } else {
        const base = web.displayDomain.toLowerCase();
        const found = new Set<string>();
        for (const entry of res.entries) {
          for (const san of entry.dnsNames) {
            const clean = san.replace(/^\*\./, '').trim().toLowerCase();
            if (
              clean &&
              clean !== base &&
              clean.endsWith(`.${base}`) &&
              !clean.includes('*') &&
              !clean.includes('_')
            ) {
              found.add(clean);
            }
          }
        }
        setExtraSubdomains(Array.from(found).sort().slice(0, 80));
      }
    } catch (err) {
      setSubScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanningSubdomains(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top 4-Pillar Overview Cards (Tap to Jump to Section) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {/* Card 1: HTTPS / SVCB & ECH */}
        <button
          type="button"
          data-testid="web-scorecard-jump-https"
          onClick={() => jumpToSection('https')}
          className="text-left w-full rounded-xl border border-slate-200 dark:border-slate-800 hover:border-cyan-500/60 bg-white dark:bg-slate-900/90 p-3.5 space-y-2 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              <Globe className="w-4 h-4 text-cyan-500" />
              <span>HTTPS / SVCB &amp; ECH</span>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${httpsMeta.cls}`}>
              {httpsMeta.label}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {web.httpsSummary}
          </p>
          <div className="flex flex-wrap items-center justify-between gap-1.5 pt-1 text-[11px] font-mono">
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusBadge status={web.httpsDnssecStatus} size="sm" />
              {web.supportsHttp3 && (
                <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-semibold">
                  HTTP/3 (h3)
                </span>
              )}
              {web.echEnabled && (
                <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-semibold">
                  ECH
                </span>
              )}
            </div>
            <span className="font-sans text-[10px] font-medium text-cyan-600 dark:text-cyan-400 opacity-80 group-hover:opacity-100">
              Jump ↓
            </span>
          </div>
        </button>

        {/* Card 2: Tree-Walking CAA */}
        <button
          type="button"
          data-testid="web-scorecard-jump-caa"
          onClick={() => jumpToSection('caa')}
          className="text-left w-full rounded-xl border border-slate-200 dark:border-slate-800 hover:border-cyan-500/60 bg-white dark:bg-slate-900/90 p-3.5 space-y-2 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              <Shield className="w-4 h-4 text-cyan-500" />
              <span>CAA Policy (RFC 8659)</span>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${caaMeta.cls}`}>
              {caaMeta.label}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {web.caa.summary}
          </p>
          <div className="flex flex-wrap items-center justify-between gap-1.5 pt-1 text-[11px] font-mono">
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusBadge status={web.caa.dnssecStatus} size="sm" />
              {web.caa.hasAcmeAccountBinding && (
                <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-semibold">
                  RFC 8657 ACME
                </span>
              )}
              {ct && ctMeta && ct.status !== 'unavailable' && (
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${ctMeta.cls}`}>
                  {ctMeta.label}
                </span>
              )}
            </div>
            <span className="font-sans text-[10px] font-medium text-cyan-600 dark:text-cyan-400 opacity-80 group-hover:opacity-100">
              Jump ↓
            </span>
          </div>
        </button>

        {/* Card 3: _443._tcp Web DANE */}
        <button
          type="button"
          data-testid="web-scorecard-jump-dane"
          onClick={() => jumpToSection('dane')}
          className="text-left w-full rounded-xl border border-slate-200 dark:border-slate-800 hover:border-cyan-500/60 bg-white dark:bg-slate-900/90 p-3.5 space-y-2 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              <Lock className="w-4 h-4 text-cyan-500" />
              <span>Web DANE (_443._tcp)</span>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${daneMeta.cls}`}>
              {daneMeta.label}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {web.webDane.summary}
          </p>
          <div className="flex flex-wrap items-center justify-between gap-1.5 pt-1 text-[11px] font-mono">
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusBadge status={web.webDane.dnssecStatus} size="sm" />
              {web.webDane.rolloverReady && (
                <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-semibold">
                  Rollover Ready ({web.webDane.records.length} TLSAs)
                </span>
              )}
            </div>
            <span className="font-sans text-[10px] font-medium text-cyan-600 dark:text-cyan-400 opacity-80 group-hover:opacity-100">
              Jump ↓
            </span>
          </div>
        </button>

        {/* Card 4: SSHFP Host Keys */}
        <button
          type="button"
          data-testid="web-scorecard-jump-sshfp"
          onClick={() => jumpToSection('sshfp')}
          className="text-left w-full rounded-xl border border-slate-200 dark:border-slate-800 hover:border-cyan-500/60 bg-white dark:bg-slate-900/90 p-3.5 space-y-2 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              <Terminal className="w-4 h-4 text-cyan-500" />
              <span>SSHFP (RFC 4255)</span>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${sshfpMeta.cls}`}>
              {sshfpMeta.label}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {web.sshfp.summary}
          </p>
          <div className="flex flex-wrap items-center justify-between gap-1.5 pt-1 text-[11px] font-mono">
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusBadge status={web.sshfp.dnssecStatus} size="sm" />
              {web.sshfp.records.length > 0 && (
                <span className="text-slate-500">
                  {web.sshfp.records.length} fingerprint{web.sshfp.records.length === 1 ? '' : 's'}
                </span>
              )}
            </div>
            <span className="font-sans text-[10px] font-medium text-cyan-600 dark:text-cyan-400 opacity-80 group-hover:opacity-100">
              Jump ↓
            </span>
          </div>
        </button>
      </div>

      {/* Sticky Compact Section Jump & Accordion Control Strip */}
      <div
        data-testid="web-section-jump-bar"
        className="sticky top-2 md:static z-20 rounded-xl border border-slate-200/90 dark:border-slate-800/90 bg-white/95 dark:bg-slate-900/95 backdrop-blur-sm px-3 py-2 shadow-sm flex items-center justify-between gap-2"
      >
        <div className="flex items-center gap-1.5 overflow-x-auto min-w-0">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 shrink-0 mr-0.5 hidden sm:inline">
            Jump:
          </span>
          {presentSections.map((sec) => (
            <button
              key={sec.id}
              type="button"
              data-testid={`web-jump-chip-${sec.id}`}
              onClick={() => jumpToSection(sec.id)}
              className="inline-flex items-center gap-1 shrink-0 whitespace-nowrap rounded-lg border border-slate-200 dark:border-slate-800 hover:border-cyan-500 bg-slate-50 dark:bg-slate-950 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <span>{sec.label}</span>
            </button>
          ))}
        </div>

        <button
          type="button"
          data-testid="web-toggle-all-sections"
          onClick={() => setAllSectionsCollapsed(!anySectionCollapsed)}
          className="inline-flex items-center gap-1 shrink-0 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
        >
          {anySectionCollapsed ? (
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

      {/* Section 1: HTTPS (TYPE65) & SVCB (TYPE64) Service Binding Details */}
      <section
        id="web-section-https"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3 scroll-mt-16 md:scroll-mt-44"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            data-testid="web-section-toggle-https"
            aria-expanded={!collapsedSections.https}
            onClick={() => toggleSection('https')}
            className="flex items-center gap-2 text-left min-w-0 cursor-pointer group"
          >
            {collapsedSections.https ? (
              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
            )}
            <Server className="w-4 h-4 text-cyan-500 shrink-0" />
            <h2 className="font-semibold text-sm group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              HTTPS (TYPE65) &amp; SVCB (TYPE64) Service Bindings · A/AAAA Resolution
            </h2>
          </button>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {web.ipv4Addresses.length > 0 && (
              <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5">
                A:{' '}
                {web.ipv4Addresses.map((ip, idx) => (
                  <span key={ip}>
                    <IpHoverBadge ip={ip} />
                    {idx < web.ipv4Addresses.length - 1 ? ', ' : ''}
                  </span>
                ))}
              </span>
            )}
            {web.ipv6Addresses.length > 0 && (
              <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5">
                AAAA:{' '}
                {web.ipv6Addresses.map((ip, idx) => (
                  <span key={ip}>
                    <IpHoverBadge ip={ip} />
                    {idx < web.ipv6Addresses.length - 1 ? ', ' : ''}
                  </span>
                ))}
              </span>
            )}
            <button
              type="button"
              onClick={onOpenChainGraph}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 font-sans text-xs font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span>DNSSEC Chain Graph</span>
            </button>
          </div>
        </div>

        {!collapsedSections.https &&
          (web.httpsRecords.length === 0 && web.svcbRecords.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-800 p-4 text-xs text-slate-500 dark:text-slate-400">
              No <code className="font-mono">HTTPS</code> (<code className="font-mono">TYPE65</code>)
              or <code className="font-mono">SVCB</code> (<code className="font-mono">TYPE64</code>)
              records published at <code className="font-mono">{web.displayDomain}</code>.
            </div>
          ) : (
            <div className="space-y-2.5">
              {[...web.httpsRecords, ...web.svcbRecords].map((rec, idx) => (
                <SvcbRecordCard
                  key={`${rec.ownerName}-${rec.rrtypeName}-${rec.priority}-${idx}`}
                  rec={rec}
                  onJumpToGraphTarget={onJumpToGraphTarget}
                  onInspectWireQuery={onInspectWireQuery}
                  rrsetId={web.httpsRrsetId}
                  wireQueryId={
                    onInspectWireQuery
                      ? findWireQueryByOwnerAndType(
                          snapshot.queries,
                          rec.ownerName,
                          rec.rrtypeName
                        )?.id
                      : undefined
                  }
                />
              ))}
            </div>
          ))}
      </section>

      {/* Section 2: RFC 8659 Tree-Walking CAA Hierarchy & RFC 8657 ACME Bindings */}
      <section
        id="web-section-caa"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3 scroll-mt-16 md:scroll-mt-44"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            data-testid="web-section-toggle-caa"
            aria-expanded={!collapsedSections.caa}
            onClick={() => toggleSection('caa')}
            className="flex items-center gap-2 text-left min-w-0 cursor-pointer group"
          >
            {collapsedSections.caa ? (
              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
            )}
            <ShieldCheck className="w-4 h-4 text-cyan-500 shrink-0" />
            <h2 className="font-semibold text-sm group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              Tree-Walking Certificate Authority Authorization (CAA · RFC 8659 &amp; RFC 8657)
            </h2>
          </button>
          <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${caaMeta.cls}`}>
            {caaMeta.label}
          </span>
        </div>

        {!collapsedSections.caa && (
          <>
        {/* Visual Tree-Walk Path */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-500 font-medium mr-1">RFC 8659 §3 Climb Order:</span>
          {web.caa.hops.map((hop, idx) => (
            <div key={hop.name} className="inline-flex items-center gap-1.5">
              {idx > 0 && <ArrowRight className="w-3.5 h-3.5 text-slate-400" />}
              <span
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-xs ${
                  hop.isEffectivePolicySource
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200 font-bold'
                    : hop.records.length > 0
                      ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-800 dark:text-cyan-200'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-500'
                }`}
              >
                <span>{hop.displayName}</span>
                <span className="text-[10px] opacity-80">
                  ({hop.records.length > 0 ? `${hop.records.length} CAA` : 'no CAA'})
                </span>
              </span>
            </div>
          ))}
        </div>

        {/* CAA Records Table if any hop has CAA records */}
        {web.caa.hops.some((h) => h.records.length > 0) ? (
          <div className="space-y-2">
            {web.caa.hops
              .filter((h) => h.records.length > 0)
              .map((hop) => (
                <div
                  key={hop.name}
                  className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-xs">{hop.displayName}</span>
                      {hop.isEffectivePolicySource && (
                        <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-mono text-[10px] font-semibold">
                          Effective Policy Source
                        </span>
                      )}
                      <StatusBadge status={hop.dnssecStatus} size="sm" />
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {hop.rrsetId && (
                        <button
                          type="button"
                          onClick={() => onJumpToGraphTarget(hop.rrsetId!)}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-0.5 text-[11px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
                        >
                          <span>Inspect in Graph</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      )}
                      {onInspectWireQuery &&
                        (findWireQueryByGraphTargetId(hop.rrsetId, snapshot) ??
                          findWireQueryByOwnerAndType(snapshot.queries, hop.name, 'CAA')) && (
                          <button
                            type="button"
                            onClick={() => {
                              const q =
                                findWireQueryByGraphTargetId(hop.rrsetId, snapshot) ??
                                findWireQueryByOwnerAndType(snapshot.queries, hop.name, 'CAA');
                              if (q) onInspectWireQuery(q.id, 'dig');
                            }}
                            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                          >
                            <Terminal className="w-3 h-3 text-cyan-500" />
                            <span>Wire</span>
                          </button>
                        )}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    {hop.records.map((rec, rIdx) => (
                      <div
                        key={rIdx}
                        className="rounded border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                              rec.critical
                                ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                            }`}
                          >
                            flags={rec.flags} {rec.critical ? '(critical)' : ''}
                          </span>
                          <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-bold">
                            {rec.tag}
                          </span>
                          <span className="text-slate-800 dark:text-slate-200 break-all">
                            &quot;{rec.rawValue}&quot;
                          </span>
                        </div>
                        {rec.parameters.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1">
                            {rec.parameters.map((p, pIdx) => (
                              <span
                                key={pIdx}
                                className="rounded bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30 px-1.5 py-0.5 text-[10px]"
                              >
                                {p.key}={p.value}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-800 p-4 text-xs text-slate-500 dark:text-slate-400">
            No <code className="font-mono">CAA</code> records found at{' '}
            <code className="font-mono">{web.displayDomain}</code> or any parent zone.
          </div>
        )}
          </>
        )}
      </section>

      {/* Section 2.5: Certificate Transparency (CT) ↔ CAA Cross-Check & Subdomain Discovery */}
      {ct && (
        <section
          id="web-section-ct"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3 scroll-mt-16 md:scroll-mt-44"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              data-testid="web-section-toggle-ct"
              aria-expanded={!collapsedSections.ct}
              onClick={() => toggleSection('ct')}
              className="flex items-center gap-2 text-left min-w-0 cursor-pointer group"
            >
              {collapsedSections.ct ? (
                <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              )}
              <FileCheck2 className="w-4 h-4 text-cyan-500 shrink-0" />
              <h2 className="font-semibold text-sm group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                Certificate Transparency (CT) ↔ CAA Policy Cross-Check &amp; Subdomain Discovery
              </h2>
            </button>
            <div className="flex flex-wrap items-center gap-2">
              {ct.source !== 'unavailable' && (
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300">
                  Source: {ct.source === 'certspotter' ? 'CertSpotter CT API' : 'crt.sh CT Log'}
                </span>
              )}
              {ctMeta && (
                <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${ctMeta.cls}`}>
                  {ctMeta.label}
                </span>
              )}
            </div>
          </div>

          {!collapsedSections.ct && (
            <>
          <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{ct.summary}</p>

          {/* Metrics & Subdomain Scan Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5">
                Active Certs: <strong>{ct.activeCertCount}</strong>
              </span>
              {ct.expiredCertCount > 0 && (
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-500">
                  Historical/Expired: {ct.expiredCertCount}
                </span>
              )}
              {ct.mismatchedActiveCertCount > 0 && (
                <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-2 py-0.5 font-bold">
                  CAA Mismatched Active Certs: {ct.mismatchedActiveCertCount}
                </span>
              )}
              {ct.tlsaMatchedCertCount > 0 && (
                <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-bold">
                  Matches _443._tcp TLSA: {ct.tlsaMatchedCertCount}
                </span>
              )}
            </div>

            <button
              type="button"
              disabled={scanningSubdomains}
              onClick={() => void handleScanSubdomainCtLogs()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 disabled:opacity-60 px-2.5 py-1 font-sans text-xs font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
              title="Query CertSpotter CT logs with include_subdomains=true to discover additional child hostnames"
            >
              {scanningSubdomains ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Scanning Subdomain CT Logs…</span>
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  <span>Scan Subdomain CT Logs</span>
                </>
              )}
            </button>
          </div>

          {subScanError && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-300">
              Subdomain CT scan note: {subScanError}
            </div>
          )}

          {/* Active CT Issuers vs. CAA Policy Grid */}
          {ct.issuers.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-xs font-semibold text-slate-600 dark:text-slate-300">
                Observed Certificate Authorities vs. Effective CAA Policy:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {ct.issuers.map((iss) => {
                  const isEnforced =
                    web.caa.status === 'enforced' ||
                    web.caa.status === 'inherited' ||
                    web.caa.issuewildCas.length > 0 ||
                    (ct.subdomainCaaPolicies?.length ?? 0) > 0 ||
                    ct.certificates.some((c) => c.caaAuthorized !== 'unrestricted');
                  return (
                    <div
                      key={iss.friendlyName}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs"
                    >
                      <div className="space-y-0.5 min-w-0">
                        <div className="font-semibold text-slate-800 dark:text-slate-100 truncate">
                          {iss.friendlyName}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          CAA domain:{' '}
                          <span className="text-cyan-700 dark:text-cyan-300">
                            {iss.mappedCaaDomains.length > 0
                              ? iss.mappedCaaDomains.join(', ')
                              : 'unmapped'}
                          </span>{' '}
                          · {iss.activeCertCount} active cert{iss.activeCertCount === 1 ? '' : 's'}
                          {iss.wildcardCertCount > 0 ? ` (${iss.wildcardCertCount} wildcard)` : ''}
                        </div>
                      </div>
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold shrink-0 ${
                          !isEnforced
                            ? 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25'
                            : iss.caaAuthorized
                              ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                              : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                        }`}
                      >
                        {!isEnforced
                          ? 'UNRESTRICTED (NO CAA)'
                          : iss.caaAuthorized
                            ? 'CAA AUTHORIZED ✓'
                            : 'NOT IN CAA POLICY'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Subdomain CAA Policies Discovered Along CT Log Chains */}
          {ct.subdomainCaaPolicies && ct.subdomainCaaPolicies.length > 0 && (
            <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3 space-y-2">
              <div className="text-xs font-semibold text-emerald-800 dark:text-emerald-200">
                Subdomain CAA Policies Discovered Along CT Log Domain Chains ({ct.subdomainCaaPolicies.length}):
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {ct.subdomainCaaPolicies.map((pol) => (
                  <div
                    key={pol.owner}
                    className="rounded border border-emerald-500/20 bg-white/80 dark:bg-slate-900/80 px-2.5 py-1.5 text-xs font-mono flex flex-wrap items-center justify-between gap-2"
                  >
                    <span className="font-bold text-slate-800 dark:text-slate-100">
                      {pol.displayOwner}
                    </span>
                    <div className="flex flex-wrap items-center gap-1">
                      {pol.issueCas.map((ca) => (
                        <span
                          key={`issue-${ca}`}
                          className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-semibold"
                        >
                          issue &quot;{ca}&quot;
                        </span>
                      ))}
                      {pol.issuewildCas.map((ca) => (
                        <span
                          key={`wild-${ca}`}
                          className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 text-[10px] font-semibold"
                        >
                          issuewild &quot;{ca}&quot;
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* One-Click Subdomain Discovery Chips from CT SANs */}
          {mergedSubdomains.length > 0 && (
            <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-semibold text-cyan-800 dark:text-cyan-200">
                  Subdomains Discovered in CT Subject Alternative Names ({mergedSubdomains.length}):
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] text-slate-500">
                    Click any hostname to run a Web &amp; HTTPS trace
                  </span>
                  {onBatchAuditDomains && (
                    <button
                      type="button"
                      data-testid="ct-audit-subdomains-portfolio-btn"
                      onClick={() => {
                        const batchList = Array.from(
                          new Set([snapshot.displayDomain, ...mergedSubdomains])
                        ).slice(0, MAX_PORTFOLIO_DOMAINS);
                        onBatchAuditDomains(
                          batchList,
                          `CT SANs (${snapshot.displayDomain})`
                        );
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 px-2.5 py-1 text-[11px] font-bold text-slate-950 shadow-sm transition-colors cursor-pointer"
                      title={`Run bounded-concurrency Portfolio Security Triage across ${snapshot.displayDomain} and up to ${MAX_PORTFOLIO_DOMAINS - 1} discovered CT subdomains`}
                    >
                      <Layers className="w-3 h-3" />
                      <span>
                        Audit Discovered CT Subdomains (
                        {Math.min(MAX_PORTFOLIO_DOMAINS, mergedSubdomains.length + 1)})
                      </span>
                    </button>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {mergedSubdomains.map((sub) =>
                  onTraceDomain ? (
                    <button
                      key={sub}
                      type="button"
                      onClick={() => onTraceDomain(sub)}
                      className="inline-flex items-center gap-1 rounded-md border border-cyan-500/30 bg-white dark:bg-slate-900 hover:border-cyan-500 hover:bg-cyan-500/10 px-2 py-1 font-mono text-xs text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer"
                      title={`Trace ${sub} in Web & HTTPS mode`}
                    >
                      <span>{sub}</span>
                      <ArrowUpRight className="w-3 h-3 opacity-75" />
                    </button>
                  ) : (
                    <span
                      key={sub}
                      className="inline-flex items-center rounded-md border border-cyan-500/25 bg-white dark:bg-slate-900 px-2 py-1 font-mono text-xs text-cyan-700 dark:text-cyan-300"
                    >
                      {sub}
                    </span>
                  )
                )}
              </div>
            </div>
          )}

          {/* Recent CT Log Certificates List */}
          {ct.certificates.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">
                  Recent CT Log Certificates ({ct.certificates.length}):
                </span>
                {ct.certificates.length > 5 && (
                  <button
                    type="button"
                    onClick={() => setShowAllCtCerts((v) => !v)}
                    className="text-xs font-medium text-cyan-700 dark:text-cyan-300 hover:underline cursor-pointer"
                  >
                    {showAllCtCerts
                      ? 'Show fewer'
                      : `Show all ${ct.certificates.length} certificates`}
                  </button>
                )}
              </div>
              <div className="space-y-1.5">
                {(showAllCtCerts ? ct.certificates : ct.certificates.slice(0, 5)).map((cert) => {
                  const verdictMeta = getCtCertVerdictMeta(cert.caaAuthorized);
                  const sanPreview = cert.dnsNames.slice(0, 5);
                  const extraSanCount = Math.max(0, cert.dnsNames.length - sanPreview.length);
                  return (
                    <div
                      key={cert.id}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-2.5 text-xs space-y-1.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-slate-800 dark:text-slate-100">
                            {cert.issuerFriendlyName}
                          </span>
                          {cert.mappedCaaDomains.length > 0 && (
                            <span className="font-mono text-[11px] text-cyan-700 dark:text-cyan-300">
                              ({cert.mappedCaaDomains[0]})
                            </span>
                          )}
                          <span
                            className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                              cert.revoked
                                ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                                : cert.isExpired
                                  ? 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                                  : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                            }`}
                          >
                            {cert.revoked ? 'REVOKED' : cert.isExpired ? 'EXPIRED' : 'ACTIVE'}
                          </span>
                          <span className="font-mono text-[11px] text-slate-500">
                            {cert.notBefore.slice(0, 10)} → {cert.notAfter.slice(0, 10)}
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-1.5">
                          {cert.matchesTlsa && (
                            <span
                              className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-mono text-[10px] font-bold"
                              title={cert.matchedTlsaSummary}
                            >
                              Matches _443._tcp TLSA ✓
                            </span>
                          )}
                          <span
                            className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${verdictMeta.cls}`}
                            title={cert.caaNote}
                          >
                            {verdictMeta.label}
                            {cert.effectiveCaaOwners &&
                            cert.effectiveCaaOwners.some(
                              (o) => o.toLowerCase() !== web.displayDomain.toLowerCase()
                            )
                              ? ` (${cert.effectiveCaaOwners.join(', ')})`
                              : ''}
                          </span>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-1 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                        <span className="text-slate-400">SANs:</span>
                        {sanPreview.map((s) => (
                          <span
                            key={s}
                            className="rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-1.5 py-0.5"
                          >
                            {s}
                          </span>
                        ))}
                        {extraSanCount > 0 && (
                          <span className="text-slate-400">+{extraSanCount} more</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
            </>
          )}
        </section>
      )}

      {/* Section 3: Web DANE (_443._tcp TLSA) & SSHFP */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        {/* _443._tcp DANE TLSA */}
        <section
          id="web-section-dane"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3 scroll-mt-16 md:scroll-mt-44"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              data-testid="web-section-toggle-dane"
              aria-expanded={!collapsedSections.dane}
              onClick={() => toggleSection('dane')}
              className="flex items-center gap-2 text-left min-w-0 cursor-pointer group"
            >
              {collapsedSections.dane ? (
                <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              )}
              <KeyRound className="w-4 h-4 text-cyan-500 shrink-0" />
              <h2 className="font-semibold text-sm group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                Web DANE (<code className="font-mono text-xs">{displayFqdn(web.webDane.qname)}</code>{' '}
                TLSA)
              </h2>
            </button>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${daneMeta.cls}`}>
              {daneMeta.label}
            </span>
          </div>

          {!collapsedSections.dane && (
            <>
              <p className="text-xs text-slate-600 dark:text-slate-400">{web.webDane.summary}</p>

              {web.webDane.records.length > 0 && (
                <div className="space-y-2">
                  {web.webDane.records.map((rec, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-2.5 text-xs font-mono space-y-1"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-bold text-cyan-700 dark:text-cyan-300">
                          {rec.usage} ({rec.usageMnemonic}) · {rec.selector} ({rec.selectorMnemonic}) ·{' '}
                          {rec.matchingType} ({rec.matchingTypeMnemonic})
                        </span>
                        <span className="text-[11px] text-slate-400">TTL {rec.ttl}s</span>
                      </div>
                      <CryptoBlob
                        value={rec.certAssociationHex}
                        compact
                        headChars={16}
                        tailChars={12}
                        copyLabel="Copy Hex"
                        testId={`crypto-web-tlsa-${idx}`}
                      />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </section>

        {/* SSHFP Host Key Fingerprints */}
        <section
          id="web-section-sshfp"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3 scroll-mt-16 md:scroll-mt-44"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              data-testid="web-section-toggle-sshfp"
              aria-expanded={!collapsedSections.sshfp}
              onClick={() => toggleSection('sshfp')}
              className="flex items-center gap-2 text-left min-w-0 cursor-pointer group"
            >
              {collapsedSections.sshfp ? (
                <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              )}
              {web.sshfp.status === 'secure' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
              ) : web.sshfp.status === 'not-deployed' ? (
                <Terminal className="w-4 h-4 text-slate-400 shrink-0" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0" />
              )}
              <h2 className="font-semibold text-sm group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                SSHFP Host Key Fingerprints (TYPE44)
              </h2>
            </button>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${sshfpMeta.cls}`}>
              {sshfpMeta.label}
            </span>
          </div>

          {!collapsedSections.sshfp && (
            <>
              <p className="text-xs text-slate-600 dark:text-slate-400">{web.sshfp.summary}</p>

              {web.sshfp.records.length > 0 && (
                <div className="space-y-2">
                  {web.sshfp.records.map((rec, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-2.5 text-xs font-mono space-y-1"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-bold text-cyan-700 dark:text-cyan-300">
                          Algo {rec.algorithm} ({rec.algorithmName}) · Hash {rec.fpType} (
                          {rec.fpTypeName})
                        </span>
                        {rec.deprecated && (
                          <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 px-1.5 py-0.5 text-[10px]">
                            Deprecated
                          </span>
                        )}
                      </div>
                      <CryptoBlob
                        value={rec.fingerprintHex}
                        compact
                        headChars={16}
                        tailChars={12}
                        copyLabel="Copy Hex"
                        testId={`crypto-web-sshfp-${idx}`}
                      />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </div>
  );
}
