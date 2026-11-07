import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Globe,
  KeyRound,
  Lock,
  Network,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { displayFqdn } from '../dns/encoding';
import type {
  AnalysisSnapshot,
  DaneHostStatus,
  WebAnalysisResult,
  WebCaaAnalysis,
  WebSvcbRecordDetail,
} from '../dns/types';
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

function SvcbRecordCard({
  rec,
  onJumpToGraphTarget,
  rrsetId,
}: {
  rec: WebSvcbRecordDetail;
  onJumpToGraphTarget: (targetId: string) => void;
  rrsetId?: string;
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
                      {ip}
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
                      {ip}
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

export function WebAnalysisView({
  snapshot,
  onJumpToGraphTarget,
  onOpenChainGraph,
}: {
  snapshot: AnalysisSnapshot;
  onJumpToGraphTarget: (targetId: string) => void;
  onOpenChainGraph: () => void;
}) {
  const web = snapshot.webAnalysis;
  if (!web) return null;

  const httpsMeta = getHttpsBadgeMeta(web.httpsStatus);
  const caaMeta = getCaaBadgeMeta(web.caa.status);
  const daneMeta = getDaneBadgeMeta(web.webDane.status);
  const sshfpMeta = getSshfpBadgeMeta(web.sshfp.status);

  return (
    <div className="space-y-4">
      {/* Top 4-Pillar Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {/* Card 1: HTTPS / SVCB & ECH */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
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
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono">
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
        </div>

        {/* Card 2: Tree-Walking CAA */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
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
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono">
            <StatusBadge status={web.caa.dnssecStatus} size="sm" />
            {web.caa.hasAcmeAccountBinding && (
              <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-semibold">
                RFC 8657 ACME
              </span>
            )}
          </div>
        </div>

        {/* Card 3: _443._tcp Web DANE */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
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
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono">
            <StatusBadge status={web.webDane.dnssecStatus} size="sm" />
            {web.webDane.rolloverReady && (
              <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-semibold">
                Rollover Ready ({web.webDane.records.length} TLSAs)
              </span>
            )}
          </div>
        </div>

        {/* Card 4: SSHFP Host Keys */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
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
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono">
            <StatusBadge status={web.sshfp.dnssecStatus} size="sm" />
            {web.sshfp.records.length > 0 && (
              <span className="text-slate-500">
                {web.sshfp.records.length} fingerprint{web.sshfp.records.length === 1 ? '' : 's'}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Section 1: HTTPS (TYPE65) & SVCB (TYPE64) Service Binding Details */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-500" />
            <h2 className="font-semibold text-sm">
              HTTPS (TYPE65) &amp; SVCB (TYPE64) Service Bindings · A/AAAA Resolution
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {web.ipv4Addresses.length > 0 && (
              <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5">
                A: {web.ipv4Addresses.join(', ')}
              </span>
            )}
            {web.ipv6Addresses.length > 0 && (
              <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5">
                AAAA: {web.ipv6Addresses.join(', ')}
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

        {web.httpsRecords.length === 0 && web.svcbRecords.length === 0 ? (
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
                rrsetId={web.httpsRrsetId}
              />
            ))}
          </div>
        )}
      </section>

      {/* Section 2: RFC 8659 Tree-Walking CAA Hierarchy & RFC 8657 ACME Bindings */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-500" />
            <h2 className="font-semibold text-sm">
              Tree-Walking Certificate Authority Authorization (CAA · RFC 8659 &amp; RFC 8657)
            </h2>
          </div>
          <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${caaMeta.cls}`}>
            {caaMeta.label}
          </span>
        </div>

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
      </section>

      {/* Section 3: Web DANE (_443._tcp TLSA) & SSHFP */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* _443._tcp DANE TLSA */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-500" />
              <h2 className="font-semibold text-sm">
                Web DANE (<code className="font-mono text-xs">{displayFqdn(web.webDane.qname)}</code>{' '}
                TLSA)
              </h2>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${daneMeta.cls}`}>
              {daneMeta.label}
            </span>
          </div>

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
                  <div className="text-[11px] text-slate-600 dark:text-slate-300 break-all">
                    {rec.certAssociationHex}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* SSHFP Host Key Fingerprints */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {web.sshfp.status === 'secure' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
              ) : web.sshfp.status === 'not-deployed' ? (
                <Terminal className="w-4 h-4 text-slate-400" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-amber-500" />
              )}
              <h2 className="font-semibold text-sm">SSHFP Host Key Fingerprints (TYPE44)</h2>
            </div>
            <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${sshfpMeta.cls}`}>
              {sshfpMeta.label}
            </span>
          </div>

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
                  <div className="text-[11px] text-slate-600 dark:text-slate-300 break-all">
                    {rec.fingerprintHex}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
