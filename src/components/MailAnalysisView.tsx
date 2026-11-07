import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileText,
  KeyRound,
  Lock,
  Mail,
  Network,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { displayFqdn } from '../dns/encoding';
import type {
  AnalysisSnapshot,
  DaneHostStatus,
  DkimKeyStatus,
  DkimSelectorResult,
  DmarcVerdict,
  MailAnalysisResult,
  MxHostAnalysis,
  SpfDomainNode,
  SpfPolicyVerdict,
  SpfTerm,
} from '../dns/types';
import { StatusBadge } from './StatusBadge';

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

function getSpfVerdictMeta(verdict: SpfPolicyVerdict): {
  label: string;
  cls: string;
} {
  switch (verdict) {
    case 'strict-fail':
      return {
        label: 'STRICT FAIL (-all)',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'soft-fail':
      return {
        label: 'SOFTFAIL (~all)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'neutral':
      return {
        label: 'NEUTRAL (?all)',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'no-default':
      return {
        label: 'NO TERMINAL ALL',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'pass-all':
      return {
        label: 'DANGER (+all)',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'permerror':
      return {
        label: 'PERMERROR',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'temperror':
      return {
        label: 'TEMPERROR',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'none':
      return {
        label: 'NOT PUBLISHED',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/30',
      };
  }
}

function SpfTermPill({ term }: { term: SpfTerm }) {
  if (term.kind === 'version') {
    return (
      <span className="inline-flex items-center rounded-md bg-slate-200/80 dark:bg-slate-800 px-2 py-0.5 font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
        {term.raw}
      </span>
    );
  }

  let colorCls =
    'bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700';
  if (!term.syntaxValid || term.error) {
    colorCls =
      'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/40';
  } else if (term.unreachableAfterAll || term.warning) {
    colorCls =
      'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/40';
  } else if (term.mechanism === 'all') {
    if (term.qualifier === '-') {
      colorCls = 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/35';
    } else if (term.qualifier === '~') {
      colorCls = 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/35';
    } else if (term.qualifier === '+') {
      colorCls = 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/40';
    } else {
      colorCls = 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35';
    }
  } else if (term.countsTowardLookupLimit) {
    colorCls = 'bg-cyan-500/10 text-cyan-800 dark:text-cyan-200 border-cyan-500/30';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-xs ${colorCls}`}
      title={term.error ?? term.warning ?? (term.countsTowardLookupLimit ? 'Counts toward 10-DNS-lookup limit' : 'Zero DNS lookups')}
    >
      <span>{term.raw}</span>
      {term.countsTowardLookupLimit && (
        <span className="rounded bg-cyan-500/20 px-1 py-0.1 text-[9px] font-bold text-cyan-700 dark:text-cyan-300">
          +1 DNS
        </span>
      )}
      {term.isVoidLookup && (
        <span className="rounded bg-amber-500/25 px-1 py-0.1 text-[9px] font-bold text-amber-700 dark:text-amber-200">
          VOID
        </span>
      )}
    </span>
  );
}

function SpfTreeBranch({ node }: { node: SpfDomainNode }) {
  const [expanded, setExpanded] = useState(true);
  const dnsTermsCount = node.terms.filter((t) => t.countsTowardLookupLimit).length;

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1 font-mono text-xs font-bold text-slate-900 dark:text-slate-100 hover:text-cyan-500 cursor-pointer"
          >
            {expanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            )}
            <span>{node.displayDomain}</span>
          </button>

          <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-600 dark:text-slate-300">
            {node.via}
          </span>

          {node.dnssecStatus && <StatusBadge status={node.dnssecStatus} size="xs" />}

          {dnsTermsCount > 0 && (
            <span className="font-mono text-[11px] text-cyan-600 dark:text-cyan-400">
              {dnsTermsCount} direct DNS {dnsTermsCount === 1 ? 'query' : 'queries'}
            </span>
          )}
        </div>

        {node.rcodeName && node.rcodeName !== 'NOERROR' && (
          <span className="rounded bg-rose-500/15 text-rose-600 dark:text-rose-300 px-2 py-0.5 font-mono text-[10px] font-semibold">
            {node.rcodeName}
          </span>
        )}
      </div>

      {node.error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
          <span>{node.error}</span>
        </div>
      )}

      {node.spfRecords.length > 1 && (
        <div className="space-y-1">
          {node.spfRecords.map((rec, i) => (
            <div
              key={`${node.domain}-dup-${i}`}
              className="rounded-lg border border-rose-500/30 bg-rose-500/5 px-2.5 py-1.5 font-mono text-xs text-rose-700 dark:text-rose-200 break-all"
            >
              TXT #{i + 1}: {rec}
            </div>
          ))}
        </div>
      )}

      {expanded && node.terms.length > 0 && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {node.terms.map((t, idx) => (
              <SpfTermPill key={`${node.domain}-term-${idx}-${t.raw}`} term={t} />
            ))}
          </div>

          {/* Detailed breakdown of mechanisms that resolve IPs, warnings, errors, or nested includes */}
          <div className="space-y-2 pl-3 border-l-2 border-slate-200 dark:border-slate-800">
            {node.terms
              .filter(
                (t) =>
                  t.childNode ||
                  (t.resolvedIps && t.resolvedIps.length > 0) ||
                  t.isVoidLookup ||
                  t.error ||
                  t.warning
              )
              .map((t, idx) => (
                <div key={`${node.domain}-sub-${idx}-${t.raw}`} className="space-y-1.5 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-semibold text-slate-700 dark:text-slate-200">
                      {t.raw}
                    </span>
                    {t.resolvedIps && t.resolvedIps.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {t.resolvedIps.slice(0, 8).map((ip) => (
                          <span
                            key={ip}
                            className="rounded bg-slate-200/70 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-300"
                          >
                            {ip}
                          </span>
                        ))}
                        {t.resolvedIps.length > 8 && (
                          <span className="font-mono text-[10px] text-slate-500">
                            +{t.resolvedIps.length - 8} more
                          </span>
                        )}
                      </div>
                    )}
                    {t.isVoidLookup && (
                      <span className="text-[11px] text-amber-600 dark:text-amber-400">
                        Void lookup (0 records / NXDOMAIN)
                      </span>
                    )}
                    {t.error && (
                      <span className="text-[11px] text-rose-600 dark:text-rose-400">
                        {t.error}
                      </span>
                    )}
                    {!t.error && t.warning && (
                      <span className="text-[11px] text-amber-600 dark:text-amber-400">
                        {t.warning}
                      </span>
                    )}
                  </div>
                  {t.childNode && <SpfTreeBranch node={t.childNode} />}
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function MxHostCard({
  host,
  onJumpToGraphTarget,
}: {
  host: MxHostAnalysis;
  onJumpToGraphTarget: (targetId: string) => void;
}) {
  const daneMeta = getDaneBadgeMeta(host.dane.status);

  if (host.isNullMx) {
    return (
      <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-cyan-500/20 text-cyan-800 dark:text-cyan-200 px-2 py-0.5 font-mono text-xs font-bold">
              Pref {host.preference}
            </span>
            <span className="font-mono font-bold text-sm text-slate-900 dark:text-slate-100">
              . (RFC 7505 Null MX)
            </span>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-300">
            Explicitly instructs remote mail servers that this domain accepts no incoming email.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-4">
      {/* MX Host Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
              Pref {host.preference}
            </span>
            <span className="font-mono font-bold text-sm sm:text-base text-slate-900 dark:text-slate-100 break-all">
              {host.displayExchange}
            </span>
            {host.cnameChain.length > 0 && (
              <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-2 py-0.5 font-mono text-[11px]">
                <span>CNAME</span>
                <ArrowRight className="w-3 h-3" />
                <span>{host.cnameChain.map(displayFqdn).join(' → ')}</span>
              </span>
            )}
            {host.isIpLiteral && (
              <span className="rounded-md bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35 px-2 py-0.5 font-mono text-[11px] font-semibold">
                INVALID IP LITERAL
              </span>
            )}
          </div>

          {/* Resolved IPv4 / IPv6 Addresses */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            {host.addresses.length === 0 ? (
              <span className="text-xs font-mono text-rose-600 dark:text-rose-400">
                No A or AAAA address records resolved
              </span>
            ) : (
              host.addresses.map((addr) => (
                <span
                  key={addr.ip}
                  className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-xs border ${
                    addr.isPublic
                      ? addr.family === 6
                        ? 'bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border-indigo-500/25'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                      : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35'
                  }`}
                >
                  <span className="text-[9px] uppercase font-bold opacity-70">
                    IPv{addr.family}
                  </span>
                  <span>{addr.ip}</span>
                  {addr.note && <span className="text-[10px]">({addr.note})</span>}
                </span>
              ))
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start lg:self-center">
          <div className="flex items-center gap-1 text-[11px] text-slate-500 font-mono">
            <span>Host DNSSEC:</span>
            <StatusBadge
              status={
                host.ipv4Status === 'bogus' || host.ipv6Status === 'bogus'
                  ? 'bogus'
                  : host.addresses.some((a) => a.family === 4)
                    ? host.ipv4Status
                    : host.ipv6Status
              }
              size="xs"
            />
          </div>
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-mono text-[11px] font-semibold ${daneMeta.cls}`}
          >
            <Lock className="w-3 h-3" />
            {daneMeta.label}
          </span>
          {host.addressRrsetIds[0] && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(host.addressRrsetIds[0])}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:border-cyan-500 transition-colors cursor-pointer"
              title="Locate MX host RRset in DNSSEC Chain Graph"
            >
              <span>Chain</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* SMTP DANE (_25._tcp.<mx> TLSA) Sub-Section */}
      <div className="rounded-lg border border-slate-200/90 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
              {displayFqdn(host.dane.qname)} TLSA
            </span>
            {host.dane.cnameChain.length > 0 && (
              <span className="inline-flex items-center gap-1 font-mono text-[11px] text-cyan-600 dark:text-cyan-400">
                <ArrowRight className="w-3 h-3" />
                <span>{host.dane.cnameChain.map(displayFqdn).join(' → ')}</span>
              </span>
            )}
            <StatusBadge status={host.dane.dnssecStatus} size="xs" />
            {host.dane.records.length > 0 && (
              <span
                className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                  host.dane.rolloverReady
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                    : 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
                }`}
                title="RFC 7671 §8.1 / §8.4 key rollover readiness (DANE-TA or multiple DANE-EE SPKI pins)"
              >
                {host.dane.rolloverReady ? 'Rollover-Ready' : 'Single Leaf Pin'}
              </span>
            )}
          </div>

          {(host.dane.rrsetId || host.dane.negativeNodeId) && (
            <button
              type="button"
              onClick={() =>
                onJumpToGraphTarget((host.dane.rrsetId ?? host.dane.negativeNodeId)!)
              }
              className="inline-flex items-center gap-1 text-[11px] font-medium text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer"
            >
              <span>Inspect TLSA Proof in Graph</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
        </div>

        <p className="text-xs text-slate-600 dark:text-slate-400">{host.dane.summary}</p>

        {host.dane.records.length > 0 && (
          <div className="space-y-2 pt-1">
            {host.dane.records.map((rec, idx) => (
              <div
                key={`${rec.ownerName}-${idx}-${rec.certAssociationHex.slice(0, 16)}`}
                className={`rounded-lg border p-2.5 space-y-1.5 text-xs ${
                  !rec.rdataValid
                    ? 'border-rose-500/40 bg-rose-500/5'
                    : rec.smtpRecommended
                      ? 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80'
                      : 'border-amber-500/40 bg-amber-500/5'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5 font-mono">
                    <span className="rounded bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 px-1.5 py-0.5 font-bold">
                      {rec.usage} {rec.selector} {rec.matchingType}
                    </span>
                    <span className="font-semibold text-slate-800 dark:text-slate-100">
                      {rec.usageMnemonic}
                    </span>
                    <span className="text-slate-400">·</span>
                    <span className="text-slate-700 dark:text-slate-300">
                      Selector: {rec.selectorMnemonic} ({rec.selector})
                    </span>
                    <span className="text-slate-400">·</span>
                    <span className="text-slate-700 dark:text-slate-300">
                      Match: {rec.matchingTypeMnemonic} ({rec.matchingType})
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400">TTL {rec.ttl}s</span>
                </div>

                <div className="font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all bg-slate-100/80 dark:bg-slate-950 rounded px-2 py-1">
                  {rec.certAssociationHex || '(empty)'}
                </div>

                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  {rec.usageDescription}
                </div>

                {rec.issues.length > 0 && (
                  <div className="text-[11px] text-rose-600 dark:text-rose-400 font-medium">
                    {rec.issues.join(' · ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function getDmarcVerdictMeta(verdict: DmarcVerdict): {
  label: string;
  cls: string;
} {
  switch (verdict) {
    case 'reject':
      return {
        label: 'REJECT (p=reject)',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'quarantine':
      return {
        label: 'QUARANTINE (p=quarantine)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'monitor-only':
      return {
        label: 'MONITOR ONLY (p=none)',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'invalid':
      return {
        label: 'INVALID SYNTAX',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'temperror':
      return {
        label: 'TEMPERROR',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'none':
      return {
        label: 'NOT PUBLISHED',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/30',
      };
  }
}

function getDkimStatusMeta(sel: DkimSelectorResult): {
  label: string;
  cls: string;
} {
  const keyTag =
    sel.keyType === 'ed25519'
      ? 'Ed25519 (256-bit)'
      : sel.keyBits
        ? `RSA ${sel.keyBits}-bit`
        : sel.keyType.toUpperCase();

  switch (sel.status as DkimKeyStatus) {
    case 'valid':
      return {
        label: `${keyTag} · STRONG`,
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'warning':
      return {
        label: `${keyTag} · WARN`,
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'revoked':
      return {
        label: 'KEY REVOKED (p=)',
        cls: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30',
      };
    case 'weak':
      return {
        label: `${keyTag} · WEAK`,
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'invalid':
      return {
        label: 'INVALID KEY',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'missing':
      return {
        label: 'NOT FOUND',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
  }
}

function DkimSelectorCard({
  sel,
  onJumpToGraphTarget,
}: {
  sel: DkimSelectorResult;
  onJumpToGraphTarget: (targetId: string) => void;
}) {
  const statusMeta = getDkimStatusMeta(sel);
  const graphTargetId = sel.txtRrsetId ?? sel.negativeNodeId;

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-lg bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
            s={sel.selector}
          </span>
          <span className="font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
            {displayFqdn(sel.qname)}
          </span>
          <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-600 dark:text-slate-300">
            {sel.source === 'custom' ? 'Custom' : 'Auto-discovered'}
          </span>
          <span className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${statusMeta.cls}`}>
            {statusMeta.label}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={sel.dnssecStatus} size="xs" />
          {graphTargetId && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(graphTargetId)}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-cyan-600 dark:text-cyan-400 hover:border-cyan-500 cursor-pointer"
            >
              <span>Inspect Key Proof in Graph</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {sel.cnameChain.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
          <span className="font-medium text-slate-500">CNAME Delegation:</span>
          <span className="font-mono">{displayFqdn(sel.qname)}</span>
          {sel.cnameChain.map((c) => (
            <span key={c} className="inline-flex items-center gap-1 font-mono text-cyan-600 dark:text-cyan-400">
              <ArrowRight className="w-3 h-3 text-slate-400" />
              {displayFqdn(c)}
            </span>
          ))}
        </div>
      )}

      {sel.present && (
        <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
          {sel.version && (
            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-300">
              v={sel.version}
            </span>
          )}
          <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-300">
            k={sel.keyType}
          </span>
          {sel.keyBits !== undefined && (
            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-300">
              {sel.keyBits} bits{sel.rsaExponent ? ` (e=${sel.rsaExponent})` : ''}
            </span>
          )}
          {sel.hashAlgorithms && sel.hashAlgorithms.length > 0 && (
            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-300">
              h={sel.hashAlgorithms.join(':')}
            </span>
          )}
          {sel.serviceTypes && sel.serviceTypes.length > 0 && (
            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-300">
              s={sel.serviceTypes.join(':')}
            </span>
          )}
          {sel.isTestingMode && (
            <span className="rounded bg-amber-500/20 text-amber-800 dark:text-amber-200 px-2 py-0.5 font-semibold">
              t=y (Testing Mode)
            </span>
          )}
          {sel.isStrictSubdomain && (
            <span className="rounded bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 px-2 py-0.5 font-semibold">
              t=s (Strict Subdomain i=)
            </span>
          )}
          {sel.notesTag && (
            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-2 py-0.5 text-slate-600 dark:text-slate-400">
              n=&quot;{sel.notesTag}&quot;
            </span>
          )}
        </div>
      )}

      {sel.rawRecord && (
        <div className="rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-2.5 py-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all">
          {sel.rawRecord}
        </div>
      )}

      {sel.issues.length > 0 && (
        <div className="space-y-1">
          {sel.issues.map((iss, idx) => (
            <div
              key={`${sel.qname}-iss-${idx}`}
              className={`text-xs flex items-start gap-1.5 ${
                sel.status === 'weak' || sel.status === 'invalid'
                  ? 'text-rose-600 dark:text-rose-400'
                  : 'text-amber-700 dark:text-amber-300'
              }`}
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

export function MailAnalysisView({
  snapshot,
  onJumpToGraphTarget,
  onOpenChainGraph,
  onProbeDkimSelectors,
  loading = false,
}: {
  snapshot: AnalysisSnapshot;
  onJumpToGraphTarget: (targetId: string) => void;
  onOpenChainGraph: () => void;
  onProbeDkimSelectors?: (rawSelectorsInput: string) => void;
  loading?: boolean;
}) {
  const mail: MailAnalysisResult | undefined = snapshot.mailAnalysis;
  const [dkimInput, setDkimInput] = useState(() =>
    (snapshot.customDkimSelectors ?? []).join(', ')
  );

  if (!mail) {
    return (
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-8 text-center space-y-2">
        <Mail className="w-8 h-8 text-slate-400 mx-auto" />
        <div className="font-semibold text-sm">No Mail Analysis Data in Snapshot</div>
        <p className="text-xs text-slate-500">
          Run an analysis in Mail mode to inspect MX routing, SMTP DANE TLSA, SPF, DKIM keys, and
          DMARC policies.
        </p>
      </div>
    );
  }

  const nonNullMxCount = mail.mxHosts.filter((h) => !h.isNullMx).length;
  const daneProtectedCount = mail.mxHosts.filter(
    (h) => !h.isNullMx && (h.dane.status === 'dane-valid' || h.dane.status === 'dane-warning')
  ).length;
  const spfVerdictMeta = getSpfVerdictMeta(mail.spf.verdict);
  const dmarcVerdictMeta = getDmarcVerdictMeta(mail.dmarc.verdict);
  const activeDkimSelectors = mail.dkim.selectors.filter(
    (s) => s.present && s.status !== 'revoked'
  );
  const lookupPct = Math.min(100, Math.round((mail.spf.dnsLookupCount / mail.spf.dnsLookupLimit) * 100));
  const lookupBarColor =
    mail.spf.dnsLookupCount > mail.spf.dnsLookupLimit
      ? 'bg-rose-500'
      : mail.spf.dnsLookupCount >= 8
        ? 'bg-amber-500'
        : 'bg-emerald-500';

  const handleDkimSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (onProbeDkimSelectors) {
      onProbeDkimSelectors(dkimInput);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top 6-Pillar Mail Security Scorecard */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {/* 1. MX Routing Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <Server className="w-3.5 h-3.5" />
              MX Mail Routing
            </span>
            <StatusBadge status={mail.mxDnssecStatus} size="xs" />
          </div>
          <div className="font-bold text-sm text-slate-900 dark:text-slate-100">
            {mail.mxStatus === 'null-mx'
              ? 'Null MX (0 . — No Inbound Mail)'
              : mail.mxStatus === 'implicit-a'
                ? `Implicit A/AAAA Fallback (${mail.implicitFallbackAddresses?.length ?? 0} IPs)`
                : mail.mxStatus === 'none'
                  ? 'No MX or Address Records'
                  : mail.mxStatus === 'broken'
                    ? 'Broken MX Configuration'
                    : `${nonNullMxCount} Mail Exchanger${nonNullMxCount === 1 ? '' : 's'}`}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {mail.mxStatus === 'null-mx'
              ? 'RFC 7505 Null MX instructs senders to reject mail immediately.'
              : nonNullMxCount > 0
                ? `Priorities: ${mail.mxHosts.map((h) => `${h.preference} ${h.displayExchange}`).join(', ')}`
                : mail.mxStatus === 'implicit-a'
                  ? 'No MX RRset; MTAs fall back to apex A/AAAA per RFC 5321 §5.1.'
                  : 'Domain cannot receive inbound SMTP mail.'}
          </p>
        </div>

        {/* 2. SMTP DANE Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <Lock className="w-3.5 h-3.5" />
              SMTP DANE (RFC 7672)
            </span>
            {mail.daneStatus === 'all-valid' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            ) : mail.daneStatus === 'bogus' ? (
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            ) : mail.daneStatus === 'partial' || mail.daneStatus === 'unsigned-ignored' ? (
              <AlertTriangle className="w-4 h-4 text-amber-500" />
            ) : (
              <ShieldOff className="w-4 h-4 text-slate-400" />
            )}
          </div>
          <div className="font-bold text-sm text-slate-900 dark:text-slate-100">
            {mail.daneStatus === 'all-valid'
              ? `Active & Verified (${daneProtectedCount}/${nonNullMxCount} MX)`
              : mail.daneStatus === 'partial'
                ? `Partial / Advisory (${daneProtectedCount}/${nonNullMxCount} MX)`
                : mail.daneStatus === 'unsigned-ignored'
                  ? 'Unsigned TLSA (Ignored!)'
                  : mail.daneStatus === 'bogus'
                    ? 'BOGUS — Delivery Blocked'
                    : mail.daneStatus === 'not-applicable'
                      ? 'Not Applicable'
                      : 'Not Deployed (No TLSA)'}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {mail.daneSummary}
          </p>
        </div>

        {/* 3. SPF Policy & Lookup Budget Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <FileText className="w-3.5 h-3.5" />
              SPF Policy (RFC 7208)
            </span>
            <span
              className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${spfVerdictMeta.cls}`}
            >
              {spfVerdictMeta.label}
            </span>
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-700 dark:text-slate-200 font-semibold">
                DNS Lookups: {mail.spf.dnsLookupCount} / {mail.spf.dnsLookupLimit}
              </span>
              <span className="text-slate-500">
                Void: {mail.spf.voidLookupCount}/{mail.spf.voidLookupLimit}
              </span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${lookupBarColor}`}
                style={{ width: `${mail.spf.present ? Math.max(4, lookupPct) : 0}%` }}
              />
            </div>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {mail.spf.summary}
          </p>
        </div>

        {/* 4. DKIM Keys Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <KeyRound className="w-3.5 h-3.5" />
              DKIM Keys (RFC 6376)
            </span>
            {mail.dkim.status === 'verified' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            ) : mail.dkim.status === 'broken' ? (
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            ) : mail.dkim.status === 'warning' ? (
              <AlertTriangle className="w-4 h-4 text-amber-500" />
            ) : (
              <ShieldOff className="w-4 h-4 text-slate-400" />
            )}
          </div>
          <div className="font-bold text-sm text-slate-900 dark:text-slate-100">
            {activeDkimSelectors.length > 0
              ? `${activeDkimSelectors.length} Active Selector${activeDkimSelectors.length === 1 ? '' : 's'} Found`
              : mail.dkim.status === 'broken'
                ? 'Selector Error / Missing'
                : 'No Common Selector Matched'}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {mail.dkim.summary}
          </p>
        </div>

        {/* 5. DMARC Policy Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <Shield className="w-3.5 h-3.5" />
              DMARC Policy (RFC 7489)
            </span>
            <span
              className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${dmarcVerdictMeta.cls}`}
            >
              {dmarcVerdictMeta.label}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="font-bold text-sm text-slate-900 dark:text-slate-100 font-mono">
              {displayFqdn(mail.dmarc.queriedOwner)}
            </span>
            <StatusBadge status={mail.dmarc.dnssecStatus} size="xs" />
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {mail.dmarc.summary}
          </p>
        </div>

        {/* 6. Multi-Zone DNSSEC Chain Card */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 flex flex-col justify-between gap-2">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                <ShieldCheck className="w-3.5 h-3.5" />
                WebCrypto DNSSEC
              </span>
              <span className="font-mono text-[11px] text-slate-500">
                {snapshot.zones.length} zones
              </span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              Verified DS, DNSKEY, RRSIG &amp; NSEC/NSEC3 chains across{' '}
              <span className="font-mono font-semibold">{snapshot.displayDomain}</span>, MX,{' '}
              <span className="font-mono">_25._tcp</span> TLSA,{' '}
              <span className="font-mono">_domainkey</span>, and{' '}
              <span className="font-mono">_dmarc</span>.
            </p>
          </div>
          <button
            type="button"
            onClick={onOpenChainGraph}
            className="inline-flex items-center justify-center gap-1.5 w-full rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer"
          >
            <Network className="w-3.5 h-3.5" />
            <span>View Full DNSSEC Chain Graph</span>
          </button>
        </div>
      </div>

      {/* Section 1: MX Exchangers & SMTP DANE (_25._tcp TLSA) */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Mail className="w-4 h-4 text-cyan-500" />
              <span>Mail Exchangers (MX) &amp; SMTP DANE (_25._tcp TLSA)</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Ordered by SMTP preference (lowest number tried first). DANE requires DNSSEC
              validation of TLSA records per RFC 7672.
            </p>
          </div>
          {mail.mxRrsetId && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(mail.mxRrsetId!)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
            >
              <span>Locate MX RRset in Graph</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {mail.mxHosts.length > 0 ? (
          <div className="space-y-3">
            {mail.mxHosts.map((host) => (
              <MxHostCard
                key={`${host.preference}-${host.exchange}`}
                host={host}
                onJumpToGraphTarget={onJumpToGraphTarget}
              />
            ))}
          </div>
        ) : mail.mxStatus === 'implicit-a' && mail.implicitFallbackAddresses ? (
          <div className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4 space-y-2">
            <div className="font-semibold text-sm text-amber-800 dark:text-amber-200">
              Implicit Address MX Fallback (RFC 5321 §5.1)
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              No explicit MX records exist at{' '}
              <span className="font-mono font-semibold">{snapshot.displayDomain}</span>. Senders may
              attempt SMTP delivery directly to the apex address record(s):
            </p>
            <div className="flex flex-wrap gap-1.5">
              {mail.implicitFallbackAddresses.map((addr) => (
                <span
                  key={addr.ip}
                  className="rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-2 py-0.5 font-mono text-xs"
                >
                  IPv{addr.family}: {addr.ip}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-6 text-center text-xs text-slate-500">
            No MX or fallback A/AAAA records found for {snapshot.displayDomain}.
          </div>
        )}
      </section>

      {/* Section 2: SPF Policy & Recursive Lookup Tree */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-500" />
              <span>Sender Policy Framework (SPF · RFC 7208)</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Evaluates TXT <code className="font-mono">v=spf1</code> syntax, recursive{' '}
              <code className="font-mono">include:</code> / <code className="font-mono">redirect=</code>{' '}
              chains, and the mandatory 10-DNS-lookup limit.
            </p>
          </div>
          {mail.spf.txtRrsetId && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(mail.spf.txtRrsetId!)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
            >
              <span>Locate TXT RRset in Graph</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {!mail.spf.present ? (
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/5 p-5 space-y-1.5">
            <div className="font-semibold text-sm text-amber-800 dark:text-amber-200">
              No SPF (v=spf1) TXT Record Published
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Publishing <code className="font-mono font-semibold">v=spf1 -all</code> (if this
              domain sends no mail) or listing authorized sending netblocks/includes ending with{' '}
              <code className="font-mono font-semibold">~all</code> /{' '}
              <code className="font-mono font-semibold">-all</code> prevents envelope-from spoofing.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-4">
            {mail.spf.rawRecord && (
              <div className="space-y-1">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Published Apex SPF TXT Policy
                </div>
                <div className="rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3 py-2 font-mono text-xs text-slate-800 dark:text-slate-200 break-all">
                  {mail.spf.rawRecord}
                </div>
              </div>
            )}

            {mail.spf.legacySpfRecords.length > 0 && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200">
                Obsolete <code className="font-mono font-semibold">SPF (TYPE99)</code> record also
                present: <span className="font-mono">{mail.spf.legacySpfRecords.join(' | ')}</span>{' '}
                (discontinued by RFC 7208 §3.1).
              </div>
            )}

            <SpfTreeBranch node={mail.spf.rootNode} />
          </div>
        )}
      </section>

      {/* Section 3: DMARC Policy, Identifier Alignment & External Report Verification */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-500" />
              <span>DMARC Policy &amp; Alignment (_dmarc · RFC 7489 / RFC 9091)</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Inspects <code className="font-mono">_dmarc</code> disposition policy, SPF/DKIM From:
              alignment, organizational fallback, and RFC 7489 §7.1 external{' '}
              <code className="font-mono">_report._dmarc</code> authorization.
            </p>
          </div>
          {(mail.dmarc.txtRrsetId || mail.dmarc.negativeNodeId) && (
            <button
              type="button"
              onClick={() =>
                onJumpToGraphTarget((mail.dmarc.txtRrsetId ?? mail.dmarc.negativeNodeId)!)
              }
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
            >
              <span>
                {mail.dmarc.txtRrsetId ? 'Locate DMARC RRset in Graph' : 'Locate NSEC Proof in Graph'}
              </span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {!mail.dmarc.present ? (
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/5 p-5 space-y-1.5">
            <div className="font-semibold text-sm text-amber-800 dark:text-amber-200">
              No DMARC (v=DMARC1) Record Published at {displayFqdn(mail.dmarc.queriedOwner)}
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              Publish a TXT record at{' '}
              <code className="font-mono font-semibold">
                _dmarc.{snapshot.displayDomain}
              </code>{' '}
              (e.g.{' '}
              <code className="font-mono">
                v=DMARC1; p=quarantine; rua=mailto:dmarc@{snapshot.displayDomain}
              </code>
              ) to protect visible <code className="font-mono">From:</code> headers against spoofing.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100">
                  {displayFqdn(mail.dmarc.queriedOwner)}
                </span>
                {mail.dmarc.usedOrgFallback && (
                  <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[10px] font-semibold">
                    ORG DOMAIN FALLBACK (RFC 7489 §6.6.3)
                  </span>
                )}
                <span
                  className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${dmarcVerdictMeta.cls}`}
                >
                  {dmarcVerdictMeta.label}
                </span>
                <StatusBadge status={mail.dmarc.dnssecStatus} size="xs" />
              </div>

              <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                {mail.dmarc.policy && (
                  <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                    p={mail.dmarc.policy}
                  </span>
                )}
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                  sp={mail.dmarc.subdomainPolicy ?? `${mail.dmarc.policy ?? 'none'} (inherited)`}
                </span>
                {mail.dmarc.nonExistentSubdomainPolicy && (
                  <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                    np={mail.dmarc.nonExistentSubdomainPolicy}
                  </span>
                )}
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                  adkim={mail.dmarc.adkim === 's' ? 's (strict)' : 'r (relaxed)'}
                </span>
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                  aspf={mail.dmarc.aspf === 's' ? 's (strict)' : 'r (relaxed)'}
                </span>
                <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200">
                  pct={mail.dmarc.pct}%
                </span>
              </div>
            </div>

            {mail.dmarc.cnameChain.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
                <span className="font-medium text-slate-500">CNAME Delegation:</span>
                <span className="font-mono">{displayFqdn(mail.dmarc.queriedOwner)}</span>
                {mail.dmarc.cnameChain.map((c) => (
                  <span
                    key={c}
                    className="inline-flex items-center gap-1 font-mono text-cyan-600 dark:text-cyan-400"
                  >
                    <ArrowRight className="w-3 h-3 text-slate-400" />
                    {displayFqdn(c)}
                  </span>
                ))}
              </div>
            )}

            {mail.dmarc.rawRecord && (
              <div className="rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3 py-2 font-mono text-xs text-slate-800 dark:text-slate-200 break-all">
                {mail.dmarc.rawRecord}
              </div>
            )}

            {mail.dmarc.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {mail.dmarc.tags.map((t, idx) => (
                  <span
                    key={`dmarc-tag-${idx}-${t.tag}`}
                    title={t.note}
                    className={`rounded-md border px-2 py-0.5 font-mono text-xs ${
                      !t.valid
                        ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/40'
                        : !t.known
                          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30'
                          : 'bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                    }`}
                  >
                    {t.tag}={t.value}
                  </span>
                ))}
              </div>
            )}

            {(mail.dmarc.rua.length > 0 || mail.dmarc.ruf.length > 0) && (
              <div className="space-y-2 pt-1 border-t border-slate-200/80 dark:border-slate-800">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  DMARC Reporting Destinations &amp; RFC 7489 §7.1 Authorization
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {[
                    ...mail.dmarc.rua.map((u) => ({ kind: 'rua (Aggregate)', u })),
                    ...mail.dmarc.ruf.map((u) => ({ kind: 'ruf (Forensic)', u })),
                  ].map(({ kind, u }, idx) => (
                    <div
                      key={`dmarc-uri-${idx}-${u.raw}`}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-2.5 space-y-1 text-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-1.5">
                        <span className="font-mono text-[10px] uppercase font-semibold text-slate-500">
                          {kind}
                        </span>
                        {!u.syntaxValid ? (
                          <span className="rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                            INVALID URI
                          </span>
                        ) : !u.isExternalDomain ? (
                          <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                            SAME ORG DOMAIN
                          </span>
                        ) : u.externalAuthorized === 'authorized' ? (
                          <span
                            className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
                            title={
                              u.externalVerifyQname
                                ? `Verified ${displayFqdn(u.externalVerifyQname)} TXT = v=DMARC1`
                                : undefined
                            }
                          >
                            EXTERNAL AUTHORIZED (v=DMARC1)
                          </span>
                        ) : u.externalAuthorized === 'unauthorized' ? (
                          <span
                            className="rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
                            title={
                              u.externalVerifyQname
                                ? `Missing ${displayFqdn(u.externalVerifyQname)} TXT v=DMARC1`
                                : undefined
                            }
                          >
                            MISSING _report._dmarc
                          </span>
                        ) : (
                          <span className="rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-1.5 py-0.5 font-mono text-[10px]">
                            EXTERNAL
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-slate-800 dark:text-slate-200 break-all">
                        {u.uri}
                        {u.maxSizeSpec && (
                          <span className="ml-1.5 rounded bg-slate-200/80 dark:bg-slate-800 px-1 py-0.2 text-[10px] text-slate-600 dark:text-slate-300">
                            max {u.maxSizeSpec}
                          </span>
                        )}
                      </div>
                      {u.isExternalDomain && u.externalVerifyQname && (
                        <div className="font-mono text-[10px] text-slate-500 break-all">
                          Auth record: {displayFqdn(u.externalVerifyQname)} TXT
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {mail.dmarc.issues.length > 0 && (
              <div className="space-y-1">
                {mail.dmarc.issues.map((iss, i) => (
                  <div
                    key={`dmarc-iss-${i}`}
                    className="text-xs text-rose-600 dark:text-rose-400 flex items-start gap-1.5"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <span>{iss}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Section 4: DKIM Public Keys & Custom Selector / Header Inspector */}
      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-cyan-500" />
            <span>DKIM Public Keys (_domainkey · RFC 6376 / RFC 8301 / RFC 8463)</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Automatically probes common &amp; provider-hinted selectors, decodes RSA/Ed25519 key
            sizes, and lets you inspect custom selectors or a pasted{' '}
            <code className="font-mono">DKIM-Signature:</code> email header.
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-3.5">
          {onProbeDkimSelectors && (
            <form onSubmit={handleDkimSubmit} className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={dkimInput}
                  onChange={(e) => setDkimInput(e.target.value)}
                  placeholder="Enter DKIM selector(s) (e.g. selector1, google, ietf1) or paste a DKIM-Signature: header…"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 pl-9 pr-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:font-sans placeholder:text-slate-400 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 px-3.5 py-2 text-xs font-semibold text-slate-950 transition-colors cursor-pointer shrink-0"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Probe DKIM Selector(s)</span>
              </button>
            </form>
          )}

          {mail.dkim.probedSelectors.length > 0 && (
            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              Probed {mail.dkim.probedSelectors.length} selector
              {mail.dkim.probedSelectors.length === 1 ? '' : 's'} under{' '}
              <span className="font-mono">_domainkey.{snapshot.displayDomain}</span>:{' '}
              <span className="font-mono text-slate-600 dark:text-slate-300">
                {mail.dkim.probedSelectors.join(', ')}
              </span>
            </div>
          )}

          {mail.dkim.selectors.length > 0 ? (
            <div className="space-y-2.5">
              {mail.dkim.selectors.map((sel) => (
                <DkimSelectorCard
                  key={sel.qname}
                  sel={sel}
                  onJumpToGraphTarget={onJumpToGraphTarget}
                />
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 p-4 text-xs text-slate-600 dark:text-slate-400">
              No active DKIM keys matched common selector names for{' '}
              <span className="font-mono font-semibold">{snapshot.displayDomain}</span>. Because
              DKIM selectors are chosen by the sender (and cannot be enumerated in DNS), enter a
              selector name or paste a <code className="font-mono">DKIM-Signature</code> header
              above to inspect its public key.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
