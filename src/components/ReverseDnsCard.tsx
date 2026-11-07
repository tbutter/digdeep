import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Globe,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from 'lucide-react';
import { displayFqdn } from '../dns/encoding';
import type { ReverseDnsAnalysis } from '../dns/types';
import { IpHoverBadge } from './IpHoverBadge';
import { StatusBadge } from './StatusBadge';

export interface ReverseDnsCardProps {
  reverseDns: ReverseDnsAnalysis;
  onJumpToGraphTarget?: (targetId: string) => void;
  onTraceHostname?: (hostname: string) => void;
}

function fcrdnsBadgeMeta(status: ReverseDnsAnalysis['fcrdnsStatus']): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'valid':
      return {
        label: 'FCrDNS VERIFIED ✓',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35',
      };
    case 'partial':
      return {
        label: 'PARTIAL FCrDNS',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'ptr-mismatch':
      return {
        label: 'FCrDNS MISMATCH',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'no-ptr':
      return {
        label: 'NO PTR RECORD',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/30',
      };
    case 'temperror':
      return {
        label: 'PTR SERVFAIL',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'not-applicable':
      return {
        label: 'PTR RESOLVED',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
  }
}

export function ReverseDnsCard({
  reverseDns,
  onJumpToGraphTarget,
  onTraceHostname,
}: ReverseDnsCardProps) {
  const fcrdnsMeta = fcrdnsBadgeMeta(reverseDns.fcrdnsStatus);
  const graphTargetId = reverseDns.ptrRrsetId
    ? `rrset:${reverseDns.ptrRrsetId}`
    : reverseDns.ptrNegativeNodeId
      ? `neg:${reverseDns.ptrNegativeNodeId}`
      : undefined;

  return (
    <section
      aria-label="Reverse DNS (PTR), FCrDNS & BGP ASN Summary"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-4 space-y-3.5"
    >
      {/* Top Row: IP -> .arpa mapping, DNSSEC badge, FCrDNS badge, and BGP ASN summary */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded-md bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
              <Server className="w-3.5 h-3.5" />
              <span>IPv{reverseDns.family} rDNS</span>
            </span>
            <span className="font-mono font-bold text-sm sm:text-base text-slate-900 dark:text-slate-100">
              <IpHoverBadge ip={reverseDns.ip} />
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <span className="font-mono text-xs sm:text-sm font-semibold text-cyan-700 dark:text-cyan-300 break-all">
              {reverseDns.displayArpa}
            </span>
            <StatusBadge status={reverseDns.ptrDnssecStatus} size="xs" />
            <span
              className={`rounded-full px-2.5 py-0.5 font-mono text-[10px] font-semibold ${fcrdnsMeta.cls}`}
            >
              {fcrdnsMeta.label}
            </span>
            {reverseDns.dnsbl && reverseDns.dnsbl.checkedCount > 0 && (
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-mono text-[10px] font-semibold border ${
                  reverseDns.dnsbl.status === 'listed'
                    ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35'
                    : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/35'
                }`}
              >
                {reverseDns.dnsbl.status === 'listed' ? (
                  <>
                    <ShieldAlert className="w-3 h-3" />
                    DNSBL: {reverseDns.dnsbl.listedCount}/{reverseDns.dnsbl.checkedCount} LISTED
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-3 h-3" />
                    DNSBL: 0/{reverseDns.dnsbl.checkedCount} CLEAN ✓
                  </>
                )}
              </span>
            )}
            {reverseDns.isRfc2317ClasslessDelegation && (
              <span className="rounded-md bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 px-2 py-0.5 font-mono text-[10px] font-semibold">
                RFC 2317 Classless CNAME ({reverseDns.cnameChain.map(displayFqdn).join(' → ')})
              </span>
            )}
            {!reverseDns.isPublic && reverseDns.specialRangeNote && (
              <span className="rounded-md bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-2 py-0.5 font-mono text-[10px]">
                {reverseDns.specialRangeNote}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">{reverseDns.fcrdnsSummary}</p>
        </div>

        {graphTargetId && onJumpToGraphTarget && (
          <button
            type="button"
            onClick={() => onJumpToGraphTarget(graphTargetId)}
            className="inline-flex items-center gap-1 self-start lg:self-center rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer shrink-0"
          >
            <span>Locate PTR in Graph</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Middle / Bottom Grid: PTR Target Hostnames (FCrDNS) + BGP ASN Ownership */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* PTR Hostnames & Forward-Confirmed Reverse DNS */}
        <div className="lg:col-span-2 rounded-lg border border-slate-200/90 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2">
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-cyan-500" />
              <span>PTR Target Hostnames &amp; Forward-Confirmed rDNS (FCrDNS)</span>
            </span>
            <span className="font-mono text-[11px] text-slate-400">
              {reverseDns.targets.length} PTR record{reverseDns.targets.length === 1 ? '' : 's'}
            </span>
          </div>

          {reverseDns.targets.length === 0 ? (
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 py-1">
              <ShieldOff className="w-4 h-4 text-slate-400 shrink-0" />
              <span>
                No <code className="font-mono">PTR</code> record published at{' '}
                <code className="font-mono">{reverseDns.displayArpa}</code> (
                {reverseDns.ptrStatus.toUpperCase()}).
              </span>
            </div>
          ) : (
            <div className="space-y-2">
              {reverseDns.targets.map((target) => {
                const forwardIps = [
                  ...target.forwardIpv4.map((ip) => ({ ip, family: 4 as const })),
                  ...target.forwardIpv6.map((ip) => ({ ip, family: 6 as const })),
                ];
                return (
                  <div
                    key={target.hostname}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        {target.forwardStatus === 'match' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                        )}
                        <span className="font-mono text-xs sm:text-sm font-bold text-slate-900 dark:text-slate-100 break-all">
                          {target.displayHostname}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                            target.forwardStatus === 'match'
                              ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                              : target.forwardStatus === 'unchecked'
                                ? 'bg-slate-500/15 text-slate-600 dark:text-slate-400'
                                : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                          }`}
                        >
                          {target.forwardStatus === 'match'
                            ? `FCrDNS Match (${reverseDns.ip})`
                            : target.forwardStatus === 'mismatch'
                              ? 'Forward IP Mismatch'
                              : target.forwardStatus === 'nxdomain'
                                ? 'Forward NXDOMAIN'
                                : target.forwardStatus === 'nodata'
                                  ? 'Forward NODATA'
                                  : target.forwardStatus.toUpperCase()}
                        </span>
                        {target.forwardStatus !== 'unchecked' && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-500">
                            <span>Forward A/AAAA:</span>
                            <StatusBadge status={target.forwardDnssecStatus} size="xs" />
                          </span>
                        )}
                      </div>

                      {forwardIps.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1 pt-0.5">
                          {forwardIps.map((entry) => {
                            const matchesTarget =
                              entry.ip.toLowerCase() === reverseDns.ip.toLowerCase();
                            return (
                              <span
                                key={`${entry.family}-${entry.ip}`}
                                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] border ${
                                  matchesTarget
                                    ? 'bg-emerald-500/15 text-emerald-800 dark:text-emerald-200 border-emerald-500/35 font-semibold'
                                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700'
                                }`}
                              >
                                <span className="text-[9px] uppercase opacity-70">
                                  IPv{entry.family}
                                </span>
                                <IpHoverBadge ip={entry.ip} />
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {onTraceHostname && (
                      <button
                        type="button"
                        onClick={() => onTraceHostname(target.displayHostname)}
                        className="inline-flex items-center gap-1 self-start sm:self-center rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-2.5 py-1 text-[11px] font-semibold text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer shrink-0"
                        title={`Run a forward DNSSEC trace for ${target.displayHostname}`}
                      >
                        <span>Trace {target.displayHostname}</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* BGP ASN & Routed Prefix Card */}
        <div className="rounded-lg border border-slate-200/90 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2 text-xs">
              <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-cyan-500" />
                <span>BGP Origin ASN &amp; Prefix</span>
              </span>
              {reverseDns.bgp?.rir && (
                <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase">
                  {reverseDns.bgp.rir}
                  {reverseDns.bgp.country ? ` · ${reverseDns.bgp.country}` : ''}
                </span>
              )}
            </div>

            {reverseDns.bgp && reverseDns.bgp.asns.length > 0 ? (
              <div className="space-y-2">
                {reverseDns.bgp.asns.map((asnInfo) => (
                  <div key={asnInfo.asn} className="space-y-0.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="rounded-md bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
                        AS{asnInfo.asn}
                      </span>
                      {asnInfo.asName && (
                        <span className="text-xs font-semibold text-slate-800 dark:text-slate-100 break-words">
                          {asnInfo.asName}
                        </span>
                      )}
                    </div>
                  </div>
                ))}

                <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono text-slate-600 dark:text-slate-300">
                  {reverseDns.bgp.bgpPrefix && (
                    <span className="rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-0.5">
                      Prefix: <strong className="text-slate-900 dark:text-slate-100">{reverseDns.bgp.bgpPrefix}</strong>
                    </span>
                  )}
                  {reverseDns.bgp.allocatedDate && (
                    <span className="rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-0.5">
                      Allocated: {reverseDns.bgp.allocatedDate}
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {reverseDns.isPublic
                  ? 'No BGP origin announcement found via Team Cymru DNS.'
                  : `Special-use address range (${reverseDns.specialRangeNote ?? 'not publicly routed in global BGP'}).`}
              </p>
            )}
          </div>

          {reverseDns.bgp?.originQueryName && (
            <div className="text-[10px] font-mono text-slate-400 truncate pt-1 border-t border-slate-200/60 dark:border-slate-800/80">
              Source: {displayFqdn(reverseDns.bgp.originQueryName)} TXT
            </div>
          )}
        </div>
      </div>

      {/* DNSBL IP Reputation Bar (RFC 5782) */}
      {reverseDns.dnsbl && reverseDns.dnsbl.checkedCount > 0 && (
        <div className="rounded-lg border border-slate-200/90 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              {reverseDns.dnsbl.status === 'listed' ? (
                <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
              )}
              <span>DNSBL IP Reputation &amp; Blocklist Check (RFC 5782)</span>
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              {reverseDns.dnsbl.summary}
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {reverseDns.dnsbl.providers.map((prov) => (
              <div
                key={prov.id}
                className={`rounded border px-2.5 py-1.5 text-xs ${
                  prov.status === 'listed'
                    ? 'border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-200'
                    : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 text-slate-700 dark:text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="font-semibold truncate">{prov.label}</span>
                  <span
                    className={`font-mono text-[10px] font-bold shrink-0 ${
                      prov.status === 'listed'
                        ? 'text-rose-600 dark:text-rose-400'
                        : 'text-emerald-600 dark:text-emerald-400'
                    }`}
                  >
                    {prov.status === 'listed'
                      ? prov.returnCodes[0] ?? 'LISTED'
                      : prov.status === 'admin-blocked'
                        ? 'REFUSED'
                        : 'CLEAN'}
                  </span>
                </div>
                <div className="font-mono text-[10px] text-slate-400 truncate">{prov.zone}</div>
                {prov.reasons.length > 0 && (
                  <div
                    className="font-mono text-[10px] text-rose-600 dark:text-rose-300 truncate mt-0.5"
                    title={prov.reasons.join(' | ')}
                  >
                    {prov.reasons[0]}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
