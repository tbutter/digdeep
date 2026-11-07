import {
  Activity,
  AlertTriangle,
  GitCommit,
  KeyRound,
  Network,
  Radio,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { DohResolverRole } from '../dns/constants';
import { displayFqdn } from '../dns/encoding';
import type {
  AnalysisSnapshot,
  ConsensusAnalysisResult,
  ConsensusResolverClassification,
} from '../dns/types';
import { IpHoverBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';

function getRoleBadgeMeta(role: DohResolverRole): { label: string; cls: string } {
  switch (role) {
    case 'unfiltered':
      return {
        label: 'UNFILTERED',
        cls: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30',
      };
    case 'protective':
      return {
        label: 'PROTECTIVE',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'family-adblock':
      return {
        label: 'FAMILY · NOADS',
        cls: 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30',
      };
  }
}

function getClassificationBadgeMeta(
  classification: ConsensusResolverClassification
): { label: string; cls: string } {
  switch (classification) {
    case 'resolved-secure':
      return {
        label: 'RESOLVED · AD=1',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'resolved-insecure':
      return {
        label: 'UNSIGNED · AD=0',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'policy-blocked':
      return {
        label: 'PROTECTIVE BLOCKED',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/40',
      };
    case 'dnssec-bogus':
      return {
        label: 'DNSSEC BOGUS',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'nxdomain':
      return {
        label: 'NXDOMAIN',
        cls: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30',
      };
    case 'nodata':
      return {
        label: 'NODATA',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
    case 'upstream-error':
      return {
        label: 'UPSTREAM ERROR',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
      };
    case 'unreachable':
      return {
        label: 'UNREACHABLE',
        cls: 'bg-slate-500/15 text-slate-500 border border-slate-500/25',
      };
  }
}

function getVerdictBadgeMeta(verdict: ConsensusAnalysisResult['overallVerdict']): {
  label: string;
  cls: string;
} {
  switch (verdict) {
    case 'unanimous-secure':
      return {
        label: 'UNANIMOUS SECURE (AD=1)',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'unanimous-unsigned':
      return {
        label: 'UNANIMOUS UNSIGNED (AD=0)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'geodns-consistent':
      return {
        label: 'GEODNS / ANYCAST SYNC',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'protective-blocked':
      return {
        label: 'PROTECTIVE FILTERED',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'propagation-skew':
      return {
        label: 'SOA / KEY ROLLOVER SKEW',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'split-horizon-divergent':
      return {
        label: 'SPLIT-HORIZON / AD MISMATCH',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
    case 'dnssec-bogus':
      return {
        label: 'DNSSEC BOGUS REJECTED',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
  }
}

export function ConsensusView({
  snapshot,
  onOpenChainGraph,
  onOpenWireResponses,
}: {
  snapshot: AnalysisSnapshot;
  onOpenChainGraph: () => void;
  onOpenWireResponses: () => void;
}) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const consensus = snapshot.consensusAnalysis;
  if (!consensus) return null;

  const verdictMeta = getVerdictBadgeMeta(consensus.overallVerdict);

  return (
    <div className="space-y-4">
      {/* Top 4 Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {/* Card 1: Multi-Resolver Consensus Verdict */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <Radio className="w-4 h-4 text-cyan-500" />
              <span>Resolver Consensus</span>
            </div>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${verdictMeta.cls}`}
            >
              {verdictMeta.label}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {consensus.summary}
          </p>
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] font-mono text-slate-500">
            <span>
              {consensus.reachableCount}/{consensus.resolvers.length} resolvers reachable
            </span>
            <span>·</span>
            <span>AD: {consensus.adBitConsensus.toUpperCase()}</span>
          </div>
        </div>

        {/* Card 2: Protective DNS Filtering & RFC 8914 EDE */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
              {consensus.protectiveBlockedResolvers.length > 0 ? (
                <ShieldAlert className="w-4 h-4 text-amber-500" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
              )}
              <span>Protective Filtering &amp; EDE</span>
            </div>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${
                consensus.protectiveBlockedResolvers.length > 0
                  ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                  : consensus.dnssecBogusResolvers.length > 0
                    ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35'
                    : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
              }`}
            >
              {consensus.protectiveBlockedResolvers.length > 0
                ? `${consensus.protectiveBlockedResolvers.length} BLOCKED`
                : consensus.dnssecBogusResolvers.length > 0
                  ? `${consensus.dnssecBogusResolvers.length} EDE BOGUS`
                  : 'NOT BLOCKED'}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {consensus.protectiveBlockedResolvers.length > 0
              ? `Filtered by: ${consensus.protectiveBlockedResolvers.join(', ')}.`
              : consensus.edeHighlights.length > 0
                ? `${consensus.edeHighlights.length} RFC 8914 Extended DNS Error(s) reported across resolvers.`
                : 'No protective threat-blocking or family-filter blocks triggered across Quad9 or DNS4EU.'}
          </p>
        </div>

        {/* Card 3: SOA Serial & Zone Propagation */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <GitCommit className="w-4 h-4 text-cyan-500" />
              <span>SOA Serial Propagation</span>
            </div>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${
                consensus.soaSerialConsensus === 'synchronized'
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                  : consensus.soaSerialConsensus === 'skew-detected'
                    ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                    : 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25'
              }`}
            >
              {consensus.soaSerialConsensus === 'synchronized'
                ? 'SYNCHRONIZED'
                : consensus.soaSerialConsensus === 'skew-detected'
                  ? `${consensus.uniqueSoaSerials.length} SERIALS (SKEW)`
                  : 'N/A'}
            </span>
          </div>
          <div className="space-y-1 text-xs font-mono">
            {consensus.uniqueSoaSerials.length > 0 ? (
              consensus.uniqueSoaSerials.map((s) => (
                <div key={s.serial} className="flex items-center justify-between gap-2">
                  <span className="font-bold text-slate-800 dark:text-slate-200">{s.serial}</span>
                  <span className="text-[11px] text-slate-500 truncate">
                    {s.resolvers.length} resolver{s.resolvers.length === 1 ? '' : 's'}
                  </span>
                </div>
              ))
            ) : (
              <span className="text-slate-500 font-sans">No SOA serial returned</span>
            )}
          </div>
        </div>

        {/* Card 4: DNSKEY / DS Key-Tag Rollover Consistency */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <KeyRound className="w-4 h-4 text-cyan-500" />
              <span>DNSKEY &amp; Answer Sync</span>
            </div>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${
                consensus.keyTagConsensus === 'synchronized'
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                  : consensus.keyTagConsensus === 'rollover-skew'
                    ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                    : 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25'
              }`}
            >
              {consensus.keyTagConsensus === 'synchronized'
                ? 'KEYS IN SYNC'
                : consensus.keyTagConsensus === 'rollover-skew'
                  ? 'KEY ROLLOVER SKEW'
                  : 'UNSIGNED'}
            </span>
          </div>
          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
            {consensus.answerConsensus === 'identical'
              ? 'All resolvers return identical A/AAAA IP sets.'
              : consensus.answerConsensus === 'geodns-anycast'
                ? 'Resolvers receive GeoDNS / CDN anycast regional IP sets with synchronized SOA.'
                : consensus.answerConsensus === 'protective-sinkhole'
                  ? 'Protective resolver(s) sinkholed or blocked A/AAAA resolution.'
                  : 'No A/AAAA answers returned.'}
          </p>
        </div>
      </div>

      {/* RFC 8914 Extended DNS Error (EDE) Highlights Banner */}
      {consensus.edeHighlights.length > 0 && (
        <section className="rounded-xl border border-amber-500/35 bg-amber-500/5 p-4 space-y-2.5">
          <div className="flex items-center gap-2 text-xs font-semibold text-amber-800 dark:text-amber-200">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span>
              RFC 8914 Extended DNS Error (EDE · EDNS0 Option 15) Diagnostics Across Resolvers
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {consensus.edeHighlights.map((item, idx) => (
              <div
                key={`${item.resolverLabel}-${item.infoCode}-${idx}`}
                className="rounded-lg border border-amber-500/25 bg-white/90 dark:bg-slate-900/90 px-3 py-2 text-xs flex flex-col gap-1"
              >
                <div className="flex items-center justify-between gap-2 font-mono">
                  <span className="font-bold text-slate-900 dark:text-slate-100">
                    {item.resolverLabel}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                      item.category === 'dnssec-bogus'
                        ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30'
                        : item.category === 'policy-blocked'
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                          : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300'
                    }`}
                  >
                    EDE {item.infoCode}: {item.name}
                  </span>
                </div>
                {item.extraText && (
                  <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 break-all">
                    EXTRA-TEXT: &quot;{item.extraText}&quot;
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Multi-Resolver Comparison Matrix Table */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 overflow-hidden">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-500" />
            <h2 className="font-semibold text-sm">
              Multi-Resolver DoH Matrix for{' '}
              <code className="font-mono text-cyan-700 dark:text-cyan-300">
                {consensus.displayDomain}
              </code>{' '}
              (SOA Zone: <code className="font-mono">{displayFqdn(consensus.soaZone)}</code>)
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onOpenWireResponses}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
            >
              <span>Inspect Wire Packets</span>
            </button>
            <button
              type="button"
              onClick={onOpenChainGraph}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span>DNSSEC Chain Graph</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-2.5 px-3.5">DoH Resolver</th>
                <th className="py-2.5 px-3">Policy Role</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">RCODE &amp; AD</th>
                <th className="py-2.5 px-3">A / AAAA Answers</th>
                <th className="py-2.5 px-3">SOA Serial &amp; Key Tags</th>
                <th className="py-2.5 px-3">RFC 8914 EDE</th>
                <th className="py-2.5 px-3.5 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70 font-mono">
              {consensus.resolvers.map((r) => {
                const roleMeta = getRoleBadgeMeta(r.role);
                const classMeta = getClassificationBadgeMeta(r.classification);
                return (
                  <tr
                    key={r.endpoint}
                    className="hover:bg-slate-50/80 dark:hover:bg-slate-950/40 transition-colors"
                  >
                    <td className="py-2.5 px-3.5">
                      <div className="font-bold text-slate-900 dark:text-slate-100">
                        {r.shortLabel}
                      </div>
                      <div className="font-sans text-[11px] text-slate-500">{r.provider}</div>
                    </td>

                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold ${roleMeta.cls}`}
                      >
                        {roleMeta.label}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold ${classMeta.cls}`}
                      >
                        {classMeta.label}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      {r.reachable ? (
                        <div className="flex items-center gap-1.5">
                          <span
                            className={
                              r.rcode === 0
                                ? 'text-emerald-600 dark:text-emerald-400 font-bold'
                                : r.rcode === 3
                                  ? 'text-amber-600 dark:text-amber-400 font-bold'
                                  : 'text-rose-600 dark:text-rose-400 font-bold'
                            }
                          >
                            {r.rcodeName}
                          </span>
                          <span
                            className={`rounded px-1.5 py-0.2 text-[10px] ${
                              r.adBit
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-bold'
                                : 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                            }`}
                          >
                            AD={r.adBit ? '1' : '0'}
                          </span>
                        </div>
                      ) : (
                        <span className="text-slate-400">TIMEOUT</span>
                      )}
                    </td>

                    <td className="py-2.5 px-3 max-w-[260px]">
                      {r.ipv4Answers.length === 0 && r.ipv6Answers.length === 0 ? (
                        <span className="text-slate-400 font-sans italic">none</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {[...r.ipv4Answers, ...r.ipv6Answers].slice(0, 4).map((ip) => (
                            <span
                              key={ip}
                              className={`rounded px-1.5 py-0.5 text-[11px] ${
                                r.isSinkholed
                                  ? 'bg-amber-500/20 text-amber-800 dark:text-amber-200 border border-amber-500/40 font-bold'
                                  : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                              }`}
                            >
                              <IpHoverBadge ip={ip} />
                            </span>
                          ))}
                          {r.ipv4Answers.length + r.ipv6Answers.length > 4 && (
                            <span className="text-[10px] text-slate-400">
                              +{r.ipv4Answers.length + r.ipv6Answers.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="space-y-0.5 text-[11px]">
                        <div>
                          SOA:{' '}
                          <strong className="text-slate-800 dark:text-slate-200">
                            {r.soaSerial ?? '—'}
                          </strong>
                        </div>
                        {r.dnskeyKeyTags.length > 0 && (
                          <div className="text-[10px] text-slate-500">
                            DNSKEY: #{r.dnskeyKeyTags.join(', #')}
                          </div>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-3">
                      {r.ede.length === 0 ? (
                        <span className="text-slate-400">—</span>
                      ) : (
                        <div className="space-y-1">
                          {r.ede.map((e, i) => (
                            <div key={i} className="text-[11px]">
                              <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-semibold">
                                EDE {e.infoCode}: {e.name}
                              </span>
                              {e.extraText && (
                                <div className="text-[10px] text-slate-500 truncate max-w-[200px]">
                                  {e.extraText}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </td>

                    <td className="py-2.5 px-3.5 text-right text-slate-500">
                      {r.reachable ? `${r.latencyMs}ms` : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
