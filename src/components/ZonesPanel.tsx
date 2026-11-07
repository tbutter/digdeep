import { AlertTriangle, CheckCircle2, Globe, KeyRound, RefreshCw, Server } from 'lucide-react';
import { formatAlgorithm, formatDigestType } from '../dns/constants';
import { displayFqdn } from '../dns/encoding';
import type { AnalysisSnapshot } from '../dns/types';
import { StatusBadge } from './StatusBadge';

export function ZonesPanel({ snapshot }: { snapshot: AnalysisSnapshot }) {
  return (
    <div className="space-y-5">
      {snapshot.zones.map((zone) => (
        <div
          key={zone.zoneName}
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden"
        >
          {/* Zone Header */}
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <Globe className="w-4 h-4 text-cyan-500" />
              <span className="font-mono font-bold text-base text-slate-900 dark:text-slate-100">
                {zone.zoneName === '.' ? '. (Root Zone)' : zone.zoneName}
              </span>
              <span className="rounded bg-slate-200 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                {zone.nsecMode}
              </span>
            </div>
            <StatusBadge status={zone.status} />
          </div>

          <div className="p-5 space-y-5">
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
                          <div className="font-mono text-[10px] text-slate-500 truncate mt-0.5">
                            {[...ns.ipv4, ...ns.ipv6].join(', ')}
                          </div>
                        )}
                        {((ns.asns && ns.asns.length > 0) ||
                          (ns.bgpPrefixes && ns.bgpPrefixes.length > 0)) && (
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
        </div>
      ))}
    </div>
  );
}
