import { Globe, KeyRound, Server } from 'lucide-react';
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
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    SOA Parameters
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
                </div>
              )}

              {zone.nameservers.length > 0 && (
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3.5 space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <Server className="w-3.5 h-3.5" />
                    Authoritative Nameservers ({zone.nameservers.length})
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs">
                    {zone.nameservers.map((ns) => (
                      <div
                        key={ns.hostname}
                        className="rounded border border-slate-100 dark:border-slate-800/90 bg-slate-50 dark:bg-slate-950/50 px-2.5 py-1.5"
                      >
                        <div className="font-mono font-medium text-slate-800 dark:text-slate-200 truncate">
                          {displayFqdn(ns.hostname)}
                        </div>
                        {(ns.ipv4.length > 0 || ns.ipv6.length > 0) && (
                          <div className="font-mono text-[10px] text-slate-500 truncate mt-0.5">
                            {[...ns.ipv4, ...ns.ipv6].join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

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
