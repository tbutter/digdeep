import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Fingerprint,
  Globe,
  KeyRound,
  RefreshCw,
  Server,
  Sparkles,
} from 'lucide-react';
import { formatAlgorithm, formatDigestType } from '../dns/constants';
import { displayFqdn } from '../dns/encoding';
import type { AnalysisSnapshot } from '../dns/types';
import { IpHoverBadge, RpkiStatusBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { StatusBadge } from './StatusBadge';

export function ZonesPanel({ snapshot }: { snapshot: AnalysisSnapshot }) {
  seedIpAsnCacheFromSnapshot(snapshot);
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
        </div>
      ))}
    </div>
  );
}
