import {
  Binary,
  Check,
  Copy,
  ExternalLink,
  KeyRound,
  Layers,
  Link2,
  Shield,
  Terminal,
  X,
} from 'lucide-react';
import { useState } from 'react';
import { DNSSEC_ALGORITHMS, formatAlgorithm, formatDigestType } from '../dns/constants';
import { generateCliReproducerCommands } from '../dns/digFormat';
import { displayFqdn } from '../dns/encoding';
import type { DohQueryLog, NegativeProofVerification, ZoneAnalysis } from '../dns/types';
import {
  type FocusedWireSubMode,
  findGraphSelectionWireQuery,
} from '../dns/wireQueryFilter';
import type { GraphEdge, GraphNode } from '../graph/layout';
import { IpHoverBadge, RpkiStatusBadge } from './IpHoverBadge';
import { StatusBadge } from './StatusBadge';

export type GraphSelection =
  | { kind: 'node'; node: GraphNode }
  | { kind: 'edge'; edge: GraphEdge }
  | { kind: 'zone'; zone: ZoneAnalysis };

function getCliTargetForSelection(
  selection: GraphSelection
): { qname: string; qtypeName: string } | null {
  if (selection.kind === 'zone') {
    return {
      qname: selection.zone.zoneName,
      qtypeName: selection.zone.dnskeys.length > 0 ? 'DNSKEY' : 'SOA',
    };
  }
  if (selection.kind === 'node') {
    const n = selection.node;
    if (n.dnskey) {
      return { qname: n.dnskey.zone, qtypeName: 'DNSKEY' };
    }
    if (n.rrset) {
      return { qname: n.rrset.name, qtypeName: n.rrset.typeName };
    }
    if (n.dsVerifications && n.dsVerifications.length > 0) {
      return { qname: n.zone, qtypeName: 'DS' };
    }
    if (n.negativeNode) {
      return { qname: n.negativeNode.qname, qtypeName: n.negativeNode.qtypeName };
    }
    if (n.delegationProof) {
      return { qname: n.zone, qtypeName: 'DS' };
    }
  }
  if (selection.kind === 'edge') {
    const e = selection.edge;
    if (e.rrsigVerification) {
      return {
        qname: e.rrsigVerification.rrsig.signerName,
        qtypeName: e.rrsigVerification.rrsig.typeCoveredName,
      };
    }
    if (e.dsVerification) {
      const dsMatch = /^ds-(.+)-\d+$/.exec(e.dsVerification.id);
      return {
        qname: dsMatch ? dsMatch[1] : '.',
        qtypeName: 'DS',
      };
    }
    if (e.cnameEdge) {
      return {
        qname: e.cnameEdge.fromName,
        qtypeName: e.cnameEdge.qtypeName,
      };
    }
    if (e.proof) {
      return {
        qname: e.proof.qname,
        qtypeName: e.proof.qtype ?? 'DS',
      };
    }
  }
  return null;
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium bg-slate-200/70 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer"
    >
      {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

function formatDuration(sec: number): string {
  const abs = Math.abs(sec);
  if (abs >= 86400) return `${(abs / 86400).toFixed(1)}d`;
  if (abs >= 3600) return `${(abs / 3600).toFixed(1)}h`;
  if (abs >= 60) return `${Math.round(abs / 60)}m`;
  return `${abs}s`;
}

function ProofDetails({ proof }: { proof: NegativeProofVerification }) {
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 p-3 text-xs space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-slate-700 dark:text-slate-200">
            Denial Protocol: {proof.protocol}
          </span>
          {proof.optOutUsed && (
            <span className="rounded bg-amber-500/15 text-amber-600 dark:text-amber-300 px-1.5 py-0.5 font-mono text-[10px]">
              RFC 5155 Opt-Out
            </span>
          )}
        </div>
        <p className="text-slate-600 dark:text-slate-400 leading-relaxed">{proof.summary}</p>
      </div>

      {proof.computedHashes && proof.computedHashes.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Computed NSEC3 SHA-1 Hashes
          </h4>
          <div className="space-y-1.5">
            {proof.computedHashes.map((h) => (
              <div
                key={`${h.label}-${h.name}`}
                className="rounded border border-slate-200 dark:border-slate-800 p-2 text-[11px] bg-white dark:bg-slate-900/40"
              >
                <div className="flex justify-between text-slate-500 dark:text-slate-400">
                  <span>{h.label}</span>
                  <span className="font-mono text-slate-700 dark:text-slate-300">{h.name}</span>
                </div>
                <div className="font-mono text-[10px] text-cyan-700 dark:text-cyan-300 break-all mt-0.5">
                  {h.hash}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {proof.items.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Covering {proof.protocol} Records ({proof.items.length})
          </h4>
          {proof.items.map((item, idx) => (
            <div
              key={`${item.owner}-${idx}`}
              className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 text-xs space-y-1 bg-white dark:bg-slate-900/40"
            >
              <div className="text-[11px] font-medium text-cyan-700 dark:text-cyan-300">
                {item.role}
              </div>
              <div className="font-mono text-[11px] break-all text-slate-700 dark:text-slate-200">
                {item.owner} → {item.next}
              </div>
              {item.iterations !== undefined && (
                <div className="text-[10px] text-slate-500 font-mono">
                  iter={item.iterations} salt={item.saltHex || '-'}
                  {item.optOut ? ' flags=1(Opt-Out)' : ' flags=0'}
                </div>
              )}
              <div className="flex flex-wrap gap-1 pt-1">
                {item.types.map((t) => (
                  <span
                    key={t}
                    className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-300"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function GraphInspector({
  selection,
  dohEndpoint,
  capturedAt,
  validatedAt,
  queries,
  onInspectWireQuery,
  onClose,
  dockedWireRail = null,
}: {
  selection: GraphSelection | null;
  dohEndpoint?: string;
  capturedAt?: number;
  validatedAt?: number;
  queries?: DohQueryLog[];
  onInspectWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
  onClose: () => void;
  dockedWireRail?: {
    wireSize?: number;
    onSwitchToWire: () => void;
  } | null;
}) {
  const [cliTool, setCliTool] = useState<'dig' | 'delv' | 'kdig'>('dig');
  if (!selection) return null;

  const matchedWireQuery = queries ? findGraphSelectionWireQuery(selection, queries) : undefined;
  const cliTarget = getCliTargetForSelection(selection);
  const cliCommands = cliTarget
    ? generateCliReproducerCommands({
        qname: cliTarget.qname,
        qtypeName: cliTarget.qtypeName,
        dohEndpoint,
        cd: true,
        capturedAt,
        validatedAt,
      })
    : null;

  const widthCls = dockedWireRail
    ? 'w-full lg:w-[390px] xl:w-[500px] 2xl:w-[556px]'
    : 'w-full lg:w-[390px]';

  return (
    <aside
      className={`safe-area-bottom ${widthCls} shrink-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md shadow-lg flex flex-col sticky bottom-[max(0.75rem,env(safe-area-inset-bottom,0px))] lg:top-44 lg:bottom-auto z-20 max-h-[46dvh] lg:max-h-[calc(100dvh-12rem)] overflow-hidden`}
    >
      {dockedWireRail && (
        <div
          data-testid="graph-inspector-rail-switcher"
          className="grid grid-cols-2 gap-1.5 px-2.5 py-1.5 border-b border-slate-200 dark:border-slate-800 bg-slate-100/90 dark:bg-slate-900/95 shrink-0"
        >
          <button
            type="button"
            data-testid="rail-switch-node-crypto"
            aria-pressed="true"
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-500 px-2.5 py-1.5 text-xs font-semibold text-slate-950 shadow-sm min-w-0 cursor-pointer"
          >
            <Shield className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Node Crypto ●</span>
          </button>
          <button
            type="button"
            data-testid="rail-switch-wire-hex"
            onClick={dockedWireRail.onSwitchToWire}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 hover:border-cyan-500 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 transition-colors min-w-0 cursor-pointer"
            title="Switch right rail to Docked DoH Wire & Hex Inspector"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
            <span className="truncate">
              Wire &amp; Hex{dockedWireRail.wireSize ? ` (${dockedWireRail.wireSize}B)` : ''}
            </span>
          </button>
        </div>
      )}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-2 min-w-0">
          {selection.kind === 'zone' && <Layers className="w-4 h-4 text-cyan-500 shrink-0" />}
          {selection.kind === 'node' && selection.node.kind === 'dnskey' && (
            <KeyRound className="w-4 h-4 text-cyan-500 shrink-0" />
          )}
          {selection.kind === 'node' && selection.node.kind !== 'dnskey' && (
            <Shield className="w-4 h-4 text-cyan-500 shrink-0" />
          )}
          {selection.kind === 'edge' && <Link2 className="w-4 h-4 text-cyan-500 shrink-0" />}
          <h3 className="font-semibold text-sm truncate text-slate-900 dark:text-slate-100">
            {selection.kind === 'zone'
              ? `Zone: ${selection.zone.zoneName}`
              : selection.kind === 'node'
                ? selection.node.title
                : selection.edge.label}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          aria-label="Close inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 overflow-y-auto space-y-4 text-sm flex-1">
        {/* ZONE INSPECTOR */}
        {selection.kind === 'zone' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <StatusBadge status={selection.zone.status} />
              <span className="font-mono text-xs text-slate-500">{selection.zone.nsecMode}</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              {selection.zone.statusReason}
            </p>

            {selection.zone.trustAnchorMatches.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Trust Anchors Checked
                </h4>
                {selection.zone.trustAnchorMatches.map((tm) => (
                  <div
                    key={tm.anchorId}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between font-medium">
                      <span>{tm.label}</span>
                      <span
                        className={
                          tm.matched
                            ? 'text-emerald-600 dark:text-emerald-400 font-mono text-[11px]'
                            : 'text-slate-400 font-mono text-[11px]'
                        }
                      >
                        {tm.matched ? 'MATCHED ✓' : 'NOT PRESENT'}
                      </span>
                    </div>
                    <div className="font-mono text-[10px] text-slate-500 break-all">
                      SHA-256: {tm.expectedDigestHex}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {selection.zone.soa && (
              <div className="space-y-1.5">
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Start of Authority (SOA)
                </h4>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 text-xs font-mono space-y-1 bg-slate-50 dark:bg-slate-900/50">
                  <div>Primary NS: {selection.zone.soa.mname}</div>
                  <div>Hostmaster: {selection.zone.soa.rname}</div>
                  <div>Serial: {selection.zone.soa.serial}</div>
                  <div className="text-[11px] text-slate-500">
                    Refresh {selection.zone.soa.refresh}s · Retry {selection.zone.soa.retry}s ·
                    Minimum {selection.zone.soa.minimum}s
                  </div>
                </div>
              </div>
            )}

            {selection.zone.nameservers.length > 0 && (
              <div className="space-y-1.5">
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Authoritative Nameservers ({selection.zone.nameservers.length})
                </h4>
                <div className="space-y-1">
                  {selection.zone.nameservers.map((ns) => (
                    <div
                      key={ns.hostname}
                      className="rounded border border-slate-200 dark:border-slate-800 px-2.5 py-1.5 text-xs"
                    >
                      <div className="font-mono font-medium text-slate-800 dark:text-slate-200">
                        {displayFqdn(ns.hostname)}
                      </div>
                      {(ns.ipv4.length > 0 || ns.ipv6.length > 0) && (
                        <div className="font-mono text-[10px] text-slate-500 mt-0.5 break-all flex flex-wrap gap-x-1.5 gap-y-0.5">
                          {[...ns.ipv4, ...ns.ipv6].map((ip, idx, arr) => (
                            <span key={ip}>
                              <IpHoverBadge ip={ip} />
                              {idx < arr.length - 1 ? ' ·' : ''}
                            </span>
                          ))}
                        </div>
                      )}
                      {((ns.asns && ns.asns.length > 0) ||
                        (ns.bgpPrefixes && ns.bgpPrefixes.length > 0) ||
                        (ns.rpkiStatus && ns.rpkiStatus !== 'error')) && (
                        <div className="flex flex-wrap items-center gap-1 mt-1">
                          {ns.asns?.map((a) => (
                            <span
                              key={a.asn}
                              className="rounded bg-cyan-500/10 border border-cyan-500/25 px-1.5 py-0.5 font-mono text-[10px] font-bold text-cyan-700 dark:text-cyan-300"
                            >
                              AS{a.asn}
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
              </div>
            )}
          </div>
        )}

        {/* DNSKEY NODE INSPECTOR */}
        {selection.kind === 'node' && selection.node.dnskey && (
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <StatusBadge status={selection.node.dnskey.status} />
              <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-2 py-0.5 font-mono text-xs">
                {selection.node.badge}
              </span>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              {selection.node.dnskey.statusReason}
            </p>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5">
                <div className="text-[10px] uppercase text-slate-500">Key Tag</div>
                <div className="font-mono font-semibold mt-0.5">
                  #{selection.node.dnskey.keyTag}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5">
                <div className="text-[10px] uppercase text-slate-500">Flags</div>
                <div className="font-mono font-semibold mt-0.5">
                  {selection.node.dnskey.flags}
                  {selection.node.dnskey.isSep ? ' (SEP)' : ' (ZSK)'}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 col-span-2">
                <div className="text-[10px] uppercase text-slate-500">Algorithm & Strength</div>
                <div className="font-mono font-medium mt-0.5">
                  {formatAlgorithm(selection.node.dnskey.algorithm)} ·{' '}
                  {selection.node.dnskey.keySizeInfo}
                </div>
                {DNSSEC_ALGORITHMS[selection.node.dnskey.algorithm] && (
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    RFC 8624 status:{' '}
                    <span className="font-mono">
                      {DNSSEC_ALGORITHMS[selection.node.dnskey.algorithm].rfc8624}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {selection.node.dnskey.signsTypes.length > 0 && (
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">
                  Verified Signatures Made By This Key
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {selection.node.dnskey.signsTypes.map((t) => (
                    <span
                      key={t}
                      className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-2 py-0.5 font-mono text-xs"
                    >
                      RRSIG({t})
                    </span>
                  ))}
                </div>
              </div>
            )}

            {selection.node.dnskey.computedSha256 && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Computed DS (SHA-256)
                  </span>
                  <CopyButton
                    text={`${selection.node.dnskey.zone} IN DS ${selection.node.dnskey.keyTag} ${selection.node.dnskey.algorithm} 2 ${selection.node.dnskey.computedSha256}`}
                    label="Copy DS RR"
                  />
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 p-2.5 font-mono text-[11px] break-all text-slate-700 dark:text-slate-300">
                  {selection.node.dnskey.computedSha256}
                </div>
              </div>
            )}

            {selection.node.dnskey.publicKeyBase64 && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Public Key (Base64)
                  </span>
                  <CopyButton text={selection.node.dnskey.publicKeyBase64} />
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 p-2.5 font-mono text-[10px] break-all max-h-28 overflow-y-auto text-slate-600 dark:text-slate-400">
                  {selection.node.dnskey.publicKeyBase64}
                </div>
              </div>
            )}
          </div>
        )}

        {/* RRSET / DS-GROUP NODE INSPECTOR */}
        {selection.kind === 'node' &&
          (selection.node.kind === 'rrset' || selection.node.kind === 'ds-group') && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <StatusBadge status={selection.node.status} />
                <span className="rounded bg-slate-200 dark:bg-slate-800 px-2 py-0.5 font-mono text-xs">
                  {selection.node.badge}
                </span>
              </div>

              {selection.node.rrset && (
                <>
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    {selection.node.rrset.statusReason}
                  </p>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Records ({selection.node.rrset.records.length}) · TTL{' '}
                        {selection.node.rrset.ttl}s
                      </span>
                      <CopyButton
                        text={selection.node.rrset.records
                          .map(
                            (r) => `${r.name}\t${r.ttl}\tIN\t${r.typeName}\t${r.rdataText}`
                          )
                          .join('\n')}
                        label="Copy RRset"
                      />
                    </div>
                    <div className="space-y-1.5">
                      {selection.node.rrset.records.map((rec, i) => (
                        <div
                          key={`${rec.rdataBase64}-${i}`}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 p-2.5 font-mono text-xs break-all text-slate-800 dark:text-slate-200"
                        >
                          {rec.typeName === 'A' || rec.typeName === 'AAAA' ? (
                            <IpHoverBadge ip={rec.rdataText} />
                          ) : (
                            rec.rdataText
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {selection.node.rrset.rrsigs.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Covering RRSIGs ({selection.node.rrset.rrsigs.length})
                      </h4>
                      {selection.node.rrset.rrsigs.map((rv) => (
                        <div
                          key={rv.id}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 text-xs space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono font-semibold">
                              Key #{rv.signerKeyTag} · {formatAlgorithm(rv.rrsig.algorithm)}
                            </span>
                            <StatusBadge status={rv.status} size="xs" />
                          </div>
                          <div className="text-slate-600 dark:text-slate-400">{rv.reason}</div>
                          <div className="font-mono text-[10px] text-slate-500 space-y-0.5 pt-1">
                            <div>
                              Inception: {new Date(rv.rrsig.inception * 1000).toISOString()}
                            </div>
                            <div>
                              Expires: {new Date(rv.rrsig.expiration * 1000).toISOString()} (
                              {rv.remainingSeconds >= 0
                                ? `in ${formatDuration(rv.remainingSeconds)}`
                                : `${formatDuration(rv.remainingSeconds)} ago`}
                              )
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {selection.node.dsVerifications && selection.node.dsVerifications.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    DS → Child DNSKEY Digest Checks
                  </h4>
                  {selection.node.dsVerifications.map((dsv) => (
                    <div
                      key={dsv.id}
                      className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold">
                          Key #{dsv.ds.keyTag} · {formatDigestType(dsv.ds.digestType)}
                        </span>
                        <StatusBadge status={dsv.status} size="xs" />
                      </div>
                      <div className="text-slate-600 dark:text-slate-400">{dsv.reason}</div>
                      <div className="font-mono text-[10px] text-slate-500 break-all">
                        Parent DS: {dsv.ds.digestHex}
                      </div>
                      {dsv.computedDigestHex && (
                        <div className="font-mono text-[10px] text-emerald-600 dark:text-emerald-400 break-all">
                          Child Key: {dsv.computedDigestHex}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

        {/* UNSIGNED DELEGATION OR NEGATIVE NODE INSPECTOR */}
        {selection.kind === 'node' && selection.node.delegationProof && (
          <div className="space-y-3">
            <StatusBadge status={selection.node.status} />
            <ProofDetails proof={selection.node.delegationProof} />
          </div>
        )}

        {selection.kind === 'node' && selection.node.negativeNode && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <StatusBadge status={selection.node.negativeNode.status} />
              <span className="font-mono text-xs text-slate-500">
                {selection.node.negativeNode.kind} ({selection.node.negativeNode.qtypeName})
              </span>
            </div>
            <ProofDetails proof={selection.node.negativeNode.proof} />
          </div>
        )}

        {/* EDGE INSPECTOR */}
        {selection.kind === 'edge' && (
          <div className="space-y-4">
            <StatusBadge status={selection.edge.status} />

            {selection.edge.rrsigVerification && (
              <div className="space-y-3 text-xs">
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                  {selection.edge.rrsigVerification.reason}
                </p>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 space-y-1.5 font-mono text-[11px] bg-slate-50 dark:bg-slate-900/50">
                  <div>Signer: {selection.edge.rrsigVerification.rrsig.signerName}</div>
                  <div>Key Tag: #{selection.edge.rrsigVerification.signerKeyTag}</div>
                  <div>
                    Algorithm: {formatAlgorithm(selection.edge.rrsigVerification.rrsig.algorithm)}
                  </div>
                  <div>
                    Type Covered: {selection.edge.rrsigVerification.rrsig.typeCoveredName}
                  </div>
                  <div>
                    Labels: {selection.edge.rrsigVerification.rrsig.labels}{' '}
                    {selection.edge.rrsigVerification.wildcardSynthesized
                      ? '(Wildcard synthesized!)'
                      : '(Exact owner)'}
                  </div>
                  <div>
                    Original TTL: {selection.edge.rrsigVerification.rrsig.originalTtl}s
                  </div>
                  <div>
                    Inception:{' '}
                    {new Date(
                      selection.edge.rrsigVerification.rrsig.inception * 1000
                    ).toISOString()}
                  </div>
                  <div>
                    Expiration:{' '}
                    {new Date(
                      selection.edge.rrsigVerification.rrsig.expiration * 1000
                    ).toISOString()}
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] uppercase font-semibold text-slate-500">
                      Cryptographic Signature (Base64)
                    </span>
                    <CopyButton
                      text={selection.edge.rrsigVerification.rrsig.signatureBase64}
                    />
                  </div>
                  <div className="rounded border border-slate-200 dark:border-slate-800 p-2 font-mono text-[10px] break-all text-slate-500">
                    {selection.edge.rrsigVerification.rrsig.signatureBase64}
                  </div>
                </div>
              </div>
            )}

            {selection.edge.dsVerification && (
              <div className="space-y-3 text-xs">
                <p className="text-slate-700 dark:text-slate-300">
                  {selection.edge.dsVerification.reason}
                </p>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 space-y-1.5 font-mono text-[11px] bg-slate-50 dark:bg-slate-900/50">
                  <div>Key Tag: #{selection.edge.dsVerification.ds.keyTag}</div>
                  <div>
                    Algorithm: {formatAlgorithm(selection.edge.dsVerification.ds.algorithm)}
                  </div>
                  <div>
                    Digest Type: {formatDigestType(selection.edge.dsVerification.ds.digestType)}
                  </div>
                  <div className="break-all pt-1">
                    DS Digest: {selection.edge.dsVerification.ds.digestHex}
                  </div>
                </div>
              </div>
            )}

            {selection.edge.cnameEdge && (
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-1.5 text-violet-600 dark:text-violet-400 font-medium">
                  <ExternalLink className="w-3.5 h-3.5" />
                  Canonical Name Alias ({selection.edge.cnameEdge.qtypeName} query)
                </div>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 font-mono text-[11px] space-y-1">
                  <div>From: {selection.edge.cnameEdge.fromName}</div>
                  <div>Target: {selection.edge.cnameEdge.toName}</div>
                </div>
              </div>
            )}

            {selection.edge.proof && <ProofDetails proof={selection.edge.proof} />}
          </div>
        )}

        {/* Cross-Tab Recorded DoH Wire Packet Deep Jump */}
        {matchedWireQuery && onInspectWireQuery && (
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <div className="flex items-center justify-between gap-2 text-[11px]">
              <span className="font-semibold uppercase tracking-wider text-slate-500">
                Recorded DoH Wire Packet
              </span>
              <span className="font-mono text-[10px] text-slate-500 truncate">
                {matchedWireQuery.qname} {matchedWireQuery.qtypeName} ·{' '}
                {matchedWireQuery.packet.wireSize}B
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => onInspectWireQuery(matchedWireQuery.id, 'dig')}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
              >
                <Terminal className="w-3.5 h-3.5 text-cyan-500" />
                <span>Inspect dig</span>
              </button>
              <button
                type="button"
                onClick={() => onInspectWireQuery(matchedWireQuery.id, 'hex-resp')}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/35 hover:border-cyan-400 bg-cyan-500/10 px-2.5 py-1.5 text-xs font-medium text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer"
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Dissect Hex</span>
              </button>
            </div>
          </div>
        )}

        {/* CLI Command Reproducer (dig / delv / kdig) */}
        {cliCommands && (
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <Terminal className="w-3.5 h-3.5 text-cyan-500" />
                <span>CLI Reproducer</span>
              </div>
              <div className="inline-flex items-center rounded border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-900 p-0.5">
                {(['dig', 'delv', 'kdig'] as const).map((tool) => (
                  <button
                    key={tool}
                    type="button"
                    onClick={() => setCliTool(tool)}
                    className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold transition-colors cursor-pointer ${
                      cliTool === tool
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    {tool}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 p-2">
              <code className="font-mono text-[11px] text-cyan-800 dark:text-cyan-300 break-all">
                {cliCommands[cliTool]}
              </code>
              <div className="shrink-0">
                <CopyButton text={cliCommands[cliTool]} label={`Copy ${cliTool}`} />
              </div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
