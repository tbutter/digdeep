import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  Compass,
  Copy,
  GitCommit,
  Globe,
  KeyRound,
  Loader2,
  Network,
  Play,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type { DohResolverRole } from '../dns/constants';
import { generateCliReproducerCommands } from '../dns/digFormat';
import {
  ECS_DOH_ENDPOINTS,
  ECS_QUICK_CUSTOM_CHIPS,
  probeCustomEcsSubnet,
  selectEcsDohEndpoint,
} from '../dns/ecsProbe';
import { displayFqdn } from '../dns/encoding';
import type {
  AnalysisSnapshot,
  ConsensusAnalysisResult,
  ConsensusResolverClassification,
  EcsAddressProbeResult,
  EcsGeoAnalysisResult,
  RpkiValidationState,
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

function getEcsSteeringBadgeMeta(model: EcsGeoAnalysisResult['steeringModel']): {
  label: string;
  cls: string;
} {
  switch (model) {
    case 'geodns-cname':
      return {
        label: 'GEODNS CNAME STEERING',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'geodns-ip':
      return {
        label: 'GEODNS IP STEERING',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'anycast-uniform':
      return {
        label: 'ANYCAST UNIFORM',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30',
      };
    case 'partial-or-error':
      return {
        label: 'REGIONAL DIVERGENCE',
        cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35',
      };
  }
}

function getRpkiBadgeMeta(status: RpkiValidationState): { label: string; cls: string } {
  switch (status) {
    case 'valid':
      return {
        label: 'ROA VALID',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
    case 'invalid-asn':
      return {
        label: 'ROA INVALID ASN',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'invalid-length':
      return {
        label: 'ROA INVALID LEN',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'not-found':
      return {
        label: 'ROA UNSIGNED',
        cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25',
      };
    default:
      return {
        label: 'ROA N/A',
        cls: 'bg-slate-500/15 text-slate-500 border border-slate-500/20',
      };
  }
}

function EcsAddressCell({
  probe,
  isPrivacyOptOut,
}: {
  probe: EcsAddressProbeResult;
  isPrivacyOptOut?: boolean;
}) {
  if (!probe.reachable) {
    return <span className="text-slate-400 text-[11px]">TIMEOUT</span>;
  }

  return (
    <div className="space-y-1">
      {probe.answers.length === 0 ? (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-slate-400 font-sans italic text-[11px]">
            {probe.rcode === 0 ? 'NODATA' : probe.rcodeName}
          </span>
          {probe.isDanglingCname && (
            <span className="rounded px-1.5 py-0.5 text-[10px] font-bold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35">
              DANGLING CNAME
            </span>
          )}
        </div>
      ) : (
        <div className="flex flex-wrap gap-1">
          {probe.answers.slice(0, 3).map((ip) => (
            <span
              key={ip}
              className="rounded px-1.5 py-0.5 text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
            >
              <IpHoverBadge ip={ip} />
            </span>
          ))}
          {probe.answers.length > 3 && (
            <span className="text-[10px] text-slate-400 self-center">
              +{probe.answers.length - 3}
            </span>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1 text-[10px]">
        {probe.responseEcs ? (
          <span
            className={`rounded px-1.5 py-0.5 font-semibold ${
              probe.isCacheBustingScope ||
              probe.hasWireAnomaly ||
              (isPrivacyOptOut && probe.responseEcs.scopePrefixLength > 0)
                ? 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/40'
                : probe.responseEcs.scopePrefixLength > 0
                  ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25'
            }`}
            title={`RFC 7871 CLIENT-SUBNET: ${probe.responseEcs.presentation}`}
          >
            SRC /{probe.responseEcs.sourcePrefixLength} → SCOPE /
            {probe.responseEcs.scopePrefixLength}
            {probe.isCacheBustingScope ? ' (CACHE-BUST)' : ''}
          </span>
        ) : (
          <span className="text-slate-400">no ECS echoed</span>
        )}
        {probe.minTtl !== undefined && (
          <span className="text-slate-500">TTL {probe.minTtl}s</span>
        )}
      </div>

      {probe.wireAnomalyNotes.length > 0 && (
        <div className="text-[10px] text-amber-700 dark:text-amber-300 font-sans">
          {probe.wireAnomalyNotes[0]}
        </div>
      )}
    </div>
  );
}

function EcsGeoSection({
  targetDomain,
  displayDomain,
  primaryEndpoint,
  ecsGeo,
}: {
  targetDomain: string;
  displayDomain: string;
  primaryEndpoint: string;
  ecsGeo: EcsGeoAnalysisResult;
}) {
  const [customSubnet, setCustomSubnet] = useState('81.2.69.0/24');
  const [customQtype, setCustomQtype] = useState<'A' | 'AAAA'>('A');
  const [customEndpoint, setCustomEndpoint] = useState(() => selectEcsDohEndpoint(primaryEndpoint));
  const [customLoading, setCustomLoading] = useState(false);
  const [customError, setCustomError] = useState<string | null>(null);
  const [customResult, setCustomResult] = useState<{
    probe: EcsAddressProbeResult;
    canonicalSubnet: string;
    digCmd: string;
  } | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const steeringMeta = getEcsSteeringBadgeMeta(ecsGeo.steeringModel);

  const runCustomProbe = async (
    overrideSubnet?: string,
    overrideQtype?: 'A' | 'AAAA'
  ): Promise<void> => {
    const sub = (overrideSubnet ?? customSubnet).trim();
    const qt = overrideQtype ?? customQtype;
    if (overrideSubnet !== undefined) setCustomSubnet(overrideSubnet);
    if (overrideQtype !== undefined) setCustomQtype(overrideQtype);
    setCustomLoading(true);
    setCustomError(null);
    try {
      const res = await probeCustomEcsSubnet({
        targetName: targetDomain,
        subnetInput: sub,
        qtype: qt,
        dohEndpoint: customEndpoint,
      });
      const cli = generateCliReproducerCommands({
        qname: targetDomain,
        qtypeName: qt,
        dohEndpoint: customEndpoint,
        cd: false,
        ecsSubnet: res.canonicalSubnet,
      });
      setCustomResult({
        probe: res.probe,
        canonicalSubnet: res.canonicalSubnet,
        digCmd: cli.kdig,
      });
    } catch (err) {
      setCustomError(err instanceof Error ? err.message : String(err));
      setCustomResult(null);
    } finally {
      setCustomLoading(false);
    }
  };

  const handleCopyDig = async () => {
    if (!customResult) return;
    try {
      await navigator.clipboard.writeText(customResult.digCmd);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  };

  const hasHygieneAlerts =
    ecsGeo.cacheBustingRegions.length > 0 ||
    ecsGeo.anomalyRegions.length > 0 ||
    ecsGeo.optOutHonored === false;

  return (
    <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Compass className="w-4 h-4 text-cyan-500 shrink-0" />
            <h2 className="font-semibold text-sm">
              EDNS Client Subnet (ECS — RFC 7871) Geo-Steering &amp;{' '}
              <code className="font-mono text-xs">SCOPE</code> Cache Matrix
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${steeringMeta.cls}`}
            >
              {steeringMeta.label}
            </span>
            <span className="rounded-md px-2 py-0.5 font-mono text-[10px] bg-slate-500/10 text-slate-600 dark:text-slate-300 border border-slate-500/25">
              via {ecsGeo.ecsEndpointLabel}
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
          {ecsGeo.summary}
        </p>

        {/* Scope & Pool Metric Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          <span className="rounded-md px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
            IPv4 Pools: <strong>{ecsGeo.uniqueIpv4PoolCount}</strong>
          </span>
          <span className="rounded-md px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
            IPv6 Pools: <strong>{ecsGeo.uniqueIpv6PoolCount}</strong>
          </span>
          {ecsGeo.uniqueCnameTargets.length > 0 && (
            <span className="rounded-md px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
              CNAME Targets: <strong>{ecsGeo.uniqueCnameTargets.length}</strong>
            </span>
          )}
          {ecsGeo.ipv4ScopeRange && (
            <span
              className={`rounded-md px-2 py-0.5 ${
                ecsGeo.ipv4ScopeRange.max > 24
                  ? 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/35 font-bold'
                  : 'bg-cyan-500/10 text-cyan-800 dark:text-cyan-200 border border-cyan-500/25'
              }`}
            >
              IPv4 SCOPE: /{ecsGeo.ipv4ScopeRange.min}
              {ecsGeo.ipv4ScopeRange.max !== ecsGeo.ipv4ScopeRange.min
                ? `–/${ecsGeo.ipv4ScopeRange.max}`
                : ''}
            </span>
          )}
          {ecsGeo.ipv6ScopeRange && (
            <span
              className={`rounded-md px-2 py-0.5 ${
                ecsGeo.ipv6ScopeRange.max > 56
                  ? 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/35 font-bold'
                  : 'bg-cyan-500/10 text-cyan-800 dark:text-cyan-200 border border-cyan-500/25'
              }`}
            >
              IPv6 SCOPE: /{ecsGeo.ipv6ScopeRange.min}
              {ecsGeo.ipv6ScopeRange.max !== ecsGeo.ipv6ScopeRange.min
                ? `–/${ecsGeo.ipv6ScopeRange.max}`
                : ''}
            </span>
          )}
          {ecsGeo.optOutHonored !== undefined && (
            <span
              className={`rounded-md px-2 py-0.5 font-semibold ${
                ecsGeo.optOutHonored
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                  : 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/35'
              }`}
            >
              /0 Opt-Out: {ecsGeo.optOutHonored ? 'HONORED (SCOPE /0)' : 'VIOLATED (SCOPE > 0)'}
            </span>
          )}
        </div>

        {/* Hygiene Alert Callout */}
        {hasHygieneAlerts && (
          <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              {ecsGeo.cacheBustingRegions.length > 0 && (
                <div>
                  <strong>Cache-Busting ECS SCOPE:</strong> Overly narrow{' '}
                  <code className="font-mono">SCOPE PREFIX-LENGTH</code> (&gt; /24 IPv4 or &gt; /56
                  IPv6) returned in {ecsGeo.cacheBustingRegions.join(', ')} — fragments shared
                  recursive resolver caches (RFC 7871 §11).
                </div>
              )}
              {ecsGeo.optOutHonored === false && (
                <div>
                  <strong>RFC 7871 §7.1.2 Opt-Out Violation:</strong>{' '}
                  <code className="font-mono">0.0.0.0/0</code> /{' '}
                  <code className="font-mono">::/0</code> privacy query returned{' '}
                  <code className="font-mono">SCOPE &gt; 0</code> instead of global{' '}
                  <code className="font-mono">/0</code>.
                </div>
              )}
              {ecsGeo.anomalyRegions.length > 0 && (
                <div>
                  <strong>Regional ECS Anomalies:</strong> Detected in{' '}
                  {ecsGeo.anomalyRegions.join(', ')} (inspect Audit Findings above for RFC 7871
                  details).
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Regional ECS Matrix Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              <th className="py-2.5 px-3.5">Region &amp; ECS Prefix</th>
              <th className="py-2.5 px-3">CNAME Target</th>
              <th className="py-2.5 px-3">IPv4 Answers &amp; SCOPE</th>
              <th className="py-2.5 px-3">IPv6 Answers &amp; SCOPE</th>
              <th className="py-2.5 px-3">Edge BGP ASN &amp; RPKI</th>
              <th className="py-2.5 px-3.5">RCODE &amp; AD</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70 font-mono">
            {ecsGeo.regions.map((reg) => {
              const terminalCname =
                reg.ipv4.cnameChain[reg.ipv4.cnameChain.length - 1] ??
                reg.ipv6.cnameChain[reg.ipv6.cnameChain.length - 1];
              const rpkiMeta = reg.rpkiStatus ? getRpkiBadgeMeta(reg.rpkiStatus) : null;
              const primaryAsn = reg.asns[0];
              const v4Rcode = reg.ipv4.reachable ? reg.ipv4.rcode : -1;
              const v6Rcode = reg.ipv6.reachable ? reg.ipv6.rcode : -1;
              const adVerified =
                (reg.ipv4.reachable && reg.ipv4.rcode === 0 && reg.ipv4.adBit) ||
                (reg.ipv6.reachable && reg.ipv6.rcode === 0 && reg.ipv6.adBit);
              return (
                <tr
                  key={reg.regionId}
                  className={`hover:bg-slate-50/80 dark:hover:bg-slate-950/40 transition-colors ${
                    reg.isPrivacyOptOut ? 'bg-slate-50/40 dark:bg-slate-950/25' : ''
                  }`}
                >
                  <td className="py-2.5 px-3.5">
                    <div className="flex items-center gap-1.5 font-sans">
                      <Globe className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        {reg.regionLabel}
                      </span>
                      {reg.isPrivacyOptOut && (
                        <span className="rounded px-1.5 py-0.2 font-mono text-[9px] font-bold bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                          OPT-OUT
                        </span>
                      )}
                    </div>
                    <div className="font-sans text-[11px] text-slate-500 pl-5">
                      {reg.locationHint}
                    </div>
                    <div className="text-[10px] text-slate-500 pl-5 pt-0.5">
                      {reg.ipv4.querySubnet} · {reg.ipv6.querySubnet}
                    </div>
                  </td>

                  <td className="py-2.5 px-3 max-w-[210px]">
                    {terminalCname ? (
                      <div className="space-y-0.5">
                        <div
                          className="text-[11px] text-cyan-700 dark:text-cyan-300 break-all"
                          title={displayFqdn(terminalCname)}
                        >
                          {displayFqdn(terminalCname)}
                        </div>
                        {reg.ipv4.cnameChain.length > 1 && (
                          <div className="text-[10px] text-slate-400">
                            {reg.ipv4.cnameChain.length} CNAME hops
                          </div>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-400 font-sans text-[11px]">direct</span>
                    )}
                  </td>

                  <td className="py-2.5 px-3 max-w-[250px]">
                    <EcsAddressCell probe={reg.ipv4} isPrivacyOptOut={reg.isPrivacyOptOut} />
                  </td>

                  <td className="py-2.5 px-3 max-w-[250px]">
                    <EcsAddressCell probe={reg.ipv6} isPrivacyOptOut={reg.isPrivacyOptOut} />
                  </td>

                  <td className="py-2.5 px-3 max-w-[220px]">
                    {primaryAsn ? (
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-1 text-[11px]">
                          <span className="font-bold text-slate-800 dark:text-slate-200">
                            AS{primaryAsn.asn}
                          </span>
                          {reg.countries[0] && (
                            <span className="rounded bg-slate-200/70 dark:bg-slate-800 px-1 py-0.2 text-[10px] text-slate-600 dark:text-slate-300">
                              {reg.countries[0]}
                            </span>
                          )}
                          {rpkiMeta && (
                            <span
                              className={`rounded px-1.5 py-0.2 text-[9px] font-bold ${rpkiMeta.cls}`}
                            >
                              {rpkiMeta.label}
                            </span>
                          )}
                        </div>
                        {primaryAsn.asName && (
                          <div className="font-sans text-[11px] text-slate-500 truncate max-w-[200px]">
                            {primaryAsn.asName}
                          </div>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="py-2.5 px-3.5">
                    {!reg.ipv4.reachable && !reg.ipv6.reachable ? (
                      <span className="text-slate-400">TIMEOUT</span>
                    ) : (
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-1">
                          <span
                            className={
                              v4Rcode === 0 || v6Rcode === 0
                                ? 'text-emerald-600 dark:text-emerald-400 font-bold'
                                : 'text-rose-600 dark:text-rose-400 font-bold'
                            }
                          >
                            {reg.ipv4.reachable ? reg.ipv4.rcodeName : reg.ipv6.rcodeName}
                          </span>
                          <span
                            className={`rounded px-1.5 py-0.2 text-[10px] ${
                              adVerified
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-bold'
                                : 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                            }`}
                          >
                            AD={adVerified ? '1' : '0'}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400">
                          {Math.max(reg.ipv4.latencyMs, reg.ipv6.latencyMs)}ms
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Interactive Custom ECS Subnet Probe */}
      <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-200">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" />
            <span>
              Interactive Custom ECS Subnet Probe (<code className="font-mono">EDNS0 Option 8</code>{' '}
              on <code className="font-mono">{displayDomain}</code>)
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1">
            {ECS_QUICK_CUSTOM_CHIPS.map((chip) => (
              <button
                key={`${chip.subnet}-${chip.qtype}`}
                type="button"
                onClick={() => void runCustomProbe(chip.subnet, chip.qtype)}
                disabled={customLoading}
                className="rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[10px] font-mono text-slate-600 dark:text-slate-300 cursor-pointer disabled:opacity-50"
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void runCustomProbe();
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <input
            type="text"
            value={customSubnet}
            onChange={(e) => setCustomSubnet(e.target.value)}
            placeholder="e.g. 81.2.69.0/24 or 2601:140:4000::/56"
            aria-label="Custom ECS Client Subnet CIDR"
            className="flex-1 min-w-[200px] rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
          />

          <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-0.5 text-xs font-mono">
            {(['A', 'AAAA'] as const).map((qt) => (
              <button
                key={qt}
                type="button"
                onClick={() => setCustomQtype(qt)}
                className={`rounded-md px-2.5 py-1 font-semibold cursor-pointer ${
                  customQtype === qt
                    ? 'bg-cyan-500 text-white'
                    : 'text-slate-600 dark:text-slate-300 hover:text-cyan-600'
                }`}
              >
                {qt}
              </button>
            ))}
          </div>

          <select
            value={customEndpoint}
            onChange={(e) => setCustomEndpoint(e.target.value)}
            aria-label="ECS DoH Resolver"
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs text-slate-700 dark:text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {ECS_DOH_ENDPOINTS.map((ep) => (
              <option key={ep.url} value={ep.url}>
                {ep.label}
              </option>
            ))}
          </select>

          <button
            type="submit"
            disabled={customLoading || !customSubnet.trim()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white px-3 py-1.5 text-xs font-semibold cursor-pointer"
          >
            {customLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
            <span>Probe Subnet</span>
          </button>
        </form>

        {customError && (
          <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300">
            {customError}
          </div>
        )}

        {customResult && (
          <div className="rounded-lg border border-cyan-500/30 bg-white dark:bg-slate-900 p-3 space-y-2 text-xs font-mono">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 text-[11px] font-bold">
                  +subnet={customResult.canonicalSubnet} ({customResult.probe.qtype})
                </span>
                <span
                  className={`font-bold ${
                    customResult.probe.rcode === 0
                      ? 'text-emerald-600 dark:text-emerald-400'
                      : 'text-rose-600 dark:text-rose-400'
                  }`}
                >
                  {customResult.probe.rcodeName}
                </span>
                <span className="text-slate-500">
                  AD={customResult.probe.adBit ? '1' : '0'} · {customResult.probe.latencyMs}ms
                </span>
                {customResult.probe.responseEcs && (
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      customResult.probe.isCacheBustingScope || customResult.probe.hasWireAnomaly
                        ? 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/40'
                        : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                    }`}
                  >
                    CLIENT-SUBNET: {customResult.probe.responseEcs.presentation}
                  </span>
                )}
              </div>

              <button
                type="button"
                onClick={() => void handleCopyDig()}
                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-0.5 text-[11px] font-sans text-slate-600 dark:text-slate-300 cursor-pointer"
              >
                {copiedCmd ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-500" />
                    <span>Copied dig</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy dig +subnet</span>
                  </>
                )}
              </button>
            </div>

            {customResult.probe.cnameChain.length > 0 && (
              <div className="text-[11px] text-slate-500">
                CNAME:{' '}
                <span className="text-cyan-700 dark:text-cyan-300">
                  {customResult.probe.cnameChain.map(displayFqdn).join(' → ')}
                </span>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-1.5">
              {customResult.probe.answers.length === 0 ? (
                <span className="text-slate-400 font-sans italic">No address records returned</span>
              ) : (
                customResult.probe.answers.map((ip) => (
                  <span
                    key={ip}
                    className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-[11px] text-slate-800 dark:text-slate-200"
                  >
                    <IpHoverBadge ip={ip} />
                  </span>
                ))
              )}
              {customResult.probe.minTtl !== undefined && (
                <span className="text-[11px] text-slate-500">
                  (min TTL {customResult.probe.minTtl}s)
                </span>
              )}
            </div>

            {customResult.probe.isCacheBustingScope && (
              <div className="font-sans text-[11px] text-amber-700 dark:text-amber-300">
                Warning: Authoritative server returned cache-busting SCOPE /
                {customResult.probe.responseEcs?.scopePrefixLength} (RFC 7871 §11).
              </div>
            )}
            {customResult.probe.wireAnomalyNotes.map((n, i) => (
              <div key={i} className="font-sans text-[11px] text-amber-700 dark:text-amber-300">
                RFC 7871 Wire Anomaly: {n}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
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

      {/* RFC 7871 EDNS Client Subnet (ECS) Geo-Steering & SCOPE Cache Matrix */}
      {consensus.ecsGeo && (
        <EcsGeoSection
          targetDomain={consensus.targetDomain}
          displayDomain={consensus.displayDomain}
          primaryEndpoint={snapshot.dohEndpoint}
          ecsGeo={consensus.ecsGeo}
        />
      )}
    </div>
  );
}
