import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Binary,
  Check,
  Clock,
  GitCommit,
  GitCompare,
  KeyRound,
  Loader2,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
} from 'lucide-react';
import type { DohResolverRole } from '../dns/constants';
import { displayFqdn } from '../dns/encoding';
import {
  WATCHABLE_RR_TYPES,
  computeLiveTtlCountdown,
  getAvailableWatchResolvers,
  type TtlClampAndStaleStatus,
  type TtlWatchState,
  type WatchPollMode,
  type WatchResolverObservation,
  type WatchTransitionCategory,
  type WatchTransitionEvent,
  type WatchableRrType,
} from '../dns/ttlWatch';
import type { AnalysisSnapshot, DohQueryLog } from '../dns/types';
import type { FocusedWireSubMode } from '../dns/wireQueryFilter';
import { diffSnapshots } from '../storage/historyStore';
import { IpHoverBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { StatusBadge } from './StatusBadge';

const POLL_MODE_OPTIONS: readonly { value: WatchPollMode; label: string; hint: string }[] = [
  {
    value: 'expiry-once',
    label: 'On TTL=0 (Single Re-query)',
    hint: 'Waits until the shortest resolver TTL hits 0s, runs one automatic re-query, then stops',
  },
  {
    value: 'expiry-continuous',
    label: 'On TTL=0 (Continuous)',
    hint: 'Re-queries each time the shortest resolver TTL expires (≥8s safety cooldown)',
  },
  {
    value: 'interval-15s',
    label: 'Every 15s',
    hint: 'Bounded fixed-interval multi-resolver pulse every 15 seconds',
  },
  {
    value: 'interval-30s',
    label: 'Every 30s',
    hint: 'Bounded fixed-interval multi-resolver pulse every 30 seconds',
  },
  {
    value: 'interval-60s',
    label: 'Every 60s',
    hint: 'Bounded fixed-interval multi-resolver pulse every 60 seconds',
  },
  {
    value: 'manual',
    label: 'Manual Pulse Only',
    hint: 'Ticks live TTL countdown bars locally with zero automatic background polling',
  },
];

const MAX_ITERATION_OPTIONS = [10, 20, 40, 60] as const;

function formatShortSeconds(sec: number | null): string {
  if (sec === null || !Number.isFinite(sec)) return '—';
  if (sec <= 0) return '0s';
  if (sec < 120) return `${Math.round(sec)}s`;
  if (sec < 3600) {
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    return s > 0 ? `${m}m ${s}s` : `${m}m`;
  }
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function formatClockTime(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

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

function getTtlBehaviorBadge(status: TtlClampAndStaleStatus): {
  label: string;
  cls: string;
} {
  switch (status) {
    case 'serve-stale-ede':
      return {
        label: 'SERVE-STALE (EDE 3/19)',
        cls: 'bg-amber-500/20 text-amber-800 dark:text-amber-200 border border-amber-500/45',
      };
    case 'serve-stale-zero-ttl':
      return {
        label: 'SERVE-STALE (TTL=0)',
        cls: 'bg-amber-500/20 text-amber-800 dark:text-amber-200 border border-amber-500/45',
      };
    case 'zero-ttl-uncacheable':
      return {
        label: 'TTL=0 (UNCACHEABLE)',
        cls: 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/35',
      };
    case 'min-ttl-clamped':
      return {
        label: 'MIN-TTL FLOOR CLAMPED',
        cls: 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-200 border border-cyan-500/40',
      };
    case 'max-ttl-clamped':
      return {
        label: 'MAX-TTL CEILING CLAMPED',
        cls: 'bg-indigo-500/20 text-indigo-800 dark:text-indigo-200 border border-indigo-500/40',
      };
    case 'normal':
      return {
        label: 'NORMAL DECAY',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
      };
  }
}

function getCategoryBadge(cat: WatchTransitionCategory): { label: string; cls: string } {
  switch (cat) {
    case 'answer-ip-change':
      return {
        label: 'ANSWER / GSLB POOL',
        cls: 'bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/35',
      };
    case 'soa-serial-change':
      return {
        label: 'SOA SERIAL',
        cls: 'bg-emerald-500/15 text-emerald-800 dark:text-emerald-200 border border-emerald-500/35',
      };
    case 'dnskey-keytag-change':
      return {
        label: 'DNSKEY ROLLOVER',
        cls: 'bg-purple-500/15 text-purple-800 dark:text-purple-200 border border-purple-500/35',
      };
    case 'rrsig-resign':
      return {
        label: 'RRSIG RE-SIGN',
        cls: 'bg-indigo-500/15 text-indigo-800 dark:text-indigo-200 border border-indigo-500/35',
      };
    case 'rcode-ede-change':
      return {
        label: 'RCODE / EDE / STALE',
        cls: 'bg-amber-500/15 text-amber-800 dark:text-amber-200 border border-amber-500/40',
      };
  }
}

function isIpQtype(qtypeName: string): boolean {
  return qtypeName === 'A' || qtypeName === 'AAAA';
}

function TransitionInlineComparison({
  event,
  onLoadSnapshot,
  onOpenInHistoryDiff,
}: {
  event: WatchTransitionEvent;
  onLoadSnapshot?: (snapshot: AnalysisSnapshot) => void;
  onOpenInHistoryDiff?: (older: AnalysisSnapshot, newer: AnalysisSnapshot) => void;
}) {
  const snapDiff = useMemo(
    () => diffSnapshots(event.previousSnapshot, event.currentSnapshot),
    [event.previousSnapshot, event.currentSnapshot]
  );

  const prevByEp = useMemo(
    () => new Map(event.previousSample.resolvers.map((r) => [r.endpoint, r])),
    [event.previousSample.resolvers]
  );

  const changedResolvers = event.currentSample.resolvers.filter((curr) =>
    event.diffs.some((d) => d.endpoint === curr.endpoint)
  );

  return (
    <div
      data-testid="watch-inline-snapshot-diff"
      className="mt-3 rounded-xl border border-cyan-500/35 bg-slate-50/90 dark:bg-slate-950/75 p-3.5 space-y-3 text-xs"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 font-mono">
          <span className="font-sans font-semibold text-slate-700 dark:text-slate-200">
            Tick #{event.previousSample.tickNumber} → Tick #{event.tickNumber} Snapshot Diff:
          </span>
          <StatusBadge status={snapDiff.older.overallStatus} size="xs" />
          <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
          <StatusBadge status={snapDiff.newer.overallStatus} size="xs" />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {onLoadSnapshot && (
            <button
              type="button"
              onClick={() => onLoadSnapshot(event.currentSnapshot)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
            >
              <Network className="w-3 h-3" />
              <span>Load Tick #{event.tickNumber} Snapshot</span>
            </button>
          )}
          {onOpenInHistoryDiff && (
            <button
              type="button"
              onClick={() => onOpenInHistoryDiff(event.previousSnapshot, event.currentSnapshot)}
              className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-2.5 py-1 text-[11px] font-semibold text-cyan-800 dark:text-cyan-200 cursor-pointer"
            >
              <GitCompare className="w-3 h-3" />
              <span>Save &amp; Open in History Diff</span>
            </button>
          )}
        </div>
      </div>

      {/* Per-Resolver Before / After Table */}
      {changedResolvers.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <table className="w-full text-left border-collapse text-[11px] font-mono">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-[10px] font-sans font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-2 px-2.5">Resolver</th>
                <th className="py-2 px-2.5">Previous (Tick #{event.previousSample.tickNumber})</th>
                <th className="py-2 px-2.5">New (Tick #{event.tickNumber})</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
              {changedResolvers.map((curr) => {
                const prev = prevByEp.get(curr.endpoint);
                const renderCell = (o: WatchResolverObservation | undefined) => {
                  if (!o || !o.reachable) return <span className="text-slate-400">UNREACHABLE</span>;
                  return (
                    <div className="space-y-0.5">
                      <div>
                        <span className="font-bold">{o.rcodeName}</span> (AD={o.adBit ? '1' : '0'}) · TTL{' '}
                        <strong>{o.observedTtl ?? '—'}s</strong>
                        {o.soaSerial !== undefined ? ` · SOA ${o.soaSerial}` : ''}
                      </div>
                      {o.answerValues.length > 0 && (
                        <div className="text-slate-600 dark:text-slate-300 break-all">
                          {o.answerValues.join(', ')}
                        </div>
                      )}
                      {o.rrsigMeta && (
                        <div className="text-[10px] text-slate-500">
                          RRSIG #{o.rrsigMeta.keyTag} (exp {o.rrsigMeta.expiration})
                        </div>
                      )}
                      {o.ede.length > 0 && (
                        <div className="text-[10px] text-amber-700 dark:text-amber-300">
                          EDE {o.ede.map((e) => `${e.infoCode}: ${e.name}`).join('; ')}
                        </div>
                      )}
                    </div>
                  );
                };
                return (
                  <tr key={curr.endpoint}>
                    <td className="py-2 px-2.5 font-bold text-slate-900 dark:text-slate-100 whitespace-nowrap">
                      {curr.shortLabel}
                    </td>
                    <td className="py-2 px-2.5">{renderCell(prev)}</td>
                    <td className="py-2 px-2.5">{renderCell(curr)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Cryptographic Zone & RRset Snapshot Diff */}
      {(snapDiff.zoneChanges.some((z) => z.change !== 'unchanged') ||
        snapDiff.recordChanges.length > 0) && (
        <div className="space-y-1.5 font-mono text-[11px]">
          {snapDiff.zoneChanges
            .filter((z) => z.change !== 'unchanged')
            .map((zc) => (
              <div
                key={zc.zoneName}
                className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-2 space-y-0.5"
              >
                <div className="font-bold text-slate-800 dark:text-slate-100">
                  Zone {displayFqdn(zc.zoneName)} ({zc.change.toUpperCase()})
                </div>
                {zc.oldSerial !== zc.newSerial && (
                  <div className="text-slate-600 dark:text-slate-300">
                    SOA Serial: {zc.oldSerial ?? '—'} → {zc.newSerial ?? '—'}
                  </div>
                )}
                {zc.addedKeys.length > 0 && (
                  <div className="text-emerald-600 dark:text-emerald-400">
                    + Added DNSKEY: {zc.addedKeys.map((k) => `#${k}`).join(', ')}
                  </div>
                )}
                {zc.removedKeys.length > 0 && (
                  <div className="text-rose-600 dark:text-rose-400">
                    − Removed DNSKEY: {zc.removedKeys.map((k) => `#${k}`).join(', ')}
                  </div>
                )}
              </div>
            ))}
          {snapDiff.recordChanges.map((rc) => (
            <div
              key={`${rc.name}-${rc.typeName}`}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-2.5 py-2 space-y-0.5"
            >
              <div className="font-bold text-slate-800 dark:text-slate-100">
                RRset {displayFqdn(rc.name)} {rc.typeName}
              </div>
              {rc.addedRecords.map((r) => (
                <div key={`+${r}`} className="text-emerald-600 dark:text-emerald-400 break-all">
                  + {r}
                </div>
              ))}
              {rc.removedRecords.map((r) => (
                <div key={`-${r}`} className="text-rose-600 dark:text-rose-400 break-all">
                  − {r}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export interface LiveWatchViewProps {
  watchState: TtlWatchState;
  primaryEndpoint: string;
  activeSnapshot?: AnalysisSnapshot | null;
  isOffline?: boolean;
  /** Optional deterministic timestamp override for SSR / unit tests */
  nowMsOverride?: number;
  onPulseOnce: () => void;
  onStartWatch: (mode?: WatchPollMode) => void;
  onPauseWatch: () => void;
  onResumeWatch: () => void;
  onStopWatch: () => void;
  onContinueBeyondCap: () => void;
  onUpdateConfig: (patch: {
    qtypeName?: WatchableRrType;
    pollMode?: WatchPollMode;
    maxIterations?: number;
    enabledResolverUrls?: string[];
  }) => void;
  onInspectWatchWireQuery?: (queryLog: DohQueryLog, mode?: FocusedWireSubMode) => void;
  onLoadSnapshot?: (snapshot: AnalysisSnapshot) => void;
  onOpenInHistoryDiff?: (older: AnalysisSnapshot, newer: AnalysisSnapshot) => void;
}

export function LiveWatchView({
  watchState,
  primaryEndpoint,
  activeSnapshot,
  isOffline = false,
  nowMsOverride,
  onPulseOnce,
  onStartWatch,
  onPauseWatch,
  onResumeWatch,
  onStopWatch,
  onContinueBeyondCap,
  onUpdateConfig,
  onInspectWatchWireQuery,
  onLoadSnapshot,
  onOpenInHistoryDiff,
}: LiveWatchViewProps) {
  if (activeSnapshot) {
    seedIpAsnCacheFromSnapshot(activeSnapshot);
  }
  if (watchState.latestSnapshot) {
    seedIpAsnCacheFromSnapshot(watchState.latestSnapshot);
  }

  const [tickNowMs, setTickNowMs] = useState<number>(
    () => nowMsOverride ?? watchState.currentSample?.capturedAtMs ?? Date.now()
  );
  const [transitionFilter, setTransitionFilter] = useState<'all' | WatchTransitionCategory>('all');
  const [expandedTransitionIds, setExpandedTransitionIds] = useState<Record<string, boolean>>({});

  // 1 Hz local wall-clock ticker for smooth live TTL countdown bars while mounted
  useEffect(() => {
    if (nowMsOverride !== undefined) return;
    setTickNowMs(Date.now());
    const id = setInterval(() => {
      setTickNowMs(Date.now());
    }, 1000);
    return () => clearInterval(id);
  }, [nowMsOverride, watchState.currentSample?.capturedAtMs, watchState.status]);

  const effectiveNowMs = nowMsOverride ?? tickNowMs;

  const availableResolvers = useMemo(
    () => getAvailableWatchResolvers(primaryEndpoint),
    [primaryEndpoint]
  );

  const sample = watchState.currentSample;

  const resolverCountdowns = useMemo(() => {
    const map = new Map<string, ReturnType<typeof computeLiveTtlCountdown>>();
    if (!sample) return map;
    for (const r of sample.resolvers) {
      map.set(r.endpoint, computeLiveTtlCountdown(r, effectiveNowMs));
    }
    return map;
  }, [sample, effectiveNowMs]);

  const shortestLiveRemainingSec = useMemo(() => {
    if (!sample) return null;
    let min: number | null = null;
    for (const r of sample.resolvers) {
      if (!r.reachable || r.observedTtl === null) continue;
      const cd = resolverCountdowns.get(r.endpoint);
      if (!cd || cd.remainingSec === null) continue;
      if (min === null || cd.remainingSec < min) {
        min = cd.remainingSec;
      }
    }
    return min;
  }, [sample, resolverCountdowns]);

  const nextPollRemainingSec =
    watchState.nextPollAtMs !== null
      ? Math.max(0, Math.ceil((watchState.nextPollAtMs - effectiveNowMs) / 1000))
      : null;

  const filteredTransitions = useMemo(() => {
    if (transitionFilter === 'all') return watchState.transitions;
    return watchState.transitions.filter((t) => t.categories.includes(transitionFilter));
  }, [watchState.transitions, transitionFilter]);

  const toggleResolverUrl = (url: string) => {
    const exists = watchState.enabledResolverUrls.includes(url);
    if (exists && watchState.enabledResolverUrls.length <= 1) return;
    const next = exists
      ? watchState.enabledResolverUrls.filter((u) => u !== url)
      : [...watchState.enabledResolverUrls, url];
    onUpdateConfig({ enabledResolverUrls: next });
  };

  const toggleCompare = (id: string) => {
    setExpandedTransitionIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const isActivePolling = watchState.status === 'running' || watchState.status === 'pulsing';
  const isPulsing = watchState.status === 'pulsing';

  const anomalyCount =
    (sample?.serveStaleResolvers.length ?? 0) +
    (sample?.minClampedResolvers.length ?? 0) +
    (sample?.maxClampedResolvers.length ?? 0);

  return (
    <div data-testid="live-watch-view" className="space-y-4">
      {/* Control Deck */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-500 shrink-0" />
              <h2 className="font-semibold text-sm">
                Live TTL Countdown, Cache-Decay &amp; RFC 8767{' '}
                <code className="font-mono text-xs">Serve-Stale</code> Watch
              </h2>
              <span className="rounded-md px-2 py-0.5 font-mono text-[11px] font-bold bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30">
                {watchState.displayDomain} · {watchState.qtypeName}
              </span>
              {isActivePolling && (
                <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 font-mono text-[10px] font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  LIVE WATCH ACTIVE
                </span>
              )}
              {watchState.status === 'paused' && (
                <span className="rounded-full px-2 py-0.5 font-mono text-[10px] font-bold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35">
                  PAUSED
                </span>
              )}
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Tracks real-time cache decay across public DoH resolvers, compares served TTLs against
              signed <code className="font-mono">RRSIG</code> / <code className="font-mono">SOA</code>{' '}
              ceilings for min/max clamping &amp; <code className="font-mono">Serve-Stale</code>, and
              logs a change-only diff timeline.
            </p>
          </div>

          {/* Primary Transport Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              data-testid="watch-pulse-once-btn"
              disabled={isOffline || isPulsing}
              onClick={onPulseOnce}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 disabled:opacity-50 cursor-pointer"
              title="Execute a single multi-resolver DoH TTL pulse right now"
            >
              {isPulsing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-500" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5 text-cyan-500" />
              )}
              <span>Pulse Now</span>
            </button>

            {isActivePolling ? (
              <>
                <button
                  type="button"
                  data-testid="watch-pause-btn"
                  onClick={onPauseWatch}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/15 hover:bg-amber-500/25 px-3 py-1.5 text-xs font-semibold text-amber-800 dark:text-amber-200 cursor-pointer"
                >
                  <Pause className="w-3.5 h-3.5" />
                  <span>Pause</span>
                </button>
                <button
                  type="button"
                  data-testid="watch-stop-btn"
                  onClick={onStopWatch}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/35 bg-rose-500/10 hover:bg-rose-500/20 px-2.5 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300 cursor-pointer"
                >
                  <Square className="w-3 h-3 fill-current" />
                  <span>Stop</span>
                </button>
              </>
            ) : watchState.status === 'paused' || watchState.status === 'paused-hidden' ? (
              <>
                <button
                  type="button"
                  data-testid="watch-resume-btn"
                  disabled={isOffline}
                  onClick={onResumeWatch}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 px-3.5 py-1.5 text-xs font-semibold text-slate-950 cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Resume Watch</span>
                </button>
                <button
                  type="button"
                  data-testid="watch-stop-btn"
                  onClick={onStopWatch}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-rose-500 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Stop</span>
                </button>
              </>
            ) : (
              <button
                type="button"
                data-testid="watch-start-btn"
                disabled={isOffline}
                onClick={() => onStartWatch()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 px-3.5 py-1.5 text-xs font-semibold text-slate-950 shadow-sm shadow-cyan-500/20 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Watch</span>
              </button>
            )}
          </div>
        </div>

        {/* Selectors Row: RR Type, Poll Strategy, Max Cap */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
          <div>
            <label
              htmlFor="watch-qtype-select"
              className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1"
            >
              Watched RRset Type
            </label>
            <select
              id="watch-qtype-select"
              data-testid="watch-qtype-select"
              value={watchState.qtypeName}
              onChange={(e) =>
                onUpdateConfig({ qtypeName: e.target.value as WatchableRrType })
              }
              className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 text-base sm:text-xs font-mono text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              {WATCHABLE_RR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="watch-poll-mode-select"
              className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1"
            >
              Smart Expiry / Poll Cadence
            </label>
            <select
              id="watch-poll-mode-select"
              data-testid="watch-poll-mode-select"
              value={watchState.pollMode}
              onChange={(e) => onUpdateConfig({ pollMode: e.target.value as WatchPollMode })}
              className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 text-base sm:text-xs font-sans text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              {POLL_MODE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="watch-max-iterations-select"
              className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1"
            >
              Bounded Poll Cap ({watchState.completedTicks}/{watchState.maxIterations} ticks)
            </label>
            <select
              id="watch-max-iterations-select"
              data-testid="watch-max-iterations-select"
              value={watchState.maxIterations}
              onChange={(e) =>
                onUpdateConfig({ maxIterations: Number.parseInt(e.target.value, 10) })
              }
              className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 text-base sm:text-xs font-mono text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              {MAX_ITERATION_OPTIONS.map((cap) => (
                <option key={cap} value={cap}>
                  Max {cap} pulses
                </option>
              ))}
              {!MAX_ITERATION_OPTIONS.includes(
                watchState.maxIterations as (typeof MAX_ITERATION_OPTIONS)[number]
              ) && (
                <option value={watchState.maxIterations}>
                  Max {watchState.maxIterations} pulses
                </option>
              )}
            </select>
          </div>
        </div>

        {/* Watched DoH Resolver Toggle Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-200/70 dark:border-slate-800/70">
          <span className="text-[11px] font-semibold text-slate-500 mr-1">DoH Resolvers:</span>
          {availableResolvers.map((preset) => {
            const active = watchState.enabledResolverUrls.includes(preset.url);
            return (
              <button
                key={preset.url}
                type="button"
                onClick={() => toggleResolverUrl(preset.url)}
                title={`${preset.provider} (${preset.description})`}
                className={`inline-flex items-center gap-1 rounded-lg border px-2 py-0.5 font-mono text-[11px] transition-colors cursor-pointer ${
                  active
                    ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 font-semibold'
                    : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-500 hover:border-slate-400'
                }`}
              >
                {active && <Check className="w-3 h-3 text-cyan-500" />}
                <span>{preset.shortLabel}</span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Auto-Paused on Hidden Tab Banner */}
      {watchState.status === 'paused-hidden' && (
        <div
          data-testid="watch-hidden-paused-banner"
          className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs text-amber-900 dark:text-amber-200"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
            <span>
              <strong>Auto-paused while browser tab was hidden</strong> to prevent background DoH
              query traffic. Click <strong>Resume Watch</strong> to continue polling.
            </span>
          </div>
          <button
            type="button"
            onClick={onResumeWatch}
            className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 px-3 py-1 font-semibold text-slate-950 cursor-pointer"
          >
            <Play className="w-3 h-3 fill-current" />
            <span>Resume Watch</span>
          </button>
        </div>
      )}

      {/* Reached Max Iteration Cap Banner */}
      {watchState.status === 'completed-cap' && (
        <div
          data-testid="watch-cap-reached-banner"
          className="rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs text-cyan-900 dark:text-cyan-200"
        >
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-500 shrink-0" />
            <span>
              Reached bounded poll limit (
              <strong className="font-mono">
                {watchState.completedTicks}/{watchState.maxIterations}
              </strong>{' '}
              pulses). Live TTL countdown bars remain active locally.
            </span>
          </div>
          <button
            type="button"
            onClick={onContinueBeyondCap}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 px-3 py-1 font-semibold text-slate-950 cursor-pointer"
          >
            <Play className="w-3 h-3 fill-current" />
            <span>Continue (+20 Pulses)</span>
          </button>
        </div>
      )}

      {watchState.lastError && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-700 dark:text-rose-300">
          {watchState.lastError}
        </div>
      )}

      {/* 4 Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {/* KPI 1: Shortest Live TTL & Next Poll */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <Clock className="w-4 h-4 text-cyan-500" />
              <span>Shortest Live TTL</span>
            </span>
            <span className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
              {formatShortSeconds(shortestLiveRemainingSec)}
            </span>
          </div>
          <div className="text-xs text-slate-600 dark:text-slate-300">
            {nextPollRemainingSec !== null ? (
              <span>
                Next auto-pulse in{' '}
                <strong className="font-mono text-cyan-600 dark:text-cyan-400">
                  {formatShortSeconds(nextPollRemainingSec)}
                </strong>
              </span>
            ) : sample?.tickNumber === 0 ? (
              <span>Seeded from active snapshot — click Pulse Now for full fleet</span>
            ) : (
              <span>Local 1 Hz countdown active (no background timer scheduled)</span>
            )}
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Pulses: {watchState.completedTicks}/{watchState.maxIterations}
            {sample ? ` · Captured ${formatClockTime(sample.capturedAtMs)}` : ''}
          </div>
        </div>

        {/* KPI 2: Clamping & RFC 8767 Serve-Stale Detector */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
              {anomalyCount > 0 ? (
                <ShieldAlert className="w-4 h-4 text-amber-500" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
              )}
              <span>Clamping &amp; Serve-Stale</span>
            </span>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${
                (sample?.serveStaleResolvers.length ?? 0) > 0
                  ? 'bg-amber-500/20 text-amber-800 dark:text-amber-200 border border-amber-500/40'
                  : anomalyCount > 0
                    ? 'bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/35'
                    : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
              }`}
            >
              {(sample?.serveStaleResolvers.length ?? 0) > 0
                ? `${sample!.serveStaleResolvers.length} SERVE-STALE`
                : anomalyCount > 0
                  ? `${anomalyCount} TTL CLAMPED`
                  : 'NO CLAMP / STALE'}
            </span>
          </div>
          <div className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
            {(sample?.serveStaleResolvers.length ?? 0) > 0
              ? `RFC 8767 Serve-Stale active on: ${sample!.serveStaleResolvers.join(', ')}.`
              : (sample?.minClampedResolvers.length ?? 0) > 0 ||
                  (sample?.maxClampedResolvers.length ?? 0) > 0
                ? `TTL floor/ceiling clamping detected on ${[
                    ...sample!.minClampedResolvers,
                    ...sample!.maxClampedResolvers,
                  ].join(', ')}.`
                : 'Served TTLs match authoritative RRSIG / SOA bounds across resolvers.'}
          </div>
        </div>

        {/* KPI 3: SOA Serial Propagation */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <GitCommit className="w-4 h-4 text-cyan-500" />
              <span>SOA Serial Sync</span>
            </span>
            <span
              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${
                (sample?.uniqueSoaSerials.length ?? 0) > 1
                  ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                  : (sample?.uniqueSoaSerials.length ?? 0) === 1
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                    : 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25'
              }`}
            >
              {(sample?.uniqueSoaSerials.length ?? 0) > 1
                ? `${sample!.uniqueSoaSerials.length} SERIALS (SKEW)`
                : (sample?.uniqueSoaSerials.length ?? 0) === 1
                  ? 'SYNCHRONIZED'
                  : 'N/A'}
            </span>
          </div>
          <div className="space-y-0.5 font-mono text-xs">
            {sample && sample.uniqueSoaSerials.length > 0 ? (
              sample.uniqueSoaSerials.slice(0, 2).map((s) => (
                <div key={s.serial} className="flex items-center justify-between gap-2">
                  <span className="font-bold text-slate-800 dark:text-slate-200">{s.serial}</span>
                  <span className="text-[11px] text-slate-500">
                    {s.resolvers.length} resolver{s.resolvers.length === 1 ? '' : 's'}
                  </span>
                </div>
              ))
            ) : (
              <span className="font-sans text-slate-500">Run a pulse to compare SOA serials</span>
            )}
          </div>
        </div>

        {/* KPI 4: Answer Pool & Transitions */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
              <KeyRound className="w-4 h-4 text-cyan-500" />
              <span>Pools &amp; Transitions</span>
            </span>
            <span className="rounded-md px-2 py-0.5 font-mono text-[10px] font-bold bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30">
              {watchState.transitions.length} CHANGE{watchState.transitions.length === 1 ? '' : 'S'}
            </span>
          </div>
          <div className="text-xs text-slate-600 dark:text-slate-300">
            Distinct {watchState.qtypeName} pools:{' '}
            <strong className="font-mono">{sample?.uniqueAnswerPools.length ?? 0}</strong>
          </div>
          <div className="text-[11px] text-slate-500">
            {watchState.transitions.length === 0
              ? 'No IP, SOA, DNSKEY, RRSIG, or EDE changes yet'
              : `Latest: Tick #${watchState.transitions[0]!.tickNumber}`}
          </div>
        </div>
      </div>

      {/* Per-Resolver Live TTL Countdown & Clamping Matrix */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 overflow-hidden">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-500" />
            <h3 className="font-semibold text-sm">
              Per-Resolver Live TTL Decay Bars &amp; Authoritative Clamping Matrix
            </h3>
          </div>
          {sample && (
            <span className="font-mono text-[11px] text-slate-500">
              SOA Zone: {displayFqdn(sample.soaZone)} ·{' '}
              {sample.tickNumber === 0 ? 'Seeded Baseline' : `Pulse #${sample.tickNumber}`}
            </span>
          )}
        </div>

        {!sample ? (
          <div className="p-8 text-center space-y-3">
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Click <strong>Pulse Now</strong> or <strong>Start Watch</strong> to query live TTLs
              across {watchState.enabledResolverUrls.length} public DoH resolvers.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  <th className="py-2.5 px-3.5">DoH Resolver</th>
                  <th className="py-2.5 px-3 min-w-[230px]">Live TTL Countdown &amp; Ceiling</th>
                  <th className="py-2.5 px-3">Cache / RFC 8767 Status</th>
                  <th className="py-2.5 px-3">{sample.qtypeName} Answer Pool</th>
                  <th className="py-2.5 px-3">SOA, DNSKEY &amp; RRSIG</th>
                  <th className="py-2.5 px-3">RCODE · AD · EDE</th>
                  <th className="py-2.5 px-3.5 text-right">Wire</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70 font-mono">
                {sample.resolvers.map((r) => {
                  const cd = resolverCountdowns.get(r.endpoint);
                  const roleMeta = getRoleBadgeMeta(r.role);
                  const behaviorMeta = getTtlBehaviorBadge(r.ttlBehavior);
                  const wireLog = r.wireQueryId
                    ? sample.queries.find((q) => q.id === r.wireQueryId)
                    : undefined;

                  const barColorCls =
                    r.ttlBehavior === 'serve-stale-ede' || r.ttlBehavior === 'serve-stale-zero-ttl'
                      ? 'bg-amber-500'
                      : cd?.isExpiredLocally
                        ? 'bg-slate-400 dark:bg-slate-600'
                        : cd?.isExpiringSoon
                          ? 'bg-amber-500 animate-pulse'
                          : (cd?.percentRemaining ?? 0) < 25
                            ? 'bg-cyan-500'
                            : 'bg-emerald-500';

                  return (
                    <tr
                      key={r.endpoint}
                      data-testid="watch-resolver-row"
                      className="hover:bg-slate-50/80 dark:hover:bg-slate-950/40 transition-colors"
                    >
                      <td className="py-3 px-3.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-slate-900 dark:text-slate-100">
                            {r.shortLabel}
                          </span>
                          <span
                            className={`rounded px-1.5 py-0.2 text-[9px] font-bold ${roleMeta.cls}`}
                          >
                            {roleMeta.label}
                          </span>
                        </div>
                        <div className="font-sans text-[11px] text-slate-500">{r.provider}</div>
                      </td>

                      {/* Live Ticking TTL Countdown Bar */}
                      <td className="py-3 px-3">
                        {!r.reachable || r.observedTtl === null || !cd ? (
                          <span className="text-slate-400">
                            {r.reachable ? 'no cacheable TTL' : 'TIMEOUT'}
                          </span>
                        ) : (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between gap-2 text-[11px]">
                              <span
                                className={`font-bold ${
                                  cd.isExpiredLocally
                                    ? 'text-amber-600 dark:text-amber-400'
                                    : 'text-slate-900 dark:text-slate-100'
                                }`}
                              >
                                {cd.remainingSec}s
                                {cd.isExpiredLocally && r.observedTtl > 0 ? ' (EXPIRED)' : ''}
                              </span>
                              <span className="text-[10px] text-slate-500">
                                {r.authoritativeOriginalTtl !== undefined
                                  ? `auth ${r.authoritativeOriginalTtl}s`
                                  : cd.ceilingTtl !== null
                                    ? `ceil ${cd.ceilingTtl}s`
                                    : ''}{' '}
                                · wire {r.observedTtl}s
                              </span>
                            </div>

                            <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                              <div
                                data-testid="watch-ttl-bar"
                                className={`h-full rounded-full transition-all duration-500 ${barColorCls}`}
                                style={{
                                  width: `${
                                    r.ttlBehavior === 'serve-stale-ede' ||
                                    r.ttlBehavior === 'serve-stale-zero-ttl'
                                      ? 100
                                      : Math.max(cd.isExpiredLocally ? 0 : 3, cd.percentRemaining)
                                  }%`,
                                }}
                              />
                            </div>

                            <div className="flex flex-wrap items-center justify-between gap-1 text-[10px] font-sans text-slate-500">
                              <span>
                                {r.estimatedCacheAgeSec !== undefined
                                  ? `Cached ~${r.estimatedCacheAgeSec}s ago at capture`
                                  : r.ttlSource === 'negative-soa'
                                    ? 'Negative SOA cache TTL'
                                    : 'Unsigned RRset TTL'}
                              </span>
                              {r.cacheRefreshCount > 0 && (
                                <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.2 font-mono text-[9px] font-bold">
                                  REFRESHED ×{r.cacheRefreshCount}
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </td>

                      {/* Clamping & RFC 8767 Serve-Stale Classification */}
                      <td className="py-3 px-3 max-w-[230px]">
                        {r.reachable ? (
                          <div className="space-y-1">
                            <span
                              data-testid="watch-ttl-behavior-badge"
                              className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold ${behaviorMeta.cls}`}
                            >
                              {behaviorMeta.label}
                            </span>
                            <div className="font-sans text-[11px] text-slate-500 leading-snug">
                              {r.ttlBehaviorDetail}
                            </div>
                          </div>
                        ) : (
                          <span className="text-slate-400 font-sans text-[11px]">
                            {r.error ?? 'Unreachable'}
                          </span>
                        )}
                      </td>

                      {/* Answer Pool */}
                      <td className="py-3 px-3 max-w-[260px]">
                        {!r.reachable ? (
                          <span className="text-slate-400">—</span>
                        ) : r.answerValues.length === 0 ? (
                          <span className="text-slate-400 font-sans italic">
                            {r.rcode === 0 ? 'NODATA' : r.rcodeName}
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {r.answerValues.slice(0, 4).map((val) => (
                              <span
                                key={val}
                                className="rounded px-1.5 py-0.5 text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 break-all"
                              >
                                {isIpQtype(sample.qtypeName) ? <IpHoverBadge ip={val} /> : val}
                              </span>
                            ))}
                            {r.answerValues.length > 4 && (
                              <span className="text-[10px] text-slate-400 self-center">
                                +{r.answerValues.length - 4} more
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* SOA Serial, DNSKEY & RRSIG */}
                      <td className="py-3 px-3">
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
                          {r.rrsigMeta && (
                            <div className="text-[10px] text-cyan-700 dark:text-cyan-300">
                              RRSIG #{r.rrsigMeta.keyTag} (orig {r.rrsigMeta.originalTtl}s)
                            </div>
                          )}
                        </div>
                      </td>

                      {/* RCODE, AD & EDE */}
                      <td className="py-3 px-3">
                        {!r.reachable ? (
                          <span className="text-slate-400">TIMEOUT</span>
                        ) : (
                          <div className="space-y-1">
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
                            {r.ede.map((e, i) => (
                              <div key={i} className="text-[10px]">
                                <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-semibold">
                                  EDE {e.infoCode}: {e.name}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </td>

                      {/* Latency & Wire Dissector */}
                      <td className="py-3 px-3.5 text-right text-slate-500">
                        <div className="flex flex-col items-end gap-1">
                          <span>{r.reachable ? `${r.latencyMs}ms` : '—'}</span>
                          {wireLog && onInspectWatchWireQuery && (
                            <div className="inline-flex items-center gap-1 font-sans">
                              <button
                                type="button"
                                onClick={() => onInspectWatchWireQuery(wireLog, 'dig')}
                                title={`Inspect ${r.shortLabel} packet in dig format`}
                                className="inline-flex items-center gap-0.5 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
                              >
                                <Terminal className="w-2.5 h-2.5" />
                                <span>Wire</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => onInspectWatchWireQuery(wireLog, 'hex-resp')}
                                title={`Dissect ${r.shortLabel} wire bytes`}
                                className="inline-flex items-center gap-0.5 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
                              >
                                <Binary className="w-2.5 h-2.5" />
                                <span>Hex</span>
                              </button>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Change-Only Transition Timeline */}
      <section
        data-testid="watch-transition-timeline"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-500" />
            <h3 className="font-semibold text-sm">
              Change-Only State Transition Timeline ({watchState.transitions.length})
            </h3>
          </div>

          {watchState.transitions.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 text-[11px]">
              {(
                [
                  { id: 'all', label: 'All' },
                  { id: 'answer-ip-change', label: 'IP / GSLB' },
                  { id: 'soa-serial-change', label: 'SOA Serial' },
                  { id: 'dnskey-keytag-change', label: 'DNSKEY' },
                  { id: 'rrsig-resign', label: 'RRSIG Re-sign' },
                  { id: 'rcode-ede-change', label: 'RCODE / EDE' },
                ] as const
              ).map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  onClick={() => setTransitionFilter(pill.id)}
                  className={`rounded-lg px-2.5 py-1 font-medium cursor-pointer transition-colors ${
                    transitionFilter === pill.id
                      ? 'bg-cyan-500 text-slate-950 font-semibold'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {filteredTransitions.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 dark:border-slate-800 px-4 py-6 text-center text-xs text-slate-500">
            {watchState.completedTicks <= 1
              ? 'Pure TTL countdown ticks are suppressed from this log. Any IP pool rotation, SOA serial bump, DNSKEY key-tag rollover, online RRSIG re-signing, or RCODE/EDE shift on subsequent pulses will be recorded here with 1-click snapshot comparison.'
              : `No state transitions across ${watchState.completedTicks} pulses — cached answer sets, SOA serials, DNSKEYs, RRSIGs, and RCODEs remained steady.`}
          </div>
        ) : (
          <div className="space-y-2.5">
            {filteredTransitions.map((tr) => {
              const isExpanded = Boolean(expandedTransitionIds[tr.id]);
              return (
                <div
                  key={tr.id}
                  data-testid="watch-transition-item"
                  className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/35 p-3.5"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-1.5 flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:text-slate-300">
                          Pulse #{tr.tickNumber} · {formatClockTime(tr.detectedAtMs)}
                        </span>
                        {tr.categories.map((cat) => {
                          const meta = getCategoryBadge(cat);
                          return (
                            <span
                              key={cat}
                              className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${meta.cls}`}
                            >
                              {meta.label}
                            </span>
                          );
                        })}
                      </div>

                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">
                        {tr.headline}
                      </div>

                      <div className="space-y-1 font-mono text-[11px]">
                        {tr.diffs.slice(0, 6).map((d, idx) => (
                          <div
                            key={`${d.endpoint}-${d.category}-${idx}`}
                            className="flex flex-wrap items-center gap-1.5 text-slate-600 dark:text-slate-300"
                          >
                            <span className="font-bold text-slate-800 dark:text-slate-200">
                              [{d.shortLabel}]
                            </span>
                            {d.addedValues || d.removedValues ? (
                              <>
                                {d.removedValues && d.removedValues.length > 0 && (
                                  <span className="text-rose-600 dark:text-rose-400">
                                    −{d.removedValues.join(', −')}
                                  </span>
                                )}
                                {d.addedValues && d.addedValues.length > 0 && (
                                  <span className="text-emerald-600 dark:text-emerald-400">
                                    +{d.addedValues.join(', +')}
                                  </span>
                                )}
                              </>
                            ) : (
                              <span>
                                {d.before} → <strong>{d.after}</strong>
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    <button
                      type="button"
                      data-testid="watch-compare-transition-btn"
                      onClick={() => toggleCompare(tr.id)}
                      className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-semibold cursor-pointer transition-colors shrink-0 ${
                        isExpanded
                          ? 'border-cyan-500 bg-cyan-500 text-slate-950'
                          : 'border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 text-cyan-700 dark:text-cyan-300'
                      }`}
                    >
                      <GitCompare className="w-3.5 h-3.5" />
                      <span>{isExpanded ? 'Hide Diff' : 'Compare Snapshots'}</span>
                    </button>
                  </div>

                  {isExpanded && (
                    <TransitionInlineComparison
                      event={tr}
                      onLoadSnapshot={onLoadSnapshot}
                      onOpenInHistoryDiff={onOpenInHistoryDiff}
                    />
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
