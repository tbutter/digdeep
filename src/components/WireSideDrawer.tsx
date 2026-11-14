import {
  ArrowUpRight,
  Binary,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Shield,
  Terminal,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { formatDohShortLabel, rcodeToString } from '../dns/constants';
import {
  formatPacketAsDig,
  formatWireHexDump,
  generateCliReproducerCommands,
} from '../dns/digFormat';
import { base64ToBytes } from '../dns/encoding';
import type { AnalysisSnapshot, DohQueryLog } from '../dns/types';
import { dissectDnsWirePacket } from '../dns/wireDissector';
import type { FocusedWireQueryRequest, FocusedWireSubMode } from '../dns/wireQueryFilter';
import { seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { RichDnsTextPre } from './ResponsesPanel';
import { WirePacketDissectorView } from './WireDissectorView';

export const NARROW_WIRE_DRAWER_MEDIA_QUERY = '(max-width: 1279px)';

/**
 * Returns `true` on desktop `xl+` viewports (`>= 1280px`) where the side-by-side
 * `WireSideDrawer` has sufficient horizontal space alongside primary analysis views.
 */
export function isWideWireDrawerViewport(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  if (typeof window.matchMedia === 'function') {
    return !Boolean(window.matchMedia(NARROW_WIRE_DRAWER_MEDIA_QUERY)?.matches);
  }
  if (typeof window.innerWidth === 'number' && window.innerWidth > 0) {
    return window.innerWidth >= 1280;
  }
  return false;
}

export interface WireDrawerGraphRailContext {
  selectionLabel: string;
  onSwitchToGraphCrypto: () => void;
}

export interface WireSideDrawerProps {
  snapshot: AnalysisSnapshot;
  focusedQuery: FocusedWireQueryRequest;
  onSelectQuery: (queryId: string, mode?: FocusedWireSubMode) => void;
  onOpenFullWireTab: (queryId: string, mode: FocusedWireSubMode) => void;
  onClose: () => void;
  graphRailContext?: WireDrawerGraphRailContext | null;
}

export function WireSideDrawer({
  snapshot,
  focusedQuery,
  onSelectQuery,
  onOpenFullWireTab,
  onClose,
  graphRailContext = null,
}: WireSideDrawerProps) {
  seedIpAsnCacheFromSnapshot(snapshot);

  const [mode, setMode] = useState<FocusedWireSubMode>(() => focusedQuery.mode ?? 'dig');
  const [cliTool, setCliTool] = useState<'dig' | 'delv' | 'kdig'>('dig');
  const [copied, setCopied] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const packetScrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (focusedQuery.mode) {
      setMode(focusedQuery.mode);
    }
  }, [focusedQuery.seq, focusedQuery.queryId, focusedQuery.mode]);

  const selectedLog: DohQueryLog | undefined = useMemo(
    () =>
      snapshot.queries.find((q) => q.id === focusedQuery.queryId) ?? snapshot.queries[0],
    [snapshot.queries, focusedQuery.queryId]
  );

  const currentNavIndex = useMemo(() => {
    if (!selectedLog) return -1;
    return snapshot.queries.findIndex((q) => q.id === selectedLog.id);
  }, [snapshot.queries, selectedLog]);

  const prevQuery = currentNavIndex > 0 ? snapshot.queries[currentNavIndex - 1] : null;
  const nextQuery =
    currentNavIndex >= 0 && currentNavIndex < snapshot.queries.length - 1
      ? snapshot.queries[currentNavIndex + 1]
      : null;

  useEffect(() => {
    if (packetScrollRef.current) {
      packetScrollRef.current.scrollTop = 0;
    }
  }, [selectedLog?.id, mode]);

  const digText = useMemo(
    () => (selectedLog ? formatPacketAsDig(selectedLog) : ''),
    [selectedLog]
  );

  const cliCommands = useMemo(
    () =>
      selectedLog
        ? generateCliReproducerCommands({
            qname: selectedLog.qname,
            qtypeName: selectedLog.qtypeName,
            dohEndpoint: selectedLog.endpoint || snapshot.dohEndpoint,
            cd: selectedLog.cd,
            ecsSubnet: selectedLog.ecsSubnet,
            validatedAt: snapshot.validatedAt,
            capturedAt: snapshot.capturedAt,
          })
        : null,
    [selectedLog, snapshot.dohEndpoint, snapshot.validatedAt, snapshot.capturedAt]
  );

  const activeWireDissection = useMemo(() => {
    if (!selectedLog || (mode !== 'hex-resp' && mode !== 'hex-req')) {
      return null;
    }
    const b64 = mode === 'hex-req' ? selectedLog.requestWireBase64 : selectedLog.wireBase64;
    if (!b64) {
      return {
        dissected: null,
        error: 'Wire payload unavailable for this query.',
      };
    }
    try {
      const bytes = base64ToBytes(b64);
      return {
        dissected: dissectDnsWirePacket(bytes),
        error: null as string | null,
      };
    } catch (err) {
      return {
        dissected: null,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }, [selectedLog, mode]);

  const hexRows = useMemo(() => {
    if (!selectedLog) return [];
    const b64 = mode === 'hex-req' ? selectedLog.requestWireBase64 : selectedLog.wireBase64;
    if (!b64) return [];
    return formatWireHexDump(b64);
  }, [selectedLog, mode]);

  const firstEde = selectedLog?.packet.edns?.ede[0];
  const endpointLabel = selectedLog
    ? formatDohShortLabel(selectedLog.endpoint || snapshot.dohEndpoint)
    : formatDohShortLabel(snapshot.dohEndpoint);

  return (
    <aside
      data-testid="wire-side-drawer"
      data-query-id={selectedLog?.id ?? ''}
      data-wire-mode={mode}
      aria-label="Docked DoH Wire & Hex Inspector"
      className="w-full xl:w-[500px] 2xl:w-[556px] shrink-0 rounded-xl border border-cyan-500/35 dark:border-cyan-500/40 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md shadow-xl flex flex-col sticky top-44 z-20 max-h-[calc(100dvh-12rem)] overflow-hidden"
    >
      {/* Optional Unified Right Rail Switcher (when paired with ChainGraphView selection) */}
      {graphRailContext && (
        <div
          data-testid="wire-drawer-graph-rail-switcher"
          className="grid grid-cols-2 gap-1.5 px-2.5 py-1.5 border-b border-slate-200 dark:border-slate-800 bg-slate-100/90 dark:bg-slate-900/95 shrink-0"
        >
          <button
            type="button"
            data-testid="rail-switch-node-crypto"
            onClick={graphRailContext.onSwitchToGraphCrypto}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 hover:border-cyan-500 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 transition-colors min-w-0 cursor-pointer"
            title={`Switch right rail back to cryptographic details for ${graphRailContext.selectionLabel}`}
          >
            <Shield className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
            <span className="truncate">Node Crypto ({graphRailContext.selectionLabel})</span>
          </button>
          <button
            type="button"
            data-testid="rail-switch-wire-hex"
            aria-pressed="true"
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-500 px-2.5 py-1.5 text-xs font-semibold text-slate-950 shadow-sm min-w-0 cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">
              Wire &amp; Hex{selectedLog ? ` (${selectedLog.packet.wireSize}B)` : ''} ●
            </span>
          </button>
        </div>
      )}

      {/* Row 1: Docked Wire Drawer Top Chrome Bar */}
      <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800 bg-slate-50/95 dark:bg-slate-900/95 flex items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="w-2 h-2 rounded-full bg-cyan-500 dark:bg-cyan-400 shrink-0"
            aria-hidden="true"
          />
          <h3 className="font-semibold text-xs sm:text-sm text-slate-900 dark:text-slate-100 truncate">
            Docked Wire Drawer
          </h3>

          {snapshot.queries.length > 0 && (
            <div className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-1 py-0.5 text-[11px] font-mono shrink-0">
              <button
                type="button"
                data-testid="wire-drawer-prev"
                disabled={!prevQuery}
                onClick={() => {
                  if (prevQuery) onSelectQuery(prevQuery.id, mode);
                }}
                aria-label="Previous recorded wire packet"
                title={
                  prevQuery
                    ? `Previous: ${prevQuery.qname} ${prevQuery.qtypeName}`
                    : 'First wire packet'
                }
                className="p-0.5 rounded text-slate-600 dark:text-slate-300 enabled:hover:text-cyan-500 disabled:opacity-35 disabled:cursor-not-allowed enabled:cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span
                data-testid="wire-drawer-counter"
                className="px-1.5 text-[10px] font-semibold text-slate-600 dark:text-slate-300 select-none"
              >
                {currentNavIndex >= 0
                  ? `${currentNavIndex + 1} / ${snapshot.queries.length}`
                  : `0 / ${snapshot.queries.length}`}
              </span>
              <button
                type="button"
                data-testid="wire-drawer-next"
                disabled={!nextQuery}
                onClick={() => {
                  if (nextQuery) onSelectQuery(nextQuery.id, mode);
                }}
                aria-label="Next recorded wire packet"
                title={
                  nextQuery
                    ? `Next: ${nextQuery.qname} ${nextQuery.qtypeName}`
                    : 'Last wire packet'
                }
                className="p-0.5 rounded text-slate-600 dark:text-slate-300 enabled:hover:text-cyan-500 disabled:opacity-35 disabled:cursor-not-allowed enabled:cursor-pointer"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {selectedLog && (
            <button
              type="button"
              data-testid="wire-drawer-open-full-tab"
              onClick={() => onOpenFullWireTab(selectedLog.id, mode)}
              title="Open full DoH Wire Responses tab (query waterfall, .zone export & offline ?dns= decoder)"
              className="inline-flex items-center gap-1 rounded-md border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 text-[11px] font-semibold text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer"
            >
              <span>Full Wire Tab</span>
              <ArrowUpRight className="w-3 h-3 shrink-0" />
            </button>
          )}
          <button
            type="button"
            data-testid="wire-drawer-close"
            onClick={onClose}
            aria-label="Close docked wire drawer"
            title="Close docked wire drawer (Esc)"
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 hover:border-cyan-500 px-2 py-1 font-mono text-[10px] font-semibold text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
          >
            <span>Esc</span>
            <X className="w-3 h-3 shrink-0" />
          </button>
        </div>
      </div>

      {selectedLog ? (
        <>
          {/* Row 2: Active Query Summary Strip */}
          <div
            data-testid="wire-drawer-summary"
            className="px-3 py-1.5 border-b border-slate-200 dark:border-slate-800 bg-slate-100/60 dark:bg-slate-900/60 flex flex-wrap items-center justify-between gap-2 text-[11px] shrink-0"
          >
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:text-slate-200 shrink-0">
                {selectedLog.qtypeName}
              </span>
              <span className="font-mono font-semibold truncate text-slate-900 dark:text-slate-100">
                {selectedLog.qname}
              </span>
              {selectedLog.ecsSubnet && (
                <span className="rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                  ECS {selectedLog.ecsSubnet}
                </span>
              )}
              <span className="rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                {endpointLabel} ({selectedLog.cd ? 'CD=1' : 'CD=0'})
              </span>
            </div>

            <div className="font-mono text-[10px] text-slate-500 dark:text-slate-400 shrink-0 flex items-center gap-1">
              <span
                className={`font-semibold ${
                  selectedLog.packet.flags.rcode === 0
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : selectedLog.packet.flags.rcode === 3
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-rose-600 dark:text-rose-400'
                }`}
              >
                {rcodeToString(selectedLog.packet.flags.rcode)}
                {selectedLog.packet.flags.ad ? ' · AD=1' : ''}
              </span>
              {firstEde && (
                <span className="rounded bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/30 px-1 py-0.2 text-[9.5px] font-semibold">
                  EDE {firstEde.infoCode}
                </span>
              )}
              <span>
                · {selectedLog.packet.wireSize}B · {selectedLog.latencyMs}ms
              </span>
            </div>
          </div>

          {/* Row 3: Mode Switcher (dig Output | Response Wire | Request Wire) + Copy */}
          <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 flex items-center justify-between gap-2 overflow-x-auto shrink-0">
            <div className="flex items-center gap-1 shrink-0">
              <button
                type="button"
                data-testid="wire-drawer-mode-dig"
                aria-pressed={mode === 'dig'}
                onClick={() => {
                  setMode('dig');
                  onSelectQuery(selectedLog.id, 'dig');
                }}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap cursor-pointer ${
                  mode === 'dig'
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>dig Output</span>
              </button>
              <button
                type="button"
                data-testid="wire-drawer-mode-hex-resp"
                aria-pressed={mode === 'hex-resp'}
                onClick={() => {
                  setMode('hex-resp');
                  onSelectQuery(selectedLog.id, 'hex-resp');
                }}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap cursor-pointer ${
                  mode === 'hex-resp'
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Response Wire ({selectedLog.packet.wireSize}B)</span>
              </button>
              <button
                type="button"
                data-testid="wire-drawer-mode-hex-req"
                aria-pressed={mode === 'hex-req'}
                onClick={() => {
                  setMode('hex-req');
                  onSelectQuery(selectedLog.id, 'hex-req');
                }}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap cursor-pointer ${
                  mode === 'hex-req'
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Request Wire</span>
              </button>
            </div>

            <button
              type="button"
              data-testid="wire-drawer-copy"
              onClick={() => {
                const content =
                  mode === 'dig'
                    ? digText
                    : hexRows
                        .map((r) => `${r.offsetHex}  ${r.hexGroups}  |${r.ascii}|`)
                        .join('\n');
                navigator.clipboard?.writeText(content);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }}
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copied ? (
                <Check className="w-3.5 h-3.5 text-emerald-500" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          {/* Row 4: CLI Reproducer Bar (dig / delv / kdig) */}
          {cliCommands && (
            <div className="px-3 py-1.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-900/90 flex items-center justify-between gap-1.5 text-xs shrink-0">
              <div className="flex items-center gap-1.5 min-w-0 flex-1">
                <div className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 p-0.5 shrink-0">
                  {(['dig', 'delv', 'kdig'] as const).map((tool) => (
                    <button
                      key={tool}
                      type="button"
                      data-testid={`wire-drawer-cli-${tool}`}
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
                <code className="font-mono text-[11px] text-cyan-800 dark:text-cyan-300 bg-slate-200/60 dark:bg-slate-950 px-2 py-0.5 rounded border border-slate-200/80 dark:border-slate-800 truncate flex-1">
                  {cliCommands[cliTool]}
                </code>
              </div>
              <button
                type="button"
                data-testid="wire-drawer-copy-cli"
                onClick={() => {
                  navigator.clipboard?.writeText(cliCommands[cliTool]);
                  setCopiedCli(true);
                  setTimeout(() => setCopiedCli(false), 1500);
                }}
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200 shrink-0 cursor-pointer"
                title={`Copy ${cliTool} command to clipboard`}
              >
                {copiedCli ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-500" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy {cliTool}</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Row 5: Scrollable Wire Payload Body */}
          <div
            ref={packetScrollRef}
            data-testid="wire-drawer-body"
            className="p-3 overflow-auto flex-1 bg-slate-950 text-slate-200 font-mono text-xs leading-relaxed"
          >
            {mode === 'dig' ? (
              <RichDnsTextPre text={digText} />
            ) : activeWireDissection?.dissected ? (
              <WirePacketDissectorView
                key={`${selectedLog.id}-${mode}`}
                dissected={activeWireDissection.dissected}
                packetLabel={
                  mode === 'hex-req'
                    ? `DNS Request Wire — ${selectedLog.qname} ${selectedLog.qtypeName}`
                    : `DNS Response Wire — ${selectedLog.qname} ${selectedLog.qtypeName}`
                }
              />
            ) : (
              <div className="rounded-lg border border-rose-500/40 bg-rose-950/20 p-3 text-rose-200 text-xs">
                {activeWireDissection?.error ?? 'Wire payload unavailable for this query.'}
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="p-6 text-center text-xs text-slate-500">
          No recorded DoH wire packet found for this selection.
        </div>
      )}
    </aside>
  );
}
