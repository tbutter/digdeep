import {
  AlertTriangle,
  ArrowLeft,
  Binary,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  FileCode2,
  RotateCcw,
  Search,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { formatDohShortLabel, rcodeToString } from '../dns/constants';
import {
  downloadTextFile,
  formatPacketAsDig,
  formatSnapshotAsZonefile,
  formatWireHexDump,
  generateCliReproducerCommands,
} from '../dns/digFormat';
import { base64ToBytes, bytesToBase64, bytesToBase64Url } from '../dns/encoding';
import type { AnalysisSnapshot, DohQueryLog } from '../dns/types';
import {
  buildSyntheticLogFromDissected,
  decodeUserWireInput,
  dissectDnsWirePacket,
} from '../dns/wireDissector';
import {
  computeWireQueryCategoryCounts,
  type FocusedWireQueryRequest,
  filterDohQueryLogs,
  matchesWireQueryCategory,
  matchesWireQuerySearch,
  type WireQueryFilterCategory,
} from '../dns/wireQueryFilter';
import { IpHoverBadge, parseIpToken, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { WirePacketDissectorView } from './WireDissectorView';

/**
 * Compact RFC 1035 sample response for `www.example.org. A` with CNAME + A records
 * demonstrating direct (`0xC00C`, `0xC010`) and chained (`0xC02D` -> `0xC010`) compression pointer jumps.
 */
const SAMPLE_COMPRESSED_HEX =
  '1a2b81a00001000200000000' +
  '03777777076578616d706c65036f72670000010001' +
  'c00c0005000100000e1000070465646765c010' +
  'c02d000100010000012c00045db8d822';

const DETECTED_FORMAT_LABELS: Record<'doh-url' | 'hex-dump' | 'hex' | 'base64url', string> = {
  'doh-url': 'RFC 8484 DoH ?dns= URL',
  'hex-dump': 'Offset Hex Dump (xxd / DigDeep)',
  hex: 'Raw Hexadecimal',
  base64url: 'Base64 / Base64url',
};

export interface ExternalCustomWireRequest {
  payload: string;
  seq: number;
}

export function ResponsesPanel({
  snapshot,
  focusedQuery = null,
  externalCustomWire = null,
  resetToListSeq = 0,
}: {
  snapshot: AnalysisSnapshot;
  focusedQuery?: FocusedWireQueryRequest | null;
  externalCustomWire?: ExternalCustomWireRequest | null;
  resetToListSeq?: number;
}) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const [selectedId, setSelectedId] = useState<string>(() => {
    if (focusedQuery && snapshot.queries.some((q) => q.id === focusedQuery.queryId)) {
      return focusedQuery.queryId;
    }
    return snapshot.queries[0]?.id ?? '';
  });
  const [mode, setMode] = useState<'dig' | 'zonefile' | 'hex-resp' | 'hex-req' | 'custom-decode'>(
    () =>
      externalCustomWire
        ? 'custom-decode'
        : (focusedQuery?.mode ?? (snapshot.queries.length === 0 ? 'custom-decode' : 'dig'))
  );
  const [mobilePane, setMobilePane] = useState<'list' | 'detail'>(() => {
    const hasValidFocusedQuery = Boolean(
      focusedQuery && snapshot.queries.some((q) => q.id === focusedQuery.queryId)
    );
    if (externalCustomWire || hasValidFocusedQuery || snapshot.queries.length === 0) {
      return 'detail';
    }
    return 'list';
  });
  const [category, setCategory] = useState<WireQueryFilterCategory>('all');
  const [searchText, setSearchText] = useState<string>('');
  const [cliTool, setCliTool] = useState<'dig' | 'delv' | 'kdig'>('dig');
  const [copied, setCopied] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [customWireInput, setCustomWireInput] = useState<string>(
    () => externalCustomWire?.payload ?? ''
  );
  const [customSubView, setCustomSubView] = useState<'dissector' | 'dig'>('dissector');
  const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const listPaneRef = useRef<HTMLDivElement | null>(null);
  const detailPaneRef = useRef<HTMLDivElement | null>(null);
  const packetScrollRef = useRef<HTMLDivElement | null>(null);
  const prevSnapshotIdRef = useRef<string>(snapshot.id);
  const prevResetSeqRef = useRef<number>(resetToListSeq);

  // Sync external omnibox-pasted ?dns= / wire hex payloads into the Offline Wire Dissector
  useEffect(() => {
    if (!externalCustomWire) return;
    setCustomWireInput(externalCustomWire.payload);
    setMode('custom-decode');
    setCustomSubView('dissector');
    setMobilePane('detail');
  }, [externalCustomWire?.seq, externalCustomWire?.payload, externalCustomWire]);

  // Return to mobile waterfall list when the user explicitly taps the Wire nav tab again
  useEffect(() => {
    if (prevResetSeqRef.current !== resetToListSeq) {
      prevResetSeqRef.current = resetToListSeq;
      if (snapshot.queries.length > 0) {
        setMobilePane('list');
      }
    }
  }, [resetToListSeq, snapshot.queries.length]);

  // Reset filters and selection when switching to a different snapshot while mounted
  useEffect(() => {
    if (prevSnapshotIdRef.current !== snapshot.id) {
      prevSnapshotIdRef.current = snapshot.id;
      setCategory('all');
      setSearchText('');
      if (focusedQuery && snapshot.queries.some((q) => q.id === focusedQuery.queryId)) {
        setSelectedId(focusedQuery.queryId);
        setMobilePane('detail');
      } else {
        setSelectedId(snapshot.queries[0]?.id ?? '');
        setMobilePane(snapshot.queries.length === 0 ? 'detail' : 'list');
      }
    }
  }, [snapshot.id, snapshot.queries, focusedQuery]);

  // Focus & scroll to a cross-tab requested wire packet
  useEffect(() => {
    if (!focusedQuery) return;
    const target = snapshot.queries.find((q) => q.id === focusedQuery.queryId);
    if (!target) return;
    setSelectedId(target.id);
    if (focusedQuery.mode) {
      setMode(focusedQuery.mode);
    }
    setMobilePane('detail');
    setCategory((prevCat) => (matchesWireQueryCategory(target, prevCat) ? prevCat : 'all'));
    setSearchText((prevSearch) => (matchesWireQuerySearch(target, prevSearch) ? prevSearch : ''));
    const timer = setTimeout(() => {
      const el = rowRefs.current.get(target.id);
      if (el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ block: 'nearest' });
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [focusedQuery?.seq, focusedQuery?.queryId, focusedQuery?.mode, snapshot.queries, focusedQuery]);

  const categoryCounts = useMemo(
    () => computeWireQueryCategoryCounts(snapshot.queries),
    [snapshot.queries]
  );

  const filteredQueries = useMemo(
    () => filterDohQueryLogs(snapshot.queries, category, searchText),
    [snapshot.queries, category, searchText]
  );

  const isFiltered = category !== 'all' || searchText.trim().length > 0;

  const selectedLog: DohQueryLog | undefined = useMemo(
    () =>
      snapshot.queries.find((q) => q.id === selectedId) ??
      filteredQueries[0] ??
      snapshot.queries[0],
    [snapshot.queries, filteredQueries, selectedId]
  );

  const navigationQueries = useMemo(() => {
    if (
      selectedLog &&
      filteredQueries.length > 0 &&
      filteredQueries.some((q) => q.id === selectedLog.id)
    ) {
      return filteredQueries;
    }
    return snapshot.queries;
  }, [snapshot.queries, filteredQueries, selectedLog]);

  const currentNavIndex = useMemo(() => {
    if (!selectedLog) return -1;
    return navigationQueries.findIndex((q) => q.id === selectedLog.id);
  }, [navigationQueries, selectedLog]);

  const prevQuery = currentNavIndex > 0 ? navigationQueries[currentNavIndex - 1] : null;
  const nextQuery =
    currentNavIndex >= 0 && currentNavIndex < navigationQueries.length - 1
      ? navigationQueries[currentNavIndex + 1]
      : null;

  useEffect(() => {
    if (packetScrollRef.current) {
      packetScrollRef.current.scrollTop = 0;
    }
  }, [selectedLog?.id, mode]);

  useEffect(() => {
    if (mobilePane === 'detail') {
      const el = detailPaneRef.current;
      if (el && typeof el.getBoundingClientRect === 'function') {
        const rect = el.getBoundingClientRect();
        if (rect.top < 0 && typeof el.scrollIntoView === 'function') {
          el.scrollIntoView({ block: 'start' });
        }
      }
      return;
    }
    const timer = setTimeout(() => {
      if (selectedLog) {
        const rowEl = rowRefs.current.get(selectedLog.id);
        if (rowEl && typeof rowEl.scrollIntoView === 'function') {
          rowEl.scrollIntoView({ block: 'nearest' });
        }
      }
      const listEl = listPaneRef.current;
      if (listEl && typeof listEl.getBoundingClientRect === 'function') {
        const rect = listEl.getBoundingClientRect();
        if (rect.top < 0 && typeof listEl.scrollIntoView === 'function') {
          listEl.scrollIntoView({ block: 'start' });
        }
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [mobilePane, selectedLog]);

  const maxLatency = useMemo(
    () => Math.max(1, ...snapshot.queries.map((q) => q.latencyMs)),
    [snapshot.queries]
  );

  const digText = useMemo(
    () => (selectedLog ? formatPacketAsDig(selectedLog) : ''),
    [selectedLog]
  );

  const zonefileText = useMemo(() => formatSnapshotAsZonefile(snapshot), [snapshot]);

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
    if (!b64) return null;
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

  const customDecodeResult = useMemo(() => {
    if (!customWireInput.trim()) return null;
    try {
      const { bytes, detectedFormat } = decodeUserWireInput(customWireInput);
      const dissected = dissectDnsWirePacket(bytes);
      const syntheticLog = buildSyntheticLogFromDissected(dissected);
      const digFormatted = syntheticLog ? formatPacketAsDig(syntheticLog) : '';
      return {
        detectedFormat,
        dissected,
        digFormatted,
        error: null as string | null,
      };
    } catch (err) {
      return {
        detectedFormat: null,
        dissected: null,
        digFormatted: '',
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }, [customWireInput]);

  const hexRows = useMemo(() => {
    if (mode === 'custom-decode') {
      if (!customDecodeResult?.dissected) return [];
      return formatWireHexDump(bytesToBase64(customDecodeResult.dissected.bytes));
    }
    if (!selectedLog) return [];
    return formatWireHexDump(
      mode === 'hex-req' ? selectedLog.requestWireBase64 : selectedLog.wireBase64
    );
  }, [selectedLog, mode, customDecodeResult]);

  const zoneFilename = `${snapshot.displayDomain === '.' ? 'root' : snapshot.displayDomain.replace(/[^a-z0-9.-]/gi, '_')}.zone`;

  return (
    <div
      data-testid="wire-responses-panel"
      data-mobile-pane={mobilePane}
      className="grid grid-cols-1 lg:grid-cols-12 gap-4 lg:min-h-[540px]"
    >
      {/* Left: DoH Query Waterfall Table */}
      <div
        ref={listPaneRef}
        data-testid="wire-waterfall-pane"
        className={`${
          mobilePane === 'list' ? 'flex' : 'hidden lg:flex'
        } lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden flex-col max-h-[80vh]`}
      >
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            {formatDohShortLabel(snapshot.dohEndpoint)} DoH Wire Queries (
            {isFiltered
              ? `${filteredQueries.length}/${snapshot.queries.length}`
              : snapshot.queries.length}
            )
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <div className="hidden sm:block font-mono text-[11px] text-slate-400">
              application/dns-message
            </div>
            <button
              type="button"
              data-testid="wire-mobile-open-decoder"
              onClick={() => {
                setMode('custom-decode');
                setMobilePane('detail');
              }}
              className="lg:hidden inline-flex items-center gap-1 rounded-md border border-fuchsia-500/35 bg-fuchsia-500/10 hover:bg-fuchsia-500/20 px-2 py-0.5 text-[11px] font-medium text-fuchsia-700 dark:text-fuchsia-300 cursor-pointer"
            >
              <Sparkles className="w-3 h-3" />
              <span>Decode ?dns=</span>
            </button>
          </div>
        </div>

        {/* Search Input & Category Filter Pills */}
        {snapshot.queries.length > 0 && (
          <div className="px-3 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/75 dark:bg-slate-950/45 space-y-2">
            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
              <input
                type="text"
                value={searchText}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                enterKeyHint="search"
                onChange={(e) => {
                  const next = e.target.value;
                  setSearchText(next);
                  const nextMatches = filterDohQueryLogs(snapshot.queries, category, next);
                  if (nextMatches.length > 0 && !nextMatches.some((q) => q.id === selectedId)) {
                    setSelectedId(nextMatches[0].id);
                  }
                }}
                placeholder="Filter qname, type, resolver, ECS, RCODE, EDE…"
                aria-label="Filter DoH wire queries"
                data-testid="wire-query-search"
                className="w-full rounded-lg border border-slate-200 dark:border-slate-700/90 bg-white dark:bg-slate-900 pl-8 pr-7 py-1.5 text-base sm:text-xs font-mono text-slate-900 dark:text-slate-100 placeholder:font-sans placeholder:text-slate-400 focus:outline-none focus:border-cyan-500"
              />
              {searchText.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSearchText('')}
                  aria-label="Clear wire query filter"
                  className="absolute right-2 rounded p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1">
              {(
                [
                  { id: 'all' as const, label: 'All', count: categoryCounts.all, show: true },
                  {
                    id: 'target' as const,
                    label: 'Target',
                    count: categoryCounts.target,
                    show: true,
                  },
                  {
                    id: 'dnssec' as const,
                    label: 'DNSSEC',
                    count: categoryCounts.dnssec,
                    show: true,
                  },
                  {
                    id: 'errors' as const,
                    label: 'Errors / EDE',
                    count: categoryCounts.errors,
                    show: true,
                  },
                  {
                    id: 'consensus' as const,
                    label: 'Consensus',
                    count: categoryCounts.consensus,
                    show: categoryCounts.consensus > 0,
                  },
                  {
                    id: 'ecs' as const,
                    label: 'ECS Geo',
                    count: categoryCounts.ecs,
                    show: categoryCounts.ecs > 0,
                  },
                  {
                    id: 'aux' as const,
                    label: 'BGP / Aux',
                    count: categoryCounts.aux,
                    show: categoryCounts.aux > 0,
                  },
                ] as const
              )
                .filter((pill) => pill.show)
                .map((pill) => {
                  const activePill = category === pill.id;
                  const hasErrorsHighlight =
                    pill.id === 'errors' && pill.count > 0 && !activePill;
                  return (
                    <button
                      key={pill.id}
                      type="button"
                      data-testid={`wire-filter-pill-${pill.id}`}
                      onClick={() => {
                        setCategory(pill.id);
                        const nextMatches = filterDohQueryLogs(
                          snapshot.queries,
                          pill.id,
                          searchText
                        );
                        if (
                          nextMatches.length > 0 &&
                          !nextMatches.some((q) => q.id === selectedId)
                        ) {
                          setSelectedId(nextMatches[0].id);
                        }
                      }}
                      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors cursor-pointer ${
                        activePill
                          ? 'bg-cyan-500 text-slate-950 font-semibold'
                          : hasErrorsHighlight
                            ? 'bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/35 hover:border-amber-400'
                            : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:border-cyan-500/60'
                      }`}
                    >
                      <span>{pill.label}</span>
                      <span
                        className={`font-mono text-[10px] ${
                          activePill ? 'text-slate-950/80' : 'text-slate-400'
                        }`}
                      >
                        {pill.count}
                      </span>
                    </button>
                  );
                })}
            </div>
          </div>
        )}

        <div className="divide-y divide-slate-100 dark:divide-slate-800/80 overflow-y-auto flex-1">
          {filteredQueries.length === 0 && snapshot.queries.length > 0 ? (
            <div className="p-6 text-center space-y-2.5">
              <div className="text-xs font-medium text-slate-600 dark:text-slate-300">
                No wire queries match the active filter.
              </div>
              <button
                type="button"
                onClick={() => {
                  setCategory('all');
                  setSearchText('');
                }}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset filters</span>
              </button>
            </div>
          ) : (
            filteredQueries.map((q) => {
              const active = selectedLog?.id === q.id;
              const rcode = rcodeToString(q.packet.flags.rcode);
              const rcodeColor =
                q.packet.flags.rcode === 0
                  ? 'text-emerald-600 dark:text-emerald-400'
                  : q.packet.flags.rcode === 3
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-rose-600 dark:text-rose-400';
              const firstEde = q.packet.edns?.ede[0];
              const isSecondaryEndpoint =
                Boolean(q.endpoint) && q.endpoint !== snapshot.dohEndpoint;

              return (
                <button
                  key={q.id}
                  ref={(el) => {
                    if (el) {
                      rowRefs.current.set(q.id, el);
                    } else {
                      rowRefs.current.delete(q.id);
                    }
                  }}
                  data-query-id={q.id}
                  type="button"
                  onClick={() => {
                    setSelectedId(q.id);
                    if (mode === 'custom-decode') {
                      setMode('dig');
                    }
                    setMobilePane('detail');
                  }}
                  className={`w-full text-left px-3.5 py-2.5 transition-colors cursor-pointer ${
                    active
                      ? 'bg-cyan-500/10 border-l-2 border-l-cyan-500'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:text-slate-200 shrink-0">
                        {q.qtypeName}
                      </span>
                      <span className="font-mono text-xs font-medium truncate text-slate-900 dark:text-slate-100">
                        {q.qname}
                      </span>
                      {q.ecsSubnet && (
                        <span className="rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                          ECS {q.ecsSubnet}
                        </span>
                      )}
                      {isSecondaryEndpoint && !q.ecsSubnet && (
                        <span className="rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                          {formatDohShortLabel(q.endpoint)}
                        </span>
                      )}
                      {firstEde && (
                        <span className="rounded bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                          EDE {firstEde.infoCode}
                        </span>
                      )}
                    </div>
                    <div className="inline-flex items-center gap-1 shrink-0">
                      <span className={`font-mono text-[11px] font-semibold ${rcodeColor}`}>
                        {rcode}
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 lg:hidden" />
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-500 mt-1">
                    <span className="truncate pr-2">{q.purpose}</span>
                    <span className="font-mono shrink-0">
                      {q.cd ? 'CD=1' : 'CD=0'}
                      {q.packet.flags.ad ? ' AD=1' : ''} · {q.packet.wireSize}B · {q.latencyMs}ms
                    </span>
                  </div>

                  <div className="mt-1.5 h-1 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-cyan-500/70"
                      style={{ width: `${Math.max(4, (q.latencyMs / maxLatency) * 100)}%` }}
                    />
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* Right: Packet Presentation (`dig`, RFC 1035 `.zone`, Interactive Wire Dissector & Offline Decoder) */}
      <div
        ref={detailPaneRef}
        data-testid="wire-detail-pane"
        className={`${
          mobilePane === 'detail' ? 'flex' : 'hidden lg:flex'
        } lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden flex-col max-h-[82vh] lg:max-h-[80vh]`}
      >
        {/* Sticky Mobile Packet Navigation Bar (`< lg`) */}
        {snapshot.queries.length > 0 && (
          <div
            data-testid="wire-mobile-nav-bar"
            className="lg:hidden sticky top-0 z-30 shrink-0 px-3 py-2 border-b border-slate-200 dark:border-slate-800 bg-slate-100/95 dark:bg-slate-900/95 backdrop-blur-sm space-y-1.5"
          >
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                data-testid="wire-mobile-back"
                onClick={() => setMobilePane('list')}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-950 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400 shrink-0" />
                <span>
                  All Queries (
                  {currentNavIndex >= 0
                    ? `${currentNavIndex + 1}/${navigationQueries.length}`
                    : navigationQueries.length}
                  )
                </span>
              </button>

              <div className="inline-flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  data-testid="wire-mobile-prev"
                  disabled={!prevQuery}
                  onClick={() => {
                    if (!prevQuery) return;
                    setSelectedId(prevQuery.id);
                    if (mode === 'custom-decode') {
                      setMode('dig');
                    }
                  }}
                  aria-label="Previous DoH wire query"
                  className="inline-flex items-center gap-0.5 rounded-lg border border-slate-200 dark:border-slate-700 enabled:hover:border-cyan-500 bg-white dark:bg-slate-950 px-2 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed enabled:cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Prev</span>
                </button>
                <button
                  type="button"
                  data-testid="wire-mobile-next"
                  disabled={!nextQuery}
                  onClick={() => {
                    if (!nextQuery) return;
                    setSelectedId(nextQuery.id);
                    if (mode === 'custom-decode') {
                      setMode('dig');
                    }
                  }}
                  aria-label="Next DoH wire query"
                  className="inline-flex items-center gap-0.5 rounded-lg border border-slate-200 dark:border-slate-700 enabled:hover:border-cyan-500 bg-white dark:bg-slate-950 px-2 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed enabled:cursor-pointer"
                >
                  <span>Next</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {selectedLog && mode !== 'custom-decode' && (
              <div
                data-testid="wire-mobile-active-summary"
                className="flex items-center justify-between gap-2 text-[11px]"
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:text-slate-200 shrink-0">
                    {selectedLog.qtypeName}
                  </span>
                  <span className="font-mono font-medium truncate text-slate-900 dark:text-slate-100">
                    {selectedLog.qname}
                  </span>
                  {selectedLog.ecsSubnet && (
                    <span className="rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                      ECS {selectedLog.ecsSubnet}
                    </span>
                  )}
                  {Boolean(selectedLog.endpoint) &&
                    selectedLog.endpoint !== snapshot.dohEndpoint &&
                    !selectedLog.ecsSubnet && (
                      <span className="rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25 px-1.5 py-0.2 font-mono text-[10px] shrink-0">
                        {formatDohShortLabel(selectedLog.endpoint)}
                      </span>
                    )}
                </div>
                <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400 shrink-0">
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
                  </span>{' '}
                  · {selectedLog.packet.wireSize}B · {selectedLog.latencyMs}ms
                </span>
              </div>
            )}
          </div>
        )}

        {selectedLog || mode === 'custom-decode' ? (
          <>
            <div className="px-3 sm:px-4 py-2 sm:py-2.5 shrink-0 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2 overflow-x-auto sm:flex-wrap">
              <div className="flex items-center sm:flex-wrap gap-1.5 shrink-0">
                {selectedLog && (
                  <>
                    <button
                      type="button"
                      onClick={() => setMode('dig')}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                        mode === 'dig'
                          ? 'bg-cyan-500 text-slate-950 font-semibold'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      dig Output
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode('zonefile')}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                        mode === 'zonefile'
                          ? 'bg-cyan-500 text-slate-950 font-semibold'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      <FileCode2 className="w-3.5 h-3.5" />
                      Zonefile (.zone)
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode('hex-resp')}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                        mode === 'hex-resp'
                          ? 'bg-cyan-500 text-slate-950 font-semibold'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      <Binary className="w-3.5 h-3.5" />
                      Response Wire ({selectedLog.packet.wireSize}B)
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode('hex-req')}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                        mode === 'hex-req'
                          ? 'bg-cyan-500 text-slate-950 font-semibold'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      <Binary className="w-3.5 h-3.5" />
                      Request Wire
                    </button>
                  </>
                )}
                <button
                  type="button"
                  onClick={() => setMode('custom-decode')}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                    mode === 'custom-decode'
                      ? 'bg-fuchsia-500 text-slate-950 font-semibold'
                      : 'text-fuchsia-700 dark:text-fuchsia-300 hover:bg-fuchsia-500/15'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  Decode ?dns= / Hex
                </button>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                {(selectedLog || snapshot.zones.length > 0) && (
                  <button
                    type="button"
                    onClick={() => downloadTextFile(zonefileText, zoneFilename)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 font-medium whitespace-nowrap shrink-0 cursor-pointer"
                    title={`Download RFC 1035 Master Zonefile (${zoneFilename})`}
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export .zone</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    const content =
                      mode === 'dig'
                        ? digText
                        : mode === 'zonefile'
                          ? zonefileText
                          : mode === 'custom-decode' && customSubView === 'dig'
                            ? (customDecodeResult?.digFormatted ?? '')
                            : hexRows
                                .map((r) => `${r.offsetHex}  ${r.hexGroups}  |${r.ascii}|`)
                                .join('\n');
                    navigator.clipboard?.writeText(content);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copied ? (
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            {/* CLI Command Reproducer Bar (dig / delv / kdig) */}
            {cliCommands && mode !== 'custom-decode' && (
              <div className="px-3 sm:px-4 py-2 shrink-0 border-b border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-900/90 flex sm:flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <div className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 p-0.5 shrink-0">
                    {(['dig', 'delv', 'kdig'] as const).map((tool) => (
                      <button
                        key={tool}
                        type="button"
                        onClick={() => setCliTool(tool)}
                        className={`px-2 py-0.5 rounded font-mono text-[11px] font-semibold transition-colors cursor-pointer ${
                          cliTool === tool
                            ? 'bg-cyan-500 text-slate-950'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                        }`}
                      >
                        {tool}
                      </button>
                    ))}
                  </div>
                  <code className="font-mono text-[11px] text-cyan-800 dark:text-cyan-300 bg-slate-200/60 dark:bg-slate-950 px-2.5 py-1 rounded border border-slate-200/80 dark:border-slate-800 truncate flex-1">
                    {cliCommands[cliTool]}
                  </code>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard?.writeText(cliCommands[cliTool]);
                    setCopiedCli(true);
                    setTimeout(() => setCopiedCli(false), 1500);
                  }}
                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 shrink-0 cursor-pointer"
                  title={`Copy ${cliTool} command to clipboard`}
                >
                  {copiedCli ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-500" />
                      <span>Copied CLI</span>
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

            <div
              ref={packetScrollRef}
              className="p-2.5 sm:p-4 overflow-auto flex-1 bg-slate-950 text-slate-200 font-mono text-xs leading-relaxed"
            >
              {mode === 'dig' || mode === 'zonefile' ? (
                <pre className="whitespace-pre overflow-x-auto">
                  {(mode === 'dig' ? digText : zonefileText).split('\n').map((line, idx, lines) => {
                    const nl = idx < lines.length - 1 ? '\n' : '';
                    if (!line.startsWith(';') && !line.startsWith('$')) {
                      const match = /^(\S+\s+\d+\s+\S+\s+(?:A|AAAA)\s+)(\S+)$/.exec(line);
                      if (match && parseIpToken(match[2])) {
                        return (
                          <span key={idx}>
                            {match[1]}
                            <IpHoverBadge ip={match[2]} className="text-cyan-300" />
                            {nl}
                          </span>
                        );
                      }
                    }
                    return (
                      <span key={idx}>
                        {line}
                        {nl}
                      </span>
                    );
                  })}
                </pre>
              ) : mode === 'hex-resp' || mode === 'hex-req' ? (
                selectedLog && activeWireDissection?.dissected ? (
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
                )
              ) : (
                /* Offline Raw Packet Decoder (?dns= / Base64url / Hex Dump) */
                <div className="space-y-3 font-sans">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/90 p-3 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-xs font-semibold text-slate-100">
                          Offline Raw DNS Wire Packet Decoder
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Paste an RFC 8484 DoH <code className="text-cyan-300">?dns=</code> URL,
                          Base64url/Base64 payload, raw hex, or <code className="text-cyan-300">xxd</code> /
                          DigDeep hex dump — decoded 100% locally in your browser.
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {selectedLog && (
                          <button
                            type="button"
                            onClick={() => {
                              const bytes = base64ToBytes(selectedLog.wireBase64);
                              setCustomWireInput(bytesToBase64Url(bytes));
                            }}
                            className="rounded border border-slate-700 hover:border-cyan-500 bg-slate-950 px-2 py-1 text-[11px] font-medium text-slate-200 cursor-pointer"
                          >
                            Load Selected Response
                          </button>
                        )}
                        {selectedLog?.requestWireBase64 && (
                          <button
                            type="button"
                            onClick={() => {
                              const reqB64Url = bytesToBase64Url(
                                base64ToBytes(selectedLog.requestWireBase64)
                              );
                              const endpoint = selectedLog.endpoint || snapshot.dohEndpoint;
                              setCustomWireInput(`${endpoint}?dns=${reqB64Url}`);
                            }}
                            className="rounded border border-slate-700 hover:border-cyan-500 bg-slate-950 px-2 py-1 text-[11px] font-medium text-slate-200 cursor-pointer"
                          >
                            Load Request ?dns= URL
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setCustomWireInput(SAMPLE_COMPRESSED_HEX)}
                          className="rounded border border-fuchsia-500/40 hover:border-fuchsia-400 bg-fuchsia-950/30 px-2 py-1 text-[11px] font-medium text-fuchsia-200 cursor-pointer"
                        >
                          Sample Compressed Hex
                        </button>
                        {customWireInput && (
                          <button
                            type="button"
                            onClick={() => setCustomWireInput('')}
                            className="rounded border border-slate-800 hover:border-slate-600 bg-slate-950 px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                          >
                            Clear
                          </button>
                        )}
                      </div>
                    </div>

                    <textarea
                      value={customWireInput}
                      onChange={(e) => setCustomWireInput(e.target.value)}
                      rows={3}
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      placeholder="https://1.1.1.1/dns-query?dns=AAABAAAB... or Base64url or hex bytes (1a 2b 81 a0 ...)"
                      className="w-full rounded-md border border-slate-700 focus:border-cyan-500 focus:outline-none bg-slate-950 px-3 py-2 font-mono text-base sm:text-xs text-slate-100 placeholder:text-slate-600"
                    />

                    {customDecodeResult?.detectedFormat && customDecodeResult.dissected && (
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                        <span className="inline-flex items-center gap-1.5 rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
                          Detected: {DETECTED_FORMAT_LABELS[customDecodeResult.detectedFormat]} (
                          {customDecodeResult.dissected.wireSize}B)
                        </span>

                        <div className="inline-flex items-center rounded-md border border-slate-700 bg-slate-950 p-0.5">
                          <button
                            type="button"
                            onClick={() => setCustomSubView('dissector')}
                            className={`px-2.5 py-0.5 rounded text-[11px] font-medium cursor-pointer ${
                              customSubView === 'dissector'
                                ? 'bg-cyan-500 text-slate-950 font-semibold'
                                : 'text-slate-300 hover:text-white'
                            }`}
                          >
                            Wire Dissector
                          </button>
                          <button
                            type="button"
                            onClick={() => setCustomSubView('dig')}
                            disabled={!customDecodeResult.digFormatted}
                            className={`px-2.5 py-0.5 rounded text-[11px] font-medium cursor-pointer disabled:opacity-40 ${
                              customSubView === 'dig'
                                ? 'bg-cyan-500 text-slate-950 font-semibold'
                                : 'text-slate-300 hover:text-white'
                            }`}
                          >
                            Decoded dig Output
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {customDecodeResult?.error && (
                    <div className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-950/25 p-3 text-xs text-rose-200">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <span>{customDecodeResult.error}</span>
                    </div>
                  )}

                  {customDecodeResult?.dissected &&
                    (customSubView === 'dig' && customDecodeResult.digFormatted ? (
                      <pre className="whitespace-pre overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60 p-3 font-mono text-xs text-slate-200">
                        {customDecodeResult.digFormatted}
                      </pre>
                    ) : (
                      <WirePacketDissectorView
                        key={`custom-${customDecodeResult.dissected.base64Url.slice(0, 32)}-${customDecodeResult.dissected.wireSize}`}
                        dissected={customDecodeResult.dissected}
                        packetLabel="Offline Decoded DNS Wire Packet"
                      />
                    ))}
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="p-8 text-center text-sm text-slate-500">No DoH queries recorded.</div>
        )}
      </div>
    </div>
  );
}
