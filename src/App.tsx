import {
  Activity,
  AlertTriangle,
  Clock,
  Globe,
  Moon,
  Network,
  Play,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Terminal,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AuditPanel } from './components/AuditPanel';
import { ChainGraphView } from './components/ChainGraphView';
import { DohChooser } from './components/DohChooser';
import { HistoryPanel } from './components/HistoryPanel';
import { ResponsesPanel } from './components/ResponsesPanel';
import { SettingsModal } from './components/SettingsModal';
import { StatusBadge } from './components/StatusBadge';
import { ZonesPanel } from './components/ZonesPanel';
import { reverifySnapshot, runDnsvizAnalysis } from './dns/analyzer';
import { formatDohShortLabel, PRESET_DOMAINS, QUERYABLE_RR_TYPES } from './dns/constants';
import type { AnalysisProgress, AnalysisSnapshot } from './dns/types';
import {
  clearUnpinnedSnapshots,
  deleteSnapshot,
  importSnapshotsFromJson,
  loadSnapshots,
  loadTheme,
  loadUserSettings,
  saveSnapshot,
  saveTheme,
  saveUserSettings,
  updateSnapshotMeta,
  type UserSettings,
} from './storage/historyStore';

type ActiveTab = 'graph' | 'audit' | 'responses' | 'zones' | 'history';

const PRIMARY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'HTTPS', 'DNSKEY'];
const EXTRA_TYPES = QUERYABLE_RR_TYPES.filter((t) => !PRIMARY_TYPES.includes(t));

export function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => loadTheme());
  const [settings, setSettings] = useState<UserSettings>(() => loadUserSettings());
  const [snapshots, setSnapshots] = useState<AnalysisSnapshot[]>(() => loadSnapshots());
  const [activeSnapshot, setActiveSnapshot] = useState<AnalysisSnapshot | null>(
    () => loadSnapshots()[0] ?? null
  );

  const [domainInput, setDomainInput] = useState<string>(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get('name') ?? loadSnapshots()[0]?.displayDomain ?? 'cloudflare.com';
  });
  const [selectedTypes, setSelectedTypes] = useState<string[]>(() => {
    const params = new URLSearchParams(window.location.search);
    const tParam = params.get('types');
    if (tParam) {
      const parsed = tParam
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean);
      if (parsed.length > 0) return parsed;
    }
    return loadSnapshots()[0]?.queryTypes ?? ['A', 'AAAA'];
  });
  const [showExtraTypes, setShowExtraTypes] = useState(false);

  const [activeTab, setActiveTab] = useState<ActiveTab>('graph');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [focusedGraphTarget, setFocusedGraphTarget] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement | null>(null);
  const didBootRef = useRef(false);

  // Sync dark/light class on <html>
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    saveTheme(theme);
  }, [theme]);

  // Press '/' anywhere outside inputs to focus domain search bar
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === '/' &&
        document.activeElement?.tagName !== 'INPUT' &&
        document.activeElement?.tagName !== 'TEXTAREA' &&
        document.activeElement?.tagName !== 'SELECT'
      ) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const executeAnalysis = useCallback(
    async (targetDomain: string, typesToQuery: string[]) => {
      const cleanDomain = targetDomain.trim() || '.';
      const cleanTypes = typesToQuery.length > 0 ? typesToQuery : ['A'];

      setLoading(true);
      setError(null);
      setProgress({
        phase: 'zone-cuts',
        message: `Starting ${formatDohShortLabel(settings.dohEndpoint)} DoH trace for ${cleanDomain}…`,
        completedQueries: 0,
      });

      try {
        const snap = await runDnsvizAnalysis(cleanDomain, {
          endpoint: settings.dohEndpoint,
          queryTypes: cleanTypes,
          trustAnchors: settings.trustAnchors,
          onProgress: (p) => setProgress(p),
        });

        const updatedList = saveSnapshot(snap);
        setSnapshots(updatedList);
        setActiveSnapshot(snap);

        const url = new URL(window.location.href);
        url.searchParams.set('name', snap.displayDomain);
        url.searchParams.set('types', snap.queryTypes.join(','));
        window.history.replaceState({}, '', url.toString());

        if (activeTab === 'history') {
          setActiveTab('graph');
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : `Failed to query ${formatDohShortLabel(settings.dohEndpoint)} DoH. Check network connectivity.`
        );
      } finally {
        setLoading(false);
        setProgress(null);
      }
    },
    [settings.dohEndpoint, settings.trustAnchors, activeTab]
  );

  // Auto-run on initial visit if URL specifies ?name= or if localStorage has no snapshots yet
  useEffect(() => {
    if (didBootRef.current) return;
    didBootRef.current = true;
    const params = new URLSearchParams(window.location.search);
    if (params.has('name') || snapshots.length === 0) {
      void executeAnalysis(domainInput, selectedTypes);
    }
  }, [domainInput, executeAnalysis, selectedTypes, snapshots.length]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void executeAnalysis(domainInput, selectedTypes);
  };

  const toggleQueryType = (t: string) => {
    setSelectedTypes((prev) => {
      if (prev.includes(t)) {
        return prev.length > 1 ? prev.filter((x) => x !== t) : prev;
      }
      return [...prev, t];
    });
  };

  const handleUpdateSettings = async (next: UserSettings) => {
    setSettings(next);
    saveUserSettings(next);
    if (activeSnapshot && next.trustAnchors !== settings.trustAnchors) {
      const reverified = await reverifySnapshot(activeSnapshot, {
        trustAnchors: next.trustAnchors,
      });
      setActiveSnapshot(reverified);
      setSnapshots(saveSnapshot(reverified));
    }
  };

  const handleReverifyAtTime = async (timestampMs: number) => {
    if (!activeSnapshot) return;
    const reverified = await reverifySnapshot(activeSnapshot, {
      validationTimeMs: timestampMs,
      trustAnchors: settings.trustAnchors,
    });
    setActiveSnapshot(reverified);
    setSettingsOpen(false);
  };

  const issueCount = activeSnapshot
    ? activeSnapshot.findings.filter((f) => f.severity === 'error' || f.severity === 'warning')
        .length
    : 0;

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* Top Header Bar */}
      <header className="border-b border-slate-200 dark:border-slate-800/90 bg-white/90 dark:bg-slate-950/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-500 flex items-center justify-center shadow-sm shadow-cyan-500/20">
              <Network className="w-5 h-5 text-slate-950 stroke-[2.3]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight">DigDeep</span>
                <span className="rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                  {formatDohShortLabel(settings.dohEndpoint)} DoH
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:block">
                Client-Side DNSSEC Chain-of-Trust Visualizer &amp; Wire Inspector
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab('history')}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
              title="Browse snapshots stored in browser localStorage"
            >
              <Clock className="w-3.5 h-3.5 text-cyan-500" />
              <span>History</span>
              <span className="rounded-full bg-slate-200 dark:bg-slate-800 px-1.5 py-0.2 font-mono text-[10px]">
                {snapshots.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
              title="Trust Anchors, Time-Travel Validation & DoH Endpoint"
            >
              <Settings className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
              <span className="hidden md:inline">Trust Anchors &amp; Clock</span>
            </button>

            <button
              type="button"
              onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
              className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-cyan-500 transition-colors cursor-pointer"
              aria-label="Toggle color theme"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Domain Query & RR Type Bar */}
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 pb-3.5 space-y-2.5">
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                ref={inputRef}
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="Enter domain name (e.g. cloudflare.com, dnssec-failed.org, www.iana.org, .) — press / to focus"
                className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 pl-10 pr-10 py-2.5 font-mono text-sm text-slate-900 dark:text-slate-100 placeholder:font-sans placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
              />
              <kbd className="hidden sm:inline-block absolute right-3 top-1/2 -translate-y-1/2 rounded border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                /
              </kbd>
            </div>

            <DohChooser
              settings={settings}
              onSaveSettings={(next) => void handleUpdateSettings(next)}
            />

            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-60 px-5 py-2.5 font-semibold text-sm text-slate-950 shadow-sm shadow-cyan-500/20 transition-all cursor-pointer shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Tracing ({progress?.completedQueries ?? 0} queries)…</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Analyze DNSSEC</span>
                </>
              )}
            </button>
          </form>

          {/* RR Type Selector + Preset Scenarios */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-[11px] font-medium text-slate-500 mr-1">RR Types:</span>
              {PRIMARY_TYPES.map((t) => {
                const active = selectedTypes.includes(t);
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => toggleQueryType(t)}
                    className={`px-2 py-0.5 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                      active
                        ? 'bg-cyan-500 text-slate-950 font-bold'
                        : 'bg-slate-200/70 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:bg-slate-300/70 dark:hover:bg-slate-800'
                    }`}
                  >
                    {t}
                  </button>
                );
              })}
              {showExtraTypes &&
                EXTRA_TYPES.map((t) => {
                  const active = selectedTypes.includes(t);
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() => toggleQueryType(t)}
                      className={`px-2 py-0.5 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                        active
                          ? 'bg-cyan-500 text-slate-950 font-bold'
                          : 'bg-slate-200/70 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:bg-slate-300/70 dark:hover:bg-slate-800'
                      }`}
                    >
                      {t}
                    </button>
                  );
                })}
              <button
                type="button"
                onClick={() => setShowExtraTypes((v) => !v)}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] text-slate-500 hover:text-cyan-500 cursor-pointer"
              >
                <SlidersHorizontal className="w-3 h-3" />
                {showExtraTypes ? 'Less' : 'More'}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-slate-500">Presets:</span>
              {PRESET_DOMAINS.map((preset) => {
                const dotColor =
                  preset.badge === 'secure'
                    ? 'bg-emerald-500'
                    : preset.badge === 'bogus'
                      ? 'bg-rose-500'
                      : preset.badge === 'cname'
                        ? 'bg-violet-500'
                        : 'bg-slate-400';
                return (
                  <button
                    key={preset.domain}
                    type="button"
                    title={preset.description}
                    onClick={() => {
                      setDomainInput(preset.domain);
                      setSelectedTypes(preset.types);
                      void executeAnalysis(preset.domain, preset.types);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 hover:border-cyan-500 px-2.5 py-0.5 font-mono text-[11px] text-slate-700 dark:text-slate-300 transition-colors cursor-pointer"
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
                    {preset.label}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </header>

      {/* Live Progress / Error Banner */}
      <main className="max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-4 flex-1 space-y-4">
        {loading && progress && (
          <div className="rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-4 py-3 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <Activity className="w-4 h-4 text-cyan-500 animate-pulse shrink-0" />
              <span className="font-medium text-slate-800 dark:text-slate-100">
                {progress.message}
              </span>
            </div>
            <span className="font-mono text-cyan-700 dark:text-cyan-300 shrink-0">
              {progress.completedQueries} DoH wire packets
            </span>
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-xs text-rose-700 dark:text-rose-300 flex items-center justify-between">
            <span>{error}</span>
            <button
              type="button"
              onClick={() => void executeAnalysis(domainInput, selectedTypes)}
              className="underline font-semibold cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {activeSnapshot && (
          <>
            {/* Snapshot Summary Banner + Segmented View Tabs */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-3.5 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3 min-w-0">
                <StatusBadge status={activeSnapshot.overallStatus} size="md" />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-bold text-base text-slate-900 dark:text-slate-100">
                      {activeSnapshot.displayDomain}
                    </span>
                    <span className="font-mono text-xs text-slate-500">
                      [{activeSnapshot.queryTypes.join(', ')}]
                    </span>
                    {activeSnapshot.resolverVerdict && (
                      <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                        {formatDohShortLabel(activeSnapshot.dohEndpoint)}:{' '}
                        {activeSnapshot.resolverVerdict.rcodeName} · AD=
                        {activeSnapshot.resolverVerdict.adBit ? '1' : '0'}
                      </span>
                    )}
                    {activeSnapshot.validatedAt !== activeSnapshot.capturedAt && (
                      <span className="rounded bg-amber-500/15 text-amber-600 dark:text-amber-300 px-2 py-0.5 font-mono text-[11px]">
                        Clock Override: {new Date(activeSnapshot.validatedAt).toISOString().slice(0, 16)}Z
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 truncate mt-0.5">
                    {activeSnapshot.overallSummary}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 justify-between xl:justify-end">
                <div className="text-[11px] font-mono text-slate-400 pr-2">
                  { new Date(activeSnapshot.capturedAt).toLocaleString() } ·{' '}
                  {activeSnapshot.queries.length} queries ({activeSnapshot.durationMs}ms)
                </div>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() =>
                    void executeAnalysis(activeSnapshot.displayDomain, activeSnapshot.queryTypes)
                  }
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                  title="Run a fresh live 1.1.1.1 DoH trace and save a new snapshot"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Re-probe
                </button>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-200 dark:border-slate-800 pb-2">
              {(
                [
                  { id: 'graph', label: 'DNSSEC Chain Graph', icon: Network },
                  {
                    id: 'audit',
                    label: 'Audit & RFC Checks',
                    icon: issueCount > 0 ? AlertTriangle : ShieldCheck,
                    badge: issueCount,
                  },
                  {
                    id: 'responses',
                    label: 'DoH Wire Responses',
                    icon: Terminal,
                    badge: activeSnapshot.queries.length,
                  },
                  {
                    id: 'zones',
                    label: 'Zones & Nameservers',
                    icon: Globe,
                    badge: activeSnapshot.zones.length,
                  },
                  {
                    id: 'history',
                    label: 'Local History & Diff',
                    icon: Clock,
                    badge: snapshots.length,
                  },
                ] as const
              ).map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                      active
                        ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-200/70 dark:hover:bg-slate-900'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                    {'badge' in tab && tab.badge !== undefined && (
                      <span
                        className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] ${
                          active
                            ? 'bg-slate-950/20 text-slate-950'
                            : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Active View Content */}
            {activeTab === 'graph' && (
              <ChainGraphView
                snapshot={activeSnapshot}
                theme={theme}
                filters={{
                  showSoaAndNs: settings.showSoaAndNs,
                  showStandbyKeys: settings.showStandbyKeys,
                }}
                onChangeFilters={(f) =>
                  void handleUpdateSettings({
                    ...settings,
                    showSoaAndNs: f.showSoaAndNs,
                    showStandbyKeys: f.showStandbyKeys,
                  })
                }
                focusedTargetId={focusedGraphTarget}
              />
            )}

            {activeTab === 'audit' && (
              <AuditPanel
                snapshot={activeSnapshot}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
              />
            )}

            {activeTab === 'responses' && <ResponsesPanel snapshot={activeSnapshot} />}

            {activeTab === 'zones' && <ZonesPanel snapshot={activeSnapshot} />}

            {activeTab === 'history' && (
              <HistoryPanel
                snapshots={snapshots}
                activeSnapshotId={activeSnapshot.id}
                onSelectSnapshot={(snap) => {
                  setActiveSnapshot(snap);
                  setDomainInput(snap.displayDomain);
                  setSelectedTypes(snap.queryTypes);
                  setActiveTab('graph');
                }}
                onReprobe={(dom, types) => {
                  setDomainInput(dom);
                  setSelectedTypes(types);
                  void executeAnalysis(dom, types);
                }}
                onTogglePin={(id, pinned) => {
                  const next = updateSnapshotMeta(id, { pinned });
                  setSnapshots(next);
                  if (activeSnapshot.id === id) {
                    setActiveSnapshot({ ...activeSnapshot, pinned });
                  }
                }}
                onDelete={(id) => {
                  const next = deleteSnapshot(id);
                  setSnapshots(next);
                  if (activeSnapshot.id === id) {
                    setActiveSnapshot(next[0] ?? null);
                  }
                }}
                onClearUnpinned={() => {
                  const next = clearUnpinnedSnapshots();
                  setSnapshots(next);
                  if (!next.some((s) => s.id === activeSnapshot.id)) {
                    setActiveSnapshot(next[0] ?? null);
                  }
                }}
                onImportJson={(txt) => {
                  const next = importSnapshotsFromJson(txt);
                  setSnapshots(next);
                  if (next[0]) setActiveSnapshot(next[0]);
                }}
              />
            )}
          </>
        )}

        {!activeSnapshot && !loading && (
          <HistoryPanel
            snapshots={snapshots}
            onSelectSnapshot={(snap) => {
              setActiveSnapshot(snap);
              setActiveTab('graph');
            }}
            onReprobe={(dom, types) => {
              setDomainInput(dom);
              setSelectedTypes(types);
              void executeAnalysis(dom, types);
            }}
            onTogglePin={(id, pinned) => setSnapshots(updateSnapshotMeta(id, { pinned }))}
            onDelete={(id) => setSnapshots(deleteSnapshot(id))}
            onClearUnpinned={() => setSnapshots(clearUnpinnedSnapshots())}
            onImportJson={(txt) => {
              const next = importSnapshotsFromJson(txt);
              setSnapshots(next);
              if (next[0]) setActiveSnapshot(next[0]);
            }}
          />
        )}
      </main>

      <SettingsModal
        open={settingsOpen}
        settings={settings}
        activeSnapshot={activeSnapshot}
        onClose={() => setSettingsOpen(false)}
        onSaveSettings={(next) => void handleUpdateSettings(next)}
        onReverifyAtTime={(ts) => void handleReverifyAtTime(ts)}
      />
    </div>
  );
}
