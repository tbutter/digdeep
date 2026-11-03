import {
  ArrowRight,
  Clock,
  Download,
  GitCompare,
  HardDrive,
  Pin,
  RefreshCw,
  Search,
  Trash2,
  Upload,
} from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import type { AnalysisSnapshot } from '../dns/types';
import { diffSnapshots, getStorageStats } from '../storage/historyStore';
import { StatusBadge } from './StatusBadge';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function HistoryPanel({
  snapshots,
  activeSnapshotId,
  onSelectSnapshot,
  onReprobe,
  onTogglePin,
  onDelete,
  onClearUnpinned,
  onImportJson,
}: {
  snapshots: AnalysisSnapshot[];
  activeSnapshotId?: string;
  onSelectSnapshot: (snap: AnalysisSnapshot) => void;
  onReprobe: (domain: string, types: string[]) => void;
  onTogglePin: (id: string, pinned: boolean) => void;
  onDelete: (id: string) => void;
  onClearUnpinned: () => void;
  onImportJson: (text: string) => void;
}) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'pinned' | 'secure' | 'bogus' | 'insecure'>('all');
  const [diffAId, setDiffAId] = useState<string>(snapshots[1]?.id ?? snapshots[0]?.id ?? '');
  const [diffBId, setDiffBId] = useState<string>(snapshots[0]?.id ?? '');
  const [showDiff, setShowDiff] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const stats = useMemo(() => getStorageStats(), [snapshots]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return snapshots.filter((s) => {
      if (filter === 'pinned' && !s.pinned) return false;
      if (filter === 'secure' && s.overallStatus !== 'secure' && s.overallStatus !== 'warning') {
        return false;
      }
      if (filter === 'bogus' && s.overallStatus !== 'bogus') return false;
      if (filter === 'insecure' && s.overallStatus !== 'insecure') return false;
      if (!q) return true;
      return (
        s.displayDomain.toLowerCase().includes(q) ||
        s.queryTypes.join(',').toLowerCase().includes(q) ||
        (s.note ?? '').toLowerCase().includes(q)
      );
    });
  }, [snapshots, query, filter]);

  const snapA = snapshots.find((s) => s.id === diffAId);
  const snapB = snapshots.find((s) => s.id === diffBId);
  const diffResult = useMemo(
    () => (showDiff && snapA && snapB && snapA.id !== snapB.id ? diffSnapshots(snapA, snapB) : null),
    [showDiff, snapA, snapB]
  );

  const exportJson = (data: unknown, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      {/* LocalStorage Status & Actions Header */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1.5 flex-1">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
            <HardDrive className="w-4 h-4" />
            Client-Side LocalStorage Archive ({snapshots.length} saved snapshots)
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500">
            <span>
              Storage used: <strong className="font-mono">{formatBytes(stats.usedBytes)}</strong> /{' '}
              ~5.0 MB ({stats.percentUsed}%)
            </span>
            <div className="w-36 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-cyan-500"
                style={{ width: `${Math.max(2, stats.percentUsed)}%` }}
              />
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {snapshots.length >= 2 && (
            <button
              type="button"
              onClick={() => setShowDiff((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer transition-colors ${
                showDiff
                  ? 'bg-cyan-500 text-slate-950 border-cyan-500 font-semibold'
                  : 'border-slate-200 dark:border-slate-700 hover:border-cyan-500 text-slate-700 dark:text-slate-200'
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              Compare Snapshots
            </button>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const reader = new FileReader();
              reader.onload = () => {
                try {
                  setImportError(null);
                  onImportJson(String(reader.result));
                } catch (err) {
                  setImportError(err instanceof Error ? err.message : 'Invalid JSON file');
                }
              };
              reader.readAsText(file);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5" />
            Import JSON
          </button>
          {snapshots.length > 0 && (
            <>
              <button
                type="button"
                onClick={() => exportJson(snapshots, 'digdeep-history.json')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                Export All
              </button>
              <button
                type="button"
                onClick={onClearUnpinned}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-rose-500/30 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear Unpinned
              </button>
            </>
          )}
        </div>
      </div>

      {importError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-600 dark:text-rose-300">
          Import failed: {importError}
        </div>
      )}

      {/* Interactive Snapshot Diff Comparison Panel */}
      {showDiff && snapshots.length >= 2 && (
        <div className="rounded-xl border border-cyan-500/40 bg-white dark:bg-slate-900/90 p-4 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center gap-3">
            <div className="flex-1">
              <label className="block text-[10px] font-semibold uppercase text-slate-500 mb-1">
                Snapshot A
              </label>
              <select
                value={diffAId}
                onChange={(e) => setDiffAId(e.target.value)}
                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs font-mono"
              >
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.displayDomain} [{s.queryTypes.join(',')}] —{' '}
                    {new Date(s.capturedAt).toLocaleString()} ({s.overallStatus.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-[10px] font-semibold uppercase text-slate-500 mb-1">
                Snapshot B
              </label>
              <select
                value={diffBId}
                onChange={(e) => setDiffBId(e.target.value)}
                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs font-mono"
              >
                {snapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.displayDomain} [{s.queryTypes.join(',')}] —{' '}
                    {new Date(s.capturedAt).toLocaleString()} ({s.overallStatus.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {diffAId === diffBId ? (
            <div className="text-xs text-slate-500">
              Select two distinct snapshots above to inspect key rollovers, serial bumps, and
              record changes.
            </div>
          ) : (
            diffResult && (
              <div className="space-y-3 text-xs">
                <div className="flex flex-wrap items-center gap-2 font-mono">
                  <span className="text-slate-500">Comparing older → newer:</span>
                  <StatusBadge status={diffResult.older.overallStatus} size="xs" />
                  <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                  <StatusBadge status={diffResult.newer.overallStatus} size="xs" />
                </div>

                {/* Zone & Key Changes */}
                <div className="space-y-1.5">
                  <div className="font-semibold uppercase text-[11px] text-slate-500">
                    Zone, SOA Serial &amp; Key Rollover Diff
                  </div>
                  {diffResult.zoneChanges.every((z) => z.change === 'unchanged') ? (
                    <div className="text-slate-500">
                      No zone status, SOA serial, DNSKEY, or DS changes detected.
                    </div>
                  ) : (
                    diffResult.zoneChanges
                      .filter((z) => z.change !== 'unchanged')
                      .map((zc) => (
                        <div
                          key={zc.zoneName}
                          className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 font-mono space-y-1"
                        >
                          <div className="font-semibold text-slate-800 dark:text-slate-100">
                            {zc.zoneName} ({zc.change.toUpperCase()})
                          </div>
                          {zc.oldSerial !== zc.newSerial && (
                            <div className="text-slate-500">
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
                          {zc.addedDs.length > 0 && (
                            <div className="text-emerald-600 dark:text-emerald-400">
                              + Added DS: {zc.addedDs.map((k) => `#${k}`).join(', ')}
                            </div>
                          )}
                          {zc.removedDs.length > 0 && (
                            <div className="text-rose-600 dark:text-rose-400">
                              − Removed DS: {zc.removedDs.map((k) => `#${k}`).join(', ')}
                            </div>
                          )}
                        </div>
                      ))
                  )}
                </div>

                {/* Record Changes */}
                {diffResult.recordChanges.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="font-semibold uppercase text-[11px] text-slate-500">
                      RRset &amp; Signer Changes ({diffResult.recordChanges.length})
                    </div>
                    {diffResult.recordChanges.map((rc) => (
                      <div
                        key={`${rc.name}-${rc.typeName}`}
                        className="rounded-lg border border-slate-200 dark:border-slate-800 p-2.5 font-mono space-y-1"
                      >
                        <div className="font-semibold">
                          {rc.name} {rc.typeName}
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
                        {rc.oldSignerTags.join(',') !== rc.newSignerTags.join(',') && (
                          <div className="text-cyan-600 dark:text-cyan-400">
                            RRSIG Signers: #{rc.oldSignerTags.join(', #') || 'none'} → #
                            {rc.newSignerTags.join(', #') || 'none'}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          )}
        </div>
      )}

      {/* Search & Filter Row */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter historic snapshots in localStorage by domain or RR type…"
            className="w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 pl-9 pr-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(['all', 'pinned', 'secure', 'bogus', 'insecure'] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize cursor-pointer ${
                filter === f
                  ? 'bg-cyan-500 text-slate-950 font-semibold'
                  : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Snapshot List */}
      {filtered.length === 0 ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 p-10 text-center space-y-2">
          <Clock className="w-8 h-8 text-slate-400 mx-auto" />
          <div className="font-semibold text-sm text-slate-800 dark:text-slate-200">
            No matching snapshots in localStorage
          </div>
          <p className="text-xs text-slate-500">
            Every domain analysis you run is automatically saved right in your browser for instant
            offline inspection and comparison.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filtered.map((snap) => {
            const isCurrent = snap.id === activeSnapshotId;
            return (
              <div
                key={snap.id}
                className={`rounded-xl border p-4 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  isCurrent
                    ? 'border-cyan-500 bg-cyan-500/5'
                    : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onSelectSnapshot(snap)}
                      className="font-mono font-bold text-sm text-slate-900 dark:text-slate-100 hover:text-cyan-500 cursor-pointer"
                    >
                      {snap.displayDomain}
                    </button>
                    <StatusBadge status={snap.overallStatus} size="xs" />
                    <div className="flex gap-1">
                      {snap.queryTypes.map((qt) => (
                        <span
                          key={qt}
                          className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300"
                        >
                          {qt}
                        </span>
                      ))}
                    </div>
                    {isCurrent && (
                      <span className="rounded bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 px-1.5 py-0.5 text-[10px] font-semibold">
                        Viewing
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500 truncate">{snap.overallSummary}</p>
                  <div className="text-[11px] font-mono text-slate-400">
                    Captured {new Date(snap.capturedAt).toLocaleString()} · {snap.zones.length}{' '}
                    zones · {snap.queries.length} DoH queries · {snap.durationMs}ms
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => onSelectSnapshot(snap)}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 hover:bg-cyan-500/25 cursor-pointer"
                  >
                    Open
                  </button>
                  <button
                    type="button"
                    onClick={() => onReprobe(snap.displayDomain, snap.queryTypes)}
                    className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 cursor-pointer"
                    title="Re-probe live via 1.1.1.1 DoH"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onTogglePin(snap.id, !snap.pinned)}
                    className={`p-1.5 rounded-lg border cursor-pointer ${
                      snap.pinned
                        ? 'border-amber-500/40 bg-amber-500/15 text-amber-500'
                        : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400'
                    }`}
                    title={snap.pinned ? 'Unpin snapshot' : 'Pin snapshot to prevent eviction'}
                  >
                    <Pin className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      exportJson(
                        snap,
                        `digdeep-${snap.displayDomain.replace(/[^a-z0-9.-]/gi, '_')}-${snap.capturedAt}.json`
                      )
                    }
                    className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 cursor-pointer"
                    title="Export snapshot JSON"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onDelete(snap.id)}
                    className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-rose-500/10 hover:text-rose-500 text-slate-400 cursor-pointer"
                    title="Delete from localStorage"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
