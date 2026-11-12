import {
  Check,
  CheckCircle2,
  Copy,
  Download,
  FileCode2,
  FileText,
  GitBranch,
  Terminal,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { downloadTextFile } from '../dns/digFormat';
import {
  buildReportFilename,
  extractSnapshotCiInvariants,
  formatSnapshotMarkdownReport,
  generateSnapshotCiScript,
  generateSnapshotGitHubWorkflow,
  type WireTranscriptMode,
} from '../dns/reportExport';
import type { AnalysisSnapshot } from '../dns/types';
import { StatusBadge } from './StatusBadge';

export type ReportExportTab = 'markdown' | 'shell' | 'workflow';

const CRON_PRESETS: ReadonlyArray<{ label: string; value: string }> = [
  { label: 'Every 6 hours', value: '17 */6 * * *' },
  { label: 'Hourly', value: '17 * * * *' },
  { label: 'Daily (03:17 UTC)', value: '17 3 * * *' },
];

const RRSIG_HOUR_PRESETS = [6, 12, 24, 72, 168] as const;

export async function copyTextToClipboard(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through to legacy textarea copy
    }
  }
  if (typeof document === 'undefined') return false;
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', 'true');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return true;
  } catch {
    return false;
  }
}

export function ReportExportModal({
  open,
  snapshot,
  initialTab = 'markdown',
  focusedGraphTarget,
  onClose,
}: {
  open: boolean;
  snapshot: AnalysisSnapshot | null;
  initialTab?: ReportExportTab;
  focusedGraphTarget?: string | null;
  onClose: () => void;
}) {
  const [activeTab, setActiveTab] = useState<ReportExportTab>(initialTab);
  const [wireMode, setWireMode] = useState<WireTranscriptMode>('key');
  const [includeInfoFindings, setIncludeInfoFindings] = useState(true);
  const [rrsigHoursOverride, setRrsigHoursOverride] = useState<{
    snapshotId: string;
    hours: number;
  } | null>(null);
  const [cronSchedule, setCronSchedule] = useState<string>('17 */6 * * *');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (open) {
      setActiveTab(initialTab);
    }
  }, [open, initialTab]);

  useEffect(() => {
    if (!open || typeof window === 'undefined') return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  const baseInvariants = useMemo(
    () => (snapshot ? extractSnapshotCiInvariants(snapshot) : null),
    [snapshot]
  );

  const effectiveMinRrsigHours =
    snapshot && rrsigHoursOverride?.snapshotId === snapshot.id
      ? rrsigHoursOverride.hours
      : (baseInvariants?.recommendedMinRrsigHours ?? 24);

  const activeInvariants = useMemo(
    () =>
      snapshot
        ? extractSnapshotCiInvariants(snapshot, {
            minRrsigHours: effectiveMinRrsigHours,
            cronSchedule,
          })
        : null,
    [snapshot, effectiveMinRrsigHours, cronSchedule]
  );

  const activeContent = useMemo(() => {
    if (!snapshot) return '';
    if (activeTab === 'markdown') {
      return formatSnapshotMarkdownReport(snapshot, {
        focus: focusedGraphTarget,
        wireTranscriptMode: wireMode,
        includeInfoFindings,
      });
    }
    if (activeTab === 'shell') {
      return generateSnapshotCiScript(snapshot, {
        minRrsigHours: effectiveMinRrsigHours,
      });
    }
    return generateSnapshotGitHubWorkflow(snapshot, {
      minRrsigHours: effectiveMinRrsigHours,
      cronSchedule,
    });
  }, [
    snapshot,
    activeTab,
    focusedGraphTarget,
    wireMode,
    includeInfoFindings,
    effectiveMinRrsigHours,
    cronSchedule,
  ]);

  if (!open || !snapshot || !activeInvariants) return null;

  const filename = buildReportFilename(snapshot, activeTab);
  const mimeType =
    activeTab === 'markdown'
      ? 'text/markdown;charset=utf-8'
      : activeTab === 'shell'
        ? 'text/x-shellscript;charset=utf-8'
        : 'text/yaml;charset=utf-8';

  const handleCopy = async () => {
    const ok = await copyTextToClipboard(activeContent);
    if (!ok) return;
    setCopiedKey(activeTab);
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    copyTimerRef.current = setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownload = () => {
    downloadTextFile(activeContent, filename, mimeType);
  };

  const isCopied = copiedKey === activeTab;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Incident Report & CI Regression Check Generator"
      data-testid="report-export-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="safe-area-x fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-slate-950/70 backdrop-blur-sm p-0 sm:p-6"
    >
      <div className="safe-area-bottom w-full max-w-4xl max-h-[92dvh] flex flex-col rounded-t-2xl sm:rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden">
        <div className="sm:hidden flex justify-center pt-2.5 pb-0.5 shrink-0" aria-hidden="true">
          <div className="w-10 h-1 rounded-full bg-slate-300 dark:bg-slate-700" />
        </div>
        {/* Header */}
        <div className="flex items-start sm:items-center justify-between gap-3 px-4 sm:px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <FileCode2 className="w-4 h-4 text-cyan-500 shrink-0" />
              <h2 className="font-semibold text-sm sm:text-base text-slate-900 dark:text-slate-100">
                Incident Report &amp; CI Regression Check
              </h2>
              <StatusBadge status={snapshot.overallStatus} size="xs" />
              <code className="font-mono text-xs text-cyan-700 dark:text-cyan-300 break-all">
                {snapshot.queriedEmail ?? snapshot.queriedIp ?? snapshot.displayDomain}
              </code>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              1-click GitHub/postmortem Markdown report and zero-dependency{' '}
              <code className="font-mono">dig</code>/<code className="font-mono">delv</code> CI
              invariants tailored to this snapshot.
            </p>
          </div>
          <button
            type="button"
            aria-label="Close export modal"
            data-testid="report-modal-close-btn"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Format Tabs */}
        <div className="px-4 sm:px-5 pt-3 pb-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 space-y-3">
          <div
            role="tablist"
            aria-label="Export artifact format"
            className="flex flex-wrap items-center gap-1.5"
          >
            {(
              [
                {
                  id: 'markdown' as const,
                  label: 'Incident Report (.md)',
                  shortLabel: 'Markdown',
                  icon: FileText,
                },
                {
                  id: 'shell' as const,
                  label: 'CI Shell Script (.sh)',
                  shortLabel: 'POSIX .sh',
                  icon: Terminal,
                },
                {
                  id: 'workflow' as const,
                  label: 'GitHub Actions (.yml)',
                  shortLabel: 'Actions .yml',
                  icon: GitBranch,
                },
              ] as const
            ).map((t) => {
              const Icon = t.icon;
              const active = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  data-testid={`report-modal-tab-${t.id}`}
                  onClick={() => setActiveTab(t.id)}
                  className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer ${
                    active
                      ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                      : 'border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-cyan-500/60'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                  <span className="sm:hidden">{t.shortLabel}</span>
                  <span className="hidden sm:inline">{t.label}</span>
                </button>
              );
            })}
          </div>

          {/* Contextual Controls */}
          {activeTab === 'markdown' ? (
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                  DoH wire transcripts:
                </span>
                <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-0.5">
                  {(
                    [
                      ['key', `Key (≤8)`],
                      ['all', `All (${snapshot.queries.length})`],
                      ['none', 'None'],
                    ] as const
                  ).map(([val, lbl]) => (
                    <button
                      key={val}
                      type="button"
                      data-testid={`report-wire-mode-${val}`}
                      onClick={() => setWireMode(val)}
                      className={`px-2 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                        wireMode === val
                          ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-200 font-semibold'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                      }`}
                    >
                      {lbl}
                    </button>
                  ))}
                </div>
              </div>

              <label className="inline-flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeInfoFindings}
                  onChange={(e) => setIncludeInfoFindings(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-700 text-cyan-500 focus:ring-cyan-500"
                />
                <span>Include informational RFC notices</span>
              </label>
            </div>
          ) : (
            <div className="space-y-2.5">
              {/* Detected Security Invariant Badges */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                  Asserted invariants:
                </span>
                {activeInvariants.badges.map((b) => (
                  <span
                    key={b.id}
                    title={b.detail}
                    className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-medium text-emerald-700 dark:text-emerald-300"
                  >
                    <CheckCircle2 className="w-3 h-3 shrink-0" />
                    <span>{b.label}</span>
                  </span>
                ))}
              </div>

              {/* Threshold & Cron Controls */}
              <div className="flex flex-wrap items-center gap-3 text-xs">
                {activeInvariants.expectDnssecAd && activeInvariants.signedZone && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <label
                      htmlFor="report-min-rrsig-hours"
                      className="text-[11px] font-medium text-slate-600 dark:text-slate-300"
                    >
                      Min RRSIG lifetime (h):
                    </label>
                    <input
                      id="report-min-rrsig-hours"
                      data-testid="report-min-rrsig-input"
                      type="number"
                      inputMode="numeric"
                      min={1}
                      max={720}
                      value={effectiveMinRrsigHours}
                      onChange={(e) => {
                        const parsed = Number.parseInt(e.target.value, 10);
                        if (!Number.isNaN(parsed) && parsed >= 1) {
                          setRrsigHoursOverride({
                            snapshotId: snapshot.id,
                            hours: Math.min(720, parsed),
                          });
                        }
                      }}
                      className="w-16 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 font-mono text-base sm:text-xs text-slate-900 dark:text-slate-100"
                    />
                    <div className="inline-flex items-center gap-1">
                      {RRSIG_HOUR_PRESETS.map((hrs) => (
                        <button
                          key={hrs}
                          type="button"
                          onClick={() =>
                            setRrsigHoursOverride({ snapshotId: snapshot.id, hours: hrs })
                          }
                          className={`rounded px-1.5 py-0.5 font-mono text-[10px] cursor-pointer ${
                            effectiveMinRrsigHours === hrs
                              ? 'bg-cyan-500 text-slate-950 font-semibold'
                              : 'bg-slate-200/70 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-300/70 dark:hover:bg-slate-700'
                          }`}
                        >
                          {hrs}h
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === 'workflow' && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <label
                      htmlFor="report-cron-select"
                      className="text-[11px] font-medium text-slate-600 dark:text-slate-300"
                    >
                      Schedule:
                    </label>
                    <select
                      id="report-cron-select"
                      data-testid="report-cron-select"
                      value={cronSchedule}
                      onChange={(e) => setCronSchedule(e.target.value)}
                      className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-base sm:text-xs text-slate-900 dark:text-slate-100"
                    >
                      {CRON_PRESETS.map((p) => (
                        <option key={p.value} value={p.value}>
                          {p.label} ({p.value})
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Action Toolbar + Target Path */}
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 sm:px-5 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center gap-2 min-w-0 text-xs">
            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate">
              {activeTab === 'workflow' ? `.github/workflows/${filename}` : filename}
            </span>
            <span className="text-[10px] font-mono text-slate-400 shrink-0">
              ({activeContent.split('\n').length} lines)
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              data-testid="report-modal-copy-btn"
              onClick={() => void handleCopy()}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer ${
                isCopied
                  ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'border-cyan-500/50 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-800 dark:text-cyan-200'
              }`}
            >
              {isCopied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>
                    {activeTab === 'markdown'
                      ? 'Copy Markdown'
                      : activeTab === 'shell'
                        ? 'Copy Script'
                        : 'Copy Workflow YAML'}
                  </span>
                </>
              )}
            </button>

            <button
              type="button"
              data-testid="report-modal-download-btn"
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>
          </div>
        </div>

        {/* Code Preview */}
        <div className="flex-1 min-h-0 overflow-auto bg-slate-950 p-4">
          <pre
            data-testid="report-modal-preview"
            className="font-mono text-[11px] leading-relaxed text-slate-200 whitespace-pre overflow-x-auto"
          >
            {activeContent}
          </pre>
        </div>
      </div>
    </div>
  );
}
