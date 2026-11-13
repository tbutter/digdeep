import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Check,
  CheckCircle2,
  Clock,
  Download,
  FileSpreadsheet,
  FileText,
  Filter,
  FolderUp,
  Globe,
  Layers,
  Mail,
  Network,
  Pause,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  X,
} from 'lucide-react';
import { useMemo, useRef, useState, type ChangeEvent } from 'react';
import { formatDohShortLabel } from '../dns/constants';
import { downloadTextFile } from '../dns/digFormat';
import {
  formatPortfolioCsv,
  formatPortfolioJsonBundle,
  formatPortfolioMarkdown,
  formatRemainingValidityShort,
  MAX_PORTFOLIO_DOMAINS,
  parsePortfolioDomainList,
  SAMPLE_PORTFOLIO_DOMAINS,
  sortPortfolioRows,
  type PortfolioBatchState,
  type PortfolioDomainRow,
  type PortfolioPostureMetrics,
  type PortfolioSortDirection,
  type PortfolioSortField,
} from '../dns/portfolioAnalyzer';
import type { AnalysisSnapshot } from '../dns/types';
import { copyTextToClipboard } from './ReportExportModal';
import { StatusBadge } from './StatusBadge';

export type PortfolioQuickFilter =
  | 'all'
  | 'attention'
  | 'unsigned'
  | 'single-asn'
  | 'weak-dmarc'
  | 'no-caa';

export type PortfolioDrillDownTab = 'graph' | 'audit' | 'mail' | 'web' | 'zones' | 'responses';

export interface PortfolioViewProps {
  domainsText: string;
  onChangeDomainsText: (value: string) => void;
  concurrency: number;
  onChangeConcurrency: (value: number) => void;
  dohEndpoint: string;
  batchState: PortfolioBatchState | null;
  recentHistoryDomains: string[];
  isOffline?: boolean;
  onStartBatch: (domains: string[], sourceLabel?: string) => void;
  onPauseBatch: () => void;
  onResumeBatch: () => void;
  onCancelBatch: () => void;
  onSelectSnapshot: (snapshot: AnalysisSnapshot, targetTab?: PortfolioDrillDownTab) => void;
}

const DEFAULT_SORT_DIRECTION: Record<PortfolioSortField, PortfolioSortDirection> = {
  order: 'asc',
  domain: 'asc',
  risk: 'desc',
  dnssec: 'asc',
  rrsig: 'asc',
  nsAsn: 'desc',
  dmarc: 'asc',
  mail: 'asc',
  web: 'desc',
  issues: 'desc',
};

function renderSpfBadge(p: PortfolioPostureMetrics) {
  if (!p.spfPresent) {
    return (
      <span className="rounded bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25 px-1.5 py-0.5 font-mono text-[10px]">
        No SPF
      </span>
    );
  }
  if (p.spfVerdict === 'strict-fail') {
    return (
      <span
        title={`SPF strict fail (-all) · ${p.spfLookups}/10 DNS lookups`}
        className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
      >
        SPF -all
      </span>
    );
  }
  if (p.spfVerdict === 'soft-fail') {
    return (
      <span
        title={`SPF softfail (~all) · ${p.spfLookups}/10 DNS lookups`}
        className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
      >
        SPF ~all
      </span>
    );
  }
  if (p.spfVerdict === 'permerror' || p.spfVerdict === 'pass-all') {
    return (
      <span
        title={`SPF ${p.spfVerdict} (${p.spfLookups}/10 DNS lookups)`}
        className="rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35 px-1.5 py-0.5 font-mono text-[10px] font-bold"
      >
        {p.spfVerdict === 'pass-all' ? 'SPF +all!' : 'SPF PermErr'}
      </span>
    );
  }
  return (
    <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px]">
      SPF {p.spfQualifier ? `${p.spfQualifier}all` : p.spfVerdict}
    </span>
  );
}

function renderDmarcBadge(p: PortfolioPostureMetrics) {
  switch (p.dmarcPolicy) {
    case 'reject':
      return (
        <span
          title={p.dmarcUsedOrgFallback ? 'Inherited organizational DMARC p=reject' : 'DMARC p=reject'}
          className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
        >
          p=reject{p.dmarcUsedOrgFallback ? '*' : ''}
        </span>
      );
    case 'quarantine':
      return (
        <span
          title={
            p.dmarcUsedOrgFallback
              ? 'Inherited organizational DMARC p=quarantine'
              : 'DMARC p=quarantine'
          }
          className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
        >
          p=quarantine{p.dmarcUsedOrgFallback ? '*' : ''}
        </span>
      );
    case 'none':
      return (
        <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
          p=none
        </span>
      );
    case 'invalid':
      return (
        <span className="rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35 px-1.5 py-0.5 font-mono text-[10px] font-bold">
          DMARC Invalid
        </span>
      );
    case 'missing':
      return (
        <span className="rounded bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/25 px-1.5 py-0.5 font-mono text-[10px]">
          No DMARC
        </span>
      );
  }
}

function renderDaneBadge(p: PortfolioPostureMetrics) {
  if (p.mxStatus === 'null-mx') {
    return (
      <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[10px]">
        Null MX
      </span>
    );
  }
  if (p.mxStatus === 'none') {
    return (
      <span className="rounded bg-slate-500/15 text-slate-500 dark:text-slate-400 border border-slate-500/25 px-1.5 py-0.5 font-mono text-[10px]">
        No MX
      </span>
    );
  }
  switch (p.daneStatus) {
    case 'all-valid':
      return (
        <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
          DANE ✓
        </span>
      );
    case 'partial':
      return (
        <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
          DANE Partial
        </span>
      );
    case 'unsigned-ignored':
      return (
        <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
          TLSA Unsigned
        </span>
      );
    case 'bogus':
      return (
        <span className="rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35 px-1.5 py-0.5 font-mono text-[10px] font-bold">
          DANE BOGUS
        </span>
      );
    case 'not-deployed':
      return (
        <span className="rounded bg-slate-500/15 text-slate-600 dark:text-slate-400 border border-slate-500/25 px-1.5 py-0.5 font-mono text-[10px]">
          {p.mxCount} MX · No DANE
        </span>
      );
  }
}

export function PortfolioView({
  domainsText,
  onChangeDomainsText,
  concurrency,
  onChangeConcurrency,
  dohEndpoint,
  batchState,
  recentHistoryDomains,
  isOffline = false,
  onStartBatch,
  onPauseBatch,
  onResumeBatch,
  onCancelBatch,
  onSelectSnapshot,
}: PortfolioViewProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [sourceLabel, setSourceLabel] = useState<string | undefined>(undefined);
  const [inputCollapsed, setInputCollapsed] = useState(false);

  const [sortField, setSortField] = useState<PortfolioSortField>('order');
  const [sortDirection, setSortDirection] = useState<PortfolioSortDirection>('asc');
  const [quickFilter, setQuickFilter] = useState<PortfolioQuickFilter>('all');
  const [selectedAsnFilter, setSelectedAsnFilter] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);

  const parsedInput = useMemo(
    () => parsePortfolioDomainList(domainsText, MAX_PORTFOLIO_DOMAINS),
    [domainsText]
  );

  const isRunning = batchState?.status === 'running';
  const isPaused = batchState?.status === 'paused';
  const isActiveRun = isRunning || isPaused;

  const asnShareMap = useMemo(() => {
    const map = new Map<number, number>();
    for (const entry of batchState?.asnConcentration ?? []) {
      map.set(entry.asn, entry.sharePercent);
    }
    return map;
  }, [batchState?.asnConcentration]);

  const doneRows = useMemo(
    () => (batchState?.rows ?? []).filter((r) => r.status === 'done' && r.posture),
    [batchState?.rows]
  );

  const summaryStats = useMemo(() => {
    const total = doneRows.length;
    if (total === 0) return null;

    let signedCount = 0;
    let bogusCount = 0;
    let unsignedCount = 0;
    let minRrsigSec: number | null = null;
    let minRrsigDomain: string | null = null;
    let singleAsnSpofCount = 0;
    let daneValidCount = 0;
    let mxActiveCount = 0;
    let dmarcEnforcedCount = 0;
    let spfStrictCount = 0;
    let echCount = 0;
    let httpsCount = 0;
    let caaProtectedCount = 0;

    for (const row of doneRows) {
      const p = row.posture!;
      if (p.dnssecStatus === 'secure' || p.dnssecStatus === 'warning') signedCount++;
      else if (p.dnssecStatus === 'bogus') bogusCount++;
      else if (p.dnssecStatus === 'insecure') unsignedCount++;

      if (p.shortestRrsigRemainingSec !== null) {
        if (minRrsigSec === null || p.shortestRrsigRemainingSec < minRrsigSec) {
          minRrsigSec = p.shortestRrsigRemainingSec;
          minRrsigDomain = p.domain;
        }
      }

      if (p.singleNsAsnSpof) singleAsnSpofCount++;
      if (p.mxStatus === 'valid' || p.mxStatus === 'warning' || p.mxStatus === 'broken') {
        mxActiveCount++;
      }
      if (p.daneStatus === 'all-valid') daneValidCount++;
      if (p.dmarcPolicy === 'reject' || p.dmarcPolicy === 'quarantine') dmarcEnforcedCount++;
      if (p.spfVerdict === 'strict-fail') spfStrictCount++;
      if (p.echEnabled) echCount++;
      if (p.hasHttps) httpsCount++;
      if (p.caaStatus === 'enforced' || p.caaStatus === 'inherited') caaProtectedCount++;
    }

    return {
      total,
      signedCount,
      bogusCount,
      unsignedCount,
      minRrsigSec,
      minRrsigDomain,
      singleAsnSpofCount,
      daneValidCount,
      mxActiveCount,
      dmarcEnforcedCount,
      spfStrictCount,
      echCount,
      httpsCount,
      caaProtectedCount,
    };
  }, [doneRows]);

  const filteredAndSortedRows = useMemo(() => {
    const baseRows = batchState?.rows ?? [];
    const q = searchQuery.trim().toLowerCase();

    const filtered = baseRows.filter((row) => {
      if (q) {
        const hay = [
          row.domain,
          row.posture?.leafZone ?? '',
          row.posture?.dnssecAlgorithmLabel ?? '',
          ...(row.posture?.nsProviders ?? []),
          ...(row.posture?.nsAsns.map((a) => `as${a.asn} ${a.asName ?? ''}`) ?? []),
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }

      if (selectedAsnFilter !== null) {
        if (!row.posture?.nsAsns.some((a) => a.asn === selectedAsnFilter)) {
          return false;
        }
      }

      const p = row.posture;
      switch (quickFilter) {
        case 'all':
          return true;
        case 'attention':
          return (
            row.status === 'error' ||
            Boolean(
              p &&
                (p.errorCount > 0 ||
                  p.dnssecStatus === 'bogus' ||
                  p.rrsigExpiringSoon ||
                  p.dmarcPolicy === 'missing' ||
                  p.dmarcPolicy === 'invalid' ||
                  p.spfVerdict === 'permerror' ||
                  p.spfVerdict === 'pass-all')
            )
          );
        case 'unsigned':
          return Boolean(p && p.dnssecStatus === 'insecure');
        case 'single-asn':
          return Boolean(p && p.singleNsAsnSpof);
        case 'weak-dmarc':
          return Boolean(
            p &&
              (p.dmarcPolicy === 'missing' ||
                p.dmarcPolicy === 'none' ||
                p.dmarcPolicy === 'invalid')
          );
        case 'no-caa':
          return Boolean(p && (p.caaStatus === 'unprotected' || p.caaStatus === 'permissive'));
      }
    });

    return sortPortfolioRows(filtered, sortField, sortDirection, asnShareMap);
  }, [batchState?.rows, searchQuery, selectedAsnFilter, quickFilter, sortField, sortDirection, asnShareMap]);

  const handleToggleSort = (field: PortfolioSortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(DEFAULT_SORT_DIRECTION[field]);
    }
  };

  const handleFileUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      onChangeDomainsText(content);
      setSourceLabel(file.name);
    } finally {
      e.target.value = '';
    }
  };

  const dateStamp = () => new Date().toISOString().slice(0, 10);

  const handleCopyMarkdown = async () => {
    if (!batchState) return;
    const md = formatPortfolioMarkdown(batchState.rows, batchState.asnConcentration, {
      dohEndpoint: batchState.dohEndpoint,
      sourceLabel: batchState.sourceLabel,
    });
    const ok = await copyTextToClipboard(md);
    if (ok) {
      setCopiedMarkdown(true);
      setTimeout(() => setCopiedMarkdown(false), 2000);
    }
  };

  const handleDownloadMarkdown = () => {
    if (!batchState) return;
    const md = formatPortfolioMarkdown(batchState.rows, batchState.asnConcentration, {
      dohEndpoint: batchState.dohEndpoint,
      sourceLabel: batchState.sourceLabel,
    });
    downloadTextFile(md, `digdeep-portfolio-${dateStamp()}.md`, 'text/markdown;charset=utf-8');
  };

  const handleDownloadCsv = () => {
    if (!batchState) return;
    const csv = formatPortfolioCsv(batchState.rows, batchState.asnConcentration);
    downloadTextFile(csv, `digdeep-portfolio-${dateStamp()}.csv`, 'text/csv;charset=utf-8');
  };

  const handleDownloadJsonBundle = () => {
    if (!batchState) return;
    const json = formatPortfolioJsonBundle(batchState.rows, batchState.asnConcentration, {
      dohEndpoint: batchState.dohEndpoint,
      sourceLabel: batchState.sourceLabel,
    });
    downloadTextFile(
      json,
      `digdeep-portfolio-${dateStamp()}.json`,
      'application/json;charset=utf-8'
    );
  };

  const renderSortIcon = (field: PortfolioSortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 opacity-45 shrink-0" />;
    }
    return sortDirection === 'asc' ? (
      <ArrowUp className="w-3 h-3 text-cyan-500 shrink-0" />
    ) : (
      <ArrowDown className="w-3 h-3 text-cyan-500 shrink-0" />
    );
  };

  const progressPct = batchState
    ? Math.round(
        ((batchState.completedDomains + batchState.failedDomains) /
          Math.max(1, batchState.totalDomains)) *
          100
      )
    : 0;

  return (
    <div data-testid="portfolio-view" className="space-y-4">
      {/* Input & Bounded-Concurrency Batch Runner Card */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex flex-wrap items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-500" />
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                Multi-Domain Portfolio Security &amp; Resilience Triage
              </h2>
              <span className="rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[10px] font-semibold">
                Up to {MAX_PORTFOLIO_DOMAINS} domains · Client-Side DoH
              </span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Audit DNSSEC algorithms, RRSIG expiry windows, cross-portfolio authoritative NS BGP
              ASN concentration, SMTP DANE / SPF / DMARC / MTA-STS, and HTTPS / ECH / CAA in one
              sortable matrix.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,text/plain,text/csv"
              data-testid="portfolio-file-input"
              onChange={(e) => void handleFileUpload(e)}
              className="hidden"
            />
            <button
              type="button"
              data-testid="portfolio-upload-btn"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800/70 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <FolderUp className="w-3.5 h-3.5 text-cyan-500" />
              <span>Upload .txt / .csv</span>
            </button>

            <button
              type="button"
              data-testid="portfolio-load-sample-btn"
              onClick={() => {
                onChangeDomainsText(SAMPLE_PORTFOLIO_DOMAINS.join('\n'));
                setSourceLabel('Sample Portfolio');
                setInputCollapsed(false);
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800/70 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-500" />
              <span>Sample ({SAMPLE_PORTFOLIO_DOMAINS.length})</span>
            </button>

            {recentHistoryDomains.length > 0 && (
              <button
                type="button"
                data-testid="portfolio-load-history-btn"
                onClick={() => {
                  onChangeDomainsText(recentHistoryDomains.slice(0, MAX_PORTFOLIO_DOMAINS).join('\n'));
                  setSourceLabel('Recent History');
                  setInputCollapsed(false);
                }}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800/70 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
              >
                <Clock className="w-3.5 h-3.5 text-cyan-500" />
                <span>From History ({Math.min(MAX_PORTFOLIO_DOMAINS, recentHistoryDomains.length)})</span>
              </button>
            )}

            {batchState && batchState.rows.length > 0 && (
              <button
                type="button"
                onClick={() => setInputCollapsed((c) => !c)}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 cursor-pointer"
              >
                {inputCollapsed ? 'Edit Domain List' : 'Hide Input'}
              </button>
            )}
          </div>
        </div>

        {!inputCollapsed && (
          <div className="space-y-2">
            <textarea
              data-testid="portfolio-domains-input"
              rows={5}
              value={domainsText}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="Paste up to 50 domains (one per line, comma-separated, Markdown list, URLs, or CT SANs)…"
              onChange={(e) => {
                onChangeDomainsText(e.target.value);
                setSourceLabel(undefined);
              }}
              className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950/80 px-3.5 py-2.5 font-mono text-base sm:text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500"
            />

            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2 text-slate-600 dark:text-slate-400">
                <span
                  data-testid="portfolio-parsed-count"
                  className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-700 dark:text-slate-200"
                >
                  {parsedInput.domains.length} / {MAX_PORTFOLIO_DOMAINS} domains ready
                </span>
                {sourceLabel && (
                  <span className="font-mono text-[11px] text-cyan-700 dark:text-cyan-300">
                    Source: {sourceLabel}
                  </span>
                )}
                {parsedInput.truncatedCount > 0 && (
                  <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-2 py-0.5 text-[11px] font-medium">
                    Capped at {MAX_PORTFOLIO_DOMAINS} ({parsedInput.truncatedCount} extra omitted)
                  </span>
                )}
                {parsedInput.skippedTokens.length > 0 && (
                  <span className="text-[11px] text-slate-500">
                    ({parsedInput.skippedTokens.length} non-domain token
                    {parsedInput.skippedTokens.length === 1 ? '' : 's'} ignored)
                  </span>
                )}
              </div>

              {domainsText.trim().length > 0 && !isActiveRun && (
                <button
                  type="button"
                  onClick={() => {
                    onChangeDomainsText('');
                    setSourceLabel(undefined);
                  }}
                  className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-rose-500 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                  <span>Clear list</span>
                </button>
              )}
            </div>
          </div>
        )}

        {/* Runner Action Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-slate-200/70 dark:border-slate-800/80">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <label className="inline-flex items-center gap-2 text-slate-600 dark:text-slate-300">
              <span className="font-medium">Concurrency:</span>
              <select
                data-testid="portfolio-concurrency-select"
                value={concurrency}
                disabled={isActiveRun}
                onChange={(e) => onChangeConcurrency(Number(e.target.value))}
                className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 font-mono text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {n} parallel {n === 1 ? 'domain' : 'domains'}
                  </option>
                ))}
              </select>
            </label>

            <span className="text-slate-500 dark:text-slate-400 font-mono text-[11px]">
              Resolver: {formatDohShortLabel(dohEndpoint)} DoH (shared root/TLD/ASN cache)
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {isRunning && (
              <button
                type="button"
                data-testid="portfolio-pause-btn"
                onClick={onPauseBatch}
                className="inline-flex items-center gap-1.5 rounded-xl border border-amber-500/40 bg-amber-500/15 hover:bg-amber-500/25 px-3.5 py-2 text-xs font-semibold text-amber-800 dark:text-amber-200 transition-colors cursor-pointer"
              >
                <Pause className="w-3.5 h-3.5" />
                <span>Pause</span>
              </button>
            )}

            {isPaused && (
              <button
                type="button"
                data-testid="portfolio-resume-btn"
                onClick={onResumeBatch}
                className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 px-3.5 py-2 text-xs font-bold text-slate-950 transition-colors cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Resume</span>
              </button>
            )}

            {isActiveRun && (
              <button
                type="button"
                data-testid="portfolio-cancel-btn"
                onClick={onCancelBatch}
                className="inline-flex items-center gap-1.5 rounded-xl border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 px-3.5 py-2 text-xs font-semibold text-rose-700 dark:text-rose-300 transition-colors cursor-pointer"
              >
                <Square className="w-3.5 h-3.5" />
                <span>Cancel</span>
              </button>
            )}

            <button
              type="button"
              data-testid="portfolio-start-btn"
              disabled={parsedInput.domains.length === 0 || isOffline || isActiveRun}
              onClick={() => onStartBatch(parsedInput.domains, sourceLabel)}
              className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed px-4 py-2 text-xs font-bold text-slate-950 shadow-sm shadow-cyan-500/20 transition-all cursor-pointer"
            >
              {batchState && !isActiveRun ? (
                <RotateCcw className="w-3.5 h-3.5" />
              ) : (
                <Play className="w-3.5 h-3.5 fill-current" />
              )}
              <span>
                {isOffline
                  ? 'Offline'
                  : `Run Portfolio Audit (${parsedInput.domains.length})`}
              </span>
            </button>
          </div>
        </div>

        {/* Live Progress Strip */}
        {batchState && (
          <div
            data-testid="portfolio-progress-strip"
            className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3 space-y-2"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                {batchState.status === 'running' ? (
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                    <Activity className="w-3 h-3 animate-pulse" />
                    RUNNING ({batchState.runningDomains} active)
                  </span>
                ) : batchState.status === 'paused' ? (
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                    PAUSED
                  </span>
                ) : batchState.status === 'canceled' ? (
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                    CANCELED
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                    <CheckCircle2 className="w-3 h-3" />
                    COMPLETED
                  </span>
                )}
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  {batchState.completedDomains} / {batchState.totalDomains} domains audited
                  {batchState.failedDomains > 0 ? ` · ${batchState.failedDomains} failed` : ''}
                </span>
                {batchState.sourceLabel && (
                  <span className="text-slate-500 font-mono text-[11px]">
                    ({batchState.sourceLabel})
                  </span>
                )}
              </div>

              <span className="font-mono text-[11px] text-cyan-700 dark:text-cyan-300">
                {batchState.totalQueries} DoH wire packets · {progressPct}%
              </span>
            </div>

            <div className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  batchState.status === 'canceled'
                    ? 'bg-rose-500'
                    : batchState.status === 'paused'
                      ? 'bg-amber-500'
                      : 'bg-gradient-to-r from-cyan-500 to-emerald-500'
                }`}
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Executive Posture Scorecard & Cross-Portfolio BGP ASN Concentration */}
      {batchState && summaryStats && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-2.5">
            {/* KPI 1: DNSSEC */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                <span>DNSSEC Signed</span>
              </div>
              <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                {summaryStats.signedCount} / {summaryStats.total}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {summaryStats.bogusCount > 0 ? (
                  <span className="text-rose-600 dark:text-rose-400 font-semibold">
                    {summaryStats.bogusCount} BOGUS
                  </span>
                ) : (
                  <span>{summaryStats.unsignedCount} unsigned</span>
                )}
              </div>
            </div>

            {/* KPI 2: Shortest RRSIG */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <Clock className="w-3.5 h-3.5 text-cyan-500" />
                <span>Shortest RRSIG</span>
              </div>
              <div
                className={`font-mono text-lg font-bold ${
                  summaryStats.minRrsigSec !== null && summaryStats.minRrsigSec <= 0
                    ? 'text-rose-600 dark:text-rose-400'
                    : summaryStats.minRrsigSec !== null && summaryStats.minRrsigSec < 72 * 3600
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-slate-900 dark:text-slate-100'
                }`}
              >
                {formatRemainingValidityShort(summaryStats.minRrsigSec)}
              </div>
              <div className="text-[11px] font-mono text-slate-500 truncate">
                {summaryStats.minRrsigDomain ?? 'No signed zones'}
              </div>
            </div>

            {/* KPI 3: NS ASN Resilience */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <Network className="w-3.5 h-3.5 text-cyan-500" />
                <span>1-ASN NS SPOF</span>
              </div>
              <div
                className={`font-mono text-lg font-bold ${
                  summaryStats.singleAsnSpofCount > 0
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-emerald-600 dark:text-emerald-400'
                }`}
              >
                {summaryStats.singleAsnSpofCount} / {summaryStats.total}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {batchState.asnConcentration.length} unique NS BGP ASNs
              </div>
            </div>

            {/* KPI 4: SMTP DANE */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <Mail className="w-3.5 h-3.5 text-cyan-500" />
                <span>SMTP DANE</span>
              </div>
              <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                {summaryStats.daneValidCount} / {summaryStats.mxActiveCount || summaryStats.total}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                _25._tcp TLSA verified
              </div>
            </div>

            {/* KPI 5: DMARC & SPF */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <Shield className="w-3.5 h-3.5 text-cyan-500" />
                <span>DMARC Enforced</span>
              </div>
              <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                {summaryStats.dmarcEnforcedCount} / {summaryStats.total}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {summaryStats.spfStrictCount} strict SPF (-all)
              </div>
            </div>

            {/* KPI 6: Web HTTPS/ECH & CAA */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                <Globe className="w-3.5 h-3.5 text-cyan-500" />
                <span>Web ECH &amp; CAA</span>
              </div>
              <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                {summaryStats.caaProtectedCount} / {summaryStats.total} CAA
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {summaryStats.echCount} ECH · {summaryStats.httpsCount} HTTPS RR
              </div>
            </div>
          </div>

          {/* Cross-Portfolio BGP ASN Concentration Strip */}
          {batchState.asnConcentration.length > 0 && (
            <div
              data-testid="portfolio-asn-concentration"
              className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-3.5 space-y-2"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-800 dark:text-slate-200">
                  <Network className="w-4 h-4 text-cyan-500" />
                  <span>
                    Cross-Portfolio Authoritative NS BGP ASN Concentration (click an ASN to filter)
                  </span>
                </div>
                {selectedAsnFilter !== null && (
                  <button
                    type="button"
                    onClick={() => setSelectedAsnFilter(null)}
                    className="inline-flex items-center gap-1 rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-2 py-0.5 font-mono text-[11px] font-semibold cursor-pointer"
                  >
                    <span>Showing AS{selectedAsnFilter}</span>
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>

              <div className="flex flex-wrap gap-1.5">
                {batchState.asnConcentration.map((entry) => {
                  const selected = selectedAsnFilter === entry.asn;
                  const riskCls =
                    entry.concentrationRisk === 'critical'
                      ? 'border-rose-500/45 bg-rose-500/10 text-rose-800 dark:text-rose-200'
                      : entry.concentrationRisk === 'elevated'
                        ? 'border-amber-500/45 bg-amber-500/10 text-amber-800 dark:text-amber-200'
                        : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 text-slate-700 dark:text-slate-200';
                  return (
                    <button
                      key={entry.asn}
                      type="button"
                      data-testid={`portfolio-asn-pill-${entry.asn}`}
                      onClick={() =>
                        setSelectedAsnFilter((cur) => (cur === entry.asn ? null : entry.asn))
                      }
                      title={`Domains on AS${entry.asn}${entry.asName ? ` (${entry.asName})` : ''}: ${entry.domains.join(', ')}`}
                      className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs transition-all cursor-pointer ${
                        selected
                          ? 'ring-2 ring-cyan-500 border-cyan-500 bg-cyan-500/15 text-cyan-900 dark:text-cyan-100'
                          : `${riskCls} hover:border-cyan-500/60`
                      }`}
                    >
                      <span className="font-mono font-bold">AS{entry.asn}</span>
                      {entry.asName && (
                        <span className="max-w-[140px] truncate opacity-85 text-[11px]">
                          {entry.asName}
                        </span>
                      )}
                      <span className="rounded bg-slate-900/10 dark:bg-white/10 px-1.5 py-0.2 font-mono text-[10px] font-semibold">
                        {entry.domainCount}/{entry.completedPortfolioCount} ({entry.sharePercent}%)
                      </span>
                      {entry.soleSpofDomainCount > 0 && (
                        <span className="font-mono text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                          · {entry.soleSpofDomainCount} 1-ASN
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filter, Quick-Triage & Batch Export Toolbar + Sortable Matrix */}
      {batchState && batchState.rows.length > 0 && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 overflow-hidden">
          <div className="p-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  data-testid="portfolio-filter-search"
                  value={searchQuery}
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter domain, ASN, provider…"
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 pl-8 pr-3 py-1 font-mono text-base sm:text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 w-48 sm:w-56"
                />
              </div>

              {(
                [
                  { id: 'all', label: `All (${batchState.rows.length})` },
                  { id: 'attention', label: 'Needs Attention' },
                  { id: 'unsigned', label: 'Unsigned' },
                  { id: 'single-asn', label: '1-ASN SPOF' },
                  { id: 'weak-dmarc', label: 'Weak DMARC' },
                  { id: 'no-caa', label: 'No CAA' },
                ] as const
              ).map((f) => (
                <button
                  key={f.id}
                  type="button"
                  data-testid={`portfolio-quick-filter-${f.id}`}
                  onClick={() => setQuickFilter(f.id)}
                  className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer ${
                    quickFilter === f.id
                      ? 'bg-cyan-500 text-slate-950 font-semibold'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {f.id === 'all' && <Filter className="w-3 h-3" />}
                  <span>{f.label}</span>
                </button>
              ))}
            </div>

            {/* Structured Batch Report Exports */}
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                data-testid="portfolio-copy-md-btn"
                onClick={() => void handleCopyMarkdown()}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer ${
                  copiedMarkdown
                    ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-200 dark:border-slate-700 hover:border-cyan-500 text-slate-700 dark:text-slate-200'
                }`}
                title="Copy GitHub-Flavored Markdown matrix & ASN concentration report"
              >
                {copiedMarkdown ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                    <span>Copied MD!</span>
                  </>
                ) : (
                  <>
                    <FileText className="w-3.5 h-3.5 text-cyan-500" />
                    <span>Copy MD</span>
                  </>
                )}
              </button>

              <button
                type="button"
                data-testid="portfolio-export-md-btn"
                onClick={handleDownloadMarkdown}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                title="Download GitHub-Flavored Markdown (.md) report"
              >
                <Download className="w-3.5 h-3.5 text-cyan-500" />
                <span>.md</span>
              </button>

              <button
                type="button"
                data-testid="portfolio-export-csv-btn"
                onClick={handleDownloadCsv}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                title="Download RFC 4180 CSV spreadsheet (.csv)"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-500" />
                <span>.csv</span>
              </button>

              <button
                type="button"
                data-testid="portfolio-export-json-btn"
                onClick={handleDownloadJsonBundle}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                title="Download DigDeep JSON Snapshot Bundle (.json — re-importable in Local History)"
              >
                <Download className="w-3.5 h-3.5 text-cyan-500" />
                <span>.json Bundle</span>
              </button>
            </div>
          </div>

          {/* Sortable Posture Matrix Table */}
          <div className="overflow-x-auto">
            <table
              data-testid="portfolio-matrix-table"
              className="w-full text-left border-collapse text-xs"
            >
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-950/60 text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-order"
                      onClick={() => handleToggleSort('order')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>#</span>
                      {renderSortIcon('order')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-domain"
                      onClick={() => handleToggleSort('domain')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Domain</span>
                      {renderSortIcon('domain')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-dnssec"
                      onClick={() => handleToggleSort('dnssec')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>DNSSEC &amp; Alg</span>
                      {renderSortIcon('dnssec')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-rrsig"
                      onClick={() => handleToggleSort('rrsig')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Min RRSIG</span>
                      {renderSortIcon('rrsig')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-nsAsn"
                      onClick={() => handleToggleSort('nsAsn')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Authoritative NS &amp; BGP ASNs</span>
                      {renderSortIcon('nsAsn')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-mail"
                      onClick={() => handleToggleSort('mail')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Mail (MX · DANE · SPF · DMARC · STS)</span>
                      {renderSortIcon('mail')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-web"
                      onClick={() => handleToggleSort('web')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Web (HTTPS/ECH · CAA)</span>
                      {renderSortIcon('web')}
                    </button>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">
                    <button
                      type="button"
                      data-testid="portfolio-sort-risk"
                      onClick={() => handleToggleSort('risk')}
                      className="inline-flex items-center gap-1 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
                    >
                      <span>Triage &amp; Drill-Down</span>
                      {renderSortIcon('risk')}
                    </button>
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-200/80 dark:divide-slate-800/80">
                {filteredAndSortedRows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="py-8 px-4 text-center text-xs text-slate-500 dark:text-slate-400"
                    >
                      No domains match the active filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredAndSortedRows.map((row: PortfolioDomainRow) => {
                    const p = row.posture;
                    const clickable = row.status === 'done' && Boolean(row.snapshot);
                    return (
                      <tr
                        key={row.domain}
                        data-testid={`portfolio-row-${row.domain}`}
                        onClick={() => {
                          if (row.snapshot) {
                            onSelectSnapshot(row.snapshot, 'graph');
                          }
                        }}
                        className={`transition-colors ${
                          clickable
                            ? 'hover:bg-cyan-500/5 cursor-pointer'
                            : 'bg-slate-50/40 dark:bg-slate-950/30'
                        }`}
                      >
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 align-top">
                          {row.index + 1}
                        </td>

                        {/* Domain & Live Query Telemetry */}
                        <td className="py-2.5 px-3 align-top">
                          <div className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100">
                            {row.domain}
                          </div>
                          {p && p.leafZone !== p.domain && (
                            <div className="font-mono text-[10px] text-slate-500">
                              zone: {p.leafZone}
                            </div>
                          )}
                          {row.status === 'running' && (
                            <div className="flex items-center gap-1.5 text-[11px] text-cyan-600 dark:text-cyan-400 mt-0.5">
                              <Activity className="w-3 h-3 animate-pulse shrink-0" />
                              <span className="font-mono">{row.completedQueries}q</span>
                              <span className="truncate max-w-[180px] opacity-85">
                                {row.phaseMessage ?? 'Probing…'}
                              </span>
                            </div>
                          )}
                          {row.status === 'queued' && (
                            <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                              Queued…
                            </div>
                          )}
                          {row.status === 'canceled' && (
                            <div className="text-[10px] font-mono text-rose-500 mt-0.5">
                              Canceled
                            </div>
                          )}
                          {row.status === 'error' && (
                            <div className="text-[11px] text-rose-600 dark:text-rose-400 mt-0.5 max-w-[220px]">
                              {row.error ?? 'Probe failed'}
                            </div>
                          )}
                          {row.status === 'done' && (
                            <div className="font-mono text-[10px] text-slate-400 mt-0.5">
                              {row.completedQueries}q · {row.durationMs ?? 0}ms
                            </div>
                          )}
                        </td>

                        {!p ? (
                          <td
                            colSpan={6}
                            className="py-2.5 px-3 text-slate-400 font-mono text-[11px] align-middle"
                          >
                            {row.status === 'running'
                              ? 'Collecting DNSSEC, NS BGP ASN, Mail & Web wire responses…'
                              : row.status === 'error'
                                ? 'Audit failed before snapshot synthesis'
                                : row.status === 'canceled'
                                  ? 'Skipped (batch canceled)'
                                  : 'Waiting for available worker slot…'}
                          </td>
                        ) : (
                          <>
                            {/* DNSSEC & Algorithm */}
                            <td className="py-2.5 px-3 align-top">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <StatusBadge status={p.dnssecStatus} size="sm" />
                              </div>
                              <div className="font-mono text-[10px] text-slate-600 dark:text-slate-400 mt-1">
                                {p.dnssecAlgorithmLabel}
                                {p.nsecMode !== 'UNSIGNED' ? ` · ${p.nsecMode}` : ''}
                              </div>
                            </td>

                            {/* Shortest RRSIG */}
                            <td className="py-2.5 px-3 align-top font-mono">
                              <span
                                className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-semibold ${
                                  p.rrsigExpired
                                    ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35'
                                    : p.rrsigExpiringSoon
                                      ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                                      : p.shortestRrsigRemainingSec !== null
                                        ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                                        : 'text-slate-400'
                                }`}
                              >
                                {p.shortestRrsigLabel}
                              </span>
                            </td>

                            {/* Authoritative NS & BGP ASNs */}
                            <td className="py-2.5 px-3 align-top">
                              <div className="flex flex-wrap items-center gap-1">
                                {p.nsAsns.length > 0 ? (
                                  p.nsAsns.map((a) => {
                                    const share = asnShareMap.get(a.asn) ?? 0;
                                    return (
                                      <span
                                        key={a.asn}
                                        title={`AS${a.asn}${a.asName ? ` (${a.asName})` : ''} · ${share}% of portfolio`}
                                        className="rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-slate-700 dark:text-slate-200"
                                      >
                                        AS{a.asn}
                                      </span>
                                    );
                                  })
                                ) : (
                                  <span className="font-mono text-[10px] text-slate-400">
                                    {p.nsCount} NS
                                  </span>
                                )}
                                {p.singleNsAsnSpof && (
                                  <span
                                    title="All authoritative nameservers route through a single BGP Autonomous System"
                                    className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
                                  >
                                    1-ASN
                                  </span>
                                )}
                                {p.dualStackReady === false && (
                                  <span
                                    title="Missing IPv4 or IPv6 glue/address transport (RFC 3901)"
                                    className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px]"
                                  >
                                    No IPv6 NS
                                  </span>
                                )}
                                {p.nsConsistent === false && (
                                  <span
                                    title="Parent delegation NS and authoritative apex NS differ"
                                    className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px]"
                                  >
                                    NS Skew
                                  </span>
                                )}
                              </div>
                              {p.nsProviders.length > 0 && (
                                <div className="font-mono text-[10px] text-slate-500 truncate max-w-[200px] mt-1">
                                  {p.nsProviders.join(', ')} ({p.nsCount} NS)
                                </div>
                              )}
                            </td>

                            {/* Mail Posture */}
                            <td className="py-2.5 px-3 align-top">
                              <div className="flex flex-wrap items-center gap-1">
                                {renderDaneBadge(p)}
                                {renderSpfBadge(p)}
                                {renderDmarcBadge(p)}
                                {p.mtaStsStatus !== 'not-deployed' && (
                                  <span
                                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                                      p.mtaStsStatus === 'enforce'
                                        ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold'
                                        : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30'
                                    }`}
                                  >
                                    STS:{p.mtaStsStatus}
                                  </span>
                                )}
                              </div>
                            </td>

                            {/* Web Posture */}
                            <td className="py-2.5 px-3 align-top">
                              <div className="flex flex-wrap items-center gap-1">
                                {p.echEnabled ? (
                                  <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                                    HTTPS+ECH
                                  </span>
                                ) : p.hasHttps ? (
                                  <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                                    HTTPS RR
                                  </span>
                                ) : (
                                  <span className="rounded bg-slate-500/15 text-slate-500 dark:text-slate-400 border border-slate-500/25 px-1.5 py-0.5 font-mono text-[10px]">
                                    No HTTPS
                                  </span>
                                )}
                                {p.supportsHttp3 && (
                                  <span className="rounded bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                                    h3
                                  </span>
                                )}
                                {p.caaStatus === 'enforced' || p.caaStatus === 'inherited' ? (
                                  <span
                                    title={`Authorized CAs: ${p.caaIssueCas.join(', ')}`}
                                    className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold"
                                  >
                                    CAA ✓
                                  </span>
                                ) : (
                                  <span className="rounded bg-slate-500/15 text-slate-500 dark:text-slate-400 border border-slate-500/25 px-1.5 py-0.5 font-mono text-[10px]">
                                    No CAA
                                  </span>
                                )}
                              </div>
                            </td>

                            {/* Issues & Drill-Down */}
                            <td
                              className="py-2.5 px-3 align-top"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <div className="flex flex-wrap items-center gap-1">
                                {p.errorCount > 0 && (
                                  <span className="inline-flex items-center gap-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35 px-1.5 py-0.5 font-mono text-[10px] font-bold">
                                    <ShieldAlert className="w-3 h-3" />
                                    {p.errorCount}E
                                  </span>
                                )}
                                {p.warningCount > 0 && (
                                  <span className="inline-flex items-center gap-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                                    <AlertTriangle className="w-3 h-3" />
                                    {p.warningCount}W
                                  </span>
                                )}
                                {p.errorCount === 0 && p.warningCount === 0 && (
                                  <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                                    0 issues
                                  </span>
                                )}
                              </div>

                              {row.snapshot && (
                                <div className="flex flex-wrap items-center gap-1 mt-1.5">
                                  <button
                                    type="button"
                                    data-testid={`portfolio-drill-graph-${row.domain}`}
                                    onClick={() => onSelectSnapshot(row.snapshot!, 'graph')}
                                    className="rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                                  >
                                    Graph
                                  </button>
                                  <button
                                    type="button"
                                    data-testid={`portfolio-drill-audit-${row.domain}`}
                                    onClick={() => onSelectSnapshot(row.snapshot!, 'audit')}
                                    className="rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                                  >
                                    Audit
                                  </button>
                                  <button
                                    type="button"
                                    data-testid={`portfolio-drill-mail-${row.domain}`}
                                    onClick={() => onSelectSnapshot(row.snapshot!, 'mail')}
                                    className="rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                                  >
                                    Mail
                                  </button>
                                  <button
                                    type="button"
                                    data-testid={`portfolio-drill-web-${row.domain}`}
                                    onClick={() => onSelectSnapshot(row.snapshot!, 'web')}
                                    className="rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                                  >
                                    Web
                                  </button>
                                </div>
                              )}
                            </td>
                          </>
                        )}
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
