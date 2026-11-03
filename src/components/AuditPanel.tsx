import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Info,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useState } from 'react';
import { formatDohShortLabel } from '../dns/constants';
import type { AnalysisSnapshot, AuditFinding } from '../dns/types';
import { StatusBadge } from './StatusBadge';

export function AuditPanel({
  snapshot,
  onJumpToGraphTarget,
}: {
  snapshot: AnalysisSnapshot;
  onJumpToGraphTarget: (targetId: string) => void;
}) {
  const [filter, setFilter] = useState<'all' | AuditFinding['severity']>('all');

  const errors = snapshot.findings.filter((f) => f.severity === 'error');
  const warnings = snapshot.findings.filter((f) => f.severity === 'warning');
  const infos = snapshot.findings.filter((f) => f.severity === 'info');

  const shown =
    filter === 'all'
      ? snapshot.findings
      : snapshot.findings.filter((f) => f.severity === filter);

  return (
    <div className="space-y-5">
      {/* Side-by-Side Client WebCrypto vs 1.1.1.1 Validating Resolver Comparison */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
              <ShieldCheck className="w-4 h-4" />
              Client-Side WebCrypto Validator
            </div>
            <StatusBadge status={snapshot.overallStatus} size="xs" />
          </div>
          <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">
            {snapshot.overallSummary}
          </p>
          <div className="text-xs text-slate-500 font-mono">
            Validated @ {new Date(snapshot.validatedAt).toISOString()} across{' '}
            {snapshot.zones.length} zone(s)
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-4 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              <Server className="w-4 h-4" />
              {formatDohShortLabel(snapshot.dohEndpoint)} Resolver Verdict (CD=0)
            </div>
            {snapshot.resolverVerdict && (
              <span
                className={`rounded-full px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                  snapshot.resolverVerdict.rcode === 2
                    ? 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border border-rose-500/30'
                    : snapshot.resolverVerdict.adBit
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border border-emerald-500/30'
                      : 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border border-slate-500/30'
                }`}
              >
                {snapshot.resolverVerdict.rcodeName} · AD=
                {snapshot.resolverVerdict.adBit ? '1' : '0'}
              </span>
            )}
          </div>
          {snapshot.resolverVerdict ? (
            <>
              <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">
                {snapshot.resolverVerdict.rcode === 2
                  ? `${formatDohShortLabel(snapshot.dohEndpoint)} returned SERVFAIL when DNSSEC checking was enabled (CD=0), confirming upstream validation failure.`
                  : snapshot.resolverVerdict.adBit
                    ? `${formatDohShortLabel(snapshot.dohEndpoint)} set the Authenticated Data (AD=1) bit, confirming recursive validation.`
                    : `${formatDohShortLabel(snapshot.dohEndpoint)} returned AD=0 (unsigned answer or insecure delegation).`}
              </p>
              {snapshot.resolverVerdict.ede.length > 0 && (
                <div className="text-xs font-mono text-rose-600 dark:text-rose-400">
                  {snapshot.resolverVerdict.ede
                    .map(
                      (e) =>
                        `EDE(${e.infoCode} ${e.name})${e.extraText ? `: ${e.extraText}` : ''}`
                    )
                    .join(' · ')}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-slate-500">No CD=0 resolver check recorded.</p>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-2">
        {(
          [
            ['all', `All Findings (${snapshot.findings.length})`],
            ['error', `Errors (${errors.length})`],
            ['warning', `Warnings (${warnings.length})`],
            ['info', `Notices (${infos.length})`],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setFilter(key)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              filter === key
                ? 'bg-cyan-500 text-slate-950 font-semibold'
                : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Findings List */}
      {shown.length === 0 ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-8 text-center space-y-2">
          <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
          <div className="font-semibold text-slate-900 dark:text-slate-100">
            Zero issues in this category
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            All cryptographic signatures, DS digests, and RFC best-practice checks passed cleanly.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {shown.map((f) => {
            const borderCls =
              f.severity === 'error'
                ? 'border-rose-500/40 bg-rose-500/5'
                : f.severity === 'warning'
                  ? 'border-amber-500/40 bg-amber-500/5'
                  : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60';
            return (
              <div
                key={f.id}
                className={`rounded-xl border p-4 flex flex-col sm:flex-row sm:items-start justify-between gap-3 ${borderCls}`}
              >
                <div className="flex items-start gap-3">
                  {f.severity === 'error' ? (
                    <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />
                  ) : f.severity === 'warning' ? (
                    <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                  ) : (
                    <Info className="w-5 h-5 text-cyan-500 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                        {f.title}
                      </span>
                      <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300">
                        {f.code}
                      </span>
                      {f.rfc && (
                        <span className="rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-mono text-[10px]">
                          {f.rfc}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                      {f.detail}
                    </p>
                  </div>
                </div>

                {(f.targetId || f.zone) && (
                  <button
                    type="button"
                    onClick={() => onJumpToGraphTarget(f.targetId ?? `zone-${f.zone}`)}
                    className="inline-flex items-center gap-1 self-start shrink-0 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
                  >
                    Locate in Graph
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
