import { Binary, Check, Copy, Terminal } from 'lucide-react';
import { useMemo, useState } from 'react';
import { formatDohShortLabel, rcodeToString } from '../dns/constants';
import { formatPacketAsDig, formatWireHexDump } from '../dns/digFormat';
import type { AnalysisSnapshot, DohQueryLog } from '../dns/types';
import { IpHoverBadge, parseIpToken, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';

export function ResponsesPanel({ snapshot }: { snapshot: AnalysisSnapshot }) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const [selectedId, setSelectedId] = useState<string>(snapshot.queries[0]?.id ?? '');
  const [mode, setMode] = useState<'dig' | 'hex-resp' | 'hex-req'>('dig');
  const [copied, setCopied] = useState(false);

  const selectedLog: DohQueryLog | undefined = useMemo(
    () => snapshot.queries.find((q) => q.id === selectedId) ?? snapshot.queries[0],
    [snapshot.queries, selectedId]
  );

  const maxLatency = useMemo(
    () => Math.max(1, ...snapshot.queries.map((q) => q.latencyMs)),
    [snapshot.queries]
  );

  const digText = useMemo(
    () => (selectedLog ? formatPacketAsDig(selectedLog) : ''),
    [selectedLog]
  );

  const hexRows = useMemo(() => {
    if (!selectedLog) return [];
    return formatWireHexDump(
      mode === 'hex-req' ? selectedLog.requestWireBase64 : selectedLog.wireBase64
    );
  }, [selectedLog, mode]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 min-h-[540px]">
      {/* Left: DoH Query Waterfall Table */}
      <div className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden flex flex-col max-h-[70vh]">
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            {formatDohShortLabel(snapshot.dohEndpoint)} DoH Wire Queries ({snapshot.queries.length})
          </div>
          <div className="font-mono text-[11px] text-slate-400">application/dns-message</div>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800/80 overflow-y-auto flex-1">
          {snapshot.queries.map((q) => {
            const active = selectedLog?.id === q.id;
            const rcode = rcodeToString(q.packet.flags.rcode);
            const rcodeColor =
              q.packet.flags.rcode === 0
                ? 'text-emerald-600 dark:text-emerald-400'
                : q.packet.flags.rcode === 3
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-rose-600 dark:text-rose-400';

            return (
              <button
                key={q.id}
                type="button"
                onClick={() => setSelectedId(q.id)}
                className={`w-full text-left px-3.5 py-2.5 transition-colors cursor-pointer ${
                  active
                    ? 'bg-cyan-500/10 border-l-2 border-l-cyan-500'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:text-slate-200 shrink-0">
                      {q.qtypeName}
                    </span>
                    <span className="font-mono text-xs font-medium truncate text-slate-900 dark:text-slate-100">
                      {q.qname}
                    </span>
                  </div>
                  <span className={`font-mono text-[11px] font-semibold shrink-0 ${rcodeColor}`}>
                    {rcode}
                  </span>
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
          })}
        </div>
      </div>

      {/* Right: Packet Presentation (`dig` & Wire Hex) */}
      <div className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 overflow-hidden flex flex-col max-h-[70vh]">
        {selectedLog ? (
          <>
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setMode('dig')}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer ${
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
                  onClick={() => setMode('hex-resp')}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer ${
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
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer ${
                    mode === 'hex-req'
                      ? 'bg-cyan-500 text-slate-950 font-semibold'
                      : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  Request Wire
                </button>
              </div>

              <button
                type="button"
                onClick={() => {
                  const content =
                    mode === 'dig'
                      ? digText
                      : hexRows.map((r) => `${r.offsetHex}  ${r.hexGroups}  |${r.ascii}|`).join('\n');
                  navigator.clipboard?.writeText(content);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>

            <div className="p-4 overflow-auto flex-1 bg-slate-950 text-slate-200 font-mono text-xs leading-relaxed">
              {mode === 'dig' ? (
                <pre className="whitespace-pre overflow-x-auto">
                  {digText.split('\n').map((line, idx, lines) => {
                    const nl = idx < lines.length - 1 ? '\n' : '';
                    if (!line.startsWith(';')) {
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
              ) : (
                <div className="space-y-0.5">
                  {hexRows.map((row) => (
                    <div key={row.offsetHex} className="flex gap-4 whitespace-pre">
                      <span className="text-slate-500 select-none">{row.offsetHex}</span>
                      <span className="text-cyan-300">{row.hexGroups}</span>
                      <span className="text-emerald-300/80">|{row.ascii}|</span>
                    </div>
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
