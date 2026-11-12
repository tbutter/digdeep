import { Check, ChevronDown, ChevronRight, Copy } from 'lucide-react';
import { useState } from 'react';

export function formatMiddleEllipsis(
  value: string,
  headChars = 14,
  tailChars = 10
): { truncated: boolean; preview: string } {
  const clean = value.trim();
  if (clean.length <= headChars + tailChars + 5) {
    return { truncated: false, preview: value };
  }
  return {
    truncated: true,
    preview: `${clean.slice(0, headChars)}…${clean.slice(-tailChars)}`,
  };
}

export interface CryptoBlobProps {
  value: string;
  copyValue?: string;
  copyLabel?: string;
  headChars?: number;
  tailChars?: number;
  /**
   * When false (default), mobile viewports (`< sm`) show a single-line middle-ellipsis
   * preview with tap-to-expand, while `sm:`+ viewports show the full value inline.
   * When true, all viewports show the compact preview until expanded.
   */
  collapseOnDesktop?: boolean;
  /**
   * When true, renders as a lightweight inline flex group without an outer card border/background.
   */
  compact?: boolean;
  className?: string;
  testId?: string;
}

export function CryptoBlob({
  value,
  copyValue,
  copyLabel = 'Copy',
  headChars = 14,
  tailChars = 10,
  collapseOnDesktop = false,
  compact = false,
  className = '',
  testId,
}: CryptoBlobProps) {
  const [expandedForValue, setExpandedForValue] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const expanded = expandedForValue === value;
  const { truncated, preview } = formatMiddleEllipsis(value, headChars, tailChars);
  const textToCopy = copyValue ?? value;

  const handleCopy = () => {
    if (!textToCopy) return;
    navigator.clipboard?.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const containerCls = compact
    ? `inline-flex flex-wrap items-center gap-1.5 min-w-0 max-w-full align-middle text-[11px] text-slate-600 dark:text-slate-300 ${className}`
    : `rounded-lg bg-slate-100/90 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 px-2.5 py-1.5 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-700 dark:text-slate-300 ${className}`;

  return (
    <div
      data-testid={testId}
      data-expanded={expanded ? 'true' : 'false'}
      className={containerCls}
    >
      <div className="min-w-0 flex-1 flex flex-wrap items-center gap-1.5">
        {!truncated ? (
          <code className="font-mono break-all">{value}</code>
        ) : expanded ? (
          <>
            <code
              data-testid={testId ? `${testId}-expanded-full` : undefined}
              className="font-mono break-all"
            >
              {value}
            </code>
            <button
              type="button"
              data-testid={testId ? `${testId}-toggle` : undefined}
              aria-expanded={true}
              onClick={() => setExpandedForValue(null)}
              className={`${
                collapseOnDesktop ? 'inline-flex' : 'sm:hidden inline-flex'
              } items-center gap-0.5 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-1.5 py-0.5 font-sans text-[10px] font-medium text-slate-600 dark:text-slate-300 shrink-0 cursor-pointer`}
            >
              <ChevronDown className="w-2.5 h-2.5 text-cyan-500" />
              <span>Collapse</span>
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              data-testid={testId ? `${testId}-toggle` : undefined}
              aria-expanded={false}
              onClick={() => setExpandedForValue(value)}
              title="Tap to expand full cryptographic value"
              className={`${
                collapseOnDesktop ? 'inline-flex' : 'sm:hidden inline-flex'
              } items-center gap-1.5 text-left min-w-0 max-w-full cursor-pointer group`}
            >
              <code className="font-mono truncate">{preview}</code>
              <span className="inline-flex items-center gap-0.5 rounded bg-slate-200/80 dark:bg-slate-800 group-hover:bg-cyan-500/15 px-1.5 py-0.5 font-sans text-[10px] font-medium text-cyan-700 dark:text-cyan-300 shrink-0 transition-colors">
                <ChevronRight className="w-2.5 h-2.5" />
                <span>Expand</span>
              </span>
            </button>
            {!collapseOnDesktop && (
              <code
                data-testid={testId ? `${testId}-desktop-full` : undefined}
                className="hidden sm:inline font-mono break-all"
              >
                {value}
              </code>
            )}
          </>
        )}
      </div>

      {textToCopy.length > 0 && (
        <button
          type="button"
          data-testid={testId ? `${testId}-copy` : undefined}
          onClick={handleCopy}
          title={`Copy full value (${textToCopy.length} chars)`}
          className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-1.5 py-0.5 font-sans text-[10px] font-medium text-slate-600 dark:text-slate-300 shrink-0 cursor-pointer transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-2.5 h-2.5 text-emerald-500" />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-2.5 h-2.5" />
              <span>{copyLabel}</span>
            </>
          )}
        </button>
      )}
    </div>
  );
}
