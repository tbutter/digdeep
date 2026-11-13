import { Check, Copy, ExternalLink, Search, X } from 'lucide-react';
import {
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { createPortal } from 'react-dom';
import { DEFAULT_DOH_ENDPOINT } from '../dns/constants';
import { displayFqdn, normalizeFqdn, splitPresentationLabels } from '../dns/encoding';
import { parseReverseIpInput } from '../dns/ipUtils';
import type { AnalysisMode } from '../dns/types';
import { buildDeepLinkSearch } from '../urlState';

export interface ParsedHostnameToken {
  /** Canonical lowercase FQDN with trailing dot, e.g. `"ns1.cloudflare.com."` */
  canonicalFqdn: string;
  /** Canonical lowercase hostname without trailing dot, e.g. `"ns1.cloudflare.com"` */
  displayHostname: string;
}

export type PivotHostnameHandler = (
  displayHostname: string,
  options: { mode: AnalysisMode; queryTypes: string[] }
) => void;

let globalPivotHostnameHandler: PivotHostnameHandler | null = null;
let globalDohEndpoint = DEFAULT_DOH_ENDPOINT;
let activePinnedDismiss: (() => void) | null = null;

/**
 * Registers the app-level callback invoked when a user clicks a `HostnameBadge`
 * to pivot & trace that FQDN in DigDeep. Returns an unsubscribe function.
 */
export function registerGlobalPivotHostnameHandler(
  handler: PivotHostnameHandler | null,
  dohEndpoint?: string
): () => void {
  globalPivotHostnameHandler = handler;
  if (dohEndpoint) {
    globalDohEndpoint = dohEndpoint;
  }
  return () => {
    if (globalPivotHostnameHandler === handler) {
      globalPivotHostnameHandler = null;
    }
  };
}

/**
 * Dismisses whichever `HostnameBadge` popover is currently pinned open, if any.
 */
export function dismissActivePinnedHostnamePopover(): void {
  if (activePinnedDismiss) {
    const fn = activePinnedDismiss;
    activePinnedDismiss = null;
    fn();
  }
}

/**
 * Extracts a canonical DNS hostname/FQDN from raw strings such as `"ns1.cloudflare.com."`,
 * `"mail.protonmail.ch"`, `"include:_spf.google.com"`, `"redirect=_spf.example.com"`,
 * or `"+mx:smtp.example.com/24"`. Rejects root `.`, wildcards, SPF macros, emails, and IP literals.
 */
export function parseHostnameToken(rawInput: string): ParsedHostnameToken | null {
  let cleaned = rawInput.trim();
  if (!cleaned || cleaned === '.') return null;

  // Strip optional SPF mechanism / modifier qualifier & prefix
  cleaned = cleaned
    .replace(/^[+\-~?]?(?:include:|redirect=|exp=|a:|mx:|exists:|ptr:)/i, '')
    .trim();

  // Strip optional SPF dual-CIDR suffix (e.g. a:mail.example.com/24/56)
  cleaned = cleaned.replace(/\/\d{1,3}(?:\/\d{1,3})?$/, '').trim();

  if (
    !cleaned ||
    cleaned === '.' ||
    /\s/.test(cleaned) ||
    cleaned.includes('@') ||
    cleaned.includes('*') ||
    cleaned.includes('%') ||
    cleaned.includes('/') ||
    cleaned.includes(':')
  ) {
    return null;
  }

  // Reject raw IPv4 / IPv6 literals (handled by IpHoverBadge)
  const ipCheck = parseReverseIpInput(cleaned);
  if (ipCheck?.wasRawIpInput) {
    return null;
  }

  const canonicalFqdn = normalizeFqdn(cleaned);
  if (canonicalFqdn === '.' || canonicalFqdn.length > 254) {
    return null;
  }

  const labels = splitPresentationLabels(canonicalFqdn);
  if (labels.length === 0) return null;
  if (labels.length === 1 && /^\d+$/.test(labels[0]!)) {
    return null;
  }

  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return null;
    }
    if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label)) {
      return null;
    }
  }

  return {
    canonicalFqdn,
    displayHostname: displayFqdn(canonicalFqdn),
  };
}

/**
 * Infers sensible default RR query types when pivoting to a discovered FQDN.
 * Policy/key owner names (`_spf`, `_dmarc`, `_domainkey`, `_mta-sts`, `_smtp._tls`, `_bimi`)
 * default to `TXT`, DANE owner names (`_443._tcp.*`) default to `TLSA`, and hostnames default to `A, AAAA`.
 */
export function inferDefaultQueryTypesForHostname(displayHostname: string): string[] {
  const low = displayHostname.toLowerCase();
  if (
    low.startsWith('_spf.') ||
    low.startsWith('_dmarc.') ||
    low.startsWith('_mta-sts.') ||
    low.startsWith('_smtp._tls.') ||
    low.includes('._domainkey.') ||
    low.includes('._bimi.')
  ) {
    return ['TXT'];
  }
  if (/^_\d+\._(?:tcp|udp|sctp)\./.test(low)) {
    return ['TLSA'];
  }
  return ['A', 'AAAA'];
}

async function copyHostnameToClipboard(text: string): Promise<boolean> {
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

/**
 * Interactive Hostname Pivot Badge (analogous to `IpHoverBadge`):
 * - **Click** (or `Enter`): pivots & traces the FQDN in DigDeep, pushing browser history so `Back`/`Forward` returns cleanly.
 * - **⌘/Ctrl-Click** (or Middle-Click): opens the FQDN trace in a new browser tab via deep link.
 * - **Hover (desktop) or Tap (touch)**: opens a floating micro-popover with 1-click **Copy FQDN**, **Trace**, and **New Tab**.
 */
export function HostnameBadge({
  hostname,
  children,
  className = '',
  mode = 'dnssec',
  queryTypes,
  onPivot,
}: {
  hostname: string;
  children?: ReactNode;
  className?: string;
  mode?: AnalysisMode;
  queryTypes?: string[];
  onPivot?: PivotHostnameHandler;
}) {
  const parsed = parseHostnameToken(hostname);
  const triggerRef = useRef<HTMLAnchorElement | null>(null);
  const cardRef = useRef<HTMLDivElement | null>(null);
  const hoverCloseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTouchTimeRef = useRef<number>(0);

  const [hovered, setHovered] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [copied, setCopied] = useState(false);
  const [coords, setCoords] = useState<{
    left: number;
    top: number;
    placement: 'top' | 'bottom';
    mobileSheet: boolean;
  } | null>(null);

  const isOpen = hovered || pinned;

  const clearHoverTimer = useCallback(() => {
    if (hoverCloseTimerRef.current !== null) {
      clearTimeout(hoverCloseTimerRef.current);
      hoverCloseTimerRef.current = null;
    }
  }, []);

  const dismissPopover = useCallback(() => {
    clearHoverTimer();
    setPinned(false);
    setHovered(false);
  }, [clearHoverTimer]);

  useEffect(() => {
    return () => {
      clearHoverTimer();
      if (copyTimerRef.current !== null) {
        clearTimeout(copyTimerRef.current);
      }
    };
  }, [clearHoverTimer]);

  useEffect(() => {
    if (!pinned) {
      if (activePinnedDismiss === dismissPopover) {
        activePinnedDismiss = null;
      }
      return;
    }
    if (activePinnedDismiss && activePinnedDismiss !== dismissPopover) {
      activePinnedDismiss();
    }
    activePinnedDismiss = dismissPopover;
    return () => {
      if (activePinnedDismiss === dismissPopover) {
        activePinnedDismiss = null;
      }
    };
  }, [pinned, dismissPopover]);

  const updatePosition = useCallback(
    (isPinnedMode?: boolean) => {
      const el = triggerRef.current;
      if (!el || typeof window === 'undefined') return;
      const vw = window.innerWidth || 1024;
      const useMobileSheet = Boolean((isPinnedMode ?? pinned) && vw < 640);
      if (useMobileSheet) {
        setCoords({ left: 12, top: 0, placement: 'bottom', mobileSheet: true });
        return;
      }
      const rect = el.getBoundingClientRect();
      const cardWidth = Math.min(300, Math.max(220, vw - 24));
      const half = cardWidth / 2;
      const center = rect.left + rect.width / 2;
      const clampedLeft = Math.max(12 + half, Math.min(vw - 12 - half, center));
      const placement: 'top' | 'bottom' = rect.top > 110 ? 'top' : 'bottom';
      const top = placement === 'top' ? rect.top - 6 : rect.bottom + 6;
      setCoords({ left: clampedLeft, top, placement, mobileSheet: false });
    },
    [pinned]
  );

  const scheduleHoverClose = useCallback(() => {
    clearHoverTimer();
    hoverCloseTimerRef.current = setTimeout(() => {
      setHovered(false);
    }, 150);
  }, [clearHoverTimer]);

  useEffect(() => {
    if (!isOpen || typeof document === 'undefined') return;

    const handleOutsideInteraction = (e: Event) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (triggerRef.current?.contains(target)) return;
      if (cardRef.current?.contains(target)) return;
      dismissPopover();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        e.stopImmediatePropagation();
        const focusWasInCard = Boolean(cardRef.current?.contains(document.activeElement));
        dismissPopover();
        if (focusWasInCard) {
          triggerRef.current?.focus();
        }
      }
    };

    const handleResize = () => updatePosition();
    const handleScroll = (e: Event) => {
      const target = e.target as Node | null;
      if (target && cardRef.current?.contains(target)) return;
      const el = triggerRef.current;
      if (!el || typeof window === 'undefined') return;
      const rect = el.getBoundingClientRect();
      const vh = window.innerHeight || 768;
      if (vh > 0 && (rect.bottom < -16 || rect.top > vh + 16)) {
        dismissPopover();
        return;
      }
      updatePosition();
    };

    document.addEventListener('pointerdown', handleOutsideInteraction, true);
    document.addEventListener('mousedown', handleOutsideInteraction, true);
    document.addEventListener('keydown', handleKeyDown, true);
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', handleResize);
      window.addEventListener('scroll', handleScroll, true);
    }
    return () => {
      document.removeEventListener('pointerdown', handleOutsideInteraction, true);
      document.removeEventListener('mousedown', handleOutsideInteraction, true);
      document.removeEventListener('keydown', handleKeyDown, true);
      if (typeof window !== 'undefined') {
        window.removeEventListener('resize', handleResize);
        window.removeEventListener('scroll', handleScroll, true);
      }
    };
  }, [isOpen, dismissPopover, updatePosition]);

  if (!parsed) {
    return <span className={className}>{children ?? hostname}</span>;
  }

  const effectiveTypes =
    queryTypes && queryTypes.length > 0
      ? queryTypes
      : inferDefaultQueryTypesForHostname(parsed.displayHostname);

  const defaultTab =
    mode === 'mail'
      ? 'mail'
      : mode === 'web'
        ? 'web'
        : mode === 'consensus'
          ? 'consensus'
          : 'graph';

  const deepLinkHref = buildDeepLinkSearch({
    name: parsed.displayHostname,
    mode,
    types: effectiveTypes,
    dohEndpoint: globalDohEndpoint,
    tab: defaultTab,
  });

  const triggerPivot = () => {
    const handler = onPivot ?? globalPivotHostnameHandler;
    dismissPopover();
    handler?.(parsed.displayHostname, { mode, queryTypes: effectiveTypes });
  };

  const handleAnchorClick = (e: ReactMouseEvent<HTMLAnchorElement>) => {
    // Allow ⌘-Click / Ctrl-Click / Shift-Click / Middle-Click to open in a new tab natively
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
      e.stopPropagation();
      dismissPopover();
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    // On coarse touch devices, first tap opens the quick-action popover (Copy / Trace / New Tab)
    if (Date.now() - lastTouchTimeRef.current < 600 && !pinned) {
      clearHoverTimer();
      updatePosition(true);
      setPinned(true);
      return;
    }

    triggerPivot();
  };

  const handleCopyFqdn = async () => {
    const ok = await copyHostnameToClipboard(parsed.displayHostname);
    if (ok) {
      setCopied(true);
      if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopied(false), 1800);
    }
  };

  const traceLabel =
    mode === 'dnssec' ? `Trace ${effectiveTypes.join('+')}` : `Trace ${mode.toUpperCase()}`;

  return (
    <>
      <a
        ref={triggerRef}
        href={deepLinkHref}
        data-testid="hostname-badge"
        data-hostname={parsed.displayHostname}
        data-fqdn={parsed.canonicalFqdn}
        aria-expanded={isOpen}
        onTouchStart={() => {
          lastTouchTimeRef.current = Date.now();
        }}
        onPointerDown={(e) => {
          if (e.pointerType === 'touch' || e.pointerType === 'pen') {
            lastTouchTimeRef.current = Date.now();
          }
        }}
        onMouseEnter={() => {
          if (Date.now() - lastTouchTimeRef.current < 600) return;
          clearHoverTimer();
          updatePosition(pinned);
          setHovered(true);
        }}
        onMouseLeave={() => {
          if (Date.now() - lastTouchTimeRef.current < 600) return;
          scheduleHoverClose();
        }}
        onClick={handleAnchorClick}
        className={`rounded-sm outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/80 ${
          pinned
            ? 'underline decoration-solid decoration-cyan-500 text-cyan-700 dark:text-cyan-300'
            : 'decoration-dotted hover:underline hover:decoration-cyan-500/80 hover:text-cyan-700 dark:hover:text-cyan-300'
        } transition-colors cursor-pointer ${className}`}
      >
        {children ?? parsed.displayHostname}
      </a>
      {isOpen &&
        coords &&
        typeof document !== 'undefined' &&
        document.body &&
        createPortal(
          <div
            ref={cardRef}
            role="dialog"
            aria-label={`Hostname actions for ${parsed.displayHostname}`}
            data-testid="hostname-badge-popover"
            data-mobile-sheet={coords.mobileSheet ? 'true' : 'false'}
            onMouseEnter={() => {
              if (Date.now() - lastTouchTimeRef.current >= 600) {
                clearHoverTimer();
                setHovered(true);
              }
            }}
            onMouseLeave={() => {
              if (Date.now() - lastTouchTimeRef.current >= 600) {
                scheduleHoverClose();
              }
            }}
            style={
              coords.mobileSheet
                ? {
                    position: 'fixed',
                    left: '12px',
                    right: '12px',
                    bottom: 'max(12px, env(safe-area-inset-bottom, 12px))',
                    zIndex: 9999,
                    pointerEvents: 'auto',
                  }
                : {
                    position: 'fixed',
                    left: `${coords.left}px`,
                    top: `${coords.top}px`,
                    transform:
                      coords.placement === 'top'
                        ? 'translate(-50%, -100%)'
                        : 'translate(-50%, 0)',
                    zIndex: 9999,
                    pointerEvents: 'auto',
                  }
            }
          >
            <div
              className={`${
                coords.mobileSheet ? 'w-full max-w-md mx-auto' : 'w-max max-w-[calc(100vw-24px)]'
              } rounded-xl border border-slate-200 dark:border-slate-700/90 bg-white/98 dark:bg-slate-900/98 backdrop-blur-md shadow-xl p-2.5 text-left text-xs text-slate-800 dark:text-slate-100 space-y-2`}
            >
              <div className="flex items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-1.5">
                <span
                  className="font-mono font-bold text-[11px] text-slate-900 dark:text-slate-100 break-all"
                  title={parsed.canonicalFqdn}
                >
                  {parsed.canonicalFqdn}
                </span>
                {pinned && (
                  <button
                    type="button"
                    data-testid="hostname-badge-close-btn"
                    aria-label="Close hostname actions"
                    onClick={(e) => {
                      e.stopPropagation();
                      dismissPopover();
                    }}
                    className="rounded p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer shrink-0"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  data-testid="hostname-badge-trace-btn"
                  data-hostname={parsed.displayHostname}
                  onClick={(e) => {
                    e.stopPropagation();
                    triggerPivot();
                  }}
                  className="inline-flex items-center justify-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 hover:border-cyan-500/70 px-2.5 py-1 text-[11px] font-semibold text-cyan-800 dark:text-cyan-200 transition-colors cursor-pointer"
                  title={`Pivot & run ${traceLabel} for ${parsed.displayHostname}`}
                >
                  <Search className="w-3 h-3 text-cyan-600 dark:text-cyan-400 shrink-0" />
                  <span>{traceLabel}</span>
                </button>

                <button
                  type="button"
                  data-testid="hostname-badge-copy-btn"
                  data-hostname={parsed.displayHostname}
                  onClick={(e) => {
                    e.stopPropagation();
                    void handleCopyFqdn();
                  }}
                  className="inline-flex items-center justify-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700/90 bg-slate-50 dark:bg-slate-800/80 hover:border-cyan-500/70 hover:bg-slate-100 dark:hover:bg-slate-800 px-2.5 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                  title={`Copy ${parsed.displayHostname} to clipboard`}
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-500 shrink-0" />
                      <span className="text-emerald-700 dark:text-emerald-300 font-semibold">
                        Copied!
                      </span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-slate-500 dark:text-slate-400 shrink-0" />
                      <span>Copy FQDN</span>
                    </>
                  )}
                </button>

                <a
                  href={deepLinkHref}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid="hostname-badge-newtab-link"
                  onClick={(e) => {
                    e.stopPropagation();
                    dismissPopover();
                  }}
                  className="inline-flex items-center justify-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700/90 bg-slate-50 dark:bg-slate-800/80 hover:border-cyan-500/70 hover:bg-slate-100 dark:hover:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
                  title={`Open ${parsed.displayHostname} in a new browser tab (⌘/Ctrl-Click)`}
                >
                  <ExternalLink className="w-3 h-3 text-slate-500 dark:text-slate-400 shrink-0" />
                  <span>New Tab</span>
                </a>
              </div>
            </div>
          </div>,
          document.body
        )}
    </>
  );
}
