import {
  AlertTriangle,
  Clock,
  Command,
  CornerDownLeft,
  Globe,
  Info,
  KeyRound,
  Layers,
  Network,
  Radio,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import {
  buildCommandPaletteItems,
  COMMAND_CATEGORY_LABELS,
  filterCommandPaletteItems,
  type BuildCommandPaletteContext,
  type CommandPaletteAction,
  type CommandPaletteCategory,
  type CommandPaletteItem,
} from '../dns/commandPalette';

export interface CommandPaletteModalProps {
  open: boolean;
  context: BuildCommandPaletteContext;
  onClose: () => void;
  onExecuteAction: (action: CommandPaletteAction) => void;
}

const CATEGORY_PILLS: ReadonlyArray<{
  id: CommandPaletteCategory | 'all';
  label: string;
}> = [
  { id: 'all', label: 'All' },
  { id: 'snapshot', label: 'Snapshot' },
  { id: 'navigation', label: 'Views & Modes' },
  { id: 'resolver', label: 'DoH Resolvers' },
  { id: 'actions', label: 'Actions' },
  { id: 'history', label: 'History' },
];

const SHORT_CATEGORY_TAG: Record<CommandPaletteCategory, string> = {
  snapshot: 'Snapshot',
  navigation: 'View / Mode',
  resolver: 'Resolver',
  actions: 'Action',
  history: 'History',
};

function renderItemIcon(item: CommandPaletteItem) {
  if (item.category === 'snapshot') {
    if (item.severity === 'error') {
      return <ShieldAlert className="w-4 h-4 text-rose-500 shrink-0" />;
    }
    if (item.severity === 'warning') {
      return <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />;
    }
    if (item.severity === 'info') {
      return <Info className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    if (item.id.startsWith('snap-dnskey-')) {
      return <KeyRound className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    if (item.id.startsWith('snap-wire-')) {
      return <Terminal className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    if (item.id.startsWith('snap-zone-')) {
      return <Globe className="w-4 h-4 text-emerald-500 shrink-0" />;
    }
    return <Network className="w-4 h-4 text-cyan-500 shrink-0" />;
  }
  if (item.category === 'resolver') {
    return <Server className="w-4 h-4 text-cyan-500 shrink-0" />;
  }
  if (item.category === 'history') {
    return <Clock className="w-4 h-4 text-slate-400 shrink-0" />;
  }
  if (item.category === 'navigation') {
    if (item.id.includes('consensus')) {
      return <Radio className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    if (item.id.includes('portfolio')) {
      return <Layers className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    if (item.id.includes('audit')) {
      return <ShieldCheck className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
    return <Network className="w-4 h-4 text-cyan-500 shrink-0" />;
  }
  if (item.id === 'action-open-settings') {
    return <Settings className="w-4 h-4 text-slate-400 shrink-0" />;
  }
  return <Sparkles className="w-4 h-4 text-cyan-500 shrink-0" />;
}

function badgeColorClass(item: CommandPaletteItem): string {
  if (item.severity === 'error' || item.status === 'bogus') {
    return 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30';
  }
  if (
    item.severity === 'warning' ||
    item.status === 'indeterminate' ||
    item.status === 'policy-error'
  ) {
    return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30';
  }
  if (item.status === 'secure' || item.isActive) {
    return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
  }
  return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700';
}

export function CommandPaletteModal({
  open,
  context,
  onClose,
  onExecuteAction,
}: CommandPaletteModalProps) {
  const [query, setQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<CommandPaletteCategory | 'all'>('all');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setCategoryFilter('all');
    setSelectedIndex(0);
    const raf =
      typeof requestAnimationFrame === 'function'
        ? requestAnimationFrame(() => inputRef.current?.focus())
        : null;
    inputRef.current?.focus();
    return () => {
      if (raf !== null && typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(raf);
      }
    };
  }, [open]);

  const allItems = useMemo(() => (open ? buildCommandPaletteItems(context) : []), [open, context]);

  const filteredItems = useMemo(
    () => filterCommandPaletteItems(allItems, query, categoryFilter),
    [allItems, query, categoryFilter]
  );

  const safeIndex =
    filteredItems.length === 0 ? -1 : Math.min(Math.max(0, selectedIndex), filteredItems.length - 1);
  const activeItem = safeIndex >= 0 ? filteredItems[safeIndex] : undefined;

  useEffect(() => {
    if (!open || !activeItem || !listRef.current) return;
    const optionEl = listRef.current.querySelector<HTMLElement>(
      `[data-cmd-index="${safeIndex}"]`
    );
    if (optionEl && typeof optionEl.scrollIntoView === 'function') {
      optionEl.scrollIntoView({ block: 'nearest' });
    }
  }, [open, safeIndex, activeItem]);

  if (!open) return null;

  const isSearching = query.trim().length > 0;

  const triggerItem = (item: CommandPaletteItem) => {
    onClose();
    onExecuteAction(item.action);
  };

  const handleKeyDown = (e: ReactKeyboardEvent<HTMLElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key === 'ArrowDown' || (e.ctrlKey && e.key.toLowerCase() === 'n')) {
      e.preventDefault();
      if (filteredItems.length > 0) {
        setSelectedIndex((prev) => (prev + 1) % filteredItems.length);
      }
      return;
    }
    if (e.key === 'ArrowUp' || (e.ctrlKey && e.key.toLowerCase() === 'p')) {
      e.preventDefault();
      if (filteredItems.length > 0) {
        setSelectedIndex((prev) => (prev <= 0 ? filteredItems.length - 1 : prev - 1));
      }
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (activeItem) {
        triggerItem(activeItem);
      }
    }
  };

  return (
    <div
      data-testid="command-palette-modal"
      role="dialog"
      aria-modal="true"
      aria-label="Global Command Palette"
      onKeyDown={handleKeyDown}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-start justify-center p-2 sm:p-6 pt-10 sm:pt-[10vh]"
    >
      <div className="w-full max-w-2xl max-h-[82dvh] rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl shadow-slate-950/50 flex flex-col overflow-hidden">
        {/* Search Combobox Bar */}
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3">
          <Search className="w-4 h-4 text-cyan-500 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-autocomplete="list"
            aria-controls="digdeep-command-listbox"
            aria-activedescendant={activeItem ? `cmd-opt-${activeItem.id}` : undefined}
            aria-label="Search commands, zones, DNSKEY tags, findings, resolvers, or history"
            data-testid="command-palette-input"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder={
              context.activeSnapshot
                ? `Jump to zone, #keyTag, finding, resolver, view, or export (${context.activeSnapshot.displayDomain})…`
                : 'Search views, analysis modes, DoH resolvers, settings, or saved history…'
            }
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            className="flex-1 bg-transparent text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none"
          />
          {query.length > 0 && (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                setSelectedIndex(0);
                inputRef.current?.focus();
              }}
              aria-label="Clear command query"
              className="p-1 rounded-md text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            type="button"
            data-testid="close-command-palette-btn"
            onClick={onClose}
            className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
          >
            ESC
          </button>
        </div>

        {/* Category Filter Pills */}
        <div className="px-3.5 py-2 border-b border-slate-200/80 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-950/40 flex items-center gap-1.5 overflow-x-auto no-scrollbar">
          {CATEGORY_PILLS.map((pill) => {
            const active = categoryFilter === pill.id;
            return (
              <button
                key={pill.id}
                type="button"
                data-testid={`command-cat-${pill.id}`}
                onClick={() => {
                  setCategoryFilter(pill.id);
                  setSelectedIndex(0);
                  inputRef.current?.focus();
                }}
                className={`shrink-0 rounded-lg px-2.5 py-1 text-[11px] font-medium transition-colors cursor-pointer ${
                  active
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800'
                }`}
              >
                {pill.label}
              </button>
            );
          })}
        </div>

        {/* Results Listbox */}
        <div
          id="digdeep-command-listbox"
          ref={listRef}
          role="listbox"
          aria-label="Command palette results"
          data-testid="command-palette-listbox"
          className="flex-1 overflow-y-auto p-2 space-y-0.5"
        >
          {filteredItems.length === 0 ? (
            <div
              data-testid="command-palette-empty"
              className="py-10 px-4 text-center space-y-1.5 text-xs text-slate-500 dark:text-slate-400"
            >
              <Command className="w-6 h-6 text-slate-400 mx-auto mb-1" />
              <div className="font-medium text-slate-700 dark:text-slate-300">
                No matching commands or snapshot entities
              </div>
              <div>
                Try searching for a zone name, <code className="font-mono">#keyTag</code>, RFC code,
                DoH resolver (<code className="font-mono">9.9.9.9</code>), or view name.
              </div>
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const prevItem = idx > 0 ? filteredItems[idx - 1] : undefined;
              const showSectionHeader =
                !isSearching && (!prevItem || prevItem.category !== item.category);
              const isSelected = idx === safeIndex;

              return (
                <div key={item.id}>
                  {showSectionHeader && (
                    <div className="px-2.5 pt-2.5 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                      {COMMAND_CATEGORY_LABELS[item.category]}
                    </div>
                  )}
                  <button
                    id={`cmd-opt-${item.id}`}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    data-cmd-index={idx}
                    data-testid={`command-item-${item.id}`}
                    onMouseEnter={() => setSelectedIndex(idx)}
                    onClick={() => triggerItem(item)}
                    className={`w-full text-left rounded-xl px-3 py-2 flex items-center justify-between gap-3 transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-cyan-500/15 dark:bg-cyan-500/20 text-slate-950 dark:text-slate-50 ring-1 ring-cyan-500/40'
                        : 'text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/70'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      {renderItemIcon(item)}
                      <div className="min-w-0">
                        <div className="text-xs font-semibold truncate">{item.title}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                          {item.subtitle}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      {isSearching && (
                        <span className="hidden sm:inline-block rounded bg-slate-100 dark:bg-slate-800/90 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 dark:text-slate-400">
                          {SHORT_CATEGORY_TAG[item.category]}
                        </span>
                      )}
                      {item.badge && (
                        <span
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${badgeColorClass(
                            item
                          )}`}
                        >
                          {item.badge}
                        </span>
                      )}
                      {isSelected && (
                        <CornerDownLeft className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400 shrink-0" />
                      )}
                    </div>
                  </button>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Shortcut Legend */}
        <div className="px-4 py-2 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1">
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.2 font-mono text-[10px]">
                ↑↓
              </kbd>
              <span>Navigate</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.2 font-mono text-[10px]">
                ↵
              </kbd>
              <span>Execute</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.2 font-mono text-[10px]">
                Esc
              </kbd>
              <span>Close</span>
            </span>
          </div>
          <span className="font-mono text-[10px] text-slate-400">
            {filteredItems.length} command{filteredItems.length === 1 ? '' : 's'}
          </span>
        </div>
      </div>
    </div>
  );
}
