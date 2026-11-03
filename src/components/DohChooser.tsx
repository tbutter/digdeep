import { Check, ChevronDown, Plus, Server, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  DOH_SERVER_PRESETS,
  formatDohShortLabel,
  normalizeDohEndpoint,
} from '../dns/constants';
import type { UserSettings } from '../storage/historyStore';

export function DohChooser({
  settings,
  onSaveSettings,
}: {
  settings: UserSettings;
  onSaveSettings: (next: UserSettings) => void;
}) {
  const [open, setOpen] = useState(false);
  const [manualInput, setManualInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    window.addEventListener('mousedown', onPointerDown);
    return () => window.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const handleSelect = (url: string) => {
    onSaveSettings({ ...settings, dohEndpoint: url });
    setOpen(false);
    setInputError(null);
  };

  const handleManualSubmit = (e: FormEvent) => {
    e.preventDefault();
    const normalized = normalizeDohEndpoint(manualInput);
    if (!normalized) {
      setInputError('Enter a valid HTTPS DoH URL or hostname/IP (e.g. https://8.8.4.4/dns-query)');
      return;
    }
    const isBuiltin = DOH_SERVER_PRESETS.some((p) => p.url === normalized);
    const nextCustom =
      !isBuiltin && !settings.customDohEndpoints.includes(normalized)
        ? [normalized, ...settings.customDohEndpoints]
        : settings.customDohEndpoints;

    onSaveSettings({
      ...settings,
      dohEndpoint: normalized,
      customDohEndpoints: nextCustom,
    });
    setManualInput('');
    setInputError(null);
    setOpen(false);
  };

  const handleRemoveCustom = (url: string) => {
    const nextCustom = settings.customDohEndpoints.filter((u) => u !== url);
    onSaveSettings({
      ...settings,
      dohEndpoint:
        settings.dohEndpoint === url ? DOH_SERVER_PRESETS[0].url : settings.dohEndpoint,
      customDohEndpoints: nextCustom,
    });
  };

  const activeLabel = formatDohShortLabel(settings.dohEndpoint);

  return (
    <div ref={wrapperRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="h-full inline-flex items-center justify-between gap-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-cyan-500 px-3.5 py-2.5 text-xs font-medium text-slate-800 dark:text-slate-200 transition-colors cursor-pointer shrink-0"
        title={`Active DoH server: ${settings.dohEndpoint}`}
      >
        <span className="inline-flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
          <span className="text-slate-500 dark:text-slate-400">DoH:</span>
          <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
            {activeLabel}
          </span>
        </span>
        <ChevronDown
          className={`w-3.5 h-3.5 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl z-50 overflow-hidden text-xs">
          <div className="px-3.5 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60">
            <div className="font-semibold text-slate-900 dark:text-slate-100">
              DNS-over-HTTPS (DoH) Resolver
            </div>
            <div className="text-[11px] text-slate-500">
              Queries run directly from your browser via RFC 8484 wireformat
            </div>
          </div>

          <div className="max-h-64 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/70">
            {DOH_SERVER_PRESETS.map((preset) => {
              const active = settings.dohEndpoint === preset.url;
              return (
                <button
                  key={preset.url}
                  type="button"
                  onClick={() => handleSelect(preset.url)}
                  className={`w-full text-left px-3.5 py-2 flex items-center justify-between gap-2 transition-colors cursor-pointer ${
                    active
                      ? 'bg-cyan-500/10'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {preset.shortLabel}
                      </span>
                      <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-600 dark:text-slate-300">
                        {preset.provider}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 truncate">{preset.description}</div>
                  </div>
                  {active && <Check className="w-4 h-4 text-cyan-500 shrink-0" />}
                </button>
              );
            })}

            {settings.customDohEndpoints.map((url) => {
              const active = settings.dohEndpoint === url;
              return (
                <div
                  key={url}
                  className={`px-3.5 py-2 flex items-center justify-between gap-2 ${
                    active
                      ? 'bg-cyan-500/10'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => handleSelect(url)}
                    className="flex-1 text-left min-w-0 cursor-pointer"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-slate-900 dark:text-slate-100 truncate">
                        {formatDohShortLabel(url)}
                      </span>
                      <span className="rounded bg-violet-500/15 text-violet-600 dark:text-violet-300 px-1.5 py-0.5 text-[10px]">
                        Custom
                      </span>
                    </div>
                    <div className="font-mono text-[10px] text-slate-500 truncate">{url}</div>
                  </button>
                  <div className="flex items-center gap-1 shrink-0">
                    {active && <Check className="w-4 h-4 text-cyan-500" />}
                    <button
                      type="button"
                      onClick={() => handleRemoveCustom(url)}
                      className="p-1 rounded text-slate-400 hover:text-rose-500 cursor-pointer"
                      title="Remove custom DoH server"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          <form
            onSubmit={handleManualSubmit}
            className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 space-y-1.5"
          >
            <label className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Custom DoH URL or IP/Hostname
            </label>
            <div className="flex gap-1.5">
              <input
                type="text"
                value={manualInput}
                onChange={(e) => {
                  setManualInput(e.target.value);
                  if (inputError) setInputError(null);
                }}
                placeholder="https://8.8.4.4/dns-query"
                className="flex-1 min-w-0 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1 rounded-lg bg-cyan-500 hover:bg-cyan-400 px-3 py-1.5 font-semibold text-slate-950 cursor-pointer shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                Use
              </button>
            </div>
            {inputError && <div className="text-[11px] text-rose-500">{inputError}</div>}
          </form>
        </div>
      )}
    </div>
  );
}
