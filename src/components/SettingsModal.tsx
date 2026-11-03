import { Clock, KeyRound, Plus, RotateCcw, Server, Trash2, X } from 'lucide-react';
import { useState } from 'react';
import { DEFAULT_DOH_ENDPOINT, type TrustAnchor } from '../dns/constants';
import { normalizeFqdn } from '../dns/encoding';
import type { AnalysisSnapshot } from '../dns/types';
import type { UserSettings } from '../storage/historyStore';

export function SettingsModal({
  open,
  settings,
  activeSnapshot,
  onClose,
  onSaveSettings,
  onReverifyAtTime,
}: {
  open: boolean;
  settings: UserSettings;
  activeSnapshot: AnalysisSnapshot | null;
  onClose: () => void;
  onSaveSettings: (next: UserSettings) => void;
  onReverifyAtTime: (timestampMs: number) => void;
}) {
  const [customZone, setCustomZone] = useState('.');
  const [customKeyTag, setCustomKeyTag] = useState('');
  const [customAlg, setCustomAlg] = useState('13');
  const [customDigestType, setCustomDigestType] = useState('2');
  const [customDigest, setCustomDigest] = useState('');
  const [customLabel, setCustomLabel] = useState('');

  const [customIsoTime, setCustomIsoTime] = useState(() =>
    new Date(activeSnapshot?.validatedAt ?? Date.now()).toISOString().slice(0, 16)
  );

  if (!open) return null;

  const handleAddAnchor = () => {
    const tag = Number.parseInt(customKeyTag, 10);
    const alg = Number.parseInt(customAlg, 10);
    const dt = Number.parseInt(customDigestType, 10);
    const hex = customDigest.replace(/\s+/g, '').toUpperCase();
    if (Number.isNaN(tag) || !/^[0-9A-F]{40,96}$/.test(hex)) return;

    const anchor: TrustAnchor = {
      id: `custom-${Date.now()}`,
      zone: normalizeFqdn(customZone),
      keyTag: tag,
      algorithm: alg,
      digestType: dt,
      digest: hex,
      label: customLabel.trim() || `Custom ${normalizeFqdn(customZone)} (#${tag})`,
      enabled: true,
    };

    onSaveSettings({
      ...settings,
      trustAnchors: [...settings.trustAnchors, anchor],
    });
    setCustomKeyTag('');
    setCustomDigest('');
    setCustomLabel('');
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl max-h-[88vh] flex flex-col overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h2 className="font-semibold text-base text-slate-900 dark:text-slate-100">
            Validator Settings, Trust Anchors &amp; Time-Travel
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto space-y-6 text-xs">
          {/* 1. DoH Endpoint */}
          <section className="space-y-2">
            <div className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-500">
              <Server className="w-3.5 h-3.5 text-cyan-500" />
              Cloudflare 1.1.1.1 DoH Endpoint (RFC 8484 Wireformat)
            </div>
            <div className="flex flex-wrap gap-2">
              {[
                ['https://1.1.1.1/dns-query', '1.1.1.1 Direct (Default)'],
                ['https://1.0.0.1/dns-query', '1.0.0.1 Secondary'],
                ['https://cloudflare-dns.com/dns-query', 'cloudflare-dns.com Hostname'],
              ].map(([url, label]) => (
                <button
                  key={url}
                  type="button"
                  onClick={() => onSaveSettings({ ...settings, dohEndpoint: url })}
                  className={`px-3 py-1.5 rounded-lg border font-mono text-xs cursor-pointer ${
                    settings.dohEndpoint === url
                      ? 'border-cyan-500 bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 font-semibold'
                      : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            {settings.dohEndpoint !== DEFAULT_DOH_ENDPOINT && (
              <button
                type="button"
                onClick={() =>
                  onSaveSettings({ ...settings, dohEndpoint: DEFAULT_DOH_ENDPOINT })
                }
                className="inline-flex items-center gap-1 text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer"
              >
                <RotateCcw className="w-3 h-3" /> Reset to https://1.1.1.1/dns-query
              </button>
            )}
          </section>

          {/* 2. Offline Time-Travel RRSIG Validation */}
          {activeSnapshot && (
            <section className="space-y-2 pt-4 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-500">
                <Clock className="w-3.5 h-3.5 text-cyan-500" />
                Offline RRSIG Time-Travel Re-Validation ({activeSnapshot.displayDomain})
              </div>
              <p className="text-slate-500">
                Re-evaluate all RRSIG inception/expiration windows on the current snapshot
                completely client-side without making new DNS queries.
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => onReverifyAtTime(activeSnapshot.capturedAt)}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 cursor-pointer font-medium"
                >
                  At Capture Time ({new Date(activeSnapshot.capturedAt).toLocaleTimeString()})
                </button>
                <button
                  type="button"
                  onClick={() => onReverifyAtTime(Date.now())}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 cursor-pointer font-medium"
                >
                  Validate Against Current Clock
                </button>
                <div className="flex items-center gap-1.5">
                  <input
                    type="datetime-local"
                    value={customIsoTime}
                    onChange={(e) => setCustomIsoTime(e.target.value)}
                    className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1 font-mono text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      const ts = Date.parse(customIsoTime);
                      if (!Number.isNaN(ts)) onReverifyAtTime(ts);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 font-semibold cursor-pointer"
                  >
                    Apply UTC/Local
                  </button>
                </div>
              </div>
            </section>
          )}

          {/* 3. Trust Anchors */}
          <section className="space-y-3 pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-500">
              <KeyRound className="w-3.5 h-3.5 text-cyan-500" />
              DNSSEC Trust Anchors
            </div>

            <div className="space-y-2">
              {settings.trustAnchors.map((ta) => (
                <div
                  key={ta.id}
                  className="rounded-lg border border-slate-200 dark:border-slate-800 p-3 flex items-start justify-between gap-3"
                >
                  <label className="flex items-start gap-2.5 cursor-pointer flex-1 min-w-0">
                    <input
                      type="checkbox"
                      checked={ta.enabled}
                      onChange={(e) => {
                        const updated = settings.trustAnchors.map((item) =>
                          item.id === ta.id ? { ...item, enabled: e.target.checked } : item
                        );
                        onSaveSettings({ ...settings, trustAnchors: updated });
                      }}
                      className="mt-0.5 accent-cyan-500"
                    />
                    <div className="min-w-0 space-y-0.5">
                      <div className="font-semibold text-slate-900 dark:text-slate-100">
                        {ta.label}{' '}
                        <span className="font-mono text-slate-500">
                          (Zone {ta.zone}, Alg {ta.algorithm}, Digest {ta.digestType})
                        </span>
                      </div>
                      <div className="font-mono text-[10px] text-slate-500 break-all">
                        {ta.digest}
                      </div>
                    </div>
                  </label>
                  {!ta.builtin && (
                    <button
                      type="button"
                      onClick={() =>
                        onSaveSettings({
                          ...settings,
                          trustAnchors: settings.trustAnchors.filter((x) => x.id !== ta.id),
                        })
                      }
                      className="p-1 text-slate-400 hover:text-rose-500 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Add Custom Trust Anchor Form */}
            <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 p-3.5 space-y-2.5">
              <div className="font-semibold text-slate-700 dark:text-slate-200">
                Add Custom DS Trust Anchor (Split-Horizon / Testing Zones)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <input
                  type="text"
                  value={customZone}
                  onChange={(e) => setCustomZone(e.target.value)}
                  placeholder="Zone (e.g. example.com.)"
                  className="rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 font-mono"
                />
                <input
                  type="text"
                  value={customKeyTag}
                  onChange={(e) => setCustomKeyTag(e.target.value)}
                  placeholder="Key Tag (e.g. 2371)"
                  className="rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 font-mono"
                />
                <input
                  type="text"
                  value={customAlg}
                  onChange={(e) => setCustomAlg(e.target.value)}
                  placeholder="Alg (8, 13, 15)"
                  className="rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 font-mono"
                />
                <select
                  value={customDigestType}
                  onChange={(e) => setCustomDigestType(e.target.value)}
                  className="rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2 py-1.5 font-mono"
                >
                  <option value="2">2 (SHA-256)</option>
                  <option value="4">4 (SHA-384)</option>
                  <option value="1">1 (SHA-1)</option>
                </select>
              </div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={customDigest}
                  onChange={(e) => setCustomDigest(e.target.value)}
                  placeholder="DS Hex Digest (SHA-256 / SHA-384)"
                  className="flex-1 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 font-mono"
                />
                <input
                  type="text"
                  value={customLabel}
                  onChange={(e) => setCustomLabel(e.target.value)}
                  placeholder="Optional label"
                  className="sm:w-40 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5"
                />
                <button
                  type="button"
                  onClick={handleAddAnchor}
                  className="inline-flex items-center justify-center gap-1 rounded-lg bg-cyan-500 px-3 py-1.5 font-semibold text-slate-950 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
