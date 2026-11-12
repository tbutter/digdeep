import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  KeyRound,
  Lock,
  Mail,
  Network,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { useState } from 'react';
import { downloadTextFile } from '../dns/digFormat';
import { displayFqdn } from '../dns/encoding';
import type { EmailDaneAnalysis } from '../dns/types';
import { CryptoBlob } from './CryptoBlob';
import { StatusBadge } from './StatusBadge';

export interface EmailDaneCardProps {
  emailDane: EmailDaneAnalysis;
  currentMode?: 'dnssec' | 'mail' | 'web' | 'consensus';
  onJumpToGraphTarget?: (targetId: string) => void;
  onInspectDomainMail?: (domain: string) => void;
}

function formatPgpFingerprintGroups(fpHex: string): string {
  const clean = fpHex.replace(/\s+/g, '').toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    groups.push(clean.slice(i, i + 4));
  }
  if (groups.length === 10) {
    return `${groups.slice(0, 5).join(' ')}  ${groups.slice(5).join(' ')}`;
  }
  return groups.join(' ');
}

function formatUtcDate(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString().slice(0, 10);
}

export function EmailDaneCard({
  emailDane,
  currentMode = 'dnssec',
  onJumpToGraphTarget,
  onInspectDomainMail,
}: EmailDaneCardProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedArmorIdx, setExpandedArmorIdx] = useState<Record<number, boolean>>({});
  const [expandedPemIdx, setExpandedPemIdx] = useState<Record<number, boolean>>({});

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1500);
  };

  const pgp = emailDane.openpgpkey;
  const smime = emailDane.smimea;

  const hasUnsignedPublished =
    (pgp?.status === 'present' && pgp.dnssecStatus === 'insecure') ||
    (smime?.status === 'present' && smime.dnssecStatus === 'insecure');
  const hasBogusPublished =
    (pgp?.status === 'present' && pgp.dnssecStatus === 'bogus') ||
    (smime?.status === 'present' && smime.dnssecStatus === 'bogus');

  const cleanDomain = displayFqdn(emailDane.domain);
  const safeFileBase = (emailDane.email ?? cleanDomain).replace(/[^a-z0-9._@-]/gi, '_');

  return (
    <section
      aria-label="Email DANE Identity (OPENPGPKEY & SMIMEA)"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-4 space-y-3.5"
    >
      {/* Header: Email -> SHA-256-224 Local-Part Hash Derivation */}
      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
        <div className="space-y-1.5 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
              <KeyRound className="w-3.5 h-3.5" />
              <span>DANE Email Identity</span>
            </span>
            {emailDane.email && (
              <span className="font-mono font-bold text-sm sm:text-base text-slate-900 dark:text-slate-100 break-all">
                {emailDane.email}
              </span>
            )}
            <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300">
              RFC 7929 (OPENPGPKEY) · RFC 8162 (SMIMEA)
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-400">
            {emailDane.localPart !== undefined && (
              <span>
                SHA-256-224(<code className="font-mono text-slate-800 dark:text-slate-200">&quot;{emailDane.localPart}&quot;</code>):
              </span>
            )}
            <CryptoBlob
              value={emailDane.exactHashHex}
              compact
              headChars={12}
              tailChars={10}
              copyLabel="Copy Hash"
              className="text-cyan-700 dark:text-cyan-300"
              testId="crypto-email-hash-exact"
            />
          </div>

          {emailDane.lowercaseHashHex && (
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
              <span>
                RFC 7929 §4 lowercase fallback (
                <code className="font-mono">&quot;{emailDane.localPart?.toLowerCase()}&quot;</code>):
              </span>
              <CryptoBlob
                value={emailDane.lowercaseHashHex}
                compact
                headChars={12}
                tailChars={10}
                copyLabel="Copy"
                testId="crypto-email-hash-lowercase"
              />
            </div>
          )}

          <p className="text-xs text-slate-600 dark:text-slate-400">{emailDane.summary}</p>
        </div>

        {onInspectDomainMail && currentMode !== 'mail' && (
          <button
            type="button"
            onClick={() => onInspectDomainMail(emailDane.email ?? cleanDomain)}
            className="inline-flex items-center gap-1.5 self-start rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer shrink-0"
          >
            <Mail className="w-3.5 h-3.5 text-cyan-500" />
            <span>Analyze {cleanDomain} Mail DNS</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
          </button>
        )}
      </div>

      {/* Mandatory DNSSEC Enforcement Warning Banner (RFC 7929 §5 / RFC 8162 §5) */}
      {(hasUnsignedPublished || hasBogusPublished) && (
        <div
          className={`rounded-lg border px-3 py-2.5 flex items-start gap-2.5 text-xs ${
            hasBogusPublished
              ? 'border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-200'
              : 'border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">
              {hasBogusPublished
                ? 'DNSSEC Validation Failed (BOGUS) — Cryptographic Identity MUST Be Rejected'
                : 'Unsigned Zone Detected — Published DANE Email Keys MUST NOT Be Trusted'}
            </div>
            <p className="text-[11px] opacity-90 mt-0.5">
              RFC 7929 §5 and RFC 8162 §5 strictly require DNSSEC validation before using{' '}
              <code className="font-mono">OPENPGPKEY</code> or <code className="font-mono">SMIMEA</code>{' '}
              records. Without a verified DNSSEC chain of trust, an active network attacker can spoof
              public keys and intercept end-to-end encrypted email.
            </p>
          </div>
        </div>
      )}

      {/* Protocol Panels: OPENPGPKEY & SMIMEA */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3.5">
        {/* 1. OPENPGPKEY (RFC 7929) */}
        {pgp && (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-3 flex flex-col justify-between">
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 text-emerald-800 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-mono text-xs font-bold">
                    <Lock className="w-3 h-3" />
                    OPENPGPKEY
                  </span>
                  <span className="font-mono text-[11px] text-slate-500">TYPE 61 · RFC 7929</span>
                  <StatusBadge status={pgp.dnssecStatus} size="xs" />
                  {pgp.status === 'present' ? (
                    pgp.daneUsable ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35 px-2 py-0.5 font-mono text-[10px] font-semibold">
                        <ShieldCheck className="w-3 h-3" />
                        DANE USABLE ✓
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35 px-2 py-0.5 font-mono text-[10px] font-semibold">
                        <AlertTriangle className="w-3 h-3" />
                        DO NOT TRUST ({pgp.dnssecStatus.toUpperCase()})
                      </span>
                    )
                  ) : (
                    <span className="rounded-full bg-slate-200 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-400">
                      {pgp.status.toUpperCase()}
                    </span>
                  )}
                </div>

                {(pgp.rrsetId || pgp.negativeNodeId) && onJumpToGraphTarget && (
                  <button
                    type="button"
                    onClick={() => onJumpToGraphTarget((pgp.rrsetId ?? pgp.negativeNodeId)!)}
                    className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                  >
                    <Network className="w-3 h-3 text-cyan-500" />
                    <span>Graph</span>
                  </button>
                )}
              </div>

              <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 break-all">
                Owner: <span className="text-slate-800 dark:text-slate-200">{displayFqdn(pgp.resolvedOwner)}</span>
                {pgp.usedLowercaseFallback && (
                  <span className="ml-1.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px]">
                    Matched lowercase fallback
                  </span>
                )}
              </div>

              {pgp.cnameChain.length > 0 && (
                <div className="text-[11px] font-mono text-indigo-600 dark:text-indigo-300 break-all">
                  CNAME → {pgp.cnameChain.map(displayFqdn).join(' → ')}
                </div>
              )}

              {pgp.status !== 'present' ? (
                <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/70 dark:bg-slate-900/50 p-3 text-xs text-slate-500 dark:text-slate-400">
                  No <code className="font-mono">OPENPGPKEY</code> RRset published at{' '}
                  <code className="font-mono break-all">{displayFqdn(pgp.queriedOwner)}</code> (
                  {pgp.status.toUpperCase()}
                  {pgp.dnssecStatus === 'secure' ? ' — cryptographically proven via NSEC/NSEC3' : ''}).
                </div>
              ) : (
                <div className="space-y-3">
                  {pgp.records.map((rec) => {
                    const dk = rec.decodedKey;
                    const armorOpen = Boolean(expandedArmorIdx[rec.index]);
                    return (
                      <div
                        key={rec.index}
                        className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 space-y-2.5 text-xs"
                      >
                        {rec.parseError || !dk ? (
                          <div className="space-y-1.5">
                            <div className="text-rose-600 dark:text-rose-400 font-mono text-[11px]">
                              Failed to parse OpenPGP key ({rec.byteLength}B): {rec.parseError}
                            </div>
                            {rec.keyBase64 && (
                              <CryptoBlob
                                value={rec.keyBase64}
                                collapseOnDesktop
                                headChars={16}
                                tailChars={12}
                                copyLabel="Copy Base64"
                                testId={`crypto-openpgpkey-raw-${rec.index}`}
                              />
                            )}
                          </div>
                        ) : (
                          <>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="rounded bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 px-1.5 py-0.5 font-mono text-[11px] font-semibold">
                                  OpenPGP v{dk.version} · {dk.algorithmName}
                                  {dk.curveOrBits ? ` (${dk.curveOrBits})` : ''}
                                </span>
                                {dk.keyFlags.map((fl) => (
                                  <span
                                    key={fl}
                                    className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300"
                                  >
                                    {fl}
                                  </span>
                                ))}
                                {dk.isRevoked && (
                                  <span className="rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40 px-1.5 py-0.5 font-mono text-[10px] font-bold">
                                    REVOKED
                                  </span>
                                )}
                                {dk.isExpired && (
                                  <span className="rounded bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40 px-1.5 py-0.5 font-mono text-[10px] font-bold">
                                    EXPIRED
                                  </span>
                                )}
                              </div>
                              <span className="font-mono text-[10px] text-slate-400">
                                TTL {rec.ttl}s · {dk.byteLength}B wire
                              </span>
                            </div>

                            {/* Primary Fingerprint */}
                            <div className="rounded bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 px-2.5 py-1.5 space-y-1">
                              <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                                Primary Key Fingerprint (Key ID 0x{dk.keyIdHex})
                              </div>
                              <CryptoBlob
                                value={formatPgpFingerprintGroups(dk.fingerprintHex)}
                                copyValue={dk.fingerprintHex}
                                compact
                                headChars={19}
                                tailChars={14}
                                copyLabel="Copy"
                                className="font-semibold text-emerald-700 dark:text-emerald-300 w-full justify-between"
                                testId={`crypto-openpgpkey-fp-${rec.index}`}
                              />
                            </div>

                            {/* Timestamps */}
                            <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                              <span>Created: {formatUtcDate(dk.createdAtSec)}</span>
                              <span>
                                Expires:{' '}
                                {dk.expiresAtSec ? formatUtcDate(dk.expiresAtSec) : 'Never (no expiry)'}
                              </span>
                            </div>

                            {/* User IDs */}
                            {dk.userIds.length > 0 && (
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                    User IDs ({dk.userIds.length})
                                  </span>
                                  {dk.matchesQueriedEmail !== undefined && (
                                    <span
                                      className={`inline-flex items-center gap-1 font-mono text-[10px] font-semibold ${
                                        dk.matchesQueriedEmail
                                          ? 'text-emerald-600 dark:text-emerald-400'
                                          : 'text-amber-600 dark:text-amber-400'
                                      }`}
                                    >
                                      {dk.matchesQueriedEmail ? (
                                        <>
                                          <CheckCircle2 className="w-3 h-3" />
                                          UID MATCHES EMAIL
                                        </>
                                      ) : (
                                        <>
                                          <AlertTriangle className="w-3 h-3" />
                                          UID EMAIL MISMATCH
                                        </>
                                      )}
                                    </span>
                                  )}
                                </div>
                                <ul className="space-y-0.5 font-mono text-[11px] text-slate-800 dark:text-slate-200">
                                  {dk.userIds.map((uid) => (
                                    <li key={uid} className="truncate" title={uid}>
                                      • {uid}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* Subkeys */}
                            {dk.subkeys.length > 0 && (
                              <div className="space-y-1">
                                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                  Subkeys ({dk.subkeys.length})
                                </div>
                                <div className="space-y-1">
                                  {dk.subkeys.map((sk) => (
                                    <div
                                      key={sk.fingerprintHex}
                                      className="rounded border border-slate-200/70 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-2 py-1 flex flex-wrap items-center justify-between gap-1.5 font-mono text-[10px]"
                                    >
                                      <span className="text-slate-700 dark:text-slate-200">
                                        0x{sk.keyIdHex} · {sk.algorithmName}
                                        {sk.curveOrBits ? ` (${sk.curveOrBits})` : ''}
                                      </span>
                                      <span className="text-slate-500">
                                        {sk.keyFlags.join(', ') || 'Subkey'}
                                        {sk.isRevoked
                                          ? ' · REVOKED'
                                          : sk.isExpired
                                            ? ' · EXPIRED'
                                            : sk.expiresAtSec
                                              ? ` · exp ${formatUtcDate(sk.expiresAtSec)}`
                                              : ''}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Armored PGP Actions */}
                            <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-100 dark:border-slate-800">
                              <button
                                type="button"
                                onClick={() =>
                                  setExpandedArmorIdx((prev) => ({
                                    ...prev,
                                    [rec.index]: !prev[rec.index],
                                  }))
                                }
                                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                              >
                                {armorOpen ? (
                                  <ChevronDown className="w-3 h-3" />
                                ) : (
                                  <ChevronRight className="w-3 h-3" />
                                )}
                                <span>ASCII-Armored Key</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => copyText(`pgp-armor-${rec.index}`, dk.armoredPublicKey)}
                                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                              >
                                {copiedId === `pgp-armor-${rec.index}` ? (
                                  <Check className="w-3 h-3 text-emerald-500" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                                <span>
                                  {copiedId === `pgp-armor-${rec.index}` ? 'Copied .asc' : 'Copy .asc'}
                                </span>
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  downloadTextFile(
                                    dk.armoredPublicKey,
                                    `${safeFileBase}-${dk.keyIdHex}.asc`
                                  )
                                }
                                className="inline-flex items-center gap-1 rounded border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 text-[11px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
                              >
                                <Download className="w-3 h-3" />
                                <span>Download .asc</span>
                              </button>
                            </div>

                            {armorOpen && (
                              <pre className="rounded bg-slate-950 text-slate-200 p-2.5 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-48">
                                {dk.armoredPublicKey}
                              </pre>
                            )}
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* CLI gpg verification command */}
            <div className="pt-2 border-t border-slate-200/80 dark:border-slate-800 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 min-w-0 flex-1">
                <Terminal className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <code className="font-mono text-[10px] text-slate-600 dark:text-slate-300 truncate">
                  {pgp.cliVerifyCommand}
                </code>
              </div>
              <button
                type="button"
                onClick={() => copyText('cli-pgp', pgp.cliVerifyCommand)}
                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-300 shrink-0 cursor-pointer"
              >
                {copiedId === 'cli-pgp' ? (
                  <Check className="w-3 h-3 text-emerald-500" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{copiedId === 'cli-pgp' ? 'Copied' : 'Copy gpg CLI'}</span>
              </button>
            </div>
          </div>
        )}

        {/* 2. SMIMEA (RFC 8162) */}
        {smime && (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-3 flex flex-col justify-between">
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded bg-indigo-500/15 text-indigo-800 dark:text-indigo-300 border border-indigo-500/30 px-2 py-0.5 font-mono text-xs font-bold">
                    <ShieldCheck className="w-3 h-3" />
                    SMIMEA
                  </span>
                  <span className="font-mono text-[11px] text-slate-500">TYPE 53 · RFC 8162</span>
                  <StatusBadge status={smime.dnssecStatus} size="xs" />
                  {smime.status === 'present' ? (
                    smime.daneUsable ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35 px-2 py-0.5 font-mono text-[10px] font-semibold">
                        <ShieldCheck className="w-3 h-3" />
                        DANE USABLE ✓
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35 px-2 py-0.5 font-mono text-[10px] font-semibold">
                        <AlertTriangle className="w-3 h-3" />
                        DO NOT TRUST ({smime.dnssecStatus.toUpperCase()})
                      </span>
                    )
                  ) : (
                    <span className="rounded-full bg-slate-200 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-400">
                      {smime.status.toUpperCase()}
                    </span>
                  )}
                </div>

                {(smime.rrsetId || smime.negativeNodeId) && onJumpToGraphTarget && (
                  <button
                    type="button"
                    onClick={() => onJumpToGraphTarget((smime.rrsetId ?? smime.negativeNodeId)!)}
                    className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                  >
                    <Network className="w-3 h-3 text-cyan-500" />
                    <span>Graph</span>
                  </button>
                )}
              </div>

              <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 break-all">
                Owner:{' '}
                <span className="text-slate-800 dark:text-slate-200">
                  {displayFqdn(smime.resolvedOwner)}
                </span>
                {smime.usedLowercaseFallback && (
                  <span className="ml-1.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 text-[10px]">
                    Matched lowercase fallback
                  </span>
                )}
              </div>

              {smime.cnameChain.length > 0 && (
                <div className="text-[11px] font-mono text-indigo-600 dark:text-indigo-300 break-all">
                  CNAME → {smime.cnameChain.map(displayFqdn).join(' → ')}
                </div>
              )}

              {smime.status !== 'present' ? (
                <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/70 dark:bg-slate-900/50 p-3 text-xs text-slate-500 dark:text-slate-400">
                  No <code className="font-mono">SMIMEA</code> RRset published at{' '}
                  <code className="font-mono break-all">{displayFqdn(smime.queriedOwner)}</code> (
                  {smime.status.toUpperCase()}
                  {smime.dnssecStatus === 'secure' ? ' — cryptographically proven via NSEC/NSEC3' : ''}).
                </div>
              ) : (
                <div className="space-y-3">
                  {smime.records.map((rec) => {
                    const cert = rec.decodedCert;
                    const spki = rec.decodedSpki;
                    const pemOpen = Boolean(expandedPemIdx[rec.index]);
                    return (
                      <div
                        key={rec.index}
                        className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 space-y-2.5 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-1.5">
                          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                            <span className="rounded bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 px-1.5 py-0.5 font-semibold">
                              {rec.usage} ({rec.usageMnemonic})
                            </span>
                            <span className="rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 px-1.5 py-0.5">
                              {rec.selector} ({rec.selectorMnemonic})
                            </span>
                            <span className="rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 px-1.5 py-0.5">
                              {rec.matchingType} ({rec.matchingMnemonic})
                            </span>
                          </div>
                          <span className="font-mono text-[10px] text-slate-400">
                            TTL {rec.ttl}s · {rec.byteLength}B
                          </span>
                        </div>

                        {rec.parseError && (
                          <div className="text-rose-600 dark:text-rose-400 font-mono text-[11px]">
                            DER parse error: {rec.parseError}
                          </div>
                        )}

                        {cert ? (
                          <div className="space-y-2">
                            <div className="grid grid-cols-1 gap-1 font-mono text-[11px]">
                              <div>
                                <span className="text-slate-400">Subject: </span>
                                <span className="text-slate-800 dark:text-slate-100 break-all">
                                  {cert.subject}
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-400">Issuer: </span>
                                <span className="text-slate-700 dark:text-slate-300 break-all">
                                  {cert.issuer}
                                </span>
                                {cert.isSelfIssued && (
                                  <span className="ml-1.5 rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-500">
                                    Self-Issued
                                  </span>
                                )}
                              </div>
                              {cert.sanRfc822Names.length > 0 && (
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span className="text-slate-400">SAN rfc822Name:</span>
                                  <span className="text-cyan-700 dark:text-cyan-300">
                                    {cert.sanRfc822Names.join(', ')}
                                  </span>
                                  {cert.matchesQueriedEmail !== undefined && (
                                    <span
                                      className={`text-[10px] font-semibold ${
                                        cert.matchesQueriedEmail
                                          ? 'text-emerald-600 dark:text-emerald-400'
                                          : 'text-amber-600 dark:text-amber-400'
                                      }`}
                                    >
                                      {cert.matchesQueriedEmail ? '✓ Match' : '⚠ Mismatch'}
                                    </span>
                                  )}
                                </div>
                              )}
                              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-500">
                                <span>
                                  Key: {cert.publicKeyAlgorithm}
                                  {cert.publicKeyBitsOrCurve ? ` (${cert.publicKeyBitsOrCurve})` : ''}
                                </span>
                                <span>Sig: {cert.signatureAlgorithm}</span>
                                <span>Serial: {cert.serialHex}</span>
                              </div>
                              <div className="flex flex-wrap items-center gap-2 text-[10px]">
                                <span className="text-slate-500">
                                  Validity: {cert.notBeforeIso.slice(0, 10)} →{' '}
                                  {cert.notAfterIso.slice(0, 10)}
                                </span>
                                {cert.isExpired ? (
                                  <span className="rounded bg-rose-500/20 text-rose-600 dark:text-rose-300 px-1.5 py-0.5 font-bold">
                                    EXPIRED
                                  </span>
                                ) : cert.isNotYetValid ? (
                                  <span className="rounded bg-amber-500/20 text-amber-600 dark:text-amber-300 px-1.5 py-0.5 font-bold">
                                    NOT YET VALID
                                  </span>
                                ) : (
                                  <span className="rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-1.5 py-0.5 font-semibold">
                                    VALID
                                  </span>
                                )}
                                {cert.hasEmailProtectionEku && (
                                  <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5">
                                    EKU: emailProtection
                                  </span>
                                )}
                              </div>
                              <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-slate-500">
                                <span>SHA-256:</span>
                                <CryptoBlob
                                  value={cert.sha256FingerprintHex}
                                  compact
                                  headChars={14}
                                  tailChars={10}
                                  copyLabel="Copy SHA-256"
                                  testId={`crypto-smimea-cert-fp-${rec.index}`}
                                />
                              </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-100 dark:border-slate-800">
                              <button
                                type="button"
                                onClick={() =>
                                  setExpandedPemIdx((prev) => ({
                                    ...prev,
                                    [rec.index]: !prev[rec.index],
                                  }))
                                }
                                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                              >
                                {pemOpen ? (
                                  <ChevronDown className="w-3 h-3" />
                                ) : (
                                  <ChevronRight className="w-3 h-3" />
                                )}
                                <span>X.509 PEM</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => copyText(`smime-pem-${rec.index}`, cert.pem)}
                                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                              >
                                {copiedId === `smime-pem-${rec.index}` ? (
                                  <Check className="w-3 h-3 text-emerald-500" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                                <span>
                                  {copiedId === `smime-pem-${rec.index}` ? 'Copied PEM' : 'Copy PEM'}
                                </span>
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  downloadTextFile(cert.pem, `${safeFileBase}-smime-${rec.index}.pem`)
                                }
                                className="inline-flex items-center gap-1 rounded border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 text-[11px] font-medium text-cyan-700 dark:text-cyan-300 cursor-pointer"
                              >
                                <Download className="w-3 h-3" />
                                <span>Download .pem</span>
                              </button>
                            </div>

                            {pemOpen && (
                              <pre className="rounded bg-slate-950 text-slate-200 p-2.5 font-mono text-[10px] leading-relaxed overflow-x-auto max-h-48">
                                {cert.pem}
                              </pre>
                            )}
                          </div>
                        ) : spki ? (
                          <div className="space-y-1.5 font-mono text-[11px]">
                            <div>
                              Public Key: {spki.publicKeyAlgorithm}
                              {spki.publicKeyBitsOrCurve ? ` (${spki.publicKeyBitsOrCurve})` : ''}
                            </div>
                            <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-slate-500">
                              <span>SPKI SHA-256:</span>
                              <CryptoBlob
                                value={spki.spkiSha256Hex}
                                compact
                                headChars={14}
                                tailChars={10}
                                copyLabel="Copy SPKI Hash"
                                testId={`crypto-smimea-spki-fp-${rec.index}`}
                              />
                            </div>
                            <button
                              type="button"
                              onClick={() => copyText(`spki-pem-${rec.index}`, spki.pem)}
                              className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-1 text-[10px] font-sans font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                            >
                              {copiedId === `spki-pem-${rec.index}` ? (
                                <Check className="w-3 h-3 text-emerald-500" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                              <span>Copy SPKI PEM</span>
                            </button>
                          </div>
                        ) : (
                          <div className="space-y-1">
                            <div className="font-mono text-[10px] text-slate-500">
                              Association Data ({rec.matchingMnemonic}):
                            </div>
                            <CryptoBlob
                              value={rec.certAssociationHex}
                              headChars={16}
                              tailChars={12}
                              copyLabel="Copy Hex"
                              testId={`crypto-smimea-assoc-${rec.index}`}
                            />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* CLI openssl / dig verification command */}
            <div className="pt-2 border-t border-slate-200/80 dark:border-slate-800 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 min-w-0 flex-1">
                <Terminal className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <code className="font-mono text-[10px] text-slate-600 dark:text-slate-300 truncate">
                  {smime.cliVerifyCommand}
                </code>
              </div>
              <button
                type="button"
                onClick={() => copyText('cli-smime', smime.cliVerifyCommand)}
                className="inline-flex items-center gap-1 rounded border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-300 shrink-0 cursor-pointer"
              >
                {copiedId === 'cli-smime' ? (
                  <Check className="w-3 h-3 text-emerald-500" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{copiedId === 'cli-smime' ? 'Copied' : 'Copy openssl CLI'}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
