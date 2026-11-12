import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardPaste,
  FileCode2,
  KeyRound,
  Loader2,
  Lock,
  MailCheck,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import {
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  type EmailMessageVerificationReport,
  type SignatureVerificationVerdict,
  type VerifiedDkimSignatureResult,
  verifyEmailMessageCryptographically,
} from '../dns/emailHeaderVerifier';
import { displayFqdn } from '../dns/encoding';
import type { AnalysisSnapshot } from '../dns/types';
import {
  type FocusedWireSubMode,
  findWireQueryByOwnerAndType,
} from '../dns/wireQueryFilter';
import { CryptoBlob } from './CryptoBlob';
import { IpHoverBadge, seedIpAsnCacheFromSnapshot } from './IpHoverBadge';
import { StatusBadge } from './StatusBadge';

export interface EmailHeaderVerifierCardProps {
  snapshot: AnalysisSnapshot;
  loading?: boolean;
  externalRawEmail?: { payload: string; seq: number } | null;
  onSwitchMailDomain?: (domain: string, dkimSelectors: string[]) => void;
  onJumpToGraphTarget?: (targetId: string) => void;
  onInspectWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
}

function getOverallBannerMeta(verdict: EmailMessageVerificationReport['overallVerdict']): {
  label: string;
  badgeCls: string;
  cardCls: string;
} {
  switch (verdict) {
    case 'pass':
      return {
        label: 'CRYPTO & DMARC PASS',
        badgeCls:
          'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40',
        cardCls: 'border-emerald-500/45 bg-emerald-500/5',
      };
    case 'pass-headers-only':
      return {
        label: 'HEADERS VERIFIED (NO BODY)',
        badgeCls:
          'bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/40',
        cardCls: 'border-cyan-500/45 bg-cyan-500/5',
      };
    case 'warning':
      return {
        label: 'PARTIAL / WARNING',
        badgeCls:
          'bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40',
        cardCls: 'border-amber-500/45 bg-amber-500/5',
      };
    case 'fail':
      return {
        label: 'VERIFICATION FAILED',
        badgeCls:
          'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40',
        cardCls: 'border-rose-500/45 bg-rose-500/5',
      };
    case 'unauthenticated':
      return {
        label: 'UNAUTHENTICATED',
        badgeCls:
          'bg-slate-500/20 text-slate-700 dark:text-slate-300 border border-slate-500/40',
        cardCls: 'border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950/60',
      };
  }
}

function getSignatureVerdictMeta(verdict: SignatureVerificationVerdict): {
  label: string;
  cls: string;
} {
  switch (verdict) {
    case 'pass':
      return {
        label: 'CRYPTO PASS ✓',
        cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35',
      };
    case 'headers-verified-only':
      return {
        label: 'HEADERS VALID (NO BODY)',
        cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/35',
      };
    case 'policy-fail':
      return {
        label: 'POLICY REJECTED (RFC 8301)',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'fail':
      return {
        label: 'CRYPTO FAIL ✗',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
    case 'temperror':
      return {
        label: 'TEMPERROR (DNSSEC BOGUS)',
        cls: 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40',
      };
    case 'permerror':
      return {
        label: 'PERMERROR',
        cls: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
      };
  }
}

function SignatureVerificationDetailCard({
  res,
  snapshot,
  onJumpToGraphTarget,
  onInspectWireQuery,
  compactTitle,
}: {
  res: VerifiedDkimSignatureResult;
  snapshot: AnalysisSnapshot;
  onJumpToGraphTarget?: (targetId: string) => void;
  onInspectWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
  compactTitle?: string;
}) {
  const [showSignedHeaders, setShowSignedHeaders] = useState(false);
  const sig = res.signature;
  const verdictMeta = getSignatureVerdictMeta(res.verdict);
  const sel = res.dnsSelector;
  const inSnapshotWire =
    sel && onInspectWireQuery
      ? findWireQueryByOwnerAndType(snapshot.queries, sel.qname, 'TXT')
      : undefined;
  const inSnapshotGraphTarget =
    sel && snapshot.zones.some((z) => sel.qname.endsWith(z.zoneName))
      ? (sel.txtRrsetId ?? sel.negativeNodeId)
      : undefined;

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-3.5 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {compactTitle && (
            <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] font-bold text-slate-800 dark:text-slate-100">
              {compactTitle}
            </span>
          )}
          <span className="rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
            d={sig.domain || '?'}
          </span>
          <span className="rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-2 py-0.5 font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
            s={sig.selector || '?'}
          </span>
          <span className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
            a={sig.algorithm || '?'}
          </span>
          <span className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
            c={sig.kind === 'arc-seal' ? 'relaxed' : `${sig.headerCanon}/${sig.bodyCanon}`}
          </span>
          {res.dmarcAligned && (
            <span
              className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${
                res.dmarcAligned.aligned
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                  : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
              }`}
              title={`DMARC alignment (adkim=${res.dmarcAligned.mode}): d=${res.dmarcAligned.candidateDomain} vs From=${res.dmarcAligned.fromDomain}`}
            >
              {res.dmarcAligned.aligned
                ? `DMARC ALIGNED (${res.dmarcAligned.matchKind})`
                : `UNALIGNED (adkim=${res.dmarcAligned.mode})`}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <StatusBadge status={res.dnssecStatus} size="xs" />
          <span className={`rounded-full px-2.5 py-0.5 font-mono text-[10px] font-bold ${verdictMeta.cls}`}>
            {verdictMeta.label}
          </span>
          {inSnapshotGraphTarget && onJumpToGraphTarget && (
            <button
              type="button"
              onClick={() => onJumpToGraphTarget(inSnapshotGraphTarget)}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2 py-0.5 text-[11px] font-medium text-cyan-600 dark:text-cyan-400 hover:border-cyan-500 cursor-pointer"
            >
              <span>Chain</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
          {inSnapshotWire && onInspectWireQuery && (
            <button
              type="button"
              onClick={() => onInspectWireQuery(inSnapshotWire.id, 'dig')}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 cursor-pointer"
            >
              <span>Wire</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Cryptographic Sub-Check Matrix */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
        <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-2.5 py-1.5">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Header Signature (b=)
          </div>
          <div
            className={`font-mono font-semibold mt-0.5 ${
              res.headerCryptoValid === true
                ? 'text-emerald-600 dark:text-emerald-400'
                : res.headerCryptoValid === false
                  ? 'text-rose-600 dark:text-rose-400'
                  : 'text-amber-600 dark:text-amber-400'
            }`}
          >
            {res.headerCryptoValid === true
              ? 'WebCrypto VALID ✓'
              : res.headerCryptoValid === false
                ? 'WebCrypto INVALID ✗'
                : 'Not Checked (Key Unavailable)'}
          </div>
        </div>

        {sig.kind !== 'arc-seal' && (
          <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-2.5 py-1.5">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Body Hash (bh=)
            </div>
            <div
              className={`font-mono font-semibold mt-0.5 ${
                res.bodyHashStatus === 'match'
                  ? 'text-emerald-600 dark:text-emerald-400'
                  : res.bodyHashStatus === 'unchecked-no-body'
                    ? 'text-cyan-600 dark:text-cyan-400'
                    : 'text-rose-600 dark:text-rose-400'
              }`}
            >
              {res.bodyHashStatus === 'match'
                ? `MATCH ✓ (${res.canonicalBodyByteLength ?? 0}B${
                    sig.bodyLengthLimit !== undefined ? `, l=${sig.bodyLengthLimit}` : ''
                  })`
                : res.bodyHashStatus === 'unchecked-no-body'
                  ? 'UNCHECKED (Headers-Only)'
                  : res.bodyHashStatus === 'length-exceeded'
                    ? `INVALID l=${sig.bodyLengthLimit}`
                    : 'MISMATCH ✗ (Body Altered)'}
            </div>
          </div>
        )}

        <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-2.5 py-1.5">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            DNS _domainkey Public Key
          </div>
          <div className="font-mono font-semibold mt-0.5 text-slate-800 dark:text-slate-200 truncate">
            {!sel || !sel.present
              ? 'Missing in DNS'
              : sel.status === 'revoked'
                ? 'Revoked (empty p=)'
                : sel.keyType === 'ed25519'
                  ? 'Ed25519 (256-bit)'
                  : sel.keyBits
                    ? `RSA ${sel.keyBits}-bit`
                    : sel.keyType.toUpperCase()}
          </div>
        </div>
      </div>

      {/* Timestamps & CNAME info if present */}
      {(res.timestampEvaluation.signedAtIso ||
        res.timestampEvaluation.expiresAtIso ||
        (sel && sel.cnameChain.length > 0)) && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400">
          {res.timestampEvaluation.signedAtIso && (
            <span>Signed t={res.timestampEvaluation.signedAtIso.replace('.000Z', 'Z')}</span>
          )}
          {res.timestampEvaluation.expiresAtIso && (
            <span
              className={
                res.timestampEvaluation.expiredAtReceipt
                  ? 'text-rose-600 dark:text-rose-400 font-semibold'
                  : res.timestampEvaluation.expiredNow
                    ? 'text-amber-600 dark:text-amber-400'
                    : ''
              }
            >
              Expires x={res.timestampEvaluation.expiresAtIso.replace('.000Z', 'Z')}
              {res.timestampEvaluation.expiredAtReceipt === false && res.timestampEvaluation.expiredNow
                ? ' (valid at receipt)'
                : ''}
            </span>
          )}
          {sel && sel.cnameChain.length > 0 && (
            <span className="inline-flex items-center gap-1 text-cyan-600 dark:text-cyan-400">
              <span>CNAME</span>
              <ArrowRight className="w-3 h-3" />
              <span>{sel.cnameChain.map(displayFqdn).join(' → ')}</span>
            </span>
          )}
        </div>
      )}

      {/* Body Hash diff on mismatch */}
      {res.bodyHashStatus === 'mismatch' && res.computedBodyHashBase64 && (
        <div className="rounded-lg border border-rose-500/35 bg-rose-500/5 p-2.5 space-y-1 font-mono text-[11px]">
          <div className="text-slate-600 dark:text-slate-300 break-all">
            <span className="font-semibold text-slate-500">Header bh=  :</span>{' '}
            {sig.bodyHashBase64}
          </div>
          <div className="text-rose-700 dark:text-rose-300 break-all">
            <span className="font-semibold">Computed bh=:</span> {res.computedBodyHashBase64}
          </div>
        </div>
      )}

      {/* Issues & Warnings */}
      {res.issues.length > 0 && (
        <div className="space-y-1">
          {res.issues.map((iss, idx) => (
            <div
              key={`sig-iss-${idx}`}
              className="text-xs text-rose-600 dark:text-rose-400 flex items-start gap-1.5"
            >
              <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{iss}</span>
            </div>
          ))}
        </div>
      )}

      {res.warnings.length > 0 && (
        <div className="space-y-1">
          {res.warnings.map((warn, idx) => (
            <div
              key={`sig-warn-${idx}`}
              className="text-xs text-amber-700 dark:text-amber-300 flex items-start gap-1.5"
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{warn}</span>
            </div>
          ))}
        </div>
      )}

      {/* Signed h= headers toggle */}
      {res.matchedSignedHeaders.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setShowSignedHeaders((v) => !v)}
            className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 cursor-pointer"
          >
            {showSignedHeaders ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
            <span>
              Signed Header Fields (h= · {res.matchedSignedHeaders.filter((m) => !m.oversigned).length}{' '}
              matched
              {res.matchedSignedHeaders.some((m) => m.oversigned)
                ? `, ${res.matchedSignedHeaders.filter((m) => m.oversigned).length} oversigned`
                : ''}
              )
            </span>
          </button>

          {showSignedHeaders && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {res.matchedSignedHeaders.map((mh, idx) => (
                <span
                  key={`mh-${idx}-${mh.requestedName}`}
                  title={
                    mh.oversigned
                      ? 'Oversigned header (not present/unconsumed in message — protects against future header injection)'
                      : `Matched message header #${(mh.matchedHeaderIndex ?? 0) + 1}`
                  }
                  className={`rounded px-1.5 py-0.5 font-mono text-[10px] border ${
                    mh.oversigned
                      ? 'bg-slate-100/70 dark:bg-slate-900 text-slate-400 border-dashed border-slate-300 dark:border-slate-700'
                      : mh.requestedName === 'from'
                        ? 'bg-emerald-500/15 text-emerald-800 dark:text-emerald-200 border-emerald-500/35 font-bold'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                  }`}
                >
                  {mh.requestedName}
                  {mh.oversigned ? ' (oversigned)' : ''}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {sel?.rawRecord && (
        <CryptoBlob
          value={sel.rawRecord}
          headChars={28}
          tailChars={12}
          copyLabel="Copy Key TXT"
          collapseOnDesktop
        />
      )}
    </div>
  );
}

export function EmailHeaderVerifierCard({
  snapshot,
  loading = false,
  externalRawEmail,
  onSwitchMailDomain,
  onJumpToGraphTarget,
  onInspectWireQuery,
}: EmailHeaderVerifierCardProps) {
  const [expanded, setExpanded] = useState(() => Boolean(externalRawEmail?.payload));
  const [rawInput, setRawInput] = useState(() => externalRawEmail?.payload ?? '');
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<EmailMessageVerificationReport | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const lastHandledSeqRef = useRef<number | null>(null);

  const runVerification = useCallback(
    async (textToVerify: string) => {
      const trimmed = textToVerify.trim();
      if (!trimmed) {
        setError('Paste raw email headers ("Show Original") or load an .eml file to verify.');
        return;
      }
      setVerifying(true);
      setError(null);
      try {
        const res = await verifyEmailMessageCryptographically(textToVerify, {
          snapshot,
          endpoint: snapshot.dohEndpoint,
        });
        seedIpAsnCacheFromSnapshot({
          ...snapshot,
          queries: res.allQueries,
        });
        setReport(res);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to verify email headers.');
      } finally {
        setVerifying(false);
      }
    },
    [snapshot]
  );

  // Automatically populate and verify when raw email headers are pasted into the top omnibox
  useEffect(() => {
    if (!externalRawEmail?.payload) return;
    setExpanded(true);
    setRawInput(externalRawEmail.payload);
    if (loading) return;
    if (lastHandledSeqRef.current === externalRawEmail.seq) return;
    lastHandledSeqRef.current = externalRawEmail.seq;
    void runVerification(externalRawEmail.payload);
  }, [externalRawEmail, loading, runVerification]);

  const handleFormSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runVerification(rawInput);
  };

  const handleLoadFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 15 * 1024 * 1024) {
      setError('Email file exceeds 15 MB browser memory limit.');
      return;
    }
    try {
      const text = await file.text();
      setExpanded(true);
      setRawInput(text);
      await runVerification(text);
    } catch {
      setError('Could not read local .eml / .txt file.');
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    void handleLoadFile(file);
    e.target.value = '';
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      void handleLoadFile(file);
    }
  };

  const handlePasteFromClipboard = async () => {
    if (typeof navigator === 'undefined' || !navigator.clipboard?.readText) {
      setError('Clipboard read API is unavailable in this browser — press Ctrl+V / Cmd+V in the box.');
      return;
    }
    try {
      const clipText = await navigator.clipboard.readText();
      if (!clipText.trim()) {
        setError('Clipboard is empty.');
        return;
      }
      setRawInput(clipText);
      await runVerification(clipText);
    } catch {
      setError('Clipboard permission denied — click inside the text box and press Ctrl+V / Cmd+V.');
    }
  };

  const handleClear = () => {
    setRawInput('');
    setReport(null);
    setError(null);
  };

  const parsedFromDomain = report?.parsed.primaryFrom?.domain;
  const differsFromSnapshotDomain =
    Boolean(parsedFromDomain) &&
    parsedFromDomain !== snapshot.displayDomain.toLowerCase().replace(/\.+$/, '');

  return (
    <section
      id="mail-section-header-verifier"
      data-testid="email-header-verifier-card"
      onDragOver={(e) => {
        e.preventDefault();
        if (!isDragging) setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={`rounded-xl border transition-colors p-4 space-y-3.5 scroll-mt-16 md:scroll-mt-44 ${
        isDragging
          ? 'border-cyan-500 bg-cyan-500/10 ring-2 ring-cyan-500/30'
          : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70'
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <button
          type="button"
          data-testid="email-verifier-toggle"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
          className="text-left min-w-0 cursor-pointer group flex-1"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-sm font-bold text-slate-900 dark:text-slate-100 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
              {expanded ? (
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              ) : (
                <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
              )}
              <MailCheck className="w-4 h-4 text-cyan-500 shrink-0" />
              <span>
                Raw Email Header &amp; .eml Cryptographic Replay Verifier (DKIM · ARC · SPF · DMARC)
              </span>
            </span>

            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2.5 py-0.5 font-mono text-[10px] font-semibold">
              <Lock className="w-3 h-3" />
              <span>100% Local WebCrypto · Zero Upload</span>
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 pl-6 mt-1">
            Paste <span className="font-medium">&ldquo;Show Original&rdquo;</span> headers or drop a{' '}
            <code className="font-mono">.eml</code> file to verify{' '}
            <code className="font-mono">DKIM-Signature</code> &amp;{' '}
            <code className="font-mono">ARC</code> cryptographic signatures in browser memory,
            replay SPF + PSL-aware DMARC alignment, and diff against{' '}
            <code className="font-mono">Authentication-Results</code>.
          </p>
        </button>

        {!expanded && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer shrink-0"
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Open Verifier</span>
          </button>
        )}
      </div>

      {expanded && (
        <div className="space-y-4 pt-1">
          <form onSubmit={handleFormSubmit} className="space-y-2.5">
            <textarea
              data-testid="email-verifier-textarea"
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              rows={7}
              spellCheck={false}
              placeholder={`Paste raw RFC 5322 email headers ("Show Original" / "View Message Source") or drop a full .eml file here…\n\nAuthentication-Results: mx.example.net; dkim=pass header.d=${snapshot.displayDomain}; spf=pass; dmarc=pass\nReceived: from mail.${snapshot.displayDomain} ([192.0.2.25]) by mx.example.net ...\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${snapshot.displayDomain}; s=selector1; bh=...; b=...\nFrom: sender@${snapshot.displayDomain}`}
              className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 p-3 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 resize-y"
            />

            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,.txt,message/rfc822,text/plain"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="submit"
                  data-testid="email-verifier-submit"
                  disabled={verifying || rawInput.trim().length === 0}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 px-3.5 py-2 text-xs font-semibold text-slate-950 transition-colors cursor-pointer"
                >
                  {verifying ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Verifying via WebCrypto &amp; DoH…</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verify DKIM / ARC / DMARC</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  data-testid="email-verifier-upload-btn"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={verifying}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-cyan-500 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5 text-cyan-500" />
                  <span>Load .eml / .txt</span>
                </button>

                <button
                  type="button"
                  onClick={() => void handlePasteFromClipboard()}
                  disabled={verifying}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-cyan-500 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                >
                  <ClipboardPaste className="w-3.5 h-3.5 text-cyan-500" />
                  <span>Paste Clipboard</span>
                </button>

                {(rawInput.length > 0 || report) && (
                  <button
                    type="button"
                    onClick={handleClear}
                    disabled={verifying}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-rose-500/60 px-2.5 py-2 text-xs font-medium text-slate-500 hover:text-rose-600 dark:hover:text-rose-400 transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Clear</span>
                  </button>
                )}
              </div>

              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                Headers &amp; body stay in RAM; only public <code className="font-mono">_domainkey</code> /{' '}
                <code className="font-mono">_dmarc</code> / SPF names are queried over DoH.
              </span>
            </div>
          </form>

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
              <span>{error}</span>
            </div>
          )}

          {report && (
            <div data-testid="email-verifier-report" className="space-y-4">
              {/* Top Overall Replay Verdict Banner */}
              <div
                className={`rounded-xl border p-4 space-y-3 ${
                  getOverallBannerMeta(report.overallVerdict).cardCls
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      data-testid="email-verifier-overall-badge"
                      className={`rounded-full px-2.5 py-0.5 font-mono text-xs font-bold ${
                        getOverallBannerMeta(report.overallVerdict).badgeCls
                      }`}
                    >
                      {getOverallBannerMeta(report.overallVerdict).label}
                    </span>
                    <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      {report.overallSummary}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-500">
                    <span>
                      {report.queriesPerformed} live DoH · {report.reusedSnapshotQueries} cached ·{' '}
                      {report.durationMs}ms
                    </span>
                    <button
                      type="button"
                      onClick={() => void runVerification(rawInput)}
                      disabled={verifying}
                      className="inline-flex items-center gap-1 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 text-[10px] font-semibold text-slate-700 dark:text-slate-200 hover:border-cyan-500 cursor-pointer"
                      title="Re-run cryptographic verification"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Re-verify</span>
                    </button>
                  </div>
                </div>

                {/* Envelope & Author Identity Strip */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2 text-xs pt-1">
                  <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-2.5 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      RFC5322.From (Author)
                    </div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 break-all mt-0.5">
                      {report.parsed.primaryFrom?.address ?? '(missing From:)'}
                    </div>
                    {report.dmarcReplay.fromOrgDomain && (
                      <div className="font-mono text-[10px] text-slate-500">
                        Org domain: {report.dmarcReplay.fromOrgDomain}
                      </div>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-2.5 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      RFC5321.MailFrom (Bounce)
                    </div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 break-all mt-0.5">
                      {report.parsed.isNullReturnPath
                        ? '<> (Null Reverse-Path)'
                        : (report.parsed.returnPathAddress ?? '(not in headers)')}
                    </div>
                    {report.spfReplay.usedHeloFallback && report.spfReplay.heloDomain && (
                      <div className="font-mono text-[10px] text-cyan-600 dark:text-cyan-400">
                        SPF HELO fallback: {report.spfReplay.heloDomain}
                      </div>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-2.5 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Connecting External MTA IP
                    </div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {report.parsed.connectingHop ? (
                        <IpHoverBadge ip={report.parsed.connectingHop.ip} />
                      ) : (
                        <span className="text-slate-400">(none detected)</span>
                      )}
                    </div>
                    {report.parsed.connectingHop && (
                      <div className="font-mono text-[10px] text-slate-500 truncate">
                        via {report.parsed.connectingHop.source}
                        {report.parsed.connectingHop.helo
                          ? ` · helo=${report.parsed.connectingHop.helo}`
                          : ''}
                      </div>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-2.5 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Input Mode &amp; Date
                    </div>
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                      {report.parsed.bodyMode === 'with-body'
                        ? `Full .eml (${report.parsed.bodyByteLength}B body)`
                        : report.parsed.bodyMode === 'empty-body'
                          ? 'Empty Body (0B)'
                          : 'Headers-Only Paste'}
                    </div>
                    {report.parsed.dateHeaderRaw && (
                      <div
                        className="font-mono text-[10px] text-slate-500 truncate"
                        title={report.parsed.dateHeaderRaw}
                      >
                        {report.parsed.dateHeaderRaw}
                      </div>
                    )}
                  </div>
                </div>

                {differsFromSnapshotDomain && parsedFromDomain && onSwitchMailDomain && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyan-500/35 bg-cyan-500/10 px-3 py-2 text-xs">
                    <span className="text-slate-700 dark:text-slate-200">
                      Pasted message <code className="font-mono font-semibold">From:</code> domain (
                      <span className="font-mono font-semibold">{parsedFromDomain}</span>) differs
                      from current Mail audit target (
                      <span className="font-mono">{snapshot.displayDomain}</span>).
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        const sels = report.parsed.dkimSignatures
                          .filter((s) => s.domain === parsedFromDomain && s.selector)
                          .map((s) => s.selector);
                        onSwitchMailDomain(parsedFromDomain, sels);
                      }}
                      className="inline-flex items-center gap-1 rounded-md bg-cyan-500 hover:bg-cyan-400 px-2.5 py-1 text-xs font-semibold text-slate-950 cursor-pointer shrink-0"
                    >
                      <span>Switch Mail Audit to {parsedFromDomain}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                {/* RFC 5322 Header Spoofing Anomalies */}
                {report.parsed.anomalies.length > 0 && (
                  <div className="space-y-1 pt-1">
                    {report.parsed.anomalies.map((anom, idx) => (
                      <div
                        key={`anom-${idx}`}
                        className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300 flex items-start gap-2 font-medium"
                      >
                        <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
                        <span>{anom}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 3-Pillar Alignment & Replay Summary Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {/* 1. DKIM Summary */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                      <KeyRound className="w-3.5 h-3.5" />
                      DKIM Replay
                    </span>
                    <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-100">
                      {
                        report.dkimResults.filter(
                          (r) => r.verdict === 'pass' || r.verdict === 'headers-verified-only'
                        ).length
                      }
                      /{report.dkimResults.length} Valid
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    {report.dkimResults.length === 0
                      ? 'No DKIM-Signature headers present in message.'
                      : report.dkimResults[0].summary}
                  </p>
                </div>

                {/* 2. SPF Replay */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                      <Shield className="w-3.5 h-3.5" />
                      SPF Sender Replay
                    </span>
                    <div className="flex items-center gap-1.5">
                      {report.spfReplay.evaluated && (
                        <StatusBadge status={report.spfReplay.spfDnssecStatus} size="xs" />
                      )}
                      <span
                        className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${
                          report.spfReplay.disposition === 'pass'
                            ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35'
                            : report.spfReplay.disposition === 'fail' ||
                                report.spfReplay.disposition === 'permerror'
                              ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35'
                              : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/35'
                        }`}
                      >
                        {report.spfReplay.evaluated ? report.spfReplay.disposition : 'N/A'}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    {report.spfReplay.summary}
                  </p>
                  {report.spfReplay.dmarcAligned && (
                    <div className="font-mono text-[10px] text-slate-500">
                      DMARC SPF Alignment (aspf={report.spfReplay.dmarcAligned.mode}):{' '}
                      <span
                        className={
                          report.spfReplay.dmarcAligned.aligned
                            ? 'text-emerald-600 dark:text-emerald-400 font-semibold'
                            : 'text-amber-600 dark:text-amber-400 font-semibold'
                        }
                      >
                        {report.spfReplay.dmarcAligned.aligned
                          ? `ALIGNED (${report.spfReplay.dmarcAligned.matchKind})`
                          : `UNALIGNED (${report.spfReplay.dmarcAligned.candidateDomain} ≠ ${report.spfReplay.dmarcAligned.fromDomain})`}
                      </span>
                    </div>
                  )}
                </div>

                {/* 3. DMARC Alignment & Disposition */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      DMARC Alignment
                    </span>
                    <span
                      className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${
                        report.dmarcReplay.verdict === 'pass'
                          ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35'
                          : report.dmarcReplay.verdict === 'pass-headers-only'
                            ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/35'
                            : report.dmarcReplay.verdict === 'fail'
                              ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35'
                              : 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/35'
                      }`}
                    >
                      {report.dmarcReplay.verdict} · p={report.dmarcReplay.appliedPolicy}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    {report.dmarcReplay.summary}
                  </p>
                  <div className="font-mono text-[10px] text-slate-500 flex flex-wrap gap-2">
                    <span>adkim={report.dmarcReplay.adkim}</span>
                    <span>·</span>
                    <span>aspf={report.dmarcReplay.aspf}</span>
                    {report.dmarcReplay.arcOverrideCandidate && (
                      <span className="text-cyan-600 dark:text-cyan-400 font-semibold">
                        · ARC Override Eligible ✓
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Authentication-Results Claim vs Live Replay Diff Table */}
              {report.authResultsDiff.length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/50 p-3.5 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
                      Authentication-Results (MTA Claim) vs. Live WebCrypto Replay
                    </h3>
                    <span className="font-mono text-[11px] text-slate-500">
                      RFC 8601 Diff ({report.authResultsDiff.length} check
                      {report.authResultsDiff.length === 1 ? '' : 's'})
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                          <th className="py-1.5 pr-3">Method</th>
                          <th className="py-1.5 pr-3">Identity</th>
                          <th className="py-1.5 pr-3">MTA Claimed</th>
                          <th className="py-1.5 pr-3">Live Replay</th>
                          <th className="py-1.5 pr-3">Comparison</th>
                          <th className="py-1.5">Diagnostic Note</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                        {report.authResultsDiff.map((row, idx) => (
                          <tr key={`ar-diff-${idx}`}>
                            <td className="py-2 pr-3 font-mono font-bold uppercase text-slate-800 dark:text-slate-200">
                              {row.protocol}
                            </td>
                            <td className="py-2 pr-3 font-mono text-[11px] text-slate-700 dark:text-slate-300 whitespace-nowrap">
                              {row.identityLabel}
                            </td>
                            <td className="py-2 pr-3 font-mono text-[11px]">
                              <span className="rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 text-slate-800 dark:text-slate-200">
                                {row.claimedResult}
                              </span>
                              <span className="ml-1 text-[10px] text-slate-400">
                                @{row.claimedAuthservId}
                              </span>
                            </td>
                            <td className="py-2 pr-3 font-mono text-[11px] font-semibold text-slate-800 dark:text-slate-100 whitespace-nowrap">
                              {row.replayedResult}
                            </td>
                            <td className="py-2 pr-3 whitespace-nowrap">
                              {row.status === 'match' ? (
                                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                                  <CheckCircle2 className="w-3 h-3" />
                                  MATCH
                                </span>
                              ) : row.status === 'headers-only-match' ? (
                                <span className="inline-flex items-center gap-1 rounded-full bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[10px] font-bold">
                                  HEADERS MATCH
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/20 text-amber-800 dark:text-amber-200 border border-amber-500/40 px-2 py-0.5 font-mono text-[10px] font-bold">
                                  <AlertTriangle className="w-3 h-3" />
                                  DRIFT Δ
                                </span>
                              )}
                            </td>
                            <td className="py-2 text-slate-600 dark:text-slate-400">
                              {row.explanation}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Per-Signature DKIM Cryptographic Verification Cards */}
              {report.dkimResults.length > 0 && (
                <div className="space-y-2.5">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
                    DKIM-Signature Cryptographic Verification ({report.dkimResults.length})
                  </h3>
                  {report.dkimResults.map((res, idx) => (
                    <SignatureVerificationDetailCard
                      key={`dkim-res-${idx}-${res.signature.headerIndex}`}
                      res={res}
                      snapshot={snapshot}
                      onJumpToGraphTarget={onJumpToGraphTarget}
                      onInspectWireQuery={onInspectWireQuery}
                      compactTitle={`DKIM #${idx + 1}`}
                    />
                  ))}
                </div>
              )}

              {/* RFC 8617 ARC Forwarding Chain Verification */}
              {report.arc.present && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/50 p-3.5 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-100">
                        Authenticated Received Chain (ARC · RFC 8617)
                      </h3>
                      <span
                        className={`rounded-full px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                          report.arc.verdict === 'pass'
                            ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/35'
                            : report.arc.verdict === 'headers-verified-only'
                              ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/35'
                              : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35'
                        }`}
                      >
                        ARC {report.arc.verdict} (1..{report.arc.sets.length})
                      </span>
                    </div>
                    <span className="text-xs text-slate-500">{report.arc.summary}</span>
                  </div>

                  <div className="space-y-3">
                    {report.arc.sets.map((arcSet) => (
                      <div
                        key={`arc-set-${arcSet.instance}`}
                        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/70 p-3 space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-xs font-bold">
                              ARC Hop i={arcSet.instance}
                            </span>
                            {arcSet.cvTag && (
                              <span
                                className={`rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${
                                  (arcSet.instance === 1 && arcSet.cvTag === 'none') ||
                                  (arcSet.instance > 1 && arcSet.cvTag === 'pass')
                                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                                    : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                                }`}
                              >
                                cv={arcSet.cvTag}
                              </span>
                            )}
                            {arcSet.aar?.authservId && (
                              <span className="font-mono text-xs text-slate-600 dark:text-slate-300">
                                Intermediary: {arcSet.aar.authservId}
                              </span>
                            )}
                            {arcSet.amsModifiedDownstream && (
                              <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 px-2 py-0.5 font-mono text-[10px] font-semibold">
                                Modified by later forwarder (Seal intact)
                              </span>
                            )}
                          </div>

                          <span
                            className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-bold ${
                              arcSet.setValid
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                                : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                            }`}
                          >
                            {arcSet.setValid ? `HOP i=${arcSet.instance} VALID ✓` : `HOP i=${arcSet.instance} BROKEN ✗`}
                          </span>
                        </div>

                        {arcSet.aar && arcSet.aar.items.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                            <span className="text-slate-500">AAR({arcSet.instance}):</span>
                            {arcSet.aar.items.map((it, idx) => (
                              <span
                                key={`aar-it-${idx}`}
                                className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-slate-700 dark:text-slate-200"
                              >
                                {it.method}={it.result}
                              </span>
                            ))}
                          </div>
                        )}

                        {arcSet.seal && (
                          <SignatureVerificationDetailCard
                            res={arcSet.seal}
                            snapshot={snapshot}
                            onJumpToGraphTarget={onJumpToGraphTarget}
                            onInspectWireQuery={onInspectWireQuery}
                            compactTitle={`ARC-Seal (i=${arcSet.instance})`}
                          />
                        )}

                        {arcSet.ams && (
                          <SignatureVerificationDetailCard
                            res={arcSet.ams}
                            snapshot={snapshot}
                            onJumpToGraphTarget={onJumpToGraphTarget}
                            onInspectWireQuery={onInspectWireQuery}
                            compactTitle={`ARC-Message-Signature (i=${arcSet.instance})`}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
