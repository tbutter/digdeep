import {
  discoverZoneCutsForName,
  evaluateSnapshotFromLogs,
  type AnalyzeOptions,
} from './analyzer';
import {
  DEFAULT_DOH_ENDPOINT,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
} from './constants';
import { toArrayBuffer } from './crypto';
import { DohSession } from './doh';
import {
  base64ToBytes,
  bytesToBase64,
  displayFqdn,
  normalizeFqdn,
} from './encoding';
import {
  formatCanonicalIpv6,
  parseIpv4Octets,
  parseIpv6Groups,
} from './ipUtils';
import {
  decodeDkimPublicKey,
  estimateOrganizationalDomain,
  evaluateDmarcFromLogs,
  evaluateMailFromSnapshotData,
  evaluateSingleDkimSelector,
  evaluateSpfForSenderIp,
  prefetchSpfTree,
  queryPublicSuffix,
  seedPublicSuffixCacheFromLogs,
} from './mailAnalyzer';
import type {
  AnalysisSnapshot,
  AuditFinding,
  DkimSelectorResult,
  DmarcAnalysis,
  DmarcPolicyValue,
  DohQueryLog,
  SpfSenderEvaluationDisposition,
  SpfSenderEvaluationResult,
  ValidationStatus,
  ZoneAnalysis,
} from './types';

export type DkimCanonicalizationMode = 'simple' | 'relaxed';

export interface ParsedEmailHeader {
  /** 0-based position from top of the RFC 5322 header block */
  index: number;
  /** Original-case field name (whitespace before colon trimmed) */
  name: string;
  /** Lowercased field name */
  lowerName: string;
  /** Exact raw header text (preserving original folding CRLFs, excluding terminating CRLF) */
  rawHeader: string;
  /** Unfolded, trimmed header field value */
  unfoldedValue: string;
}

export interface ParsedMailboxIdentity {
  raw: string;
  displayName?: string;
  address: string;
  localPart: string;
  domain: string;
}

export interface ParsedConnectingHop {
  ip: string;
  family: 4 | 6;
  isInternalRelay: boolean;
  helo?: string;
  byHost?: string;
  source: 'received-spf' | 'auth-results' | 'received';
  rawEvidence: string;
  receivedTimestampSec?: number;
  headerIndex?: number;
}

export interface ParsedAuthResultItem {
  method: string;
  result: string;
  reason?: string;
  props: Record<string, string>;
  rawClause: string;
}

export interface ParsedAuthResultsHeader {
  headerIndex: number;
  headerName: string;
  arcInstance?: number;
  authservId: string;
  items: ParsedAuthResultItem[];
  rawHeader: string;
}

export interface ParsedDkimLikeSignature {
  kind: 'dkim' | 'arc-ms' | 'arc-seal';
  headerIndex: number;
  rawHeader: string;
  tags: Record<string, string>;
  duplicateTags: string[];
  malformedTags: string[];
  instance?: number;
  chainValidation?: string;
  version?: string;
  algorithm: string;
  domain: string;
  selector: string;
  auid?: string;
  auidLocalPart?: string;
  auidDomain?: string;
  headerCanon: DkimCanonicalizationMode;
  bodyCanon: DkimCanonicalizationMode;
  hasExplicitH: boolean;
  signedHeaders: string[];
  bodyHashBase64?: string;
  signatureBase64: string;
  bodyLengthLimit?: number;
  timestampSec?: number;
  expirationSec?: number;
  queryMethods?: string;
  copiedHeaders?: string;
}

export interface ParsedRawEmailMessage {
  headers: ParsedEmailHeader[];
  hasBodySeparator: boolean;
  hasBody: boolean;
  bodyMode: 'with-body' | 'empty-body' | 'headers-only';
  rawBodyCrlf: string;
  bodyByteLength: number;
  fromIdentities: ParsedMailboxIdentity[];
  primaryFrom?: ParsedMailboxIdentity;
  multipleFromHeaderCount: number;
  returnPathAddress?: string;
  returnPathDomain?: string;
  isNullReturnPath: boolean;
  subject?: string;
  messageId?: string;
  dateHeaderRaw?: string;
  dateEpochSec?: number;
  latestReceivedEpochSec?: number;
  connectingHop?: ParsedConnectingHop;
  allCandidateHops: ParsedConnectingHop[];
  dkimSignatures: ParsedDkimLikeSignature[];
  arcMessageSignatures: ParsedDkimLikeSignature[];
  arcSeals: ParsedDkimLikeSignature[];
  arcAuthResults: ParsedAuthResultsHeader[];
  authResults: ParsedAuthResultsHeader[];
  anomalies: string[];
}

export type SignatureVerificationVerdict =
  | 'pass'
  | 'headers-verified-only'
  | 'fail'
  | 'policy-fail'
  | 'temperror'
  | 'permerror';

export interface DmarcAlignmentDetail {
  aligned: boolean;
  mode: 'r' | 's';
  matchKind: 'exact' | 'org-domain' | 'unaligned';
  candidateDomain: string;
  candidateOrgDomain: string;
  fromDomain: string;
  fromOrgDomain: string;
}

export interface SignatureTimestampEvaluation {
  signedAtIso?: string;
  expiresAtIso?: string;
  expiredNow: boolean;
  expiredAtReceipt: boolean | null;
  xBeforeT: boolean;
  futureTimestamp: boolean;
}

export interface MatchedSignedHeaderEntry {
  requestedName: string;
  matchedHeaderIndex: number | null;
  oversigned: boolean;
}

export interface VerifiedDkimSignatureResult {
  signature: ParsedDkimLikeSignature;
  verdict: SignatureVerificationVerdict;
  headerCryptoValid: boolean | null;
  bodyHashStatus:
    | 'match'
    | 'mismatch'
    | 'unchecked-no-body'
    | 'length-exceeded'
    | 'not-applicable';
  computedBodyHashBase64?: string;
  canonicalBodyByteLength?: number;
  unsignedTrailingBodyBytes?: number;
  dnsSelector: DkimSelectorResult | null;
  dnssecStatus: ValidationStatus;
  matchedSignedHeaders: MatchedSignedHeaderEntry[];
  missingFromInH: boolean;
  deprecatedAlgorithm: boolean;
  weakKeyRejected: boolean;
  timestampEvaluation: SignatureTimestampEvaluation;
  dmarcAligned?: DmarcAlignmentDetail;
  summary: string;
  issues: string[];
  warnings: string[];
}

export interface VerifiedArcSetResult {
  instance: number;
  aar?: ParsedAuthResultsHeader;
  ams?: VerifiedDkimSignatureResult;
  seal?: VerifiedDkimSignatureResult;
  cvTag?: string;
  setValid: boolean;
  amsModifiedDownstream?: boolean;
  issues: string[];
}

export interface ArcChainVerificationResult {
  present: boolean;
  verdict: 'none' | 'pass' | 'headers-verified-only' | 'fail' | 'permerror';
  sets: VerifiedArcSetResult[];
  summary: string;
  issues: string[];
}

export interface SpfReplayVerificationResult {
  evaluated: boolean;
  connectingIp?: string;
  connectingIpSource?: ParsedConnectingHop['source'];
  envelopeDomain?: string;
  envelopeSender?: string;
  heloDomain?: string;
  usedHeloFallback: boolean;
  spfPresent: boolean;
  spfDnssecStatus: ValidationStatus;
  evaluation?: SpfSenderEvaluationResult;
  disposition: SpfSenderEvaluationDisposition;
  dmarcAligned?: DmarcAlignmentDetail;
  summary: string;
  issues: string[];
}

export interface DmarcReplayVerificationResult {
  fromAddress?: string;
  fromDomain?: string;
  fromOrgDomain?: string;
  dmarcRecord: DmarcAnalysis | null;
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  dkimAlignedPass: boolean;
  dkimHeadersOnlyPass: boolean;
  spfAlignedPass: boolean;
  verdict: 'pass' | 'pass-headers-only' | 'fail' | 'no-policy' | 'missing-from';
  appliedPolicy: DmarcPolicyValue | 'none';
  effectiveDisposition: 'deliver' | 'monitor-none' | 'quarantine' | 'reject';
  arcOverrideCandidate: boolean;
  summary: string;
  issues: string[];
}

export interface AuthResultsComparisonEntry {
  protocol: 'dkim' | 'spf' | 'dmarc' | 'arc';
  identityLabel: string;
  claimedAuthservId: string;
  claimedResult: string;
  replayedResult: string;
  status: 'match' | 'headers-only-match' | 'drift';
  explanation: string;
}

export interface EmailMessageVerificationReport {
  parsed: ParsedRawEmailMessage;
  dkimResults: VerifiedDkimSignatureResult[];
  arc: ArcChainVerificationResult;
  spfReplay: SpfReplayVerificationResult;
  dmarcReplay: DmarcReplayVerificationResult;
  authResultsDiff: AuthResultsComparisonEntry[];
  overallVerdict: 'pass' | 'pass-headers-only' | 'fail' | 'warning' | 'unauthenticated';
  overallSummary: string;
  queriesPerformed: number;
  reusedSnapshotQueries: number;
  verifiedAtMs: number;
  durationMs: number;
  allQueries: DohQueryLog[];
  zones: ZoneAnalysis[];
}

export interface VerifyEmailMessageOptions extends AnalyzeOptions {
  snapshot?: AnalysisSnapshot | null;
  nowMs?: number;
}

// Well-known empty-body hashes for distinguishing headers-only trailing-blank-line pastes from intentional empty bodies
const EMPTY_BODY_HASHES = new Set([
  '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=', // SHA-256("") - relaxed empty body
  'frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=', // SHA-256("\r\n") - simple empty body
  '2jmj7l5rSw0yVb/vlWAYkK/YBwk=', // SHA-1("") - relaxed empty body
  'uoq1oCgLlTqpdDX/iUbLy7J1Wic=', // SHA-1("\r\n") - simple empty body
]);

// ASN.1 DER prefix for wrapping bare PKCS#1 RSAPublicKey into X.509 SubjectPublicKeyInfo
const RSA_OID_ALGORITHM_IDENTIFIER = new Uint8Array([
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]);

function encodeDerLength(len: number): Uint8Array {
  if (len < 0x80) {
    return new Uint8Array([len]);
  }
  const octets: number[] = [];
  let rem = len;
  while (rem > 0) {
    octets.unshift(rem & 0xff);
    rem = Math.floor(rem / 256);
  }
  return new Uint8Array([0x80 | octets.length, ...octets]);
}

function wrapPkcs1RsaInSpki(pkcs1Bytes: Uint8Array): Uint8Array {
  // BIT STRING: 0x03 <len(1 + pkcs1Bytes.length)> 0x00 <pkcs1Bytes>
  const bitStringLen = encodeDerLength(1 + pkcs1Bytes.length);
  const bitString = new Uint8Array(1 + bitStringLen.length + 1 + pkcs1Bytes.length);
  bitString[0] = 0x03;
  bitString.set(bitStringLen, 1);
  bitString[1 + bitStringLen.length] = 0x00;
  bitString.set(pkcs1Bytes, 2 + bitStringLen.length);

  // Outer SEQUENCE: 0x30 <len(algId + bitString)> <algId> <bitString>
  const seqContentLen = RSA_OID_ALGORITHM_IDENTIFIER.length + bitString.length;
  const seqLen = encodeDerLength(seqContentLen);
  const spki = new Uint8Array(1 + seqLen.length + seqContentLen);
  spki[0] = 0x30;
  spki.set(seqLen, 1);
  spki.set(RSA_OID_ALGORITHM_IDENTIFIER, 1 + seqLen.length);
  spki.set(bitString, 1 + seqLen.length + RSA_OID_ALGORITHM_IDENTIFIER.length);
  return spki;
}

/**
 * Heuristic detector for raw RFC 5322 email headers / `.eml` messages pasted into the omnibox or UI.
 */
export function looksLikeRawEmailHeaders(rawInput: string): boolean {
  const trimmed = rawInput.trim();
  if (trimmed.length < 18) return false;

  // Single-header or multi-line explicit cryptographic/trace email header
  const hasExplicitMailAuthHeader =
    /(?:^|\r?\n)(?:DKIM-Signature|ARC-Seal|ARC-Message-Signature|ARC-Authentication-Results|Authentication-Results|Received-SPF)\s*:/i.test(
      trimmed
    );

  if (!/\r|\n/.test(trimmed)) {
    return (
      /^(?:DKIM-Signature|ARC-Seal|ARC-Message-Signature)\s*:/i.test(trimmed) &&
      /\bd\s*=\s*[A-Za-z0-9.-]+/i.test(trimmed) &&
      /\bs\s*=\s*[A-Za-z0-9._-]+/i.test(trimmed)
    );
  }

  const lines = trimmed.split(/\r?\n/);
  let headerLineCount = 0;
  let hasFrom = false;
  let hasTraceOrMeta = false;

  for (const line of lines.slice(0, 120)) {
    if (!line.trim()) break; // stop at body separator
    if (/^[ \t]+/.test(line)) continue; // folded continuation
    const m = /^([A-Za-z0-9-]{2,64})\s*:/.exec(line);
    if (m) {
      headerLineCount++;
      const lower = m[1].toLowerCase();
      if (lower === 'from') hasFrom = true;
      if (
        lower === 'received' ||
        lower === 'return-path' ||
        lower === 'delivered-to' ||
        lower === 'message-id' ||
        lower === 'date' ||
        lower === 'subject' ||
        lower === 'to' ||
        lower === 'mime-version'
      ) {
        hasTraceOrMeta = true;
      }
    }
  }

  if (hasExplicitMailAuthHeader && headerLineCount >= 1) {
    return true;
  }
  return headerLineCount >= 2 && hasFrom && hasTraceOrMeta;
}

/**
 * Extracts a quick summary (primary domain + DKIM selectors) from raw pasted email headers
 * for instant omnibox routing into Mail mode.
 */
export function extractEmailHeaderQuickSummary(rawInput: string): {
  targetDomain: string;
  dkimSelectors: string[];
  dkimSignatureCount: number;
  arcSetCount: number;
  fromAddress?: string;
} | null {
  if (!looksLikeRawEmailHeaders(rawInput)) return null;
  const parsed = parseRawEmailMessage(rawInput);

  const candidateDomain =
    parsed.primaryFrom?.domain ||
    parsed.dkimSignatures[0]?.domain ||
    parsed.returnPathDomain ||
    parsed.arcMessageSignatures[0]?.domain ||
    parsed.arcSeals[0]?.domain ||
    '';

  const cleanDomain = candidateDomain.trim().toLowerCase().replace(/\.+$/, '');
  if (!cleanDomain || !cleanDomain.includes('.')) return null;

  const selectors: string[] = [];
  for (const sig of [...parsed.dkimSignatures, ...parsed.arcMessageSignatures, ...parsed.arcSeals]) {
    if (
      sig.selector &&
      (!sig.domain || sig.domain === cleanDomain) &&
      !selectors.includes(sig.selector)
    ) {
      selectors.push(sig.selector);
    }
  }

  const arcInstances = new Set<number>();
  for (const s of [...parsed.arcSeals, ...parsed.arcMessageSignatures, ...parsed.arcAuthResults]) {
    const inst = 'kind' in s ? s.instance : s.arcInstance;
    if (inst !== undefined) arcInstances.add(inst);
  }

  return {
    targetDomain: cleanDomain,
    dkimSelectors: selectors.slice(0, 12),
    dkimSignatureCount: parsed.dkimSignatures.length,
    arcSetCount: arcInstances.size,
    fromAddress: parsed.primaryFrom?.address,
  };
}

function stripRfc5322Comments(input: string): string {
  let out = '';
  let depth = 0;
  let inQuotes = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '\\' && i + 1 < input.length) {
      if (depth === 0) {
        out += ch + input[i + 1];
      }
      i++;
      continue;
    }
    if (ch === '"' && depth === 0) {
      inQuotes = !inQuotes;
      out += ch;
      continue;
    }
    if (!inQuotes) {
      if (ch === '(') {
        depth++;
        continue;
      }
      if (ch === ')' && depth > 0) {
        depth--;
        continue;
      }
    }
    if (depth === 0) {
      out += ch;
    }
  }
  return out;
}

function splitTopLevelAddresses(value: string): string[] {
  const parts: string[] = [];
  let cur = '';
  let inQuotes = false;
  let angleDepth = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '\\' && i + 1 < value.length) {
      cur += ch + value[i + 1];
      i++;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      cur += ch;
      continue;
    }
    if (!inQuotes) {
      if (ch === '<') angleDepth++;
      else if (ch === '>' && angleDepth > 0) angleDepth--;
      else if ((ch === ',' || ch === ';') && angleDepth === 0) {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

export function parseMailboxList(rawValue: string): ParsedMailboxIdentity[] {
  const uncommented = stripRfc5322Comments(rawValue);
  const chunks = splitTopLevelAddresses(uncommented);
  const results: ParsedMailboxIdentity[] = [];

  for (const chunk of chunks) {
    // Handle RFC 5322 group syntax `Group Name: addr1@ex.com`
    const groupColonIdx = chunk.indexOf(':');
    const candidateChunk =
      groupColonIdx > 0 && !chunk.slice(0, groupColonIdx).includes('@') && !chunk.slice(0, groupColonIdx).includes('<')
        ? chunk.slice(groupColonIdx + 1).trim()
        : chunk;
    if (!candidateChunk) continue;

    let displayName: string | undefined;
    let addrSpec = candidateChunk;

    const angleMatch = /^(.*)<([^<>]+)>\s*$/.exec(candidateChunk);
    if (angleMatch) {
      const rawDisp = angleMatch[1].trim().replace(/^"(.*)"$/, '$1').trim();
      if (rawDisp) displayName = rawDisp;
      addrSpec = angleMatch[2].trim();
    } else {
      addrSpec = candidateChunk.trim().replace(/^<|>$/g, '').trim();
    }

    const lastAt = addrSpec.lastIndexOf('@');
    if (lastAt <= 0 || lastAt === addrSpec.length - 1) continue;

    const localPart = addrSpec.slice(0, lastAt).trim();
    const rawDomain = addrSpec.slice(lastAt + 1).replace(/\s+/g, '').replace(/\.+$/, '').toLowerCase();
    if (!rawDomain || !/^[a-z0-9._-]+$/i.test(rawDomain)) continue;

    results.push({
      raw: chunk,
      displayName,
      address: `${localPart}@${rawDomain}`,
      localPart,
      domain: rawDomain,
    });
  }

  return results;
}

function isInternalRelayIp(ip: string, family: 4 | 6): boolean {
  if (family === 4) {
    const octets = parseIpv4Octets(ip);
    if (!octets) return true;
    const [a, b] = octets;
    if (a === 127 || a === 0 || a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('ff')) return true;
  return false;
}

function normalizeCandidateIpToken(rawToken: string): { ip: string; family: 4 | 6 } | null {
  let tok = rawToken
    .trim()
    .replace(/^\[|\]$/g, '')
    .replace(/^ipv6:/i, '')
    .replace(/[;,.)]+$/, '');
  if (!tok) return null;

  const v4 = parseIpv4Octets(tok);
  if (v4) {
    return { ip: v4.join('.'), family: 4 };
  }

  // Strip optional port on bracketed IPv6 if present
  if (tok.includes(':')) {
    const groups = parseIpv6Groups(tok);
    if (groups) {
      // Handle IPv4-mapped IPv6 `::ffff:a.b.c.d`
      if (
        groups[0] === 0 &&
        groups[1] === 0 &&
        groups[2] === 0 &&
        groups[3] === 0 &&
        groups[4] === 0 &&
        groups[5] === 0xffff
      ) {
        const a = (groups[6] >> 8) & 0xff;
        const b = groups[6] & 0xff;
        const c = (groups[7] >> 8) & 0xff;
        const d = groups[7] & 0xff;
        return { ip: `${a}.${b}.${c}.${d}`, family: 4 };
      }
      return { ip: formatCanonicalIpv6(groups), family: 6 };
    }
  }
  return null;
}

function splitSemicolonClauses(input: string): string[] {
  const clauses: string[] = [];
  let cur = '';
  let inQuotes = false;
  let parenDepth = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '\\' && i + 1 < input.length) {
      cur += ch + input[i + 1];
      i++;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      cur += ch;
      continue;
    }
    if (!inQuotes) {
      if (ch === '(') parenDepth++;
      else if (ch === ')' && parenDepth > 0) parenDepth--;
      else if (ch === ';' && parenDepth === 0) {
        if (cur.trim()) clauses.push(cur.trim());
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) clauses.push(cur.trim());
  return clauses;
}

export function parseAuthResultsHeader(header: ParsedEmailHeader): ParsedAuthResultsHeader | null {
  const isArc = header.lowerName === 'arc-authentication-results';
  const clauses = splitSemicolonClauses(header.unfoldedValue);
  if (clauses.length === 0) return null;

  let arcInstance: number | undefined;
  let authservId = '';
  let startIdx = 0;

  if (isArc) {
    const iMatch = /^i\s*=\s*(\d+)\s*$/i.exec(clauses[0]);
    if (iMatch) {
      arcInstance = Number.parseInt(iMatch[1], 10);
      authservId = stripRfc5322Comments(clauses[1] ?? '').trim().split(/\s+/)[0] ?? '';
      startIdx = 2;
    } else {
      const combinedMatch = /^i\s*=\s*(\d+)\s*;\s*(.+)$/i.exec(header.unfoldedValue);
      if (combinedMatch) {
        arcInstance = Number.parseInt(combinedMatch[1], 10);
      }
      authservId = stripRfc5322Comments(clauses[0]).trim().split(/\s+/)[0] ?? '';
      startIdx = 1;
    }
  } else {
    authservId = stripRfc5322Comments(clauses[0]).trim().split(/\s+/)[0] ?? '';
    startIdx = 1;
  }

  const items: ParsedAuthResultItem[] = [];

  for (let idx = startIdx; idx < clauses.length; idx++) {
    const rawClause = clauses[idx];
    const uncommented = stripRfc5322Comments(rawClause).trim();
    if (!uncommented || /^none$/i.test(uncommented)) continue;

    // Match `<method> = <result>` at start of clause
    const methodMatch = /^([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)([\s\S]*)$/i.exec(uncommented);
    if (!methodMatch) continue;

    const method = methodMatch[1].toLowerCase();
    const result = methodMatch[2].toLowerCase();
    const rest = methodMatch[3] ?? '';

    let reason: string | undefined;
    const reasonMatch = /\breason\s*=\s*(?:"([^"]*)"|([^\s;]+))/i.exec(rest);
    if (reasonMatch) {
      reason = (reasonMatch[1] ?? reasonMatch[2] ?? '').trim();
    } else {
      // Capture inline comment from original rawClause as human-readable reason if present
      const commentMatch = /\(([^()]{3,160})\)/.exec(rawClause);
      if (commentMatch) {
        reason = commentMatch[1].trim();
      }
    }

    const props: Record<string, string> = {};
    const propRegex = /([a-z0-9_-]+\.[a-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|([^\s;]+))/gi;
    let pm: RegExpExecArray | null;
    while ((pm = propRegex.exec(rest)) !== null) {
      const propKey = pm[1].toLowerCase();
      const propVal = (pm[2] ?? pm[3] ?? '').trim();
      props[propKey] = propVal;
    }

    items.push({
      method,
      result,
      reason,
      props,
      rawClause,
    });
  }

  return {
    headerIndex: header.index,
    headerName: header.name,
    arcInstance,
    authservId,
    items,
    rawHeader: header.rawHeader,
  };
}

export function parseDkimLikeSignature(
  header: ParsedEmailHeader,
  kind: 'dkim' | 'arc-ms' | 'arc-seal'
): ParsedDkimLikeSignature {
  const tags: Record<string, string> = {};
  const duplicateTags: string[] = [];
  const malformedTags: string[] = [];

  const rawSegments = header.unfoldedValue.split(';');
  for (const rawSeg of rawSegments) {
    const seg = rawSeg.trim();
    if (!seg) continue;
    const eqIdx = seg.indexOf('=');
    if (eqIdx <= 0) {
      malformedTags.push(seg);
      continue;
    }
    const tag = seg.slice(0, eqIdx).trim();
    const val = seg.slice(eqIdx + 1).trim();
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(tag)) {
      malformedTags.push(seg);
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(tags, tag)) {
      duplicateTags.push(tag);
      continue;
    }
    tags[tag] = val;
  }

  let headerCanon: DkimCanonicalizationMode = kind === 'arc-seal' ? 'relaxed' : 'simple';
  let bodyCanon: DkimCanonicalizationMode = 'simple';

  if (tags.c !== undefined) {
    const cParts = tags.c.toLowerCase().split('/');
    const hMode = cParts[0]?.trim();
    const bMode = cParts[1]?.trim();
    if (hMode === 'relaxed' || hMode === 'simple') {
      headerCanon = hMode;
    } else {
      malformedTags.push(`c=${tags.c}`);
    }
    if (bMode !== undefined && bMode.length > 0) {
      if (bMode === 'relaxed' || bMode === 'simple') {
        bodyCanon = bMode;
      } else {
        malformedTags.push(`c=${tags.c}`);
      }
    } else {
      // RFC 6376 §3.5: single-token c=relaxed means relaxed/simple
      bodyCanon = 'simple';
    }
  }

  const domain = (tags.d ?? '').replace(/\s+/g, '').replace(/\.+$/, '').toLowerCase();
  const selector = (tags.s ?? '').replace(/\s+/g, '').replace(/\.+$/, '').toLowerCase();
  const algorithm = (tags.a ?? '').replace(/\s+/g, '').toLowerCase();

  const hasExplicitH = Object.prototype.hasOwnProperty.call(tags, 'h');
  const signedHeaders = hasExplicitH
    ? tags.h
        .split(':')
        .map((x) => x.replace(/\s+/g, '').toLowerCase())
        .filter((x) => x.length > 0)
    : [];

  let auid: string | undefined;
  let auidLocalPart: string | undefined;
  let auidDomain: string | undefined;
  if (tags.i !== undefined) {
    auid = tags.i.replace(/\s+/g, '');
    const atIdx = auid.lastIndexOf('@');
    if (atIdx >= 0) {
      auidLocalPart = auid.slice(0, atIdx);
      auidDomain = auid.slice(atIdx + 1).replace(/\.+$/, '').toLowerCase();
    }
  } else if (kind === 'dkim' && domain) {
    auid = `@${domain}`;
    auidLocalPart = '';
    auidDomain = domain;
  }

  let instance: number | undefined;
  if (tags.i !== undefined && (kind === 'arc-ms' || kind === 'arc-seal')) {
    if (/^\d+$/.test(tags.i.trim())) {
      instance = Number.parseInt(tags.i.trim(), 10);
    } else {
      malformedTags.push(`i=${tags.i}`);
    }
  }

  let bodyLengthLimit: number | undefined;
  if (tags.l !== undefined) {
    if (/^\d+$/.test(tags.l.trim())) {
      bodyLengthLimit = Number.parseInt(tags.l.trim(), 10);
    } else {
      malformedTags.push(`l=${tags.l}`);
    }
  }

  let timestampSec: number | undefined;
  if (tags.t !== undefined) {
    if (/^\d+$/.test(tags.t.trim())) {
      timestampSec = Number.parseInt(tags.t.trim(), 10);
    } else {
      malformedTags.push(`t=${tags.t}`);
    }
  }

  let expirationSec: number | undefined;
  if (tags.x !== undefined) {
    if (/^\d+$/.test(tags.x.trim())) {
      expirationSec = Number.parseInt(tags.x.trim(), 10);
    } else {
      malformedTags.push(`x=${tags.x}`);
    }
  }

  return {
    kind,
    headerIndex: header.index,
    rawHeader: header.rawHeader,
    tags,
    duplicateTags,
    malformedTags,
    instance,
    chainValidation: tags.cv?.trim().toLowerCase(),
    version: tags.v?.trim(),
    algorithm,
    domain,
    selector,
    auid,
    auidLocalPart,
    auidDomain,
    headerCanon,
    bodyCanon,
    hasExplicitH,
    signedHeaders,
    bodyHashBase64: tags.bh !== undefined ? tags.bh.replace(/\s+/g, '') : undefined,
    signatureBase64: (tags.b ?? '').replace(/\s+/g, ''),
    bodyLengthLimit,
    timestampSec,
    expirationSec,
    queryMethods: tags.q?.trim(),
    copiedHeaders: tags.z,
  };
}

/**
 * Parses a raw RFC 5322 email message (either headers-only paste or full `.eml` with body)
 * strictly in local memory.
 */
export function parseRawEmailMessage(rawInput: string): ParsedRawEmailMessage {
  // Normalize line endings to CRLF (`\r\n`) and strip any leading blank lines before the first header
  let normalized = rawInput.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  normalized = normalized.replace(/^(?:[ \t]*\n)+/, '');
  // Strip optional Berkeley mbox `From sender date` envelope line at byte 0
  if (/^From \S+ .*\n[A-Za-z0-9-]+\s*:/.test(normalized)) {
    const nl = normalized.indexOf('\n');
    normalized = normalized.slice(nl + 1);
  }
  const crlfText = normalized.replace(/\n/g, '\r\n');

  const sepIdx = crlfText.indexOf('\r\n\r\n');
  const hasBodySeparator = sepIdx >= 0;
  const headerBlock = hasBodySeparator ? crlfText.slice(0, sepIdx) : crlfText;
  const rawAfterSep = hasBodySeparator ? crlfText.slice(sepIdx + 4) : '';

  const rawLines = headerBlock.split('\r\n');
  const rawHeaderChunks: string[] = [];

  for (const line of rawLines) {
    if (!line) continue;
    if ((line.startsWith(' ') || line.startsWith('\t')) && rawHeaderChunks.length > 0) {
      rawHeaderChunks[rawHeaderChunks.length - 1] += `\r\n${line}`;
    } else {
      rawHeaderChunks.push(line);
    }
  }

  const headers: ParsedEmailHeader[] = [];
  const anomalies: string[] = [];

  for (const chunk of rawHeaderChunks) {
    const colonIdx = chunk.indexOf(':');
    if (colonIdx <= 0) {
      anomalies.push(`Malformed non-folded header line without colon: "${chunk.slice(0, 60)}"`);
      continue;
    }
    const rawName = chunk.slice(0, colonIdx);
    const trimmedName = rawName.replace(/[ \t]+$/g, '');
    const rawVal = chunk.slice(colonIdx + 1);
    const unfoldedValue = rawVal.replace(/\r\n(?=[ \t])/g, '').trim();

    headers.push({
      index: headers.length,
      name: trimmedName,
      lowerName: trimmedName.toLowerCase(),
      rawHeader: chunk,
      unfoldedValue,
    });
  }

  const dkimSignatures: ParsedDkimLikeSignature[] = [];
  const arcMessageSignatures: ParsedDkimLikeSignature[] = [];
  const arcSeals: ParsedDkimLikeSignature[] = [];
  const arcAuthResults: ParsedAuthResultsHeader[] = [];
  const authResults: ParsedAuthResultsHeader[] = [];
  const fromHeaders: ParsedEmailHeader[] = [];
  const candidateHops: ParsedConnectingHop[] = [];

  let returnPathAddress: string | undefined;
  let returnPathDomain: string | undefined;
  let isNullReturnPath = false;
  let subject: string | undefined;
  let messageId: string | undefined;
  let dateHeaderRaw: string | undefined;
  let dateEpochSec: number | undefined;
  let latestReceivedEpochSec: number | undefined;

  for (const h of headers) {
    switch (h.lowerName) {
      case 'dkim-signature':
        dkimSignatures.push(parseDkimLikeSignature(h, 'dkim'));
        break;
      case 'arc-message-signature':
        arcMessageSignatures.push(parseDkimLikeSignature(h, 'arc-ms'));
        break;
      case 'arc-seal':
        arcSeals.push(parseDkimLikeSignature(h, 'arc-seal'));
        break;
      case 'arc-authentication-results': {
        const parsedAar = parseAuthResultsHeader(h);
        if (parsedAar) arcAuthResults.push(parsedAar);
        break;
      }
      case 'authentication-results': {
        const parsedAr = parseAuthResultsHeader(h);
        if (parsedAr) authResults.push(parsedAr);
        break;
      }
      case 'from':
        fromHeaders.push(h);
        break;
      case 'return-path':
      case 'envelope-from':
      case 'x-envelope-from':
      case 'x-original-sender': {
        if (returnPathAddress === undefined && !isNullReturnPath) {
          const val = stripRfc5322Comments(h.unfoldedValue).trim();
          if (val === '<>' || /^<\s*>$/.test(val)) {
            isNullReturnPath = true;
            returnPathAddress = '';
          } else {
            const mbs = parseMailboxList(val);
            if (mbs[0]) {
              returnPathAddress = mbs[0].address;
              returnPathDomain = mbs[0].domain;
            }
          }
        }
        break;
      }
      case 'subject':
        if (subject === undefined) subject = h.unfoldedValue;
        break;
      case 'message-id':
        if (messageId === undefined) messageId = h.unfoldedValue;
        break;
      case 'date':
        if (dateHeaderRaw === undefined) {
          dateHeaderRaw = h.unfoldedValue;
          const parsedMs = Date.parse(stripRfc5322Comments(h.unfoldedValue));
          if (!Number.isNaN(parsedMs)) {
            dateEpochSec = Math.floor(parsedMs / 1000);
          }
        }
        break;
      case 'received-spf': {
        const val = h.unfoldedValue;
        const ipMatch = /\bclient-ip\s*=\s*([^\s;]+)/i.exec(val);
        const heloMatch = /\bhelo\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(val);
        const envMatch = /\benvelope-from\s*=\s*(?:"([^"]*)"|<([^>]*)>|([^\s;]+))/i.exec(val);
        if (envMatch && returnPathAddress === undefined && !isNullReturnPath) {
          const rawEnv = (envMatch[1] ?? envMatch[2] ?? envMatch[3] ?? '').trim();
          if (rawEnv === '' || rawEnv === '<>') {
            isNullReturnPath = true;
            returnPathAddress = '';
          } else {
            const mbs = parseMailboxList(rawEnv);
            if (mbs[0]) {
              returnPathAddress = mbs[0].address;
              returnPathDomain = mbs[0].domain;
            } else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(rawEnv)) {
              returnPathDomain = rawEnv.toLowerCase().replace(/\.+$/, '');
            }
          }
        }
        if (ipMatch) {
          const normIp = normalizeCandidateIpToken(ipMatch[1]);
          if (normIp) {
            const rawHelo = (heloMatch?.[1] ?? heloMatch?.[2] ?? '').replace(/\.+$/, '').toLowerCase();
            candidateHops.push({
              ip: normIp.ip,
              family: normIp.family,
              isInternalRelay: isInternalRelayIp(normIp.ip, normIp.family),
              helo: rawHelo || undefined,
              source: 'received-spf',
              rawEvidence: `Received-SPF: ${val.slice(0, 140)}`,
              headerIndex: h.index,
            });
          }
        }
        break;
      }
      case 'received': {
        const val = h.unfoldedValue;
        // Parse trailing `; <RFC 2822 timestamp>` on Received header
        const semiIdx = val.lastIndexOf(';');
        let recEpoch: number | undefined;
        if (semiIdx >= 0) {
          const datePart = stripRfc5322Comments(val.slice(semiIdx + 1)).trim();
          const ms = Date.parse(datePart);
          if (!Number.isNaN(ms)) {
            recEpoch = Math.floor(ms / 1000);
            if (latestReceivedEpochSec === undefined || recEpoch > latestReceivedEpochSec) {
              latestReceivedEpochSec = recEpoch;
            }
          }
        }

        const fromMatch = /\bfrom\s+([^\s()[\];]+)/i.exec(val);
        const byMatch = /\bby\s+([^\s()[\];]+)/i.exec(val);
        const helo = fromMatch?.[1]?.replace(/\.+$/, '').toLowerCase();
        const byHost = byMatch?.[1]?.replace(/\.+$/, '').toLowerCase();

        // Extract IP literals inside `[...]` or `(...)` in the `from ... by` segment
        const beforeBy = byMatch && byMatch.index > 0 ? val.slice(0, byMatch.index) : val;
        const ipCandidates: string[] = [];
        const bracketRegex = /\[([^\][]+)\]/g;
        let bm: RegExpExecArray | null;
        while ((bm = bracketRegex.exec(beforeBy)) !== null) {
          ipCandidates.push(bm[1]);
        }
        const parenIpRegex = /\((?:[^()]*\s)?((?:\d{1,3}\.){3}\d{1,3}|(?:IPv6:)?[0-9a-fA-F:]{3,45})(?:[\s)])/g;
        let pm: RegExpExecArray | null;
        while ((pm = parenIpRegex.exec(beforeBy)) !== null) {
          ipCandidates.push(pm[1]);
        }

        for (const rawIpCand of ipCandidates) {
          const normIp = normalizeCandidateIpToken(rawIpCand);
          if (normIp) {
            candidateHops.push({
              ip: normIp.ip,
              family: normIp.family,
              isInternalRelay: isInternalRelayIp(normIp.ip, normIp.family),
              helo: helo && !normalizeCandidateIpToken(helo) ? helo : undefined,
              byHost,
              source: 'received',
              rawEvidence: `Received: ${val.slice(0, 140)}`,
              receivedTimestampSec: recEpoch,
              headerIndex: h.index,
            });
            break;
          }
        }
        break;
      }
    }
  }

  // Also harvest smtp.mailfrom / smtp.helo / connecting IP from Authentication-Results when missing
  for (const ar of [...authResults, ...arcAuthResults]) {
    for (const item of ar.items) {
      if (returnPathDomain === undefined && !isNullReturnPath && item.props['smtp.mailfrom']) {
        const mf = item.props['smtp.mailfrom'].trim();
        if (mf === '<>' || mf === '') {
          isNullReturnPath = true;
          returnPathAddress = '';
        } else {
          const mbs = parseMailboxList(mf);
          if (mbs[0]) {
            returnPathAddress = mbs[0].address;
            returnPathDomain = mbs[0].domain;
          } else if (/^[a-z0-9._-]+\.[a-z]{2,}$/i.test(mf.replace(/\.+$/, ''))) {
            returnPathDomain = mf.replace(/\.+$/, '').toLowerCase();
            returnPathAddress = `postmaster@${returnPathDomain}`;
          }
        }
      }

      const ipProp = item.props['policy.iprev'] ?? item.props['smtp.remote-ip'];
      const reasonIpMatch = item.reason
        ? /(?:designates|sender IP is|ip=)\s*([0-9a-fA-F:.]{7,45})/i.exec(item.reason)
        : null;
      const rawCand = ipProp ?? reasonIpMatch?.[1];
      if (rawCand) {
        const normIp = normalizeCandidateIpToken(rawCand);
        if (normIp) {
          const rawHelo = item.props['smtp.helo']?.replace(/\.+$/, '').toLowerCase();
          candidateHops.push({
            ip: normIp.ip,
            family: normIp.family,
            isInternalRelay: isInternalRelayIp(normIp.ip, normIp.family),
            helo: rawHelo || undefined,
            byHost: ar.authservId || undefined,
            source: 'auth-results',
            rawEvidence: `${ar.headerName}: ${item.rawClause.slice(0, 140)}`,
            headerIndex: ar.headerIndex,
          });
        }
      }
    }
  }

  // Choose primary connecting MTA hop:
  // 1. Prefer external (non-internal) hops over RFC 1918 / loopback internal relays.
  // 2. Prevent upstream or sender-forged Received-SPF / Authentication-Results headers below
  //    the topmost external Received header from hijacking the connecting MTA IP unless they
  //    belong to the same receiving MTA (byHost === authservId).
  const firstExternalReceived = candidateHops.find(
    (ch) => !ch.isInternalRelay && ch.source === 'received'
  );
  const isTopBoundaryClaim = (ch: ParsedConnectingHop): boolean => {
    if (!firstExternalReceived) return true;
    if (ch === firstExternalReceived) return true;
    const chIdx = ch.headerIndex ?? Number.MAX_SAFE_INTEGER;
    const recIdx = firstExternalReceived.headerIndex ?? Number.MAX_SAFE_INTEGER;
    if (chIdx <= recIdx) return true;
    if (
      ch.byHost &&
      firstExternalReceived.byHost &&
      ch.byHost.toLowerCase() === firstExternalReceived.byHost.toLowerCase()
    ) {
      return true;
    }
    return false;
  };

  const prioritizedHops = [...candidateHops].sort((a, b) => {
    if (a.isInternalRelay !== b.isInternalRelay) return a.isInternalRelay ? 1 : -1;
    const aTop = isTopBoundaryClaim(a);
    const bTop = isTopBoundaryClaim(b);
    if (aTop !== bTop) return aTop ? -1 : 1;
    const rank = (s: ParsedConnectingHop['source']) =>
      s === 'received-spf' ? 0 : s === 'auth-results' ? 1 : 2;
    const rankDiff = rank(a.source) - rank(b.source);
    if (rankDiff !== 0) return rankDiff;
    return (a.headerIndex ?? 0) - (b.headerIndex ?? 0);
  });
  const connectingHop = prioritizedHops[0];

  // Parse From: identities and flag RFC 5322 §3.6.2 multiple-From spoofing vectors
  const fromIdentities: ParsedMailboxIdentity[] = [];
  for (const fh of fromHeaders) {
    fromIdentities.push(...parseMailboxList(fh.unfoldedValue));
  }
  if (fromHeaders.length > 1) {
    anomalies.push(
      `Message contains ${fromHeaders.length} separate RFC 5322 "From:" header fields — RFC 5322 §3.6.2 requires at most one "From:" header (classic DMARC/MUA display spoofing vector).`
    );
  }
  if (fromIdentities.length > 1) {
    const distinctFromDomains = new Set(fromIdentities.map((f) => f.domain));
    if (distinctFromDomains.size > 1) {
      anomalies.push(
        `Multiple author domains in From: (${Array.from(distinctFromDomains).join(', ')}) — RFC 7489 §6.6.1 recommends rejecting multi-domain From: messages.`
      );
    }
  }
  if (fromHeaders.length === 0 && headers.length > 0) {
    anomalies.push('Message is missing a mandatory RFC 5322 "From:" header field.');
  }

  // Determine whether pasted text includes a message body vs headers-only paste
  const allSigsWithBh = [...dkimSignatures, ...arcMessageSignatures].filter(
    (s) => Boolean(s.bodyHashBase64)
  );
  const anySigExpectsEmptyBody = allSigsWithBh.some(
    (s) => s.bodyHashBase64 !== undefined && EMPTY_BODY_HASHES.has(s.bodyHashBase64)
  );

  let bodyMode: ParsedRawEmailMessage['bodyMode'];
  let hasBody: boolean;
  if (!hasBodySeparator) {
    bodyMode = 'headers-only';
    hasBody = false;
  } else if (rawAfterSep.length > 0) {
    if (rawAfterSep.trim().length === 0 && allSigsWithBh.length > 0 && !anySigExpectsEmptyBody) {
      // User pasted headers with trailing blank lines, not an empty body
      bodyMode = 'headers-only';
      hasBody = false;
    } else if (rawAfterSep.length === 0) {
      bodyMode = 'empty-body';
      hasBody = true;
    } else {
      bodyMode = 'with-body';
      hasBody = true;
    }
  } else {
    // Separator `\r\n\r\n` at very end of input with 0 chars after
    if (allSigsWithBh.length > 0 && !anySigExpectsEmptyBody) {
      bodyMode = 'headers-only';
      hasBody = false;
    } else {
      bodyMode = 'empty-body';
      hasBody = true;
    }
  }

  const bodyByteLength = hasBody ? new TextEncoder().encode(rawAfterSep).length : 0;

  return {
    headers,
    hasBodySeparator,
    hasBody,
    bodyMode,
    rawBodyCrlf: hasBody ? rawAfterSep : '',
    bodyByteLength,
    fromIdentities,
    primaryFrom: fromIdentities[0],
    multipleFromHeaderCount: fromHeaders.length,
    returnPathAddress,
    returnPathDomain,
    isNullReturnPath,
    subject,
    messageId,
    dateHeaderRaw,
    dateEpochSec,
    latestReceivedEpochSec,
    connectingHop,
    allCandidateHops: candidateHops,
    dkimSignatures,
    arcMessageSignatures,
    arcSeals,
    arcAuthResults,
    authResults,
    anomalies,
  };
}

/**
 * RFC 6376 §3.4.1 (`simple`) and §3.4.2 (`relaxed`) header canonicalization.
 * Returns canonicalized header field WITHOUT trailing `\r\n` so callers can either
 * append `\r\n` (for `h=` headers) or omit `\r\n` (for the final signing header).
 */
export function canonicalizeDkimHeader(
  rawHeader: string,
  mode: DkimCanonicalizationMode
): string {
  if (mode === 'simple') {
    return rawHeader;
  }

  const colonIdx = rawHeader.indexOf(':');
  if (colonIdx < 0) return rawHeader;

  const lowerName = rawHeader.slice(0, colonIdx).toLowerCase().replace(/[ \t]+$/g, '');
  const unfoldedVal = rawHeader
    .slice(colonIdx + 1)
    .replace(/\r\n(?=[ \t])/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/^ | $/g, '');

  return `${lowerName}:${unfoldedVal}`;
}

/**
 * RFC 6376 §3.7: Deletes the `b=` signature value (including surrounding whitespace up to `;` or end)
 * from a raw `DKIM-Signature`, `ARC-Message-Signature`, or `ARC-Seal` header prior to canonicalization.
 */
export function stripSignatureBValue(rawHeader: string): string {
  const colonIdx = rawHeader.indexOf(':');
  if (colonIdx < 0) return rawHeader;
  const prefix = rawHeader.slice(0, colonIdx + 1);
  const body = rawHeader.slice(colonIdx + 1);
  const strippedBody = body.replace(/(^|;)(\s*b(?:\r\n[ \t]+|[ \t])*)=[^;]*/i, '$1$2=');
  return `${prefix}${strippedBody}`;
}

/**
 * RFC 6376 §3.4.3 (`simple`) and §3.4.4 (`relaxed`) body canonicalization.
 * Input `rawBodyCrlf` must already have normalized `\r\n` line endings.
 */
export function canonicalizeDkimBody(
  rawBodyCrlf: string,
  mode: DkimCanonicalizationMode
): string {
  if (mode === 'simple') {
    if (rawBodyCrlf.length === 0) {
      return '\r\n';
    }
    const withTrailing = rawBodyCrlf.endsWith('\r\n') ? rawBodyCrlf : `${rawBodyCrlf}\r\n`;
    return withTrailing.replace(/(\r\n)+$/, '\r\n');
  }

  if (rawBodyCrlf.length === 0) {
    return '';
  }

  const withoutFinalCrlf = rawBodyCrlf.endsWith('\r\n')
    ? rawBodyCrlf.slice(0, -2)
    : rawBodyCrlf;
  const lines = withoutFinalCrlf
    .split('\r\n')
    .map((line) => line.replace(/[ \t]+/g, ' ').replace(/ $/g, ''));

  while (lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }

  if (lines.length === 0) {
    return '';
  }
  return `${lines.join('\r\n')}\r\n`;
}

/**
 * Builds the exact byte buffer hashed/signed by a `DKIM-Signature` or `ARC-Message-Signature`
 * using RFC 6376 §5.4.2 bottom-up header selection.
 */
export function buildDkimSigningInput(
  headers: readonly ParsedEmailHeader[],
  sig: ParsedDkimLikeSignature
): {
  signingBytes: Uint8Array;
  matchedSignedHeaders: MatchedSignedHeaderEntry[];
} {
  const consumedIndices = new Set<number>();
  const matchedSignedHeaders: MatchedSignedHeaderEntry[] = [];
  const chunks: string[] = [];

  for (const requestedName of sig.signedHeaders) {
    let matchedIdx: number | null = null;
    for (let i = headers.length - 1; i >= 0; i--) {
      if (!consumedIndices.has(i) && headers[i].lowerName === requestedName) {
        matchedIdx = i;
        consumedIndices.add(i);
        break;
      }
    }
    if (matchedIdx !== null) {
      chunks.push(`${canonicalizeDkimHeader(headers[matchedIdx].rawHeader, sig.headerCanon)}\r\n`);
      matchedSignedHeaders.push({
        requestedName,
        matchedHeaderIndex: matchedIdx,
        oversigned: false,
      });
    } else {
      matchedSignedHeaders.push({
        requestedName,
        matchedHeaderIndex: null,
        oversigned: true,
      });
    }
  }

  const strippedSigRaw = stripSignatureBValue(sig.rawHeader);
  chunks.push(canonicalizeDkimHeader(strippedSigRaw, sig.headerCanon));

  const signingBytes = new TextEncoder().encode(chunks.join(''));
  return { signingBytes, matchedSignedHeaders };
}

/**
 * Builds the exact byte buffer signed by an RFC 8617 §5.1.1 `ARC-Seal` at instance `k`.
 */
export function buildArcSealSigningInput(
  setsByInstance: ReadonlyMap<
    number,
    {
      aar: ParsedAuthResultsHeader;
      ams: ParsedDkimLikeSignature;
      seal: ParsedDkimLikeSignature;
    }
  >,
  targetInstance: number
): Uint8Array | null {
  const chunks: string[] = [];
  for (let i = 1; i <= targetInstance; i++) {
    const entry = setsByInstance.get(i);
    if (!entry) return null;
    chunks.push(`${canonicalizeDkimHeader(entry.aar.rawHeader, 'relaxed')}\r\n`);
    chunks.push(`${canonicalizeDkimHeader(entry.ams.rawHeader, 'relaxed')}\r\n`);
    if (i < targetInstance) {
      chunks.push(`${canonicalizeDkimHeader(entry.seal.rawHeader, 'relaxed')}\r\n`);
    } else {
      const strippedSeal = stripSignatureBValue(entry.seal.rawHeader);
      chunks.push(canonicalizeDkimHeader(strippedSeal, 'relaxed'));
    }
  }
  return new TextEncoder().encode(chunks.join(''));
}

async function computeDigestBase64(
  algorithm: 'SHA-1' | 'SHA-256',
  data: Uint8Array
): Promise<string> {
  const digest = await crypto.subtle.digest(algorithm, toArrayBuffer(data));
  return bytesToBase64(new Uint8Array(digest));
}

async function verifyDkimRawCrypto(params: {
  sigAlgorithm: string;
  publicKeyType: string;
  publicKeyBase64: string;
  signatureBase64: string;
  signingBytes: Uint8Array;
}): Promise<{ ok: boolean; error?: string }> {
  const { sigAlgorithm, publicKeyType, publicKeyBase64, signatureBase64, signingBytes } = params;

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64ToBytes(signatureBase64);
  } catch {
    return { ok: false, error: 'Signature b= tag is not valid Base64' };
  }

  let keyBytes: Uint8Array;
  try {
    keyBytes = base64ToBytes(publicKeyBase64);
  } catch {
    return { ok: false, error: 'DNS _domainkey p= tag is not valid Base64' };
  }

  if (sigAlgorithm === 'ed25519-sha256') {
    if (publicKeyType.toLowerCase() !== 'ed25519') {
      return {
        ok: false,
        error: `Algorithm mismatch: signature uses ${sigAlgorithm} but DNS _domainkey declares k=${publicKeyType}`,
      };
    }
    if (keyBytes.length !== 32) {
      return {
        ok: false,
        error: `RFC 8463 Ed25519 public key must be 32 raw bytes (got ${keyBytes.length})`,
      };
    }
    if (sigBytes.length !== 64) {
      return {
        ok: false,
        error: `RFC 8463 Ed25519 signature b= must be 64 bytes (got ${sigBytes.length})`,
      };
    }
    try {
      // RFC 8463 §3.4 / §4: Ed25519 signs the 32-byte SHA-256 digest of the canonicalized headers using PureEdDSA!
      const headerHashBuf = await crypto.subtle.digest('SHA-256', toArrayBuffer(signingBytes));
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        toArrayBuffer(keyBytes),
        { name: 'Ed25519' },
        false,
        ['verify']
      );
      const valid = await crypto.subtle.verify(
        { name: 'Ed25519' },
        cryptoKey,
        toArrayBuffer(sigBytes),
        headerHashBuf
      );
      return { ok: valid };
    } catch (err) {
      return {
        ok: false,
        error: `WebCrypto Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  if (sigAlgorithm === 'rsa-sha256' || sigAlgorithm === 'rsa-sha1') {
    if (publicKeyType.toLowerCase() !== 'rsa') {
      return {
        ok: false,
        error: `Algorithm mismatch: signature uses ${sigAlgorithm} but DNS _domainkey declares k=${publicKeyType}`,
      };
    }
    const hashName = sigAlgorithm === 'rsa-sha256' ? 'SHA-256' : 'SHA-1';
    const keyInfo = decodeDkimPublicKey('rsa', publicKeyBase64);
    const spkiCandidate = keyInfo.warning?.includes('bare PKCS#1')
      ? wrapPkcs1RsaInSpki(keyBytes)
      : keyBytes;

    try {
      let cryptoKey: CryptoKey;
      try {
        cryptoKey = await crypto.subtle.importKey(
          'spki',
          toArrayBuffer(spkiCandidate),
          { name: 'RSASSA-PKCS1-v1_5', hash: hashName },
          false,
          ['verify']
        );
      } catch {
        // Fallback: try wrapping as bare PKCS#1 if SPKI import failed
        cryptoKey = await crypto.subtle.importKey(
          'spki',
          toArrayBuffer(wrapPkcs1RsaInSpki(keyBytes)),
          { name: 'RSASSA-PKCS1-v1_5', hash: hashName },
          false,
          ['verify']
        );
      }

      const valid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        toArrayBuffer(sigBytes),
        toArrayBuffer(signingBytes)
      );
      return { ok: valid };
    } catch (err) {
      return {
        ok: false,
        error: `WebCrypto RSA verification error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  return {
    ok: false,
    error: `Unsupported DKIM/ARC signing algorithm a="${sigAlgorithm || '(missing)'}"`,
  };
}

function extractGranularityTag(rawTxt: string | undefined): string | undefined {
  if (!rawTxt) return undefined;
  for (const seg of rawTxt.split(';')) {
    const eq = seg.indexOf('=');
    if (eq <= 0) continue;
    if (seg.slice(0, eq).trim() === 'g') {
      return seg.slice(eq + 1).trim();
    }
  }
  return undefined;
}

function matchesDkimGranularity(granularity: string, localPart: string): boolean {
  if (granularity === '*') return true;
  if (granularity === '') return localPart === '';
  const starIdx = granularity.indexOf('*');
  if (starIdx < 0) {
    return localPart === granularity;
  }
  const prefix = granularity.slice(0, starIdx);
  const suffix = granularity.slice(starIdx + 1);
  return (
    localPart.length >= prefix.length + suffix.length &&
    localPart.startsWith(prefix) &&
    localPart.endsWith(suffix)
  );
}

export function evaluateDmarcAlignment(params: {
  candidateDomain: string;
  fromDomain: string;
  mode: 'r' | 's';
  queries: DohQueryLog[];
}): DmarcAlignmentDetail {
  const candClean = params.candidateDomain.trim().toLowerCase().replace(/\.+$/, '');
  const fromClean = params.fromDomain.trim().toLowerCase().replace(/\.+$/, '');
  const candOrg = displayFqdn(
    estimateOrganizationalDomain(normalizeFqdn(candClean), params.queries)
  ).toLowerCase();
  const fromOrg = displayFqdn(
    estimateOrganizationalDomain(normalizeFqdn(fromClean), params.queries)
  ).toLowerCase();

  if (candClean && candClean === fromClean) {
    return {
      aligned: true,
      mode: params.mode,
      matchKind: 'exact',
      candidateDomain: candClean,
      candidateOrgDomain: candOrg,
      fromDomain: fromClean,
      fromOrgDomain: fromOrg,
    };
  }

  if (params.mode === 'r' && candOrg && candOrg === fromOrg) {
    return {
      aligned: true,
      mode: 'r',
      matchKind: 'org-domain',
      candidateDomain: candClean,
      candidateOrgDomain: candOrg,
      fromDomain: fromClean,
      fromOrgDomain: fromOrg,
    };
  }

  return {
    aligned: false,
    mode: params.mode,
    matchKind: 'unaligned',
    candidateDomain: candClean,
    candidateOrgDomain: candOrg,
    fromDomain: fromClean,
    fromOrgDomain: fromOrg,
  };
}

function evaluateTimestamps(
  sig: ParsedDkimLikeSignature,
  nowSec: number,
  receiptSec: number | undefined
): SignatureTimestampEvaluation {
  const signedAtIso =
    sig.timestampSec !== undefined ? new Date(sig.timestampSec * 1000).toISOString() : undefined;
  const expiresAtIso =
    sig.expirationSec !== undefined ? new Date(sig.expirationSec * 1000).toISOString() : undefined;
  const xBeforeT =
    sig.timestampSec !== undefined &&
    sig.expirationSec !== undefined &&
    sig.expirationSec <= sig.timestampSec;
  const expiredNow = sig.expirationSec !== undefined && nowSec > sig.expirationSec;
  const expiredAtReceipt =
    sig.expirationSec !== undefined && receiptSec !== undefined
      ? receiptSec > sig.expirationSec
      : null;
  // Allow 15 minutes clock skew before flagging future t=
  const futureTimestamp = sig.timestampSec !== undefined && sig.timestampSec > nowSec + 900;

  return {
    signedAtIso,
    expiresAtIso,
    expiredNow,
    expiredAtReceipt,
    xBeforeT,
    futureTimestamp,
  };
}

async function verifySingleSignatureRecord(params: {
  sig: ParsedDkimLikeSignature;
  parsed: ParsedRawEmailMessage;
  signingBytesOverride?: Uint8Array | null;
  dnsSelector: DkimSelectorResult | null;
  nowSec: number;
  receiptSec?: number;
}): Promise<VerifiedDkimSignatureResult> {
  const { sig, parsed, signingBytesOverride, dnsSelector, nowSec, receiptSec } = params;
  const issues: string[] = [];
  const warnings: string[] = [];
  const labelPrefix =
    sig.kind === 'dkim'
      ? `DKIM (d=${sig.domain || '?'}, s=${sig.selector || '?'})`
      : sig.kind === 'arc-ms'
        ? `ARC-Message-Signature (i=${sig.instance ?? '?'}, d=${sig.domain || '?'}, s=${sig.selector || '?'})`
        : `ARC-Seal (i=${sig.instance ?? '?'}, d=${sig.domain || '?'}, s=${sig.selector || '?'})`;

  const timestampEvaluation = evaluateTimestamps(sig, nowSec, receiptSec);
  const dnssecStatus: ValidationStatus = dnsSelector?.dnssecStatus ?? 'indeterminate';

  if (sig.duplicateTags.length > 0) {
    issues.push(`Duplicate signature tag(s): ${sig.duplicateTags.join(', ')} (RFC 6376 §3.5)`);
  }
  if (sig.malformedTags.length > 0) {
    issues.push(`Malformed tag syntax: ${sig.malformedTags.join(', ')}`);
  }

  if (sig.kind === 'dkim') {
    if (sig.version !== '1') {
      issues.push(
        `Invalid or missing DKIM version v="${sig.version ?? '(missing)'}" (RFC 6376 §3.5 requires v=1)`
      );
    }
  } else if (sig.version !== undefined) {
    issues.push(`RFC 8617 §4.1 forbids v= version tag on ${sig.kind === 'arc-ms' ? 'ARC-Message-Signature' : 'ARC-Seal'}`);
  }

  if (sig.kind === 'arc-seal' && sig.hasExplicitH) {
    issues.push('RFC 8617 §4.1.3 forbids h= tag inside ARC-Seal header (automatic validation failure)');
  }
  if (
    sig.kind === 'arc-seal' &&
    sig.tags.c !== undefined &&
    sig.tags.c.trim().toLowerCase() !== 'relaxed' &&
    sig.tags.c.trim().toLowerCase() !== 'relaxed/relaxed'
  ) {
    issues.push(`RFC 8617 §4.1.3 requires relaxed canonicalization on ARC-Seal (got c=${sig.tags.c})`);
  }

  if (!sig.domain || !sig.selector || !sig.algorithm || !sig.signatureBase64) {
    issues.push('Missing one or more mandatory signature tags (a=, d=, s=, b=)');
  }
  if ((sig.kind === 'dkim' || sig.kind === 'arc-ms') && !sig.bodyHashBase64) {
    issues.push('Missing mandatory bh= body hash tag');
  }

  const missingFromInH =
    sig.kind === 'dkim' ? !sig.signedHeaders.includes('from') : false;
  if (missingFromInH) {
    issues.push('Mandatory "from" header is NOT listed in h= signed headers (RFC 6376 §5.4)');
  }
  if (
    sig.kind === 'dkim' &&
    parsed.multipleFromHeaderCount > 1 &&
    sig.signedHeaders.filter((h) => h === 'from').length < parsed.multipleFromHeaderCount
  ) {
    warnings.push(
      `Message contains ${parsed.multipleFromHeaderCount} "From:" headers, but h= only signs ${sig.signedHeaders.filter((h) => h === 'from').length} — unsigned From: injection risk!`
    );
  }

  // Check AUID `i=` domain relationship to SDID `d=`
  if (sig.kind === 'dkim' && sig.auidDomain && sig.domain) {
    if (sig.auidDomain !== sig.domain && !sig.auidDomain.endsWith(`.${sig.domain}`)) {
      issues.push(
        `Agent/User Identifier i=${sig.auid} is outside signing domain d=${sig.domain} (RFC 6376 §3.5)`
      );
    }
  }

  if (timestampEvaluation.xBeforeT) {
    issues.push(
      `Signature expiration x=${sig.expirationSec} is not greater than timestamp t=${sig.timestampSec} (RFC 6376 §3.5)`
    );
  }
  if (timestampEvaluation.futureTimestamp) {
    warnings.push(`Signature timestamp t=${sig.timestampSec} (${timestampEvaluation.signedAtIso}) is in the future`);
  }
  if (timestampEvaluation.expiredAtReceipt === true) {
    issues.push(
      `Signature had ALREADY expired (x=${timestampEvaluation.expiresAtIso}) prior to message transit/Date`
    );
  } else if (timestampEvaluation.expiredNow) {
    warnings.push(
      `Signature x=${timestampEvaluation.expiresAtIso} has expired relative to current wall clock${
        timestampEvaluation.expiredAtReceipt === false ? ' (was NOT expired at message Date/receipt time)' : ''
      }`
    );
  }

  // Step 1: Compute body hash (`bh=`) for DKIM-Signature and ARC-Message-Signature
  let bodyHashStatus: VerifiedDkimSignatureResult['bodyHashStatus'] = 'not-applicable';
  let computedBodyHashBase64: string | undefined;
  let canonicalBodyByteLength: number | undefined;
  let unsignedTrailingBodyBytes: number | undefined;

  const hashAlg =
    sig.algorithm === 'rsa-sha1' ? ('SHA-1' as const) : ('SHA-256' as const);

  if (sig.kind === 'dkim' || sig.kind === 'arc-ms') {
    if (!parsed.hasBody) {
      bodyHashStatus = 'unchecked-no-body';
      warnings.push(
        'Header-only paste — cryptographic signature b= over signed headers is verified, but body hash bh= cannot be checked without the message body.'
      );
      if (sig.bodyLengthLimit !== undefined) {
        warnings.push(
          `Signature includes l=${sig.bodyLengthLimit} body-length limit tag (RFC 6376 §8.2 unsigned appended-body spoofing risk).`
        );
      }
    } else {
      const canonicalBody = canonicalizeDkimBody(parsed.rawBodyCrlf, sig.bodyCanon);
      const canonicalBodyBytes = new TextEncoder().encode(canonicalBody);
      canonicalBodyByteLength = canonicalBodyBytes.length;

      let hashedSlice = canonicalBodyBytes;
      if (sig.bodyLengthLimit !== undefined) {
        if (sig.bodyLengthLimit > canonicalBodyBytes.length) {
          bodyHashStatus = 'length-exceeded';
          issues.push(
            `Body length tag l=${sig.bodyLengthLimit} exceeds canonicalized body size (${canonicalBodyBytes.length} bytes) — RFC 6376 §3.7 permerror`
          );
        } else {
          hashedSlice = canonicalBodyBytes.subarray(0, sig.bodyLengthLimit);
          unsignedTrailingBodyBytes = canonicalBodyBytes.length - sig.bodyLengthLimit;
          if (unsignedTrailingBodyBytes > 0) {
            warnings.push(
              `Security Warning (RFC 6376 §8.2): l=${sig.bodyLengthLimit} signs only ${sig.bodyLengthLimit} of ${canonicalBodyBytes.length} canonicalized body bytes — ${unsignedTrailingBodyBytes} trailing byte(s) are UNSIGNED!`
            );
          } else {
            warnings.push(
              `Signature uses l=${sig.bodyLengthLimit} body-length limit tag (discouraged by RFC 6376 §8.2).`
            );
          }
        }
      }

      if (bodyHashStatus !== 'length-exceeded') {
        computedBodyHashBase64 = await computeDigestBase64(hashAlg, hashedSlice);
        if (sig.bodyHashBase64 && computedBodyHashBase64 === sig.bodyHashBase64) {
          bodyHashStatus = 'match';
        } else {
          bodyHashStatus = 'mismatch';
          issues.push(
            `Body hash mismatch (${sig.bodyCanon} body canonicalization): header bh=${sig.bodyHashBase64 ?? '(none)'} vs computed ${computedBodyHashBase64}`
          );
        }
      }
    }
  }

  // Step 2: Build header signing input
  let signingBytes: Uint8Array | null = null;
  let matchedSignedHeaders: MatchedSignedHeaderEntry[] = [];
  if (sig.kind === 'arc-seal') {
    signingBytes = signingBytesOverride ?? null;
  } else {
    const built = buildDkimSigningInput(parsed.headers, sig);
    signingBytes = built.signingBytes;
    matchedSignedHeaders = built.matchedSignedHeaders;
  }

  const deprecatedAlgorithm = sig.algorithm === 'rsa-sha1';
  if (deprecatedAlgorithm) {
    issues.push(
      'RFC 8301 §3.1: rsa-sha1 is cryptographically broken and MUST NOT be treated as a valid DKIM/ARC signature.'
    );
  }

  // Step 3: Check DNS _domainkey selector record & verify `b=` signature
  let headerCryptoValid: boolean | null = null;
  let weakKeyRejected = false;

  if (!dnsSelector || !dnsSelector.present) {
    if (dnssecStatus === 'bogus') {
      issues.push(
        `DNSSEC validation failed (BOGUS) when looking up ${sig.selector}._domainkey.${sig.domain}`
      );
    } else {
      issues.push(
        `Public key record ${sig.selector}._domainkey.${sig.domain} TXT not found in DNS (key missing or rotated since delivery)`
      );
    }
  } else if (dnsSelector.status === 'revoked' || dnsSelector.publicKeyBase64 === '') {
    issues.push(
      `DKIM key at ${displayFqdn(dnsSelector.qname)} is explicitly REVOKED (empty p= tag per RFC 6376 §3.6.1)`
    );
  } else if (!dnsSelector.publicKeyBase64 || dnsSelector.status === 'invalid') {
    issues.push(
      dnsSelector.issues[0] ?? `Malformed DKIM public key record at ${displayFqdn(dnsSelector.qname)}`
    );
  } else {
    if (dnsSelector.keyType === 'rsa' && dnsSelector.keyBits !== undefined) {
      if (dnsSelector.keyBits < 1024) {
        weakKeyRejected = true;
        issues.push(
          `RFC 8301 §3.2: ${dnsSelector.keyBits}-bit RSA key is below the mandatory 1024-bit minimum and MUST be rejected`
        );
      } else if (dnsSelector.keyBits < 2048) {
        warnings.push(
          `Legacy ${dnsSelector.keyBits}-bit RSA key at ${displayFqdn(dnsSelector.qname)} (2048-bit RSA or Ed25519 recommended per RFC 8301)`
        );
      }
    }

    if (
      dnsSelector.serviceTypes &&
      !dnsSelector.serviceTypes.includes('*') &&
      !dnsSelector.serviceTypes.includes('email')
    ) {
      issues.push(
        `DNS key service type s=${dnsSelector.serviceTypes.join(':')} excludes email (RFC 6376 §3.6.1)`
      );
    }

    if (dnsSelector.hashAlgorithms) {
      const sigHashPart = sig.algorithm.split('-')[1] ?? '';
      if (sigHashPart && !dnsSelector.hashAlgorithms.includes(sigHashPart)) {
        issues.push(
          `DNS key restricts acceptable hashes to h=${dnsSelector.hashAlgorithms.join(':')}, rejecting ${sig.algorithm}`
        );
      }
    }

    if (
      sig.kind === 'dkim' &&
      dnsSelector.isStrictSubdomain &&
      sig.auidDomain &&
      sig.auidDomain !== sig.domain
    ) {
      issues.push(
        `DNS key sets strict flag t=s, forbidding subdomain AUID i=${sig.auid} under d=${sig.domain} (RFC 6376 §3.6.1)`
      );
    }

    const granularity = extractGranularityTag(dnsSelector.rawRecord);
    if (
      sig.kind === 'dkim' &&
      granularity !== undefined &&
      !matchesDkimGranularity(granularity, sig.auidLocalPart ?? '')
    ) {
      issues.push(
        `DNS key granularity g="${granularity}" does not match signature AUID local-part "${sig.auidLocalPart ?? ''}"`
      );
    }

    if (dnsSelector.isTestingMode) {
      warnings.push(
        `DNS key at ${displayFqdn(dnsSelector.qname)} sets testing flag t=y (RFC 6376 §3.6.1)`
      );
    }

    if (signingBytes && sig.signatureBase64) {
      const cryptoRes = await verifyDkimRawCrypto({
        sigAlgorithm: sig.algorithm,
        publicKeyType: dnsSelector.keyType,
        publicKeyBase64: dnsSelector.publicKeyBase64,
        signatureBase64: sig.signatureBase64,
        signingBytes,
      });
      headerCryptoValid = cryptoRes.ok;
      if (!cryptoRes.ok) {
        issues.push(
          cryptoRes.error ??
            `Cryptographic signature b= verification FAILED against ${displayFqdn(dnsSelector.qname)} (${sig.headerCanon} header canonicalization)`
        );
      }
    }
  }

  // Synthesize final verdict
  let verdict: SignatureVerificationVerdict;
  const hasStructuralPermError =
    sig.duplicateTags.length > 0 ||
    sig.malformedTags.length > 0 ||
    !sig.domain ||
    !sig.selector ||
    !sig.algorithm ||
    !sig.signatureBase64 ||
    missingFromInH ||
    timestampEvaluation.xBeforeT ||
    bodyHashStatus === 'length-exceeded' ||
    (sig.kind === 'dkim' && sig.version !== '1') ||
    (sig.kind === 'arc-seal' && sig.hasExplicitH);

  if (dnssecStatus === 'bogus') {
    verdict = 'temperror';
  } else if (hasStructuralPermError) {
    verdict = 'permerror';
  } else if (headerCryptoValid !== true) {
    verdict = !dnsSelector || !dnsSelector.present ? 'permerror' : 'fail';
  } else if (bodyHashStatus === 'mismatch') {
    verdict = 'fail';
  } else if (deprecatedAlgorithm || weakKeyRejected || timestampEvaluation.expiredAtReceipt === true) {
    verdict = 'policy-fail';
  } else if (bodyHashStatus === 'unchecked-no-body') {
    verdict = 'headers-verified-only';
  } else {
    verdict = 'pass';
  }

  let summary: string;
  if (verdict === 'pass') {
    summary = `${labelPrefix}: Cryptographic signature b=${sig.kind === 'arc-seal' ? '' : ' and body hash bh='} VALID (${sig.algorithm}, DNSSEC ${dnssecStatus.toUpperCase()}).`;
  } else if (verdict === 'headers-verified-only') {
    summary = `${labelPrefix}: Header signature b= VALID (${sig.algorithm}), body hash bh= not checked (headers-only paste).`;
  } else if (headerCryptoValid === true && bodyHashStatus === 'mismatch') {
    summary = `${labelPrefix}: Header signature b= is cryptographically VALID, but message body was modified in transit (bh= mismatch).`;
  } else if (headerCryptoValid === true && verdict === 'policy-fail') {
    summary = `${labelPrefix}: Cryptographic math matched, but REJECTED by RFC 8301 / expiration security policy (${issues[0]}).`;
  } else {
    summary = `${labelPrefix}: ${issues[0] ?? 'Signature verification failed.'}`;
  }

  return {
    signature: sig,
    verdict,
    headerCryptoValid,
    bodyHashStatus,
    computedBodyHashBase64,
    canonicalBodyByteLength,
    unsignedTrailingBodyBytes,
    dnsSelector,
    dnssecStatus,
    matchedSignedHeaders,
    missingFromInH,
    deprecatedAlgorithm,
    weakKeyRejected,
    timestampEvaluation,
    summary,
    issues,
    warnings,
  };
}

function buildAuthResultsDiff(params: {
  parsed: ParsedRawEmailMessage;
  dkimResults: VerifiedDkimSignatureResult[];
  spfReplay: SpfReplayVerificationResult;
  dmarcReplay: DmarcReplayVerificationResult;
  arc: ArcChainVerificationResult;
}): AuthResultsComparisonEntry[] {
  const { parsed, dkimResults, spfReplay, dmarcReplay, arc } = params;
  const entries: AuthResultsComparisonEntry[] = [];

  // Compare against topmost Authentication-Results headers (receiving MTA verdicts)
  for (const ar of parsed.authResults) {
    const authserv = ar.authservId || 'receiving-mta';
    for (const item of ar.items) {
      if (item.method === 'dkim') {
        const claimDom = (
          item.props['header.d'] ??
          item.props['header.i']?.split('@').pop() ??
          ''
        )
          .replace(/\.+$/, '')
          .toLowerCase();
        const claimSel = (item.props['header.s'] ?? '').replace(/\.+$/, '').toLowerCase();

        const matchedDkim =
          dkimResults.find(
            (r) =>
              (!claimDom || r.signature.domain === claimDom) &&
              (!claimSel || r.signature.selector === claimSel)
          ) ?? dkimResults[0];

        const replayed = matchedDkim
          ? matchedDkim.verdict === 'headers-verified-only'
            ? 'pass (headers-only)'
            : matchedDkim.verdict
          : 'none';
        const claimPass = item.result === 'pass';
        const replayPass =
          matchedDkim?.verdict === 'pass' || matchedDkim?.verdict === 'headers-verified-only';

        let status: AuthResultsComparisonEntry['status'];
        let explanation: string;
        if (claimPass && matchedDkim?.verdict === 'headers-verified-only') {
          status = 'headers-only-match';
          explanation =
            'Header signature b= matches receiving MTA pass; paste full .eml body to verify bh= as well.';
        } else if (
          item.result === matchedDkim?.verdict ||
          (claimPass && matchedDkim?.verdict === 'pass')
        ) {
          status = 'match';
          explanation = 'Local WebCrypto DKIM verification matches receiving MTA verdict.';
        } else {
          status = 'drift';
          if (claimPass && !replayPass) {
            if (!matchedDkim?.dnsSelector?.present) {
              explanation = `MTA recorded dkim=pass at delivery, but ${(matchedDkim?.signature.selector ?? claimSel) || '?'}._domainkey.${(matchedDkim?.signature.domain ?? claimDom) || '?'} is no longer published in live DNS (selector rotated).`;
            } else if (matchedDkim?.dnsSelector?.status === 'revoked') {
              explanation =
                'MTA recorded dkim=pass at delivery, but the selector key has since been revoked (empty p=) in DNS.';
            } else if (matchedDkim?.headerCryptoValid === true && matchedDkim.bodyHashStatus === 'mismatch') {
              explanation =
                'Header signature b= still verifies, so the message body was altered after the MTA stamped Authentication-Results (e.g. MUA/export re-encoding).';
            } else if (matchedDkim?.verdict === 'policy-fail') {
              explanation = `MTA accepted legacy signature, whereas strict RFC 8301 / expiration check rejected it: ${matchedDkim.issues[0] ?? ''}`;
            } else {
              explanation =
                matchedDkim?.issues[0] ??
                'Live WebCrypto DKIM replay differs from Authentication-Results claim.';
            }
          } else {
            explanation = `MTA recorded dkim=${item.result}, while live WebCrypto replay evaluated ${replayed}.`;
          }
        }

        entries.push({
          protocol: 'dkim',
          identityLabel: `d=${matchedDkim?.signature.domain || claimDom || '?'}${
            matchedDkim?.signature.selector || claimSel
              ? ` (s=${matchedDkim?.signature.selector || claimSel})`
              : ''
          }`,
          claimedAuthservId: authserv,
          claimedResult: item.result,
          replayedResult: replayed,
          status,
          explanation,
        });
      } else if (item.method === 'spf') {
        const replayed = spfReplay.evaluated ? spfReplay.disposition : 'not-evaluated';
        const status: AuthResultsComparisonEntry['status'] =
          spfReplay.evaluated && item.result === spfReplay.disposition ? 'match' : 'drift';
        const explanation =
          status === 'match'
            ? `Live SPF evaluation for ${spfReplay.connectingIp ?? 'sender IP'} matches MTA spf=${item.result}.`
            : !spfReplay.evaluated
              ? 'No external connecting MTA IP was found in Received/Received-SPF headers to replay SPF.'
              : `MTA recorded spf=${item.result} at delivery, while replaying ${spfReplay.connectingIp} against live SPF for ${spfReplay.envelopeDomain} returned ${spfReplay.disposition} (SPF record changed or intermediate forwarder hop).`;

        entries.push({
          protocol: 'spf',
          identityLabel: `ip=${spfReplay.connectingIp ?? '?'} · mailfrom=${
            spfReplay.envelopeDomain ?? item.props['smtp.mailfrom'] ?? '?'
          }`,
          claimedAuthservId: authserv,
          claimedResult: item.result,
          replayedResult: replayed,
          status,
          explanation,
        });
      } else if (item.method === 'dmarc') {
        const replayed =
          dmarcReplay.verdict === 'pass-headers-only'
            ? 'pass (headers-only)'
            : dmarcReplay.verdict === 'no-policy'
              ? 'none'
              : dmarcReplay.verdict;
        const claimPass = item.result === 'pass';
        let status: AuthResultsComparisonEntry['status'];
        if (claimPass && dmarcReplay.verdict === 'pass-headers-only') {
          status = 'headers-only-match';
        } else if (
          item.result === replayed ||
          (claimPass && dmarcReplay.verdict === 'pass')
        ) {
          status = 'match';
        } else {
          status = 'drift';
        }
        const explanation =
          status === 'match'
            ? 'Replayed PSL-aware DMARC organizational alignment matches receiving MTA verdict.'
            : status === 'headers-only-match'
              ? 'Aligned DKIM header signature + DMARC policy match MTA dmarc=pass (headers-only paste).'
              : `MTA recorded dmarc=${item.result}, while live DMARC replay evaluated ${replayed} (${dmarcReplay.summary})`;

        entries.push({
          protocol: 'dmarc',
          identityLabel: `header.from=${dmarcReplay.fromDomain ?? item.props['header.from'] ?? '?'}`,
          claimedAuthservId: authserv,
          claimedResult: item.result,
          replayedResult: replayed,
          status,
          explanation,
        });
      } else if (item.method === 'arc') {
        const replayed =
          arc.verdict === 'headers-verified-only' ? 'pass (headers-only)' : arc.verdict;
        const status: AuthResultsComparisonEntry['status'] =
          item.result === 'pass' && arc.verdict === 'headers-verified-only'
            ? 'headers-only-match'
            : item.result === arc.verdict
              ? 'match'
              : 'drift';
        const explanation =
          status === 'match' || status === 'headers-only-match'
            ? 'Replayed RFC 8617 ARC seal chain matches receiving MTA verdict.'
            : `MTA recorded arc=${item.result}, while local WebCrypto ARC chain replay evaluated ${replayed}.`;

        entries.push({
          protocol: 'arc',
          identityLabel: `ARC chain (1..${arc.sets.length})`,
          claimedAuthservId: authserv,
          claimedResult: item.result,
          replayedResult: replayed,
          status,
          explanation,
        });
      }
    }
  }

  return entries;
}

/**
 * Cryptographically verifies a raw RFC 5322 email header block or full `.eml` message
 * 100% locally in the browser using WebCrypto (`SubtleCrypto`) and RFC 8484 DoH DNS lookups.
 *
 * Email headers and message body NEVER leave the user's device; only public DNS names
 * (`<s>._domainkey.<d>`, `_dmarc.<from>`, SPF domains, and `*.psl.digdeep.fyi`) are resolved.
 */
export async function verifyEmailMessageCryptographically(
  rawInput: string,
  options: VerifyEmailMessageOptions = {}
): Promise<EmailMessageVerificationReport> {
  const startedAt = Date.now();
  const nowMs = options.nowMs ?? startedAt;
  const nowSec = Math.floor(nowMs / 1000);
  const parsed = parseRawEmailMessage(rawInput);

  const initialLogs = options.snapshot?.queries ?? [];
  const endpoint = options.endpoint ?? options.snapshot?.dohEndpoint ?? DEFAULT_DOH_ENDPOINT;
  const trustAnchors =
    options.trustAnchors ?? options.snapshot?.trustAnchorsUsed ?? IANA_ROOT_TRUST_ANCHORS;

  const session = new DohSession({
    endpoint,
    timeoutMs: options.timeoutMs,
    fetchImpl: options.fetchImpl,
    initialLogs,
  });

  const discoveredZones = new Set<string>(['.']);
  const checkedCandidates = new Set<string>(['.']);
  for (const z of options.snapshot?.zones ?? []) {
    discoveredZones.add(normalizeFqdn(z.zoneName));
    checkedCandidates.add(normalizeFqdn(z.zoneName));
  }

  // Collect all unique (selector, domain) pairs across DKIM-Signature, ARC-Message-Signature, and ARC-Seal
  const selectorPairs: Array<{ selector: string; domain: string; qname: string }> = [];
  const seenQnames = new Set<string>();
  for (const sig of [
    ...parsed.dkimSignatures,
    ...parsed.arcMessageSignatures,
    ...parsed.arcSeals,
  ]) {
    if (!sig.selector || !sig.domain) continue;
    const qname = normalizeFqdn(`${sig.selector}._domainkey.${sig.domain}`);
    if (qname !== '.' && !seenQnames.has(qname)) {
      seenQnames.add(qname);
      selectorPairs.push({ selector: sig.selector, domain: sig.domain, qname });
    }
  }

  const fromDomain = parsed.primaryFrom?.domain;
  const spfEnvelopeDomain = parsed.isNullReturnPath
    ? parsed.connectingHop?.helo
    : (parsed.returnPathDomain ?? parsed.connectingHop?.helo ?? fromDomain);

  // Collect all domains needing PSL organizational-domain resolution
  const pslDomains = new Set<string>();
  if (fromDomain) pslDomains.add(normalizeFqdn(fromDomain));
  if (spfEnvelopeDomain) pslDomains.add(normalizeFqdn(spfEnvelopeDomain));
  for (const sig of parsed.dkimSignatures) {
    if (sig.domain) pslDomains.add(normalizeFqdn(sig.domain));
  }

  // Phase 1: Resolve PSL suffixes, _domainkey TXT + zone cuts, _dmarc TXT + zone cuts, and SPF tree
  const phase1Tasks: Promise<unknown>[] = [];

  for (const dom of pslDomains) {
    if (dom !== '.') {
      phase1Tasks.push(
        queryPublicSuffix(dom, { session, fetchImpl: options.fetchImpl }).catch(() => null)
      );
    }
  }

  for (const pair of selectorPairs) {
    phase1Tasks.push(
      discoverZoneCutsForName(session, pair.qname, discoveredZones, checkedCandidates).catch(
        () => undefined
      ),
      session
        .query(pair.qname, RR_TYPES.TXT, {
          cd: true,
          doBit: true,
          purpose: `Mail target (${pair.qname} TXT)`,
        })
        .catch(() => undefined)
    );
  }

  if (fromDomain) {
    const dmarcQname = normalizeFqdn(`_dmarc.${fromDomain}`);
    phase1Tasks.push(
      discoverZoneCutsForName(session, dmarcQname, discoveredZones, checkedCandidates).catch(
        () => undefined
      ),
      session
        .query(dmarcQname, RR_TYPES.TXT, {
          cd: true,
          doBit: true,
          purpose: `Mail target (${dmarcQname} TXT)`,
        })
        .catch(() => undefined)
    );
  }

  if (spfEnvelopeDomain && parsed.connectingHop) {
    const spfNorm = normalizeFqdn(spfEnvelopeDomain);
    phase1Tasks.push(
      discoverZoneCutsForName(session, spfNorm, discoveredZones, checkedCandidates).catch(
        () => undefined
      ),
      session
        .query(spfNorm, RR_TYPES.TXT, {
          cd: true,
          doBit: true,
          purpose: `Target RRset (${spfNorm} TXT)`,
        })
        .catch(() => undefined),
      prefetchSpfTree(session, spfNorm).catch(() => undefined)
    );
  }

  await Promise.all(phase1Tasks);
  seedPublicSuffixCacheFromLogs(session.getLogs());

  // Phase 2: Follow CNAME chains on _domainkey and _dmarc + RFC 7489 §6.6.3 Org-Domain DMARC fallback
  const cnameStartOwners: string[] = selectorPairs.map((p) => p.qname);
  if (fromDomain) {
    const fromNorm = normalizeFqdn(fromDomain);
    const dmarcDirect = normalizeFqdn(`_dmarc.${fromDomain}`);
    cnameStartOwners.push(dmarcDirect);
    const orgNorm = estimateOrganizationalDomain(fromNorm, session.getLogs());
    if (orgNorm !== fromNorm && orgNorm !== '.') {
      const orgDmarc = normalizeFqdn(`_dmarc.${orgNorm}`);
      cnameStartOwners.push(orgDmarc);
      await Promise.all([
        discoverZoneCutsForName(session, orgDmarc, discoveredZones, checkedCandidates).catch(
          () => undefined
        ),
        session
          .query(orgDmarc, RR_TYPES.TXT, {
            cd: true,
            doBit: true,
            purpose: `Mail target (${orgDmarc} TXT)`,
          })
          .catch(() => undefined),
      ]);
    }
  }

  if (cnameStartOwners.length > 0) {
    const visitedCnames = new Set<string>(cnameStartOwners);
    for (let hop = 0; hop < 5; hop++) {
      const logsNow = session.getLogs();
      const followTasks: Promise<unknown>[] = [];
      for (const log of logsNow) {
        for (const ans of log.packet.answers) {
          if (ans.type === RR_TYPES.CNAME && visitedCnames.has(normalizeFqdn(ans.name))) {
            const target = normalizeFqdn(ans.rdataText);
            if (target !== '.' && !visitedCnames.has(target)) {
              visitedCnames.add(target);
              followTasks.push(
                discoverZoneCutsForName(session, target, discoveredZones, checkedCandidates).catch(
                  () => undefined
                ),
                session
                  .query(target, RR_TYPES.TXT, {
                    cd: true,
                    doBit: true,
                    purpose: `CNAME target (${target} TXT)`,
                  })
                  .catch(() => undefined)
              );
            }
          }
        }
      }
      if (followTasks.length === 0) break;
      await Promise.all(followTasks);
    }
  }

  // Include authoritative SOA zones from CD=1 responses
  for (const log of session.getLogs()) {
    if (!log.cd || log.purpose.startsWith('PSL lookup') || log.purpose.startsWith('SPF lookup')) {
      continue;
    }
    for (const auth of log.packet.authorities) {
      if (auth.type === RR_TYPES.SOA) {
        discoveredZones.add(normalizeFqdn(auth.name));
      }
    }
  }

  // Phase 3: Fetch missing DNSKEY / DS / SOA / NS across discovered zones for WebCrypto DNSSEC validation
  await Promise.all(
    Array.from(discoveredZones).flatMap((z) => {
      const tasks: Promise<unknown>[] = [
        session
          .query(z, RR_TYPES.DNSKEY, { cd: true, doBit: true, purpose: `Zone DNSKEY (${z})` })
          .catch(() => undefined),
        session
          .query(z, RR_TYPES.SOA, { cd: true, doBit: true, purpose: `Zone SOA (${z})` })
          .catch(() => undefined),
        session
          .query(z, RR_TYPES.NS, { cd: true, doBit: true, purpose: `Zone NS (${z})` })
          .catch(() => undefined),
      ];
      if (z !== '.') {
        tasks.push(
          session
            .query(z, RR_TYPES.DS, { cd: true, doBit: true, purpose: `Delegation DS (${z})` })
            .catch(() => undefined)
        );
      }
      return tasks;
    })
  );

  const allQueries = session.getLogs();
  seedPublicSuffixCacheFromLogs(allQueries);

  // Validate DNSSEC chains via DigDeep's WebCrypto DNSSEC engine
  const primaryTarget = normalizeFqdn(
    fromDomain || parsed.dkimSignatures[0]?.domain || spfEnvelopeDomain || 'example.com'
  );
  const dnssecSnap = await evaluateSnapshotFromLogs({
    id: `email-verify-${startedAt}`,
    mode: 'dnssec',
    targetName: primaryTarget,
    queryTypes: ['TXT'],
    dohEndpoint: endpoint,
    capturedAt: nowMs,
    validatedAt: options.validationTimeMs ?? nowMs,
    durationMs: 1,
    queries: allQueries,
    trustAnchors,
  });
  const zones = dnssecSnap.zones;

  // Evaluate all referenced _domainkey selectors
  const selectorMap = new Map<string, DkimSelectorResult | null>();
  for (const pair of selectorPairs) {
    const scratchFindings: AuditFinding[] = [];
    const selRes = evaluateSingleDkimSelector({
      selector: pair.selector,
      source: 'custom',
      effectiveMailDomain: normalizeFqdn(pair.domain),
      queries: allQueries,
      zones,
      mailFindings: scratchFindings,
    });
    selectorMap.set(pair.qname, selRes);
  }

  // Evaluate live DMARC policy for RFC5322.From domain
  let dmarcRecord: DmarcAnalysis | null = null;
  if (fromDomain) {
    const dmarcFindings: AuditFinding[] = [];
    dmarcRecord = evaluateDmarcFromLogs({
      effectiveMailDomain: normalizeFqdn(fromDomain),
      isDomainNxdomain: false,
      queries: allQueries,
      zones,
      mailFindings: dmarcFindings,
    });
  }
  const adkim: 'r' | 's' = dmarcRecord?.adkim ?? 'r';
  const aspf: 'r' | 's' = dmarcRecord?.aspf ?? 'r';

  const receiptSec = parsed.latestReceivedEpochSec ?? parsed.dateEpochSec;

  // Step 4: Verify all DKIM-Signature headers
  const dkimResults: VerifiedDkimSignatureResult[] = [];
  for (const sig of parsed.dkimSignatures) {
    const qname =
      sig.selector && sig.domain
        ? normalizeFqdn(`${sig.selector}._domainkey.${sig.domain}`)
        : '';
    const dnsSel = qname ? (selectorMap.get(qname) ?? null) : null;
    const res = await verifySingleSignatureRecord({
      sig,
      parsed,
      dnsSelector: dnsSel,
      nowSec,
      receiptSec,
    });
    if (fromDomain && sig.domain) {
      res.dmarcAligned = evaluateDmarcAlignment({
        candidateDomain: sig.domain,
        fromDomain,
        mode: adkim,
        queries: allQueries,
      });
    }
    dkimResults.push(res);
  }

  // Step 5: Verify RFC 8617 ARC Chain (`i=1..N`)
  const arcPresent =
    parsed.arcSeals.length > 0 ||
    parsed.arcMessageSignatures.length > 0 ||
    parsed.arcAuthResults.length > 0;
  let arc: ArcChainVerificationResult;

  if (!arcPresent) {
    arc = {
      present: false,
      verdict: 'none',
      sets: [],
      summary: 'No ARC (RFC 8617) forwarding chain headers present in message.',
      issues: [],
    };
  } else {
    const arcIssues: string[] = [];
    const instanceNumbers = new Set<number>();
    for (const aar of parsed.arcAuthResults) {
      if (aar.arcInstance !== undefined) instanceNumbers.add(aar.arcInstance);
      else arcIssues.push('ARC-Authentication-Results header is missing mandatory i= instance tag');
    }
    for (const ams of parsed.arcMessageSignatures) {
      if (ams.instance !== undefined) instanceNumbers.add(ams.instance);
      else arcIssues.push('ARC-Message-Signature header is missing mandatory i= instance tag');
    }
    for (const seal of parsed.arcSeals) {
      if (seal.instance !== undefined) instanceNumbers.add(seal.instance);
      else arcIssues.push('ARC-Seal header is missing mandatory i= instance tag');
    }

    const sortedInstances = Array.from(instanceNumbers).sort((a, b) => a - b);
    const maxInstance = sortedInstances.length > 0 ? sortedInstances[sortedInstances.length - 1] : 0;

    if (maxInstance < 1 || maxInstance > 50) {
      arcIssues.push(
        `Invalid ARC chain instance range (max i=${maxInstance}; RFC 8617 §5.2 requires 1..50)`
      );
    }

    const completeSetsMap = new Map<
      number,
      {
        aar: ParsedAuthResultsHeader;
        ams: ParsedDkimLikeSignature;
        seal: ParsedDkimLikeSignature;
      }
    >();
    const verifiedSets: VerifiedArcSetResult[] = [];
    let chainStructureBroken = arcIssues.length > 0;

    for (let i = 1; i <= Math.min(Math.max(maxInstance, 1), 50); i++) {
      const aars = parsed.arcAuthResults.filter((x) => x.arcInstance === i);
      const amss = parsed.arcMessageSignatures.filter((x) => x.instance === i);
      const seals = parsed.arcSeals.filter((x) => x.instance === i);
      const setIssues: string[] = [];

      if (aars.length !== 1) {
        setIssues.push(
          aars.length === 0
            ? `Missing ARC-Authentication-Results for instance i=${i}`
            : `Duplicate (${aars.length}) ARC-Authentication-Results headers for i=${i}`
        );
      }
      if (amss.length !== 1) {
        setIssues.push(
          amss.length === 0
            ? `Missing ARC-Message-Signature for instance i=${i}`
            : `Duplicate (${amss.length}) ARC-Message-Signature headers for i=${i}`
        );
      }
      if (seals.length !== 1) {
        setIssues.push(
          seals.length === 0
            ? `Missing ARC-Seal for instance i=${i}`
            : `Duplicate (${seals.length}) ARC-Seal headers for i=${i}`
        );
      }

      if (aars.length === 1 && amss.length === 1 && seals.length === 1 && !chainStructureBroken) {
        completeSetsMap.set(i, { aar: aars[0], ams: amss[0], seal: seals[0] });
      } else {
        chainStructureBroken = true;
      }

      let amsResult: VerifiedDkimSignatureResult | undefined;
      if (amss[0]) {
        const qn =
          amss[0].selector && amss[0].domain
            ? normalizeFqdn(`${amss[0].selector}._domainkey.${amss[0].domain}`)
            : '';
        amsResult = await verifySingleSignatureRecord({
          sig: amss[0],
          parsed,
          dnsSelector: qn ? (selectorMap.get(qn) ?? null) : null,
          nowSec,
          receiptSec,
        });
      }

      let sealResult: VerifiedDkimSignatureResult | undefined;
      const cvTag = seals[0]?.chainValidation;
      if (seals[0]) {
        if (i === 1 && cvTag !== 'none') {
          setIssues.push(
            `RFC 8617 §5.2 requires cv=none on ARC-Seal i=1 (found cv=${cvTag ?? '(missing)'})`
          );
        } else if (i > 1 && cvTag !== 'pass') {
          setIssues.push(
            cvTag === 'fail'
              ? `ARC-Seal i=${i} explicitly declares cv=fail (prior ARC chain failed upstream)`
              : `RFC 8617 §5.2 requires cv=pass on ARC-Seal i=${i} (found cv=${cvTag ?? '(missing)'})`
          );
        }

        const sealInput = completeSetsMap.has(i)
          ? buildArcSealSigningInput(completeSetsMap, i)
          : null;
        const qn =
          seals[0].selector && seals[0].domain
            ? normalizeFqdn(`${seals[0].selector}._domainkey.${seals[0].domain}`)
            : '';
        sealResult = await verifySingleSignatureRecord({
          sig: seals[0],
          parsed,
          signingBytesOverride: sealInput,
          dnsSelector: qn ? (selectorMap.get(qn) ?? null) : null,
          nowSec,
          receiptSec,
        });
      }

      const sealOk =
        sealResult?.verdict === 'pass' || sealResult?.verdict === 'headers-verified-only';
      const amsOk =
        amsResult?.verdict === 'pass' || amsResult?.verdict === 'headers-verified-only';
      const isMostRecent = i === maxInstance;
      const amsModifiedDownstream = !isMostRecent && sealOk && !amsOk;

      if (!sealOk && sealResult) {
        setIssues.push(...sealResult.issues);
      }
      if (isMostRecent && !amsOk && amsResult) {
        setIssues.push(...amsResult.issues);
      }

      const setValid =
        setIssues.length === 0 && sealOk && (isMostRecent ? amsOk : true);

      verifiedSets.push({
        instance: i,
        aar: aars[0],
        ams: amsResult,
        seal: sealResult,
        cvTag,
        setValid,
        amsModifiedDownstream,
        issues: setIssues,
      });
    }

    const allSetsValid =
      !chainStructureBroken &&
      verifiedSets.length === maxInstance &&
      verifiedSets.length > 0 &&
      verifiedSets.every((s) => s.setValid);

    const latestAmsHeadersOnly =
      verifiedSets[verifiedSets.length - 1]?.ams?.verdict === 'headers-verified-only';

    for (const s of verifiedSets) {
      for (const iss of s.issues) {
        if (!arcIssues.includes(iss)) arcIssues.push(iss);
      }
    }

    const arcVerdict: ArcChainVerificationResult['verdict'] = allSetsValid
      ? latestAmsHeadersOnly
        ? 'headers-verified-only'
        : 'pass'
      : chainStructureBroken
        ? 'permerror'
        : 'fail';

    arc = {
      present: true,
      verdict: arcVerdict,
      sets: verifiedSets,
      summary:
        arcVerdict === 'pass'
          ? `ARC chain (i=1..${verifiedSets.length}) cryptographically VALID — all ARC-Seal signatures and latest ARC-Message-Signature verified.`
          : arcVerdict === 'headers-verified-only'
            ? `ARC chain (i=1..${verifiedSets.length}) header seals VALID (latest ARC-Message-Signature bh= unchecked without message body).`
            : `ARC chain validation FAILED (${arcIssues[0] ?? 'broken seal or message signature'}).`,
      issues: arcIssues,
    };
  }

  // Step 6: Live SPF Replay
  let spfReplay: SpfReplayVerificationResult;
  if (!parsed.connectingHop || !spfEnvelopeDomain) {
    spfReplay = {
      evaluated: false,
      connectingIp: parsed.connectingHop?.ip,
      connectingIpSource: parsed.connectingHop?.source,
      envelopeDomain: spfEnvelopeDomain,
      envelopeSender: parsed.returnPathAddress,
      heloDomain: parsed.connectingHop?.helo,
      usedHeloFallback: parsed.isNullReturnPath || !parsed.returnPathDomain,
      spfPresent: false,
      spfDnssecStatus: 'indeterminate',
      disposition: 'none',
      summary: !parsed.connectingHop
        ? 'No connecting MTA IP found in Received-SPF, Authentication-Results, or Received headers to replay SPF.'
        : 'No Return-Path, HELO, or From domain available to evaluate SPF.',
      issues: [],
    };
  } else {
    const spfNorm = normalizeFqdn(spfEnvelopeDomain);
    const spfData = evaluateMailFromSnapshotData({
      targetName: spfNorm,
      queries: allQueries,
      zones,
      cnameEdges: dnssecSnap.cnameEdges,
      targetDomainStatus: 'insecure',
    }).mailAnalysis.spf;

    const effectiveSender =
      parsed.returnPathAddress && parsed.returnPathAddress.includes('@')
        ? parsed.returnPathAddress
        : `postmaster@${spfEnvelopeDomain}`;
    const evalRes = evaluateSpfForSenderIp(spfData.rootNode, parsed.connectingHop.ip, {
      sender: effectiveSender,
      helo: parsed.connectingHop.helo ?? spfEnvelopeDomain,
    });

    const spfAlign =
      fromDomain && spfEnvelopeDomain
        ? evaluateDmarcAlignment({
            candidateDomain: spfEnvelopeDomain,
            fromDomain,
            mode: aspf,
            queries: allQueries,
          })
        : undefined;

    const spfIssues: string[] = [];
    if (!spfData.present) {
      spfIssues.push(`No v=spf1 TXT record published at ${spfEnvelopeDomain}`);
    } else if (evalRes.disposition !== 'pass') {
      spfIssues.push(evalRes.summary);
    }

    spfReplay = {
      evaluated: true,
      connectingIp: parsed.connectingHop.ip,
      connectingIpSource: parsed.connectingHop.source,
      envelopeDomain: spfEnvelopeDomain,
      envelopeSender: effectiveSender,
      heloDomain: parsed.connectingHop.helo,
      usedHeloFallback: parsed.isNullReturnPath || !parsed.returnPathDomain,
      spfPresent: spfData.present,
      spfDnssecStatus: spfData.dnssecStatus,
      evaluation: evalRes,
      disposition: evalRes.disposition,
      dmarcAligned: spfAlign,
      summary: evalRes.summary,
      issues: spfIssues,
    };
  }

  // Step 7: PSL-Aware DMARC Organizational Alignment & Policy Evaluation
  let dmarcReplay: DmarcReplayVerificationResult;
  if (!fromDomain) {
    dmarcReplay = {
      dmarcRecord: null,
      adkim: 'r',
      aspf: 'r',
      dkimAlignedPass: false,
      dkimHeadersOnlyPass: false,
      spfAlignedPass: false,
      verdict: 'missing-from',
      appliedPolicy: 'none',
      effectiveDisposition: 'reject',
      arcOverrideCandidate: false,
      summary: 'Cannot evaluate DMARC without an RFC 5322 From: header domain.',
      issues: ['Missing RFC 5322 From: author domain'],
    };
  } else {
    const fromOrgDomain = displayFqdn(
      estimateOrganizationalDomain(normalizeFqdn(fromDomain), allQueries)
    ).toLowerCase();

    const dkimFullAligned = dkimResults.some(
      (r) => r.verdict === 'pass' && r.dmarcAligned?.aligned === true
    );
    const dkimHeadersOnlyAligned =
      !dkimFullAligned &&
      dkimResults.some(
        (r) => r.verdict === 'headers-verified-only' && r.dmarcAligned?.aligned === true
      );
    const spfAlignedPass =
      spfReplay.evaluated &&
      spfReplay.disposition === 'pass' &&
      spfReplay.dmarcAligned?.aligned === true;

    const isSubdomain = fromDomain !== fromOrgDomain;
    const appliedPolicy: DmarcPolicyValue | 'none' = dmarcRecord?.present
      ? isSubdomain && dmarcRecord.subdomainPolicy
        ? dmarcRecord.subdomainPolicy
        : (dmarcRecord.policy ?? 'none')
      : 'none';

    const dmarcIssues: string[] = [];
    if (parsed.multipleFromHeaderCount > 1) {
      dmarcIssues.push(
        `RFC 7489 §6.6.1 violation: message contains ${parsed.multipleFromHeaderCount} From: headers`
      );
    }

    let dmarcVerdict: DmarcReplayVerificationResult['verdict'];
    if (parsed.multipleFromHeaderCount > 1) {
      dmarcVerdict = 'fail';
    } else if (!dmarcRecord?.present) {
      dmarcVerdict =
        dkimFullAligned || spfAlignedPass
          ? 'pass'
          : dkimHeadersOnlyAligned
            ? 'pass-headers-only'
            : 'no-policy';
      dmarcIssues.push(`No _dmarc policy record published for ${fromDomain} (or ${fromOrgDomain})`);
    } else if (dkimFullAligned || spfAlignedPass) {
      dmarcVerdict = 'pass';
    } else if (dkimHeadersOnlyAligned) {
      dmarcVerdict = 'pass-headers-only';
    } else {
      dmarcVerdict = 'fail';
      if (dkimResults.some((r) => r.verdict === 'pass' || r.verdict === 'headers-verified-only')) {
        dmarcIssues.push(
          `DKIM signature passed cryptographically, but its d= domain did not align with From: ${fromDomain} under adkim=${adkim}`
        );
      }
      if (spfReplay.evaluated && spfReplay.disposition === 'pass' && !spfReplay.dmarcAligned?.aligned) {
        dmarcIssues.push(
          `SPF passed for ${spfReplay.envelopeDomain}, but did not align with From: ${fromDomain} under aspf=${aspf}`
        );
      }
      if (dmarcIssues.length === 0) {
        dmarcIssues.push(
          `Neither an aligned DKIM signature (adkim=${adkim}) nor aligned SPF pass (aspf=${aspf}) authenticated From: ${fromDomain}`
        );
      }
    }

    const upstreamAarHadDmarcPass = parsed.arcAuthResults.some((aar) =>
      aar.items.some((it) => it.method === 'dmarc' && it.result === 'pass')
    );
    const arcOverrideCandidate =
      dmarcVerdict === 'fail' &&
      (arc.verdict === 'pass' || arc.verdict === 'headers-verified-only') &&
      upstreamAarHadDmarcPass;

    const effectiveDisposition: DmarcReplayVerificationResult['effectiveDisposition'] =
      dmarcVerdict === 'pass' || dmarcVerdict === 'pass-headers-only'
        ? 'deliver'
        : appliedPolicy === 'reject'
          ? 'reject'
          : appliedPolicy === 'quarantine'
            ? 'quarantine'
            : 'monitor-none';

    const summary =
      dmarcVerdict === 'pass'
        ? `DMARC PASS for From: ${fromDomain} via ${
            dkimFullAligned && spfAlignedPass
              ? 'both aligned DKIM and aligned SPF'
              : dkimFullAligned
                ? 'aligned DKIM'
                : 'aligned SPF'
          } (policy p=${appliedPolicy}).`
        : dmarcVerdict === 'pass-headers-only'
          ? `DMARC PASS (headers-only) for From: ${fromDomain} via aligned DKIM header signature (paste full .eml body to verify bh=).`
          : dmarcVerdict === 'no-policy'
            ? `No _dmarc TXT policy published for ${fromDomain}, and neither aligned DKIM nor aligned SPF passed.`
            : `DMARC FAIL for From: ${fromDomain} — receiver policy action: ${effectiveDisposition.toUpperCase()}${
                arcOverrideCandidate
                  ? ' (eligible for local ARC trust override: valid ARC chain preserved upstream dmarc=pass)'
                  : ''
              }.`;

    dmarcReplay = {
      fromAddress: parsed.primaryFrom?.address,
      fromDomain,
      fromOrgDomain,
      dmarcRecord,
      adkim,
      aspf,
      dkimAlignedPass: dkimFullAligned,
      dkimHeadersOnlyPass: dkimHeadersOnlyAligned,
      spfAlignedPass,
      verdict: dmarcVerdict,
      appliedPolicy,
      effectiveDisposition,
      arcOverrideCandidate,
      summary,
      issues: dmarcIssues,
    };
  }

  // Step 8: Compare against parsed Authentication-Results claims
  const authResultsDiff = buildAuthResultsDiff({
    parsed,
    dkimResults,
    spfReplay,
    dmarcReplay,
    arc,
  });

  // Step 9: Overall synthesis
  let overallVerdict: EmailMessageVerificationReport['overallVerdict'];
  let overallSummary: string;

  const anyDkimPass = dkimResults.some((r) => r.verdict === 'pass');
  const anyDkimHeadersOnly = dkimResults.some((r) => r.verdict === 'headers-verified-only');
  const anyDkimFail = dkimResults.some(
    (r) =>
      r.verdict === 'fail' ||
      r.verdict === 'policy-fail' ||
      r.verdict === 'permerror' ||
      r.verdict === 'temperror'
  );

  if (parsed.anomalies.some((a) => a.includes('From:')) && parsed.multipleFromHeaderCount > 1) {
    overallVerdict = 'fail';
    overallSummary = parsed.anomalies[0];
  } else if (dmarcReplay.verdict === 'pass') {
    overallVerdict = anyDkimFail || arc.verdict === 'fail' ? 'warning' : 'pass';
    overallSummary = dmarcReplay.summary;
  } else if (dmarcReplay.verdict === 'pass-headers-only') {
    overallVerdict = 'pass-headers-only';
    overallSummary = dmarcReplay.summary;
  } else if (dmarcReplay.verdict === 'fail') {
    overallVerdict = 'fail';
    overallSummary = dmarcReplay.summary;
  } else if (anyDkimPass) {
    overallVerdict = 'pass';
    overallSummary = dkimResults.find((r) => r.verdict === 'pass')!.summary;
  } else if (anyDkimHeadersOnly) {
    overallVerdict = 'pass-headers-only';
    overallSummary = dkimResults.find((r) => r.verdict === 'headers-verified-only')!.summary;
  } else if (anyDkimFail || arc.verdict === 'fail' || arc.verdict === 'permerror') {
    overallVerdict = 'fail';
    overallSummary =
      dkimResults[0]?.summary ?? arc.summary ?? 'Cryptographic email verification failed.';
  } else if (spfReplay.evaluated && spfReplay.disposition === 'pass') {
    overallVerdict = 'warning';
    overallSummary = `SPF passed for ${spfReplay.envelopeDomain}, but message carries no DKIM signature or DMARC policy.`;
  } else {
    overallVerdict = 'unauthenticated';
    overallSummary =
      'No verifiable DKIM/ARC cryptographic signatures or passing SPF alignment found in pasted headers.';
  }

  const queriesPerformed = Math.max(0, allQueries.length - initialLogs.length);
  const finishedAt = Date.now();

  return {
    parsed,
    dkimResults,
    arc,
    spfReplay,
    dmarcReplay,
    authResultsDiff,
    overallVerdict,
    overallSummary,
    queriesPerformed,
    reusedSnapshotQueries: initialLogs.length,
    verifiedAtMs: finishedAt,
    durationMs: Math.max(1, finishedAt - startedAt),
    allQueries,
    zones,
  };
}
