import { IANA_ROOT_TRUST_ANCHORS, rrTypeToString, type TrustAnchor } from './constants';
import { evaluateSnapshotFromLogs } from './analyzer';
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  concatBytes,
  displayFqdn,
  normalizeFqdn,
} from './encoding';
import { seedRpkiValidationCache } from './ipUtils';
import { evaluateMailFromSnapshotData } from './mailAnalyzer';
import type {
  AnalysisMode,
  AnalysisSnapshot,
  CtLogFetchResult,
  DohQueryLog,
  MtaStsPolicyFetchResult,
  RpkiRouteValidation,
} from './types';
import { evaluateWebFromSnapshotData } from './webAnalyzer';
import { buildDnsQuery, parseDnsPacket } from './wire';
import { buildDeepLinkSearch, type DeepLinkState } from '../urlState';

/** Magic 4-byte header inside the gzipped envelope: ASCII "DDP1" */
const FROZEN_MAGIC = new Uint8Array([0x44, 0x44, 0x50, 0x31]);

/**
 * Default safe encoded `#snap=<base64url>` fragment length (~32 KB) so shared links work
 * reliably across browsers, Slack, GitHub issues, and chat clients without truncation.
 */
export const MAX_SAFE_FROZEN_FRAGMENT_CHARS = 32_768;

/**
 * Hard 10 MiB ceiling on decompressed snapshot payloads to guard against malformed or
 * adversarial gzip streams.
 */
export const MAX_DECOMPRESSED_FROZEN_BYTES = 10 * 1024 * 1024;

export class FrozenSnapshotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrozenSnapshotError';
  }
}

interface FrozenQueryMeta {
  /** Index into header.ep (deduplicated DoH endpoints) */
  e: number;
  /** Index into header.pu (deduplicated query purposes) */
  p: number;
  /** startedAt delta relative to header.ca (ms) */
  dt: number;
  /** latencyMs */
  lat: number;
  /** Bitmask: bit 0 = cd, bit 1 = doBit */
  fl: number;
  /** Raw DNS response wire byte length */
  rl: number;
  /** Raw DNS request wire byte length */
  ql: number;
  /** HTTP status code when !== 200 */
  hs?: number;
  /** RFC 7871 EDNS Client Subnet CIDR when present */
  ecs?: string;
  /** Custom query ID when !== `q-${index + 1}` */
  id?: string;
  /** Fallback qname only if response/request wire packet lacks matching Question[0] */
  qn?: string;
  /** Fallback qtype only if response/request wire packet lacks matching Question[0] */
  qt?: number;
}

interface FrozenEnvelopeHeader {
  v: 1;
  id: string;
  m?: AnalysisMode;
  tn: string;
  qip?: string;
  qem?: string;
  qts: string[];
  dkim?: string[];
  doh: string;
  ca: number;
  va: number;
  dur: number;
  note?: string;
  ta?: TrustAnchor[];
  sts?: MtaStsPolicyFetchResult;
  ct?: CtLogFetchResult;
  rpki?: RpkiRouteValidation[];
  comb?: { mail?: boolean; web?: boolean };
  ep: string[];
  pu: string[];
  qs: FrozenQueryMeta[];
}

export interface FrozenPermalinkBuildResult {
  /** True when `hashFragment.length <= maxFragmentChars` */
  fitsInUrl: boolean;
  /** Full shareable URL (`?name=...#snap=...`) when `fitsInUrl` is true (or `forceUrl` is set) */
  url?: string;
  /** Hash fragment `#snap=<base64url>` */
  hashFragment: string;
  /** Length in characters of `hashFragment` */
  encodedFragmentLength: number;
  /** Raw `.digdeep.gz` byte length */
  compressedByteLength: number;
  /** Configured safe URL fragment limit */
  maxFragmentChars: number;
  /** Raw gzipped `DDP1` container bytes suitable for `.digdeep.gz` download & import */
  gzipBytes: Uint8Array;
  /** Suggested `.digdeep.gz` filename */
  suggestedFilename: string;
  /** Whether auxiliary CT certificate rows were trimmed to fit inside the URL budget */
  trimmedCtEntries: boolean;
}

function areDefaultTrustAnchors(anchors: readonly TrustAnchor[] | undefined): boolean {
  if (!anchors || anchors.length !== IANA_ROOT_TRUST_ANCHORS.length) return false;
  for (let i = 0; i < IANA_ROOT_TRUST_ANCHORS.length; i++) {
    const a = anchors[i]!;
    const b = IANA_ROOT_TRUST_ANCHORS[i]!;
    if (
      a.id !== b.id ||
      a.enabled !== b.enabled ||
      a.keyTag !== b.keyTag ||
      a.digest !== b.digest
    ) {
      return false;
    }
  }
  return true;
}

function collectSnapshotRpkiValidations(snapshot: AnalysisSnapshot): RpkiRouteValidation[] {
  const seen = new Set<string>();
  const out: RpkiRouteValidation[] = [];
  const push = (rv: RpkiRouteValidation | undefined) => {
    if (!rv) return;
    const key = `${rv.asn}|${rv.prefix}|${rv.status}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(rv);
    }
  };

  for (const z of snapshot.zones) {
    for (const ns of z.nameservers) {
      for (const rv of ns.rpkiValidations ?? []) {
        push(rv);
      }
    }
  }
  if (snapshot.reverseDns?.bgp?.rpkiValidations) {
    for (const rv of snapshot.reverseDns.bgp.rpkiValidations) {
      push(rv);
    }
  } else {
    push(snapshot.reverseDns?.bgp?.rpki);
  }
  for (const reg of snapshot.consensusAnalysis?.ecsGeo?.regions ?? []) {
    for (const rv of reg.rpkiValidations ?? []) {
      push(rv);
    }
  }
  return out;
}

async function compressGzip(uncompressed: Uint8Array): Promise<Uint8Array> {
  if (typeof CompressionStream === 'undefined') {
    throw new FrozenSnapshotError('CompressionStream("gzip") is not supported in this runtime.');
  }
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  const reader = cs.readable.getReader();

  const writeTask = (async () => {
    await writer.write(uncompressed as unknown as BufferSource);
    await writer.close();
  })();

  const chunks: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  await writeTask;
  return concatBytes(...chunks);
}

async function decompressGzipBounded(
  compressed: Uint8Array,
  maxBytes = MAX_DECOMPRESSED_FROZEN_BYTES
): Promise<Uint8Array> {
  if (compressed.byteLength < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b) {
    throw new FrozenSnapshotError(
      'Invalid gzip header in frozen snapshot (expected RFC 1952 0x1F 0x8B magic bytes).'
    );
  }
  if (typeof DecompressionStream === 'undefined') {
    throw new FrozenSnapshotError('DecompressionStream("gzip") is not supported in this runtime.');
  }

  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();

  const writeTask = (async () => {
    try {
      await writer.write(compressed as unknown as BufferSource);
      await writer.close();
    } catch {
      // Handled on the reader side below
    }
  })();

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('Frozen snapshot exceeded maximum decompressed byte budget').catch(
            () => {}
          );
          throw new FrozenSnapshotError(
            `Frozen snapshot exceeds maximum safe decompressed size (${Math.round(
              maxBytes / (1024 * 1024)
            )} MiB).`
          );
        }
        chunks.push(value);
      }
    }
  } catch (err) {
    await reader.cancel().catch(() => {});
    await writeTask;
    if (err instanceof FrozenSnapshotError) {
      throw err;
    }
    throw new FrozenSnapshotError(
      `Corrupted or truncated gzip stream in frozen snapshot: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  await writeTask;
  return concatBytes(...chunks);
}

/**
 * Formats a suggested `.digdeep.gz` filename for a frozen incident snapshot.
 */
export function buildFrozenSnapshotFilename(snapshot: AnalysisSnapshot): string {
  const rawSubject =
    snapshot.queriedEmail ??
    snapshot.queriedIp ??
    (snapshot.displayDomain === '.' ? 'root-zone' : snapshot.displayDomain);
  const safeName = rawSubject
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || 'snapshot';
  const d = new Date(snapshot.capturedAt);
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-${pad(
    d.getUTCHours()
  )}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return `digdeep-${safeName}-${stamp}.digdeep.gz`;
}

/**
 * Serializes an `AnalysisSnapshot` into a compact `DDP1` binary wire container and compresses
 * it with `CompressionStream('gzip')`. All DNS wire bytes are stored as raw binary frames (without
 * Base64 inflation) so DEFLATE deduplicates domain names, DNSKEYs, RRSIG headers, and OPT records
 * across the entire trace.
 */
export async function encodeFrozenSnapshotBytes(
  snapshot: AnalysisSnapshot,
  options?: { maxCtEntries?: number }
): Promise<Uint8Array> {
  const endpoints: string[] = [];
  const endpointIndex = new Map<string, number>();
  const purposes: string[] = [];
  const purposeIndex = new Map<string, number>();

  const getEndpointIdx = (ep: string): number => {
    const existing = endpointIndex.get(ep);
    if (existing !== undefined) return existing;
    const idx = endpoints.length;
    endpoints.push(ep);
    endpointIndex.set(ep, idx);
    return idx;
  };

  const getPurposeIdx = (pu: string): number => {
    const existing = purposeIndex.get(pu);
    if (existing !== undefined) return existing;
    const idx = purposes.length;
    purposes.push(pu);
    purposeIndex.set(pu, idx);
    return idx;
  };

  const queryMetas: FrozenQueryMeta[] = [];
  const binaryFrames: Uint8Array[] = [];

  for (let i = 0; i < snapshot.queries.length; i++) {
    const q = snapshot.queries[i]!;
    const respBytes = q.wireBase64 ? base64ToBytes(q.wireBase64) : new Uint8Array(0);
    const reqBytes = q.requestWireBase64 ? base64ToBytes(q.requestWireBase64) : new Uint8Array(0);

    const primaryQuestion = q.packet?.questions?.[0];
    const normQname = normalizeFqdn(q.qname);
    const matchesQuestion =
      primaryQuestion !== undefined &&
      normalizeFqdn(primaryQuestion.name) === normQname &&
      primaryQuestion.type === q.qtype;

    const defaultId = `q-${i + 1}`;
    const meta: FrozenQueryMeta = {
      e: getEndpointIdx(q.endpoint),
      p: getPurposeIdx(q.purpose),
      dt: Math.round(q.startedAt - snapshot.capturedAt),
      lat: Math.max(0, Math.round(q.latencyMs)),
      fl: (q.cd ? 1 : 0) | (q.doBit ? 2 : 0),
      rl: respBytes.byteLength,
      ql: reqBytes.byteLength,
      ...(q.httpStatus !== 200 ? { hs: q.httpStatus } : {}),
      ...(q.ecsSubnet ? { ecs: q.ecsSubnet } : {}),
      ...(q.id && q.id !== defaultId ? { id: q.id } : {}),
      ...(!matchesQuestion ? { qn: normQname, qt: q.qtype } : {}),
    };

    queryMetas.push(meta);
    if (respBytes.byteLength > 0) binaryFrames.push(respBytes);
    if (reqBytes.byteLength > 0) binaryFrames.push(reqBytes);
  }

  const rpki = collectSnapshotRpkiValidations(snapshot);
  const mode = snapshot.mode && snapshot.mode !== 'dnssec' ? snapshot.mode : undefined;
  const isCombinedPortfolio =
    !mode && (Boolean(snapshot.mailAnalysis) || Boolean(snapshot.webAnalysis));

  let ctToStore = snapshot.ctLogFetch;
  if (
    ctToStore?.entries &&
    options?.maxCtEntries !== undefined &&
    ctToStore.entries.length > options.maxCtEntries
  ) {
    ctToStore = {
      ...ctToStore,
      entries: ctToStore.entries.slice(0, options.maxCtEntries),
    };
  }

  const header: FrozenEnvelopeHeader = {
    v: 1,
    id: snapshot.id,
    ...(mode ? { m: mode } : {}),
    tn: normalizeFqdn(snapshot.targetName),
    ...(snapshot.queriedIp ? { qip: snapshot.queriedIp } : {}),
    ...(snapshot.queriedEmail ? { qem: snapshot.queriedEmail } : {}),
    qts: snapshot.queryTypes.length > 0 ? [...snapshot.queryTypes] : ['A'],
    ...(snapshot.customDkimSelectors && snapshot.customDkimSelectors.length > 0
      ? { dkim: [...snapshot.customDkimSelectors] }
      : {}),
    doh: snapshot.dohEndpoint,
    ca: snapshot.capturedAt,
    va: snapshot.validatedAt,
    dur: snapshot.durationMs,
    ...(snapshot.note ? { note: snapshot.note } : {}),
    ...(!areDefaultTrustAnchors(snapshot.trustAnchorsUsed)
      ? { ta: snapshot.trustAnchorsUsed }
      : {}),
    ...(snapshot.mtaStsPolicyFetch ? { sts: snapshot.mtaStsPolicyFetch } : {}),
    ...(ctToStore ? { ct: ctToStore } : {}),
    ...(rpki.length > 0 ? { rpki } : {}),
    ...(isCombinedPortfolio
      ? {
          comb: {
            ...(snapshot.mailAnalysis ? { mail: true } : {}),
            ...(snapshot.webAnalysis ? { web: true } : {}),
          },
        }
      : {}),
    ep: endpoints,
    pu: purposes,
    qs: queryMetas,
  };

  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, headerBytes.byteLength, false);

  const uncompressed = concatBytes(FROZEN_MAGIC, lenBuf, headerBytes, ...binaryFrames);
  return compressGzip(uncompressed);
}

/**
 * Decompresses and reconstructs a full cryptographically validated `AnalysisSnapshot` from
 * raw `.digdeep.gz` bytes with **zero network requests**, pinned to the snapshot's original
 * `validatedAt` timestamp (unless overridden via `options.validationTimeMs`).
 */
export async function decodeFrozenSnapshotBytes(
  gzipBytes: Uint8Array,
  options?: { validationTimeMs?: number; trustAnchors?: TrustAnchor[] }
): Promise<AnalysisSnapshot> {
  const uncompressed = await decompressGzipBounded(gzipBytes);
  if (uncompressed.byteLength < 10) {
    throw new FrozenSnapshotError('Frozen snapshot container is truncated (< 10 bytes).');
  }

  for (let i = 0; i < FROZEN_MAGIC.length; i++) {
    if (uncompressed[i] !== FROZEN_MAGIC[i]) {
      throw new FrozenSnapshotError(
        'Unrecognized frozen snapshot container magic (expected DDP1).'
      );
    }
  }

  const headerLen = new DataView(
    uncompressed.buffer,
    uncompressed.byteOffset + 4,
    4
  ).getUint32(0, false);

  const framesOffset = 8 + headerLen;
  if (headerLen === 0 || framesOffset > uncompressed.byteLength) {
    throw new FrozenSnapshotError('Corrupted DDP1 header length in frozen snapshot.');
  }

  let header: FrozenEnvelopeHeader;
  try {
    const headerJson = new TextDecoder('utf-8', { fatal: true }).decode(
      uncompressed.subarray(8, framesOffset)
    );
    header = JSON.parse(headerJson) as FrozenEnvelopeHeader;
  } catch (err) {
    throw new FrozenSnapshotError(
      `Invalid JSON metadata in frozen snapshot: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  if (
    !header ||
    header.v !== 1 ||
    typeof header.tn !== 'string' ||
    !Array.isArray(header.qts) ||
    !Array.isArray(header.ep) ||
    !Array.isArray(header.pu) ||
    !Array.isArray(header.qs)
  ) {
    throw new FrozenSnapshotError('Malformed or unsupported DDP1 frozen snapshot schema.');
  }

  if (header.rpki && header.rpki.length > 0) {
    seedRpkiValidationCache(header.rpki);
  }

  let cursor = framesOffset;
  const queries: DohQueryLog[] = [];

  for (let i = 0; i < header.qs.length; i++) {
    const qm = header.qs[i]!;
    const rl = Math.max(0, Number(qm.rl) || 0);
    const ql = Math.max(0, Number(qm.ql) || 0);
    if (cursor + rl + ql > uncompressed.byteLength) {
      throw new FrozenSnapshotError(
        `Truncated DNS wire frame at query #${i + 1} in frozen snapshot.`
      );
    }

    const respBytes = uncompressed.subarray(cursor, cursor + rl);
    cursor += rl;
    const reqBytes = uncompressed.subarray(cursor, cursor + ql);
    cursor += ql;

    let packet;
    try {
      packet = parseDnsPacket(respBytes);
    } catch (err) {
      throw new FrozenSnapshotError(
        `Corrupted DNS wire packet at query #${i + 1}: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }

    let qname = qm.qn ?? packet.questions[0]?.name;
    let qtype = qm.qt ?? packet.questions[0]?.type;
    if ((!qname || qtype === undefined) && reqBytes.byteLength >= 12) {
      try {
        const reqPkt = parseDnsPacket(reqBytes);
        qname = qname ?? reqPkt.questions[0]?.name;
        qtype = qtype ?? reqPkt.questions[0]?.type;
      } catch {
        // Ignore fallback request parse errors
      }
    }
    const finalQname = normalizeFqdn(qname ?? header.tn);
    const finalQtype = qtype ?? 1;
    const cd = (qm.fl & 1) !== 0;
    const doBit = (qm.fl & 2) !== 0;

    const finalReqBytes =
      reqBytes.byteLength > 0
        ? reqBytes
        : buildDnsQuery(finalQname, finalQtype, {
            id: packet.id,
            cd,
            doBit,
          });

    queries.push({
      id: qm.id ?? `q-${i + 1}`,
      qname: finalQname,
      qtype: finalQtype,
      qtypeName: rrTypeToString(finalQtype),
      cd,
      doBit,
      endpoint: header.ep[qm.e] ?? header.doh,
      startedAt: header.ca + (Number(qm.dt) || 0),
      latencyMs: Math.max(0, Number(qm.lat) || 0),
      httpStatus: qm.hs ?? 200,
      wireBase64: bytesToBase64(respBytes),
      requestWireBase64: bytesToBase64(finalReqBytes),
      packet,
      purpose: header.pu[qm.p] ?? `Query (${finalQname} ${rrTypeToString(finalQtype)})`,
      ...(qm.ecs ? { ecsSubnet: qm.ecs } : {}),
    });
  }

  const trustAnchors =
    options?.trustAnchors ??
    (header.ta && header.ta.length > 0 ? header.ta : IANA_ROOT_TRUST_ANCHORS);
  const validatedAt = options?.validationTimeMs ?? header.va;

  const reconstructed = await evaluateSnapshotFromLogs({
    id: header.id || `snap-frozen-${header.ca}`,
    mode: header.m ?? 'dnssec',
    targetName: normalizeFqdn(header.tn),
    queriedIp: header.qip,
    queriedEmail: header.qem,
    queryTypes: header.qts,
    customDkimSelectors: header.dkim,
    mtaStsPolicyFetch: header.sts,
    ctLogFetch: header.ct,
    dohEndpoint: header.doh,
    capturedAt: header.ca,
    validatedAt,
    durationMs: header.dur,
    queries,
    trustAnchors,
  });

  // Restore combined Mail/Web analysis on unified Portfolio snapshots when flagged
  let extraMail = reconstructed.mailAnalysis;
  let extraWeb = reconstructed.webAnalysis;
  const extraFindings = [...reconstructed.findings];
  const dnssecStatusForSub =
    reconstructed.overallStatus === 'policy-error' ? 'secure' : reconstructed.overallStatus;

  if (!extraMail && header.comb?.mail) {
    const mailRes = evaluateMailFromSnapshotData({
      targetName: reconstructed.targetName,
      queries: reconstructed.queries,
      zones: reconstructed.zones,
      cnameEdges: reconstructed.cnameEdges,
      targetDomainStatus: dnssecStatusForSub,
      customDkimSelectors: header.dkim,
      mtaStsPolicyFetch: header.sts,
    });
    extraMail = mailRes.mailAnalysis;
    for (const mf of mailRes.mailFindings) {
      if (mf.code === 'DKIM_NO_COMMON_SELECTOR_MATCH') continue;
      if (!extraFindings.some((f) => f.id === mf.id)) extraFindings.push(mf);
    }
  }

  if (!extraWeb && header.comb?.web) {
    const webRes = evaluateWebFromSnapshotData({
      targetName: reconstructed.targetName,
      queries: reconstructed.queries,
      zones: reconstructed.zones,
      cnameEdges: reconstructed.cnameEdges,
      targetDomainStatus: dnssecStatusForSub,
      ctLogFetch: header.ct,
      validatedAt,
    });
    extraWeb = webRes.webAnalysis;
    for (const wf of webRes.webFindings) {
      if (!extraFindings.some((f) => f.id === wf.id)) extraFindings.push(wf);
    }
  }

  return {
    ...reconstructed,
    displayDomain: displayFqdn(reconstructed.targetName),
    ...(extraMail ? { mailAnalysis: extraMail } : {}),
    ...(extraWeb ? { webAnalysis: extraWeb } : {}),
    findings: extraFindings,
    ...(header.note ? { note: header.note } : {}),
  };
}

/**
 * Checks whether a URL hash fragment (e.g. `window.location.hash` or a full URL) contains a
 * `#snap=` frozen snapshot parameter (even if empty or malformed).
 */
export function hasFrozenSnapshotHash(hashOrUrl: string): boolean {
  if (!hashOrUrl) return false;
  const hashIdx = hashOrUrl.indexOf('#');
  const rawHash = hashIdx >= 0 ? hashOrUrl.slice(hashIdx + 1) : hashOrUrl.replace(/^#/, '');
  if (!rawHash) return false;
  return rawHash.split('&').some((part) => part === 'snap' || part.startsWith('snap='));
}

/**
 * Extracts the raw `snap=` token from a URL or hash fragment, returning `null` if no `snap`
 * parameter is present, or a string (possibly empty) if `snap=` was specified.
 */
export function extractFrozenSnapshotToken(hashOrUrl: string): string | null {
  if (!hashOrUrl) return null;
  const hashIdx = hashOrUrl.indexOf('#');
  const rawHash = hashIdx >= 0 ? hashOrUrl.slice(hashIdx + 1) : hashOrUrl.replace(/^#/, '');
  if (!rawHash) return null;
  for (const part of rawHash.split('&')) {
    if (part === 'snap') return '';
    if (part.startsWith('snap=')) {
      return part.slice(5).trim();
    }
  }
  return null;
}

/**
 * Encodes an `AnalysisSnapshot` into a shareable zero-server `#snap=<base64url>` permalink
 * (preserving human-readable `?name=...&tab=...` search params while keeping all wire bytes
 * strictly inside the client-only URL `#fragment`), and falls back cleanly (`fitsInUrl: false`)
 * when a massive trace exceeds `maxFragmentChars`.
 */
export async function buildFrozenPermalink(
  baseHref: string,
  snapshot: AnalysisSnapshot,
  deepLinkState: DeepLinkState,
  options?: {
    maxFragmentChars?: number;
    forceUrl?: boolean;
  }
): Promise<FrozenPermalinkBuildResult> {
  const maxFragmentChars = options?.maxFragmentChars ?? MAX_SAFE_FROZEN_FRAGMENT_CHARS;
  let gzipBytes = await encodeFrozenSnapshotBytes(snapshot);
  let b64u = bytesToBase64Url(gzipBytes);
  let hashFragment = `#snap=${b64u}`;
  let trimmedCtEntries = false;

  if (
    hashFragment.length > maxFragmentChars &&
    snapshot.ctLogFetch?.entries &&
    snapshot.ctLogFetch.entries.length > 12
  ) {
    const trimmedBytes = await encodeFrozenSnapshotBytes(snapshot, { maxCtEntries: 12 });
    const trimmedB64u = bytesToBase64Url(trimmedBytes);
    const trimmedHash = `#snap=${trimmedB64u}`;
    if (trimmedHash.length <= maxFragmentChars) {
      gzipBytes = trimmedBytes;
      b64u = trimmedB64u;
      hashFragment = trimmedHash;
      trimmedCtEntries = true;
    }
  }

  const fitsInUrl = hashFragment.length <= maxFragmentChars;
  let url: string | undefined;
  if (fitsInUrl || options?.forceUrl) {
    const parsedUrl = new URL(baseHref);
    parsedUrl.search = buildDeepLinkSearch(deepLinkState, {
      includeDefaultDoh: true,
      forShare: true,
    });
    parsedUrl.hash = hashFragment;
    url = parsedUrl.toString();
  }

  return {
    fitsInUrl,
    url,
    hashFragment,
    encodedFragmentLength: hashFragment.length,
    compressedByteLength: gzipBytes.byteLength,
    maxFragmentChars,
    gzipBytes,
    suggestedFilename: buildFrozenSnapshotFilename(snapshot),
    trimmedCtEntries,
  };
}

/**
 * Decodes a `#snap=<base64url>` URL or hash fragment into a cryptographically verified
 * `AnalysisSnapshot` with zero network requests. Throws `FrozenSnapshotError` on empty,
 * malformed Base64url, or corrupted/truncated gzip payloads.
 */
export async function decodeFrozenPermalinkHash(
  hashOrUrl: string,
  options?: { validationTimeMs?: number; trustAnchors?: TrustAnchor[] }
): Promise<{ snapshot: AnalysisSnapshot; compressedByteLength: number }> {
  const token = extractFrozenSnapshotToken(hashOrUrl);
  if (token === null) {
    throw new FrozenSnapshotError('URL does not contain a #snap= frozen snapshot fragment.');
  }
  if (token.length === 0) {
    throw new FrozenSnapshotError('Frozen #snap= permalink fragment is empty.');
  }
  if (!/^[A-Za-z0-9+/=_-]+$/.test(token)) {
    throw new FrozenSnapshotError(
      'Frozen #snap= permalink contains invalid Base64url characters.'
    );
  }

  let gzipBytes: Uint8Array;
  try {
    gzipBytes = base64UrlToBytes(token);
  } catch (err) {
    throw new FrozenSnapshotError(
      `Malformed Base64url encoding in #snap= fragment: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  const snapshot = await decodeFrozenSnapshotBytes(gzipBytes, options);
  return {
    snapshot,
    compressedByteLength: gzipBytes.byteLength,
  };
}

/**
 * Triggers a browser file download of raw binary bytes (e.g. `.digdeep.gz`).
 */
export function downloadBinaryFile(
  bytes: Uint8Array,
  filename: string,
  mimeType = 'application/gzip'
): void {
  const blob = new Blob([bytes as unknown as BlobPart], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
