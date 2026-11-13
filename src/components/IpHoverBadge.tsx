import {
  Check,
  Copy,
  Globe,
  Loader2,
  Network,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { createPortal } from 'react-dom';
import { DEFAULT_DOH_ENDPOINT, RR_TYPES } from '../dns/constants';
import { DohSession } from '../dns/doh';
import { normalizeFqdn } from '../dns/encoding';
import {
  getCachedRpkiValidation,
  ipToCymruOriginQname,
  parseCymruAsnTxt,
  parseCymruOriginTxt,
  parseReverseIpInput,
  reverseArpaToIp,
  seedRpkiValidationCache,
  summarizeRpkiValidationState,
  validateRpkiRoute,
} from '../dns/ipUtils';
import type {
  AnalysisSnapshot,
  BgpAsnOrganization,
  RpkiRouteValidation,
  RpkiValidationState,
} from '../dns/types';

export interface IpAsnNetworkInfo {
  ip: string;
  family: 4 | 6;
  isPublic: boolean;
  specialRangeNote?: string;
  asns: BgpAsnOrganization[];
  bgpPrefixes: string[];
  country?: string;
  rir?: string;
  allocatedDate?: string;
  rpkiStatus?: RpkiValidationState;
  rpkiValidations?: RpkiRouteValidation[];
  status: 'ready' | 'loading' | 'unannounced' | 'special' | 'error';
}

export interface ParsedIpToken {
  canonicalIp: string;
  cidrSuffix?: string;
  family: 4 | 6;
  isPublic: boolean;
  specialRangeNote?: string;
}

const ipInfoCache = new Map<string, IpAsnNetworkInfo>();
const asnOrgCache = new Map<number, BgpAsnOrganization>();
const inflightLookups = new Map<string, Promise<IpAsnNetworkInfo>>();
const listeners = new Set<() => void>();
let activeDohEndpoint = DEFAULT_DOH_ENDPOINT;
let lastSeededSnapshotKey = '';

export type TraceIpHandler = (canonicalIp: string) => void;
let globalTraceIpHandler: TraceIpHandler | null = null;
let activePinnedDismiss: (() => void) | null = null;

/**
 * Registers the app-level callback invoked when a user activates "Trace rDNS (PTR)"
 * inside any `IpHoverBadge` popover card. Returns an unsubscribe function.
 */
export function registerGlobalTraceIpHandler(handler: TraceIpHandler | null): () => void {
  globalTraceIpHandler = handler;
  return () => {
    if (globalTraceIpHandler === handler) {
      globalTraceIpHandler = null;
    }
  };
}

/**
 * Dismisses whichever `IpHoverBadge` popover is currently pinned open, if any.
 */
export function dismissActivePinnedIpCard(): void {
  if (activePinnedDismiss) {
    const fn = activePinnedDismiss;
    activePinnedDismiss = null;
    fn();
  }
}

async function copyIpToClipboard(text: string): Promise<boolean> {
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

function notifyCacheListeners(): void {
  for (const fn of listeners) {
    fn();
  }
}

/**
 * Extracts a canonical IPv4 or IPv6 address (and optional `/prefix` CIDR suffix)
 * from raw strings such as `"1.1.1.1"`, `"198.51.100.0/24"`, `"ip4:192.0.2.0/24"`,
 * or `"+ip6:2001:db8::/32"`.
 */
export function parseIpToken(rawInput: string): ParsedIpToken | null {
  let cleaned = rawInput.trim();
  if (!cleaned) return null;

  // Strip optional SPF qualifier and ip4:/ip6: prefix
  cleaned = cleaned.replace(/^[+\-~?]?ip[46]:/i, '').trim();

  // Strip trailing annotations like " (drift)" if caller passed raw label
  cleaned = cleaned.replace(/\s+\(.*\)$/, '').trim();

  let cidrSuffix: string | undefined;
  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) {
    const suffixPart = cleaned.slice(slashIdx);
    if (/^\/\d{1,3}(?:\/\d{1,3})?$/.test(suffixPart)) {
      cidrSuffix = suffixPart;
      cleaned = cleaned.slice(0, slashIdx);
    }
  }

  const parsed = parseReverseIpInput(cleaned);
  if (!parsed || !parsed.wasRawIpInput) return null;

  return {
    canonicalIp: parsed.ip,
    cidrSuffix,
    family: parsed.family,
    isPublic: parsed.isPublic,
    specialRangeNote: parsed.specialRangeNote,
  };
}

/**
 * Converts a Team Cymru origin query name (`*.origin.asn.cymru.com.` or `*.origin6.asn.cymru.com.`)
 * back into its canonical IPv4/IPv6 address if it represents a full host address.
 */
function cymruOriginQnameToIp(qname: string): { ip: string; family: 4 | 6 } | null {
  const norm = normalizeFqdn(qname);
  if (norm.endsWith('.origin.asn.cymru.com.')) {
    const prefix = norm.slice(0, -'.origin.asn.cymru.com.'.length);
    return reverseArpaToIp(`${prefix}.in-addr.arpa.`);
  }
  if (norm.endsWith('.origin6.asn.cymru.com.')) {
    const prefix = norm.slice(0, -'.origin6.asn.cymru.com.'.length);
    return reverseArpaToIp(`${prefix}.ip6.arpa.`);
  }
  return null;
}

/**
 * Seeds the in-memory BGP ASN & network prefix cache from an `AnalysisSnapshot`
 * so any IP already probed during analysis displays its ASN and prefix immediately on hover.
 */
export function seedIpAsnCacheFromSnapshot(snapshot?: AnalysisSnapshot | null): void {
  if (!snapshot) return;
  if (snapshot.dohEndpoint) {
    activeDohEndpoint = snapshot.dohEndpoint;
  }
  const snapKey = `${snapshot.id}:${snapshot.queries.length}`;
  if (snapKey === lastSeededSnapshotKey) return;
  lastSeededSnapshotKey = snapKey;

  let updated = false;

  // 1. Seed ASN organization names from Team Cymru AS<number>.asn.cymru.com TXT logs
  for (const log of snapshot.queries) {
    const normQ = normalizeFqdn(log.qname);
    if (log.qtype === RR_TYPES.TXT && /^as\d+\.asn\.cymru\.com\.$/i.test(normQ)) {
      const txts: string[] = [];
      for (const ans of log.packet.answers) {
        if (ans.type === RR_TYPES.TXT) {
          txts.push(ans.parsed.kind === 'TXT' ? ans.parsed.joinedText : ans.rdataText);
        }
      }
      const parsedAsn = parseCymruAsnTxt(txts);
      if (parsedAsn) {
        asnOrgCache.set(parsedAsn.asn, {
          asn: parsedAsn.asn,
          asName: parsedAsn.asName,
          country: parsedAsn.country,
          rir: parsedAsn.rir,
          allocatedDate: parsedAsn.allocatedDate,
        });
        updated = true;
      }
    }
  }

  // Also seed ASN organization & RPKI metadata from analyzed zones and reverseDns
  const snapshotRpkiEntries: RpkiRouteValidation[] = [];
  for (const zone of snapshot.zones) {
    for (const ns of zone.nameservers) {
      for (const a of ns.asns ?? []) {
        if (!asnOrgCache.has(a.asn) || (!asnOrgCache.get(a.asn)?.asName && a.asName)) {
          asnOrgCache.set(a.asn, a);
          updated = true;
        }
      }
      for (const rv of ns.rpkiValidations ?? []) {
        snapshotRpkiEntries.push(rv);
      }
    }
  }
  if (snapshot.reverseDns?.bgp) {
    for (const a of snapshot.reverseDns.bgp.asns) {
      if (!asnOrgCache.has(a.asn) || (!asnOrgCache.get(a.asn)?.asName && a.asName)) {
        asnOrgCache.set(a.asn, a);
        updated = true;
      }
    }
    if (snapshot.reverseDns.bgp.rpkiValidations) {
      snapshotRpkiEntries.push(...snapshot.reverseDns.bgp.rpkiValidations);
    } else if (snapshot.reverseDns.bgp.rpki) {
      snapshotRpkiEntries.push(snapshot.reverseDns.bgp.rpki);
    }
  }
  for (const reg of snapshot.consensusAnalysis?.ecsGeo?.regions ?? []) {
    for (const a of reg.asns) {
      if (!asnOrgCache.has(a.asn) || (!asnOrgCache.get(a.asn)?.asName && a.asName)) {
        asnOrgCache.set(a.asn, a);
        updated = true;
      }
    }
    for (const rv of reg.rpkiValidations ?? []) {
      snapshotRpkiEntries.push(rv);
    }
  }
  if (snapshotRpkiEntries.length > 0) {
    seedRpkiValidationCache(snapshotRpkiEntries);
  }

  // 2. Seed IP -> BGP prefix + ASN entries from Team Cymru *.origin.asn.cymru.com TXT logs
  for (const log of snapshot.queries) {
    if (log.qtype !== RR_TYPES.TXT) continue;
    const fromOrigin = cymruOriginQnameToIp(log.qname);
    if (!fromOrigin) continue;

    const txts: string[] = [];
    for (const ans of log.packet.answers) {
      if (ans.type === RR_TYPES.TXT) {
        txts.push(ans.parsed.kind === 'TXT' ? ans.parsed.joinedText : ans.rdataText);
      }
    }
    const origins = parseCymruOriginTxt(txts);
    if (origins.length === 0) continue;

    const primary = origins[0];
    const uniqueAsnNums = Array.from(new Set(origins.flatMap((o) => o.asns)));
    const asns: BgpAsnOrganization[] = uniqueAsnNums.map((asn) => {
      const org = asnOrgCache.get(asn);
      return {
        asn,
        asName: org?.asName,
        country: org?.country ?? primary.country,
        rir: org?.rir ?? primary.rir,
        allocatedDate: org?.allocatedDate ?? primary.allocatedDate,
      };
    });
    const bgpPrefixes = Array.from(
      new Set(origins.map((o) => o.bgpPrefix).filter((p): p is string => Boolean(p)))
    );
    const rpkiValidations: RpkiRouteValidation[] = [];
    for (const o of origins) {
      if (!o.bgpPrefix) continue;
      for (const asn of o.asns) {
        const rv = getCachedRpkiValidation(asn, o.bgpPrefix);
        if (rv && !rpkiValidations.some((ex) => ex.asn === rv.asn && ex.prefix === rv.prefix)) {
          rpkiValidations.push(rv);
        }
      }
    }
    const rpkiStatus = summarizeRpkiValidationState(rpkiValidations);

    ipInfoCache.set(fromOrigin.ip, {
      ip: fromOrigin.ip,
      family: fromOrigin.family,
      isPublic: true,
      asns,
      bgpPrefixes,
      country: primary.country ?? asns[0]?.country,
      rir: primary.rir ?? asns[0]?.rir,
      allocatedDate: primary.allocatedDate ?? asns[0]?.allocatedDate,
      ...(rpkiStatus ? { rpkiStatus } : {}),
      ...(rpkiValidations.length > 0 ? { rpkiValidations } : {}),
      status: 'ready',
    });
    updated = true;
  }

  // 3. Seed from snapshot.reverseDns if present
  if (snapshot.reverseDns) {
    const r = snapshot.reverseDns;
    const parsed = parseIpToken(r.ip);
    const keyIp = parsed?.canonicalIp ?? r.ip;
    if (r.bgp && r.bgp.asns.length > 0) {
      const rdnsRpki =
        r.bgp.rpkiValidations ?? (r.bgp.rpki ? [r.bgp.rpki] : []);
      const rdnsRpkiStatus = summarizeRpkiValidationState(rdnsRpki);
      ipInfoCache.set(keyIp, {
        ip: keyIp,
        family: r.family,
        isPublic: r.isPublic,
        specialRangeNote: r.specialRangeNote,
        asns: r.bgp.asns,
        bgpPrefixes: r.bgp.bgpPrefix ? [r.bgp.bgpPrefix] : [],
        country: r.bgp.country,
        rir: r.bgp.rir,
        allocatedDate: r.bgp.allocatedDate,
        ...(rdnsRpkiStatus ? { rpkiStatus: rdnsRpkiStatus } : {}),
        ...(rdnsRpki.length > 0 ? { rpkiValidations: rdnsRpki } : {}),
        status: 'ready',
      });
      updated = true;
    } else if (!r.isPublic) {
      ipInfoCache.set(keyIp, {
        ip: keyIp,
        family: r.family,
        isPublic: false,
        specialRangeNote: r.specialRangeNote,
        asns: [],
        bgpPrefixes: [],
        status: 'special',
      });
      updated = true;
    }
  }

  // 4. Seed fallback from zone nameservers if a nameserver has 1 IP or already-resolved BGP data
  for (const zone of snapshot.zones) {
    for (const ns of zone.nameservers) {
      if (!ns.asns || ns.asns.length === 0) continue;
      const allNsIps = [...ns.ipv4, ...ns.ipv6];
      for (const rawIp of allNsIps) {
        const tok = parseIpToken(rawIp);
        if (!tok || ipInfoCache.has(tok.canonicalIp)) continue;
        ipInfoCache.set(tok.canonicalIp, {
          ip: tok.canonicalIp,
          family: tok.family,
          isPublic: tok.isPublic,
          asns: ns.asns,
          bgpPrefixes: ns.bgpPrefixes ?? [],
          country: ns.country ?? ns.asns[0]?.country,
          rir: ns.rir ?? ns.asns[0]?.rir,
          allocatedDate: ns.asns[0]?.allocatedDate,
          ...(ns.rpkiStatus ? { rpkiStatus: ns.rpkiStatus } : {}),
          ...(ns.rpkiValidations && ns.rpkiValidations.length > 0
            ? { rpkiValidations: ns.rpkiValidations }
            : {}),
          status: 'ready',
        });
        updated = true;
      }
    }
  }

  // 5. Seed sibling regional edge IPs from ECS Geo-Steering matrix
  for (const reg of snapshot.consensusAnalysis?.ecsGeo?.regions ?? []) {
    if (reg.asns.length === 0) continue;
    const regIps = [...reg.ipv4.answers, ...reg.ipv6.answers];
    for (const rawIp of regIps) {
      const tok = parseIpToken(rawIp);
      if (!tok || !tok.isPublic || ipInfoCache.has(tok.canonicalIp)) continue;
      ipInfoCache.set(tok.canonicalIp, {
        ip: tok.canonicalIp,
        family: tok.family,
        isPublic: true,
        asns: reg.asns,
        bgpPrefixes: reg.bgpPrefixes,
        country: reg.countries[0] ?? reg.asns[0]?.country,
        rir: reg.asns[0]?.rir,
        ...(reg.rpkiStatus ? { rpkiStatus: reg.rpkiStatus } : {}),
        ...(reg.rpkiValidations && reg.rpkiValidations.length > 0
          ? { rpkiValidations: reg.rpkiValidations }
          : {}),
        status: 'ready',
      });
      updated = true;
    }
  }

  if (updated) {
    notifyCacheListeners();
  }
}

/**
 * Synchronously returns cached BGP ASN / Network info for an IP token, or a placeholder
 * (`status: 'special'` for private/reserved IPs, or `status: 'loading'` for uncached public IPs).
 */
export function getCachedOrInitialIpInfo(parsed: ParsedIpToken): IpAsnNetworkInfo {
  if (!parsed.isPublic) {
    return {
      ip: parsed.canonicalIp,
      family: parsed.family,
      isPublic: false,
      specialRangeNote: parsed.specialRangeNote,
      asns: [],
      bgpPrefixes: [],
      status: 'special',
    };
  }
  const existing = ipInfoCache.get(parsed.canonicalIp);
  if (existing) return existing;

  return {
    ip: parsed.canonicalIp,
    family: parsed.family,
    isPublic: true,
    asns: [],
    bgpPrefixes: [],
    status: 'loading',
  };
}

/**
 * Queries Team Cymru (`*.origin.asn.cymru.com` / `*.origin6.asn.cymru.com` + `AS<n>.asn.cymru.com`)
 * via DNS-over-HTTPS for a public IPv4/IPv6 address and caches the result.
 */
export async function ensureIpAsnInfoLoaded(parsed: ParsedIpToken): Promise<IpAsnNetworkInfo> {
  if (!parsed.isPublic) {
    return getCachedOrInitialIpInfo(parsed);
  }

  const cached = ipInfoCache.get(parsed.canonicalIp);
  if (cached && (cached.status === 'ready' || cached.status === 'unannounced')) {
    return cached;
  }

  const inflight = inflightLookups.get(parsed.canonicalIp);
  if (inflight) return inflight;

  const task = (async (): Promise<IpAsnNetworkInfo> => {
    const originQname = ipToCymruOriginQname(parsed.canonicalIp);
    if (!originQname) {
      const fallback: IpAsnNetworkInfo = {
        ip: parsed.canonicalIp,
        family: parsed.family,
        isPublic: false,
        asns: [],
        bgpPrefixes: [],
        status: 'error',
      };
      return fallback;
    }

    const session = new DohSession({
      endpoint: activeDohEndpoint || DEFAULT_DOH_ENDPOINT,
      timeoutMs: 6000,
    });

    try {
      const originLog = await session.query(originQname, RR_TYPES.TXT, {
        cd: false,
        doBit: false,
        purpose: `BGP ASN hover lookup (${parsed.canonicalIp})`,
      });

      const txts: string[] = [];
      for (const ans of originLog.packet.answers) {
        if (ans.type === RR_TYPES.TXT) {
          txts.push(ans.parsed.kind === 'TXT' ? ans.parsed.joinedText : ans.rdataText);
        }
      }

      const origins = parseCymruOriginTxt(txts);
      if (origins.length === 0) {
        const unannounced: IpAsnNetworkInfo = {
          ip: parsed.canonicalIp,
          family: parsed.family,
          isPublic: true,
          asns: [],
          bgpPrefixes: [],
          status: 'unannounced',
        };
        ipInfoCache.set(parsed.canonicalIp, unannounced);
        notifyCacheListeners();
        return unannounced;
      }

      const primary = origins[0];
      const uniqueAsnNums = Array.from(new Set(origins.flatMap((o) => o.asns)));
      const rpkiPairs = new Map<string, { asn: number; prefix: string }>();
      for (const o of origins) {
        if (!o.bgpPrefix) continue;
        for (const asn of o.asns) {
          rpkiPairs.set(`${asn}|${o.bgpPrefix}`, { asn, prefix: o.bgpPrefix });
        }
      }

      // Fetch any missing AS<n>.asn.cymru.com TXT records and RPKI ROA validations in parallel
      const [, rpkiResults] = await Promise.all([
        Promise.all(
          uniqueAsnNums.map(async (asn) => {
            if (asnOrgCache.has(asn)) return;
            try {
              const asnLog = await session.query(`AS${asn}.asn.cymru.com.`, RR_TYPES.TXT, {
                cd: false,
                doBit: false,
                purpose: `BGP ASN organization lookup (AS${asn})`,
              });
              const asnTxts: string[] = [];
              for (const ans of asnLog.packet.answers) {
                if (ans.type === RR_TYPES.TXT) {
                  asnTxts.push(ans.parsed.kind === 'TXT' ? ans.parsed.joinedText : ans.rdataText);
                }
              }
              const parsedAsn = parseCymruAsnTxt(asnTxts);
              if (parsedAsn) {
                asnOrgCache.set(asn, {
                  asn: parsedAsn.asn,
                  asName: parsedAsn.asName,
                  country: parsedAsn.country,
                  rir: parsedAsn.rir,
                  allocatedDate: parsedAsn.allocatedDate,
                });
              }
            } catch {
              // Keep bare ASN number if org TXT lookup fails
            }
          })
        ),
        Promise.all(
          Array.from(rpkiPairs.values()).map((pair) =>
            validateRpkiRoute(pair.asn, pair.prefix).catch(() => undefined)
          )
        ),
      ]);

      const asns: BgpAsnOrganization[] = uniqueAsnNums.map((asn) => {
        const org = asnOrgCache.get(asn);
        return {
          asn,
          asName: org?.asName,
          country: org?.country ?? primary.country,
          rir: org?.rir ?? primary.rir,
          allocatedDate: org?.allocatedDate ?? primary.allocatedDate,
        };
      });

      const bgpPrefixes = Array.from(
        new Set(origins.map((o) => o.bgpPrefix).filter((p): p is string => Boolean(p)))
      );

      const rpkiValidations = rpkiResults.filter(
        (v): v is RpkiRouteValidation => v !== undefined && v.status !== 'error'
      );
      const rpkiStatus = summarizeRpkiValidationState(rpkiValidations);

      const result: IpAsnNetworkInfo = {
        ip: parsed.canonicalIp,
        family: parsed.family,
        isPublic: true,
        asns,
        bgpPrefixes,
        country: primary.country ?? asns[0]?.country,
        rir: primary.rir ?? asns[0]?.rir,
        allocatedDate: primary.allocatedDate ?? asns[0]?.allocatedDate,
        ...(rpkiStatus ? { rpkiStatus } : {}),
        ...(rpkiValidations.length > 0 ? { rpkiValidations } : {}),
        status: 'ready',
      };

      ipInfoCache.set(parsed.canonicalIp, result);
      notifyCacheListeners();
      return result;
    } catch {
      const errEntry: IpAsnNetworkInfo = {
        ip: parsed.canonicalIp,
        family: parsed.family,
        isPublic: true,
        asns: [],
        bgpPrefixes: [],
        status: 'error',
      };
      notifyCacheListeners();
      return errEntry;
    } finally {
      inflightLookups.delete(parsed.canonicalIp);
    }
  })();

  inflightLookups.set(parsed.canonicalIp, task);
  return task;
}

/**
 * Ensures RPKI ROA validation is loaded for an already-cached `IpAsnNetworkInfo` entry when hovered.
 */
async function ensureIpRpkiLoaded(canonicalIp: string): Promise<void> {
  const cur = ipInfoCache.get(canonicalIp);
  if (!cur || cur.status !== 'ready' || cur.asns.length === 0 || cur.bgpPrefixes.length === 0) {
    return;
  }
  if (cur.rpkiValidations && cur.rpkiValidations.length > 0) {
    return;
  }

  const pairs: Array<{ asn: number; prefix: string }> = [];
  for (const a of cur.asns) {
    for (const pfx of cur.bgpPrefixes) {
      pairs.push({ asn: a.asn, prefix: pfx });
    }
  }
  if (pairs.length === 0) return;

  const results = await Promise.all(
    pairs.slice(0, 6).map((p) => validateRpkiRoute(p.asn, p.prefix).catch(() => undefined))
  );
  const validList = results.filter(
    (v): v is RpkiRouteValidation => v !== undefined && v.status !== 'error'
  );
  if (validList.length === 0) return;

  const latest = ipInfoCache.get(canonicalIp);
  if (!latest) return;
  const rpkiStatus = summarizeRpkiValidationState(validList);
  ipInfoCache.set(canonicalIp, {
    ...latest,
    rpkiStatus,
    rpkiValidations: validList,
  });
  notifyCacheListeners();
}

/**
 * Hook that subscribes to BGP ASN & network info for one or more raw IP strings.
 */
export function useIpAsnInfos(rawIps: string[], active: boolean): Array<{
  token: ParsedIpToken;
  info: IpAsnNetworkInfo;
}> {
  const [, setTick] = useState(0);

  const tokens = rawIps
    .map((ip) => parseIpToken(ip))
    .filter((t): t is ParsedIpToken => t !== null);

  useEffect(() => {
    if (!active || tokens.length === 0) return;
    const rerender = () => setTick((n) => n + 1);
    listeners.add(rerender);
    for (const tok of tokens) {
      if (tok.isPublic) {
        const cur = ipInfoCache.get(tok.canonicalIp);
        if (!cur || cur.status === 'loading' || cur.status === 'error') {
          void ensureIpAsnInfoLoaded(tok);
        } else if (
          cur.status === 'ready' &&
          cur.asns.length > 0 &&
          cur.bgpPrefixes.length > 0 &&
          (!cur.rpkiValidations || cur.rpkiValidations.length === 0)
        ) {
          void ensureIpRpkiLoaded(tok.canonicalIp);
        }
      }
    }
    return () => {
      listeners.delete(rerender);
    };
  }, [active, rawIps.join('|')]);

  return tokens.map((token) => ({
    token,
    info: getCachedOrInitialIpInfo(token),
  }));
}

/**
 * Renders a compact RPKI Route Origin Authorization (ROA — RFC 6811) status pill.
 */
export function RpkiStatusBadge({
  status,
  validation,
  compact = false,
  className = '',
}: {
  status: RpkiValidationState;
  validation?: RpkiRouteValidation;
  compact?: boolean;
  className?: string;
}) {
  if (status === 'error') return null;

  const styles =
    status === 'valid'
      ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
      : status === 'invalid-asn' || status === 'invalid-length'
        ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/35'
        : 'bg-slate-200/80 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700';

  const label =
    status === 'valid'
      ? 'RPKI VALID ✓'
      : status === 'invalid-asn'
        ? 'RPKI INVALID (ASN)'
        : status === 'invalid-length'
          ? 'RPKI INVALID (LEN)'
          : compact
            ? 'RPKI NO ROA'
            : 'RPKI NOT FOUND (NO ROA)';

  return (
    <span
      title={validation?.summary}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${styles} ${className}`}
    >
      {status === 'valid' ? (
        <ShieldCheck className="w-3 h-3 shrink-0" />
      ) : status === 'invalid-asn' || status === 'invalid-length' ? (
        <ShieldAlert className="w-3 h-3 shrink-0" />
      ) : null}
      <span>{label}</span>
    </span>
  );
}

/**
 * Renders the interior of the floating BGP ASN / Network hover & tap card for one or more IPs.
 */
export function IpAsnHoverCardContent({
  entries,
  titleLabel,
  onTraceIp,
  onDismiss,
  showCloseButton = false,
  showActions = true,
  mobileSheet = false,
}: {
  entries: Array<{ token: ParsedIpToken; info: IpAsnNetworkInfo }>;
  titleLabel?: string;
  onTraceIp?: (ip: string) => void;
  onDismiss?: () => void;
  showCloseButton?: boolean;
  showActions?: boolean;
  mobileSheet?: boolean;
}) {
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  if (entries.length === 0) return null;

  const handleCopy = async (ipToCopy: string) => {
    const ok = await copyIpToClipboard(ipToCopy);
    if (ok) {
      setCopiedIp(ipToCopy);
      if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => {
        setCopiedIp((cur) => (cur === ipToCopy ? null : cur));
      }, 1800);
    }
  };

  return (
    <div
      className={`${
        mobileSheet
          ? 'w-full max-w-md mx-auto max-h-[75vh] overflow-y-auto'
          : 'w-80 max-w-[calc(100vw-24px)]'
      } rounded-xl border border-slate-200 dark:border-slate-700/90 bg-white/98 dark:bg-slate-900/98 backdrop-blur-md shadow-xl p-3 text-left text-xs text-slate-800 dark:text-slate-100 space-y-2.5`}
    >
      {(titleLabel || (showCloseButton && onDismiss)) && (
        <div className="flex items-center justify-between gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800 pb-1.5">
          <div className="flex items-center gap-1.5 min-w-0">
            <Network className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
            <span className="truncate">{titleLabel ?? 'BGP Origin · RPKI · Quick Actions'}</span>
          </div>
          {showCloseButton && onDismiss && (
            <button
              type="button"
              data-testid="ip-card-close-btn"
              aria-label="Close IP network card"
              onClick={(e) => {
                e.stopPropagation();
                onDismiss();
              }}
              className="rounded p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

      <div className="space-y-2.5 divide-y divide-slate-100 dark:divide-slate-800/80">
        {entries.map(({ token, info }, idx) => {
          const isCopied = copiedIp === token.canonicalIp;
          return (
            <div
              key={`${token.canonicalIp}-${token.cidrSuffix ?? ''}-${idx}`}
              className={idx > 0 ? 'pt-2.5 space-y-1.5' : 'space-y-1.5'}
            >
              {/* Header Row: IPv4/IPv6 badge + IP address + RIR/Country badge */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold shrink-0 ${
                      token.family === 6
                        ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30'
                        : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30'
                    }`}
                  >
                    IPv{token.family}
                  </span>
                  <span className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100 break-all">
                    {token.canonicalIp}
                    {token.cidrSuffix ?? ''}
                  </span>
                </div>

                {info.isPublic ? (
                  (info.rir || info.country) && (
                    <span className="rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase text-slate-600 dark:text-slate-300 shrink-0">
                      {[info.rir, info.country].filter(Boolean).join(' · ')}
                    </span>
                  )
                ) : (
                  <span className="rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] font-semibold shrink-0">
                    SPECIAL RANGE
                  </span>
                )}
              </div>

              {/* Body: ASN + Organization + Routed BGP Prefix */}
              {info.status === 'special' ? (
                <div className="flex items-start gap-1.5 rounded-lg bg-amber-500/10 border border-amber-500/25 px-2.5 py-1.5 text-[11px] text-amber-800 dark:text-amber-200">
                  <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-500" />
                  <span>{info.specialRangeNote ?? 'Non-public / reserved IP address range'}</span>
                </div>
              ) : info.status === 'loading' ? (
                <div className="flex items-center gap-2 py-1 text-[11px] text-slate-500 dark:text-slate-400">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-500 shrink-0" />
                  <span>Resolving BGP ASN &amp; network via DoH…</span>
                </div>
              ) : info.status === 'ready' && info.asns.length > 0 ? (
                <div className="space-y-1.5">
                  {info.asns.map((asn) => (
                    <div
                      key={asn.asn}
                      className="rounded-lg bg-slate-50 dark:bg-slate-950/80 border border-slate-200/80 dark:border-slate-800 px-2.5 py-1.5 space-y-0.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="inline-flex items-center gap-1 rounded bg-cyan-500/15 text-cyan-800 dark:text-cyan-200 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[11px] font-bold">
                          <Globe className="w-3 h-3 text-cyan-500" />
                          AS{asn.asn}
                        </span>
                        {asn.allocatedDate && (
                          <span className="font-mono text-[10px] text-slate-400">
                            Alloc {asn.allocatedDate}
                          </span>
                        )}
                      </div>
                      {asn.asName && (
                        <div className="font-medium text-[11px] text-slate-800 dark:text-slate-200 break-words pt-0.5">
                          {asn.asName}
                        </div>
                      )}
                    </div>
                  ))}

                  {info.bgpPrefixes.length > 0 && (
                    <div className="flex flex-wrap items-center justify-between gap-1.5 pt-0.5 text-[11px] font-mono">
                      <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1">
                        <Server className="w-3 h-3 text-cyan-500" />
                        <span>BGP Network:</span>
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {info.bgpPrefixes.map((pfx) => (
                          <span
                            key={pfx}
                            className="rounded bg-cyan-500/10 border border-cyan-500/25 px-1.5 py-0.5 font-bold text-cyan-800 dark:text-cyan-200"
                          >
                            {pfx}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {info.rpkiStatus && info.rpkiStatus !== 'error' && (
                    <div className="space-y-1 pt-0.5">
                      <div className="flex flex-wrap items-center justify-between gap-1.5 text-[11px] font-mono">
                        <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1">
                          <ShieldCheck className="w-3 h-3 text-cyan-500" />
                          <span>RPKI ROA:</span>
                        </span>
                        <RpkiStatusBadge
                          status={info.rpkiStatus}
                          validation={info.rpkiValidations?.[0]}
                          compact
                        />
                      </div>
                      {info.rpkiValidations?.[0]?.roas &&
                        info.rpkiValidations[0].roas.length > 0 && (
                          <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 flex flex-wrap items-center justify-end gap-1">
                            {info.rpkiStatus === 'invalid-asn' ? (
                              <span className="text-rose-600 dark:text-rose-400">
                                ROA Origin:{' '}
                                {Array.from(
                                  new Set(
                                    info.rpkiValidations[0].roas.map((r) => `AS${r.originAsn}`)
                                  )
                                )
                                  .slice(0, 3)
                                  .join(', ')}{' '}
                                (maxLen /{info.rpkiValidations[0].roas[0].maxLength})
                              </span>
                            ) : (
                              <span>
                                ROA AS{info.rpkiValidations[0].roas[0].originAsn} ·{' '}
                                {info.rpkiValidations[0].roas[0].prefix} (maxLen /
                                {info.rpkiValidations[0].roas[0].maxLength})
                              </span>
                            )}
                          </div>
                        )}
                    </div>
                  )}
                </div>
              ) : info.status === 'unannounced' ? (
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  No global BGP origin announcement found in Team Cymru DNS.
                </div>
              ) : (
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  Unable to query BGP origin TXT via DoH.
                </div>
              )}

              {/* Quick-Action Footer: Copy IP + Trace Reverse DNS (PTR) */}
              {showActions && (
                <div className="flex items-center gap-1.5 pt-1.5 border-t border-slate-100 dark:border-slate-800/80">
                  <button
                    type="button"
                    data-testid="ip-card-copy-btn"
                    data-ip={token.canonicalIp}
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleCopy(token.canonicalIp);
                    }}
                    className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700/90 bg-slate-50 dark:bg-slate-800/80 hover:border-cyan-500/70 hover:bg-slate-100 dark:hover:bg-slate-800 px-2.5 py-1.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
                    title={`Copy ${token.canonicalIp} to clipboard`}
                  >
                    {isCopied ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-500 shrink-0" />
                        <span className="text-emerald-700 dark:text-emerald-300 font-semibold">
                          Copied!
                        </span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 text-slate-500 dark:text-slate-400 shrink-0" />
                        <span>Copy IP</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    data-testid="ip-card-trace-ptr-btn"
                    data-ip={token.canonicalIp}
                    onClick={(e) => {
                      e.stopPropagation();
                      const traceHandler = onTraceIp ?? globalTraceIpHandler;
                      onDismiss?.();
                      traceHandler?.(token.canonicalIp);
                    }}
                    className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/35 bg-cyan-500/10 hover:bg-cyan-500/20 hover:border-cyan-500/70 px-2.5 py-1.5 text-[11px] font-semibold text-cyan-800 dark:text-cyan-200 transition-colors cursor-pointer"
                    title={`Run live Reverse DNS (PTR) & DNSSEC trace for ${token.canonicalIp}`}
                  >
                    <Search className="w-3 h-3 text-cyan-600 dark:text-cyan-400 shrink-0" />
                    <span>Trace rDNS (PTR)</span>
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * Inline wrapper for any IPv4/IPv6 address (or CIDR / SPF `ip4:`/`ip6:` token) that displays
 * an interactive BGP ASN, Organization, Routed Network Prefix, RIR, Country, and RPKI ROA card
 * on desktop hover or mobile/keyboard tap, complete with Copy IP & Trace rDNS (PTR) actions.
 */
export function IpHoverBadge({
  ip,
  children,
  className = '',
  onTraceIp,
}: {
  ip: string;
  children?: ReactNode;
  className?: string;
  onTraceIp?: (ip: string) => void;
}) {
  const parsed = parseIpToken(ip);
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const cardRef = useRef<HTMLDivElement | null>(null);
  const hoverCloseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTouchTimeRef = useRef<number>(0);

  const [hovered, setHovered] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [coords, setCoords] = useState<{
    left: number;
    top: number;
    placement: 'top' | 'bottom';
    mobileSheet: boolean;
  } | null>(null);

  const isOpen = hovered || pinned;
  const entries = useIpAsnInfos(parsed ? [ip] : [], isOpen);

  const clearHoverTimer = useCallback(() => {
    if (hoverCloseTimerRef.current !== null) {
      clearTimeout(hoverCloseTimerRef.current);
      hoverCloseTimerRef.current = null;
    }
  }, []);

  const dismissCard = useCallback(() => {
    clearHoverTimer();
    setPinned(false);
    setHovered(false);
  }, [clearHoverTimer]);

  useEffect(() => {
    return () => clearHoverTimer();
  }, [clearHoverTimer]);

  // Coordinate module-level active pinned badge so tapping another IP badge closes the previous one
  useEffect(() => {
    if (!pinned) {
      if (activePinnedDismiss === dismissCard) {
        activePinnedDismiss = null;
      }
      return;
    }
    if (activePinnedDismiss && activePinnedDismiss !== dismissCard) {
      activePinnedDismiss();
    }
    activePinnedDismiss = dismissCard;
    return () => {
      if (activePinnedDismiss === dismissCard) {
        activePinnedDismiss = null;
      }
    };
  }, [pinned, dismissCard]);

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
      const cardWidth = Math.min(320, Math.max(240, vw - 24));
      const half = cardWidth / 2;
      const center = rect.left + rect.width / 2;
      const clampedLeft = Math.max(12 + half, Math.min(vw - 12 - half, center));
      const placement: 'top' | 'bottom' = rect.top > 230 ? 'top' : 'bottom';
      const top = placement === 'top' ? rect.top - 8 : rect.bottom + 8;
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

  const handleMouseEnter = () => {
    if (Date.now() - lastTouchTimeRef.current < 600) {
      return;
    }
    clearHoverTimer();
    updatePosition(pinned);
    setHovered(true);
  };

  const handleMouseLeave = () => {
    if (Date.now() - lastTouchTimeRef.current < 600) {
      return;
    }
    scheduleHoverClose();
  };

  const handleTogglePin = (e: { stopPropagation: () => void }) => {
    e.stopPropagation();
    clearHoverTimer();
    if (pinned) {
      setPinned(false);
      setHovered(false);
    } else {
      updatePosition(true);
      setPinned(true);
    }
  };

  // Dismiss on outside tap/click, Escape, or page scroll out of viewport
  useEffect(() => {
    if (!isOpen || typeof document === 'undefined') return;

    const handleOutsideInteraction = (e: Event) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (triggerRef.current?.contains(target)) return;
      if (cardRef.current?.contains(target)) return;
      dismissCard();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        e.stopImmediatePropagation();
        const focusWasInCard = Boolean(cardRef.current?.contains(document.activeElement));
        dismissCard();
        if (focusWasInCard) {
          triggerRef.current?.focus();
        }
      }
    };

    const handleResize = () => {
      updatePosition();
    };

    const handleScroll = (e: Event) => {
      const target = e.target as Node | null;
      if (target && cardRef.current?.contains(target)) {
        return;
      }
      const el = triggerRef.current;
      if (!el || typeof window === 'undefined') return;
      const rect = el.getBoundingClientRect();
      const vh = window.innerHeight || 768;
      if (vh > 0 && (rect.bottom < -16 || rect.top > vh + 16)) {
        dismissCard();
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
  }, [isOpen, dismissCard, updatePosition]);

  if (!parsed) {
    return <span className={className}>{children ?? ip}</span>;
  }

  return (
    <>
      <span
        ref={triggerRef}
        role="button"
        tabIndex={0}
        aria-expanded={isOpen}
        aria-haspopup="dialog"
        data-testid="ip-hover-badge"
        data-ip={parsed.canonicalIp}
        data-pinned={pinned ? 'true' : undefined}
        onTouchStart={() => {
          lastTouchTimeRef.current = Date.now();
        }}
        onPointerDown={(e) => {
          if (e.pointerType === 'touch' || e.pointerType === 'pen') {
            lastTouchTimeRef.current = Date.now();
          }
        }}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onClick={handleTogglePin}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleTogglePin(e);
          }
        }}
        className={`rounded-sm outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/80 ${
          pinned
            ? 'underline decoration-solid decoration-cyan-500 text-cyan-700 dark:text-cyan-300'
            : 'decoration-dotted hover:underline hover:decoration-cyan-500/80'
        } cursor-help ${className}`}
      >
        {children ?? ip}
      </span>
      {isOpen &&
        coords &&
        typeof document !== 'undefined' &&
        document.body &&
        createPortal(
          <div
            ref={cardRef}
            role="dialog"
            aria-label={`IP network details for ${parsed.canonicalIp}`}
            data-testid="ip-hover-card-portal"
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
            <IpAsnHoverCardContent
              entries={entries}
              onTraceIp={onTraceIp}
              onDismiss={dismissCard}
              showCloseButton={pinned}
              mobileSheet={coords.mobileSheet}
            />
          </div>,
          document.body
        )}
    </>
  );
}
