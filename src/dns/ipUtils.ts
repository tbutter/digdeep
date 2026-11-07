import { DNSBL_PROVIDERS, RR_TYPES } from './constants';
import type { DohSession } from './doh';
import { displayFqdn, normalizeFqdn } from './encoding';
import type { DnsblAuditSummary, DnsblProviderResult, DohQueryLog } from './types';

export interface IpClassification {
  isPublic: boolean;
  note?: string;
}

export interface ParsedReverseIpTarget {
  ip: string;
  family: 4 | 6;
  arpaFqdn: string;
  displayArpa: string;
  isPublic: boolean;
  specialRangeNote?: string;
  cymruOriginQname?: string;
  wasRawIpInput: boolean;
}

export interface CymruOriginEntry {
  asns: number[];
  bgpPrefix?: string;
  country?: string;
  rir?: string;
  allocatedDate?: string;
  raw: string;
}

export interface CymruAsnEntry {
  asn: number;
  country?: string;
  rir?: string;
  allocatedDate?: string;
  asName?: string;
  raw: string;
}

/**
 * Parses a dotted-quad IPv4 string into 4 octets (0..255), or returns null if invalid.
 */
export function parseIpv4Octets(raw: string): number[] | null {
  const trimmed = raw.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const n = Number.parseInt(part, 10);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/**
 * Parses an IPv6 string (including `::` compression and IPv4-mapped `::ffff:192.0.2.1`)
 * into 8 16-bit hextets (0..0xffff), or returns null if invalid.
 */
export function parseIpv6Groups(raw: string): number[] | null {
  const clean = raw.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!clean || !clean.includes(':')) return null;
  if (clean.split('::').length > 2) return null;

  let working = clean;
  // Convert trailing IPv4 dotted-quad (e.g. ::ffff:192.0.2.1) into two 16-bit hex groups
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4Part = working.slice(lastColon + 1);
    const octets = parseIpv4Octets(v4Part);
    if (!octets) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    working = `${working.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  let groups: string[];
  if (working.includes('::')) {
    const [leftRaw, rightRaw] = working.split('::');
    const left = leftRaw ? leftRaw.split(':') : [];
    const right = rightRaw ? rightRaw.split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
  } else {
    groups = working.split(':');
  }

  if (groups.length !== 8) return null;
  const nums: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    nums.push(Number.parseInt(g, 16));
  }
  return nums;
}

/**
 * Formats 8 16-bit IPv6 hextets into canonical RFC 5952 text representation.
 */
export function formatCanonicalIpv6(groups: number[]): string {
  if (groups.length !== 8) return groups.map((g) => g.toString(16)).join(':');

  // Find longest run of zero hextets (at least length 2 per RFC 5952 §4.2.2)
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen && curLen >= 2) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestStart === -1) {
    return groups.map((g) => g.toString(16)).join(':');
  }

  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(':');
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(':');
  return `${left}::${right}`;
}

/**
 * Classifies whether an IPv4 or IPv6 address is publicly routable unicast vs special-use.
 */
export function classifyIpAddress(ip: string, family: 4 | 6): IpClassification {
  if (family === 4) {
    const parts = parseIpv4Octets(ip);
    if (!parts) {
      return { isPublic: false, note: 'Malformed IPv4 literal' };
    }
    const [a, b, c] = parts;
    if (a === 0) return { isPublic: false, note: '0.0.0.0/8 ("this" network, RFC 1122)' };
    if (a === 10) return { isPublic: false, note: '10.0.0.0/8 private (RFC 1918)' };
    if (a === 100 && b >= 64 && b <= 127) {
      return { isPublic: false, note: '100.64.0.0/10 carrier-grade NAT (RFC 6598)' };
    }
    if (a === 127) return { isPublic: false, note: '127.0.0.0/8 loopback (RFC 1122)' };
    if (a === 169 && b === 254) return { isPublic: false, note: '169.254.0.0/16 link-local (RFC 3927)' };
    if (a === 172 && b >= 16 && b <= 31) {
      return { isPublic: false, note: '172.16.0.0/12 private (RFC 1918)' };
    }
    if (a === 192 && b === 0 && c === 2) {
      return { isPublic: false, note: '192.0.2.0/24 TEST-NET-1 documentation (RFC 5737)' };
    }
    if (a === 192 && b === 168) {
      return { isPublic: false, note: '192.168.0.0/16 private (RFC 1918)' };
    }
    if (a === 198 && (b === 18 || b === 19)) {
      return { isPublic: false, note: '198.18.0.0/15 benchmarking (RFC 2544)' };
    }
    if (a === 198 && b === 51 && c === 100) {
      return { isPublic: false, note: '198.51.100.0/24 TEST-NET-2 documentation (RFC 5737)' };
    }
    if (a === 203 && b === 0 && c === 113) {
      return { isPublic: false, note: '203.0.113.0/24 TEST-NET-3 documentation (RFC 5737)' };
    }
    if (a >= 224) {
      return { isPublic: false, note: 'Multicast / reserved IPv4 range' };
    }
    return { isPublic: true };
  }

  const groups = parseIpv6Groups(ip);
  if (!groups) {
    return { isPublic: false, note: 'Malformed IPv6 literal' };
  }
  if (groups.every((g) => g === 0)) {
    return { isPublic: false, note: '::/128 unspecified IPv6 address (RFC 4291)' };
  }
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
    return { isPublic: false, note: '::1/128 loopback IPv6 address (RFC 4291)' };
  }
  if (
    groups.slice(0, 5).every((g) => g === 0) &&
    groups[5] === 0xffff
  ) {
    return { isPublic: false, note: '::ffff:0:0/96 IPv4-mapped IPv6 address (RFC 4291)' };
  }
  if ((groups[0] & 0xfe00) === 0xfc00) {
    return { isPublic: false, note: 'fc00::/7 Unique Local Address (RFC 4193)' };
  }
  if ((groups[0] & 0xffc0) === 0xfe80) {
    return { isPublic: false, note: 'fe80::/10 link-local IPv6 address (RFC 4291)' };
  }
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) {
    return { isPublic: false, note: '2001:db8::/32 documentation IPv6 range (RFC 3849)' };
  }
  if ((groups[0] & 0xff00) === 0xff00) {
    return { isPublic: false, note: 'ff00::/8 multicast IPv6 range' };
  }
  return { isPublic: true };
}

/**
 * Converts an IPv4 or IPv6 address literal into its reverse DNS `.in-addr.arpa.` or `.ip6.arpa.` FQDN.
 * Returns `null` if the IP string is malformed.
 */
export function ipToReverseArpa(rawIp: string): string | null {
  const v4 = parseIpv4Octets(rawIp);
  if (v4) {
    return `${[...v4].reverse().join('.')}.in-addr.arpa.`;
  }
  const v6 = parseIpv6Groups(rawIp);
  if (v6) {
    const fullHex = v6.map((g) => g.toString(16).padStart(4, '0')).join('');
    if (fullHex.length !== 32) return null;
    return `${fullHex.split('').reverse().join('.')}.ip6.arpa.`;
  }
  return null;
}

/**
 * Converts a reverse DNS `.in-addr.arpa.` or `.ip6.arpa.` FQDN back into a canonical IPv4 or IPv6 address.
 * Returns `null` if `qname` is not a full host-level reverse `.arpa.` name.
 */
export function reverseArpaToIp(qname: string): { ip: string; family: 4 | 6 } | null {
  const norm = normalizeFqdn(qname);
  if (norm.endsWith('.in-addr.arpa.')) {
    const prefix = norm.slice(0, -'.in-addr.arpa.'.length);
    const labels = prefix.split('.');
    if (labels.length !== 4) return null;
    const reversed = [...labels].reverse().join('.');
    const octets = parseIpv4Octets(reversed);
    if (!octets) return null;
    return { ip: octets.join('.'), family: 4 };
  }

  if (norm.endsWith('.ip6.arpa.')) {
    const prefix = norm.slice(0, -'.ip6.arpa.'.length);
    const nibbles = prefix.split('.');
    if (nibbles.length !== 32) return null;
    if (!nibbles.every((n) => /^[0-9a-f]$/i.test(n))) return null;
    const forwardHex = [...nibbles].reverse().join('').toLowerCase();
    const groups: number[] = [];
    for (let i = 0; i < 32; i += 4) {
      groups.push(Number.parseInt(forwardHex.slice(i, i + 4), 16));
    }
    return { ip: formatCanonicalIpv6(groups), family: 6 };
  }

  return null;
}

/**
 * Builds the Team Cymru DNS-based BGP origin lookup name (`*.origin.asn.cymru.com.` or `*.origin6.asn.cymru.com.`).
 */
export function ipToCymruOriginQname(rawIp: string): string | null {
  const v4 = parseIpv4Octets(rawIp);
  if (v4) {
    return `${[...v4].reverse().join('.')}.origin.asn.cymru.com.`;
  }
  const v6 = parseIpv6Groups(rawIp);
  if (v6) {
    const fullHex = v6.map((g) => g.toString(16).padStart(4, '0')).join('');
    if (fullHex.length !== 32) return null;
    return `${fullHex.split('').reverse().join('.')}.origin6.asn.cymru.com.`;
  }
  return null;
}

/**
 * Detects whether a user search input or snapshot target name represents an IPv4 address,
 * IPv6 address, or reverse `.in-addr.arpa` / `.ip6.arpa` host query.
 */
export function parseReverseIpInput(raw: string): ParsedReverseIpTarget | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '.') return null;

  // 1. Check raw IPv4 literal
  const v4 = parseIpv4Octets(trimmed);
  if (v4) {
    const ip = v4.join('.');
    const arpaFqdn = `${[...v4].reverse().join('.')}.in-addr.arpa.`;
    const cls = classifyIpAddress(ip, 4);
    return {
      ip,
      family: 4,
      arpaFqdn,
      displayArpa: displayFqdn(arpaFqdn),
      isPublic: cls.isPublic,
      specialRangeNote: cls.note,
      cymruOriginQname: cls.isPublic ? ipToCymruOriginQname(ip) ?? undefined : undefined,
      wasRawIpInput: true,
    };
  }

  // 2. Check raw IPv6 literal
  const v6 = parseIpv6Groups(trimmed);
  if (v6) {
    const ip = formatCanonicalIpv6(v6);
    const arpaFqdn = ipToReverseArpa(ip)!;
    const cls = classifyIpAddress(ip, 6);
    return {
      ip,
      family: 6,
      arpaFqdn,
      displayArpa: displayFqdn(arpaFqdn),
      isPublic: cls.isPublic,
      specialRangeNote: cls.note,
      cymruOriginQname: cls.isPublic ? ipToCymruOriginQname(ip) ?? undefined : undefined,
      wasRawIpInput: true,
    };
  }

  // 3. Check existing reverse .in-addr.arpa or .ip6.arpa FQDN
  const fromArpa = reverseArpaToIp(trimmed);
  if (fromArpa) {
    const arpaFqdn = normalizeFqdn(trimmed);
    const cls = classifyIpAddress(fromArpa.ip, fromArpa.family);
    return {
      ip: fromArpa.ip,
      family: fromArpa.family,
      arpaFqdn,
      displayArpa: displayFqdn(arpaFqdn),
      isPublic: cls.isPublic,
      specialRangeNote: cls.note,
      cymruOriginQname: cls.isPublic ? ipToCymruOriginQname(fromArpa.ip) ?? undefined : undefined,
      wasRawIpInput: false,
    };
  }

  return null;
}

/**
 * Parses Team Cymru `origin.asn.cymru.com` / `origin6.asn.cymru.com` TXT strings.
 * Example: `"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"`
 */
export function parseCymruOriginTxt(txtStrings: string[]): CymruOriginEntry[] {
  const entries: CymruOriginEntry[] = [];
  for (const raw of txtStrings) {
    const parts = raw.split('|').map((s) => s.trim());
    if (parts.length < 2) continue;
    const asnTokens = parts[0]
      .split(/\s+/)
      .map((tok) => Number.parseInt(tok.replace(/^AS/i, ''), 10))
      .filter((n) => Number.isInteger(n) && n > 0);
    if (asnTokens.length === 0) continue;
    entries.push({
      asns: asnTokens,
      bgpPrefix: parts[1] || undefined,
      country: parts[2] || undefined,
      rir: parts[3] || undefined,
      allocatedDate: parts[4] || undefined,
      raw,
    });
  }
  return entries;
}

/**
 * Parses Team Cymru `AS<number>.asn.cymru.com` TXT strings.
 * Example: `"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"`
 */
export function parseCymruAsnTxt(txtStrings: string[]): CymruAsnEntry | null {
  for (const raw of txtStrings) {
    const parts = raw.split('|').map((s) => s.trim());
    if (parts.length < 2) continue;
    const asn = Number.parseInt(parts[0].replace(/^AS/i, ''), 10);
    if (!Number.isInteger(asn) || asn <= 0) continue;
    return {
      asn,
      country: parts[1] || undefined,
      rir: parts[2] || undefined,
      allocatedDate: parts[3] || undefined,
      asName: parts[4] || undefined,
      raw,
    };
  }
  return null;
}

/**
 * Builds an RFC 5782 DNSBL query name for an IPv4 address (`d.c.b.a.<dnsblZone>.`)
 * or IPv6 address (32 reversed nibbles + `.<dnsblZone>.`).
 */
export function ipToDnsblQname(rawIp: string, dnsblZone: string): string | null {
  const cleanZone = normalizeFqdn(dnsblZone);
  if (!cleanZone || cleanZone === '.') return null;

  const v4 = parseIpv4Octets(rawIp);
  if (v4) {
    return `${[...v4].reverse().join('.')}.${cleanZone}`;
  }
  const v6 = parseIpv6Groups(rawIp);
  if (v6) {
    const fullHex = v6.map((g) => g.toString(16).padStart(4, '0')).join('');
    if (fullHex.length !== 32) return null;
    return `${fullHex.split('').reverse().join('.')}.${cleanZone}`;
  }
  return null;
}

/**
 * Classifies an A record returned by a DNSBL query per RFC 5782:
 * - `127.255.255.x` (`127.255.255.252`–`127.255.255.255`) are administrative / open-resolver refusal codes, NOT listings.
 * - `127.0.0.1`..`127.255.254.255` are genuine blocklist return codes (`'listed'`).
 * - Any non-127.0.0.0/8 address is ignored (`'ignore'`).
 */
export function classifyDnsblReturnIp(ip: string): 'listed' | 'admin-blocked' | 'ignore' {
  const octets = parseIpv4Octets(ip);
  if (!octets || octets[0] !== 127) return 'ignore';
  if (octets[1] === 255 && octets[2] === 255) {
    return 'admin-blocked';
  }
  return 'listed';
}

/**
 * Queries all configured DoH-compatible `DNSBL_PROVIDERS` for an IPv4 address (`A`, plus `TXT` if listed).
 */
export async function queryDnsblForIp(session: DohSession, ip: string): Promise<void> {
  await Promise.all(
    DNSBL_PROVIDERS.map(async (prov) => {
      const qname = ipToDnsblQname(ip, prov.zone);
      if (!qname) return;
      try {
        const aLog = await session.query(qname, RR_TYPES.A, {
          cd: false,
          doBit: false,
          purpose: `DNSBL reputation lookup (${prov.zone} A)`,
        });
        const isListed = aLog.packet.answers.some(
          (r) =>
            r.type === RR_TYPES.A &&
            normalizeFqdn(r.name) === qname &&
            classifyDnsblReturnIp(r.rdataText.trim()) === 'listed'
        );
        if (isListed) {
          await session
            .query(qname, RR_TYPES.TXT, {
              cd: false,
              doBit: false,
              purpose: `DNSBL reputation lookup (${prov.zone} TXT)`,
            })
            .catch(() => undefined);
        }
      } catch {
        // Ignore individual DNSBL timeout or network error
      }
    })
  );
}

/**
 * Evaluates DNSBL reputation results for an IP address from captured DoH query logs.
 */
export function evaluateDnsblAuditForIp(
  ip: string,
  family: 4 | 6,
  isPublic: boolean,
  logs: DohQueryLog[]
): DnsblAuditSummary {
  const isRfc5782TestIp = ip === '127.0.0.2' || ip === '127.0.0.1';
  if (!isPublic && !isRfc5782TestIp) {
    return {
      ip,
      checkedCount: 0,
      listedCount: 0,
      status: 'not-applicable',
      providers: [],
      summary: 'Special-use / non-public IP address; DNSBL reputation checks do not apply.',
    };
  }
  if (family !== 4) {
    return {
      ip,
      checkedCount: 0,
      listedCount: 0,
      status: 'not-applicable',
      providers: [],
      summary: 'Public DoH-accessible DNSBL providers primarily index IPv4 (/32) addresses.',
    };
  }

  const providers: DnsblProviderResult[] = [];
  for (const prov of DNSBL_PROVIDERS) {
    const qname = ipToDnsblQname(ip, prov.zone);
    if (!qname) continue;
    const aLog = logs.find(
      (l) => normalizeFqdn(l.qname) === qname && l.qtype === RR_TYPES.A
    );
    if (!aLog) continue;

    const aAnswers = aLog.packet.answers.filter(
      (r) => r.type === RR_TYPES.A && normalizeFqdn(r.name) === qname
    );
    const listedCodes: string[] = [];
    const adminCodes: string[] = [];
    for (const ans of aAnswers) {
      const code = ans.rdataText.trim();
      const cls = classifyDnsblReturnIp(code);
      if (cls === 'listed') listedCodes.push(code);
      else if (cls === 'admin-blocked') adminCodes.push(code);
    }

    const txtLog = logs.find(
      (l) => normalizeFqdn(l.qname) === qname && l.qtype === RR_TYPES.TXT
    );
    const reasons: string[] = [];
    if (txtLog) {
      for (const ans of txtLog.packet.answers) {
        if (ans.type === RR_TYPES.TXT) {
          const text = ans.parsed.kind === 'TXT' ? ans.parsed.joinedText.trim() : ans.rdataText.trim();
          if (text && !reasons.includes(text)) reasons.push(text);
        }
      }
    }

    let status: DnsblProviderResult['status'] = 'clean';
    if (listedCodes.length > 0) {
      status = 'listed';
    } else if (adminCodes.length > 0) {
      status = 'admin-blocked';
    } else if (aLog.packet.flags.rcode !== 0 && aLog.packet.flags.rcode !== 3) {
      status = 'error';
    }

    providers.push({
      id: prov.zone,
      label: prov.label,
      zone: prov.zone,
      category: prov.category,
      qname,
      status,
      returnCodes: listedCodes.length > 0 ? listedCodes : adminCodes,
      reasons,
    });
  }

  if (providers.length === 0) {
    return {
      ip,
      checkedCount: 0,
      listedCount: 0,
      status: 'unchecked',
      providers: [],
      summary: 'DNSBL reputation queries were not captured in this snapshot.',
    };
  }

  const listedProviders = providers.filter((p) => p.status === 'listed');
  const cleanCount = providers.filter((p) => p.status === 'clean').length;

  if (listedProviders.length > 0) {
    const names = listedProviders.map((p) => p.label).join(', ');
    return {
      ip,
      checkedCount: providers.length,
      listedCount: listedProviders.length,
      status: 'listed',
      providers,
      summary: `Listed on ${listedProviders.length} of ${providers.length} checked DNSBL blocklists (${names}).`,
    };
  }

  return {
    ip,
    checkedCount: providers.length,
    listedCount: 0,
    status: 'all-clean',
    providers,
    summary: `Clean across all ${cleanCount} responsive DoH DNSBL providers (RFC 5782).`,
  };
}
