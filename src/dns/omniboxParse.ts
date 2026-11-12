import { SNAPSHOT_ENGINE_VERSION } from './analyzer';
import {
  DOH_SERVER_PRESETS,
  formatDohShortLabel,
  IANA_ROOT_TRUST_ANCHORS,
  RR_TYPES,
} from './constants';
import { parseEmailDaneInput } from './emailDane';
import { extractEmailHeaderQuickSummary } from './emailHeaderVerifier';
import { displayFqdn, normalizeFqdn } from './encoding';
import { parseReverseIpInput, stripIpEndpointWrappers } from './ipUtils';
import type { AnalysisMode, AnalysisSnapshot } from './types';
import {
  buildSyntheticLogFromDissected,
  decodeUserWireInput,
  dissectDnsWirePacket,
  type DissectedWirePacket,
} from './wireDissector';
import { resolveDohParam } from '../urlState';

export type OmniboxDetectedWireFormat = 'doh-url' | 'hex-dump' | 'hex' | 'base64url';

export type OmniboxParseResult =
  | {
      kind: 'wire-packet';
      wireInput: string;
      detectedFormat: OmniboxDetectedWireFormat;
      dissected: DissectedWirePacket;
      wireSize: number;
      qname: string;
      qtypeName: string;
      qr: boolean;
      summaryLabel: string;
    }
  | {
      kind: 'cli-command';
      tool: 'dig' | 'delv' | 'kdig' | 'nslookup' | 'host';
      target: string;
      rrTypes: string[] | null;
      dohEndpoint: string | null;
      dohDisplay: string | null;
      isUntrustedCustomDoh: boolean;
      summaryLabel: string;
    }
  | {
      kind: 'email-headers';
      rawHeaders: string;
      target: string;
      dkimSelectors: string[];
      dkimSignatureCount: number;
      arcSetCount: number;
      fromAddress?: string;
      summaryLabel: string;
    }
  | {
      kind: 'email';
      target: string;
      wasTransformed: boolean;
      summaryLabel: string | null;
    }
  | {
      kind: 'ip';
      target: string;
      family: 4 | 6;
      wasTransformed: boolean;
      summaryLabel: string | null;
    }
  | {
      kind: 'domain';
      target: string;
      wasTransformed: boolean;
      summaryLabel: string | null;
    };

/**
 * Maps common resolver IPv4/IPv6 anycast addresses and hostnames used in `dig @...` / `kdig @...`
 * to DigDeep's built-in CORS-enabled RFC 8484 DoH server presets.
 */
const CLI_RESOLVER_PRESET_ALIASES: Record<string, string> = {
  '1.1.1.1': 'https://1.1.1.1/dns-query',
  '1.0.0.1': 'https://1.1.1.1/dns-query',
  '2606:4700:4700::1111': 'https://1.1.1.1/dns-query',
  '2606:4700:4700::1001': 'https://1.1.1.1/dns-query',
  'one.one.one.one': 'https://1.1.1.1/dns-query',
  'cloudflare-dns.com': 'https://1.1.1.1/dns-query',
  'mozilla.cloudflare-dns.com': 'https://1.1.1.1/dns-query',

  '1.1.1.2': 'https://1.1.1.2/dns-query',
  '1.0.0.2': 'https://1.1.1.2/dns-query',
  '2606:4700:4700::1112': 'https://1.1.1.2/dns-query',
  '2606:4700:4700::1002': 'https://1.1.1.2/dns-query',
  'security.cloudflare-dns.com': 'https://1.1.1.2/dns-query',

  '1.1.1.3': 'https://1.1.1.3/dns-query',
  '1.0.0.3': 'https://1.1.1.3/dns-query',
  '2606:4700:4700::1113': 'https://1.1.1.3/dns-query',
  '2606:4700:4700::1003': 'https://1.1.1.3/dns-query',
  'family.cloudflare-dns.com': 'https://1.1.1.3/dns-query',

  '8.8.8.8': 'https://8.8.8.8/dns-query',
  '8.8.4.4': 'https://8.8.8.8/dns-query',
  '2001:4860:4860::8888': 'https://8.8.8.8/dns-query',
  '2001:4860:4860::8844': 'https://8.8.8.8/dns-query',
  'dns.google': 'https://8.8.8.8/dns-query',
  'dns.google.com': 'https://8.8.8.8/dns-query',

  '9.9.9.9': 'https://9.9.9.9/dns-query',
  '149.112.112.112': 'https://9.9.9.9/dns-query',
  '2620:fe::fe': 'https://9.9.9.9/dns-query',
  '2620:fe::9': 'https://9.9.9.9/dns-query',
  'dns.quad9.net': 'https://9.9.9.9/dns-query',
  'dns9.quad9.net': 'https://9.9.9.9/dns-query',

  '9.9.9.10': 'https://9.9.9.10/dns-query',
  '149.112.112.10': 'https://9.9.9.10/dns-query',
  '2620:fe::10': 'https://9.9.9.10/dns-query',
  'dns10.quad9.net': 'https://9.9.9.10/dns-query',

  'doh.dns.sb': 'https://doh.dns.sb/dns-query',
  '185.222.222.222': 'https://doh.dns.sb/dns-query',
  '45.11.45.11': 'https://doh.dns.sb/dns-query',

  'unfiltered.joindns4.eu': 'https://unfiltered.joindns4.eu/dns-query',
  '86.54.11.100': 'https://unfiltered.joindns4.eu/dns-query',
  'protective.joindns4.eu': 'https://protective.joindns4.eu/dns-query',
  '86.54.11.1': 'https://protective.joindns4.eu/dns-query',
  'child-noads.joindns4.eu': 'https://child-noads.joindns4.eu/dns-query',
  '86.54.11.13': 'https://child-noads.joindns4.eu/dns-query',
};

const DNS_CLASS_TOKENS = new Set(['IN', 'CH', 'HS', 'CHAOS', 'HESIOD', 'ANY_CLASS']);

function isRecognizedRrType(token: string): boolean {
  const upper = token.trim().toUpperCase();
  if (!upper) return false;
  if (RR_TYPES[upper] !== undefined) return true;
  if (/^TYPE\d{1,5}$/.test(upper)) {
    const code = Number.parseInt(upper.slice(4), 10);
    return code >= 1 && code <= 65535;
  }
  return false;
}

function stripMatchingOuterQuotes(s: string): { value: string; hadOuterQuotes: boolean } {
  if (s.length >= 2) {
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      const inner = s.slice(1, -1);
      // Do not strip quotes from RFC 5322 quoted local-part emails like `"john.doe"@example.com`
      if (!inner.includes('"') && !inner.includes("'")) {
        return { value: inner.trim(), hadOuterQuotes: true };
      }
    }
  }
  return { value: s, hadOuterQuotes: false };
}

function tryDetectWirePacket(rawInput: string): Extract<OmniboxParseResult, { kind: 'wire-packet' }> | null {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  let candidateWire: string | null = null;
  let requireStrictPacketParse = true;

  // 1. Explicit RFC 8484 DoH `?dns=...` URL (or `curl` line containing one) or `dns=...` parameter
  const urlWithDnsMatch = /(https?:\/\/[^\s'"]+[?&]dns=[A-Za-z0-9+/=_-]{16,}[^\s'"]*)/i.exec(trimmed);
  const bareDnsParamMatch = !urlWithDnsMatch
    ? /(?:^|[?&])dns=([A-Za-z0-9+/=_-]{16,})/.exec(trimmed)
    : null;

  if (urlWithDnsMatch) {
    candidateWire = urlWithDnsMatch[1];
    requireStrictPacketParse = false;
  } else if (bareDnsParamMatch) {
    candidateWire = `dns=${bareDnsParamMatch[1]}`;
    requireStrictPacketParse = false;
  } else {
    // 2. Multi-line or offset-prefixed hex dump (`xxd`, `hexdump -C`, `tcpdump -xx`, DigDeep hex view)
    const lines = trimmed
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const looksLikeOffsetHexDump =
      lines.length >= 1 &&
      lines.every((l) => /^(?:0x)?[0-9a-fA-F]{4,8}:?\s+(?:[0-9a-fA-F]{2,4}\s+)+/.test(l));

    if (looksLikeOffsetHexDump) {
      candidateWire = trimmed;
      requireStrictPacketParse = false;
    } else if (
      // 3. Space-separated hex bytes (`1a 2b 81 a0 ...`) — must not contain domain/IP/email punctuation
      /\s/.test(trimmed) &&
      !/[.@/:_-]/.test(trimmed)
    ) {
      const groups = trimmed.split(/\s+/);
      const hexJoined = groups.join('');
      if (
        groups.length >= 3 &&
        groups.every((g) => /^[0-9a-fA-F]{2}$/.test(g) || /^[0-9a-fA-F]{4}$/.test(g)) &&
        hexJoined.length >= 24 &&
        hexJoined.length % 2 === 0
      ) {
        candidateWire = trimmed;
        requireStrictPacketParse = true;
      }
    } else if (
      // 4. Continuous raw hexadecimal wire packet (`1a2b81a0...` or `0x1a2b...`)
      // Excludes `.`, `:`, `@`, `_`, `-` so IPv6 addresses, 56-hex OPENPGPKEY owners, and hex domains never false-trigger
      /^(?:0x)?[0-9a-fA-F]{24,}$/.test(trimmed)
    ) {
      const hexBody = trimmed.replace(/^0x/i, '');
      if (hexBody.length % 2 === 0) {
        candidateWire = trimmed;
        requireStrictPacketParse = true;
      }
    }
  }

  if (!candidateWire) return null;

  try {
    const { bytes, detectedFormat } = decodeUserWireInput(candidateWire);
    if (bytes.length < 12) return null;
    const dissected = dissectDnsWirePacket(bytes);

    if (requireStrictPacketParse) {
      if (
        !dissected.parsedPacket ||
        Boolean(dissected.parseWarning) ||
        dissected.counts.qdCount < 1 ||
        dissected.counts.qdCount > 16 ||
        dissected.parsedPacket.questions.length < 1
      ) {
        return null;
      }
    }

    const firstQ = dissected.parsedPacket?.questions[0];
    const qname = firstQ?.name ? (firstQ.name === '.' ? '.' : displayFqdn(firstQ.name)) : '.';
    const qtypeName = firstQ?.typeName ?? 'DNS';
    const qr = Boolean(dissected.parsedPacket?.flags.qr ?? (dissected.flagWord & 0x8000) !== 0);
    const formatTitle =
      detectedFormat === 'doh-url'
        ? 'RFC 8484 DoH ?dns= packet'
        : detectedFormat === 'hex-dump'
          ? 'wire hex dump'
          : 'DNS wire packet';

    return {
      kind: 'wire-packet',
      wireInput: candidateWire,
      detectedFormat,
      dissected,
      wireSize: dissected.wireSize,
      qname,
      qtypeName,
      qr,
      summaryLabel: `Decoded ${formatTitle} (${dissected.wireSize}B · ${qname} ${qtypeName} ${qr ? 'response' : 'query'}) in Offline Wire Dissector`,
    };
  } catch {
    return null;
  }
}

function tokenizeShellWords(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === '\\' && quote === '"' && i + 1 < input.length) {
        i++;
        current += input[i];
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) {
    tokens.push(current);
  }
  return tokens;
}

function resolveCliServerToDoh(
  rawServer: string,
  hasExplicitHttpsFlag: boolean,
  explicitHttpsPath: string | null,
  savedCustomDohEndpoints: string[]
): { dohEndpoint: string | null; dohDisplay: string | null; isUntrustedCustomDoh: boolean } {
  const trimmed = rawServer.trim().replace(/\.$/, '');
  if (!trimmed) {
    return { dohEndpoint: null, dohDisplay: null, isUntrustedCustomDoh: false };
  }

  // Strip port / brackets when checking well-known anycast IPs and hostnames
  const unwrappedIp = stripIpEndpointWrappers(trimmed).ipCandidate.toLowerCase();
  const hostNoPort = /^([^:]+):\d{1,5}$/.exec(unwrappedIp)?.[1] ?? unwrappedIp;

  const aliasUrl = CLI_RESOLVER_PRESET_ALIASES[hostNoPort];
  if (aliasUrl) {
    return {
      dohEndpoint: aliasUrl,
      dohDisplay: formatDohShortLabel(aliasUrl),
      isUntrustedCustomDoh: false,
    };
  }

  const presetMatch = DOH_SERVER_PRESETS.find(
    (p) => p.shortLabel.toLowerCase() === hostNoPort || p.url.toLowerCase() === trimmed.toLowerCase()
  );
  if (presetMatch) {
    return {
      dohEndpoint: presetMatch.url,
      dohDisplay: presetMatch.shortLabel,
      isUntrustedCustomDoh: false,
    };
  }

  const isExplicitUrl = /^https?:\/\//i.test(trimmed);
  if (isExplicitUrl || hasExplicitHttpsFlag) {
    let candidate = trimmed;
    if (!isExplicitUrl && explicitHttpsPath && !trimmed.includes('/')) {
      const cleanPath = explicitHttpsPath.startsWith('/') ? explicitHttpsPath : `/${explicitHttpsPath}`;
      candidate = `https://${trimmed}${cleanPath}`;
    }
    const resolved = resolveDohParam(candidate, savedCustomDohEndpoints);
    if (resolved.dohEndpoint) {
      return {
        dohEndpoint: resolved.dohEndpoint,
        dohDisplay: formatDohShortLabel(resolved.dohEndpoint),
        isUntrustedCustomDoh: resolved.isUntrustedCustomDoh,
      };
    }
  }

  // Also check if user already saved this host as a custom DoH endpoint even without `+https`
  if (savedCustomDohEndpoints.length > 0) {
    const savedCheck = resolveDohParam(trimmed, savedCustomDohEndpoints);
    if (savedCheck.dohEndpoint && !savedCheck.isUntrustedCustomDoh) {
      return {
        dohEndpoint: savedCheck.dohEndpoint,
        dohDisplay: formatDohShortLabel(savedCheck.dohEndpoint),
        isUntrustedCustomDoh: false,
      };
    }
  }

  // Plain UDP/TCP nameserver (e.g. `@a.iana-servers.net` or `@192.168.1.1`) — do not force HTTPS DoH
  return { dohEndpoint: null, dohDisplay: null, isUntrustedCustomDoh: false };
}

function normalizeTargetToken(rawTarget: string): string {
  const trimmed = rawTarget.trim();
  if (!trimmed || trimmed === '.') return '.';
  const email = parseEmailDaneInput(trimmed);
  if (email) return email.canonicalInput;
  const ip = parseReverseIpInput(trimmed);
  if (ip?.wasRawIpInput) return ip.ip;
  const fqdn = normalizeFqdn(trimmed);
  return fqdn === '.' ? '.' : displayFqdn(fqdn);
}

function tryParseCliCommand(
  rawInput: string,
  savedCustomDohEndpoints: string[]
): Extract<OmniboxParseResult, { kind: 'cli-command' }> | null {
  const collapsed = rawInput.replace(/\\\r?\n/g, ' ').trim();
  if (!collapsed || /[\r\n]/.test(collapsed)) return null;

  const cmdMatch = /^(?:[$#>]\s+)?(?:sudo\s+)?(?:\/\S+\/)?(dig|delv|kdig|nslookup|host)\s+(.+)$/i.exec(
    collapsed
  );
  if (!cmdMatch) return null;

  const tool = cmdMatch[1].toLowerCase() as 'dig' | 'delv' | 'kdig' | 'nslookup' | 'host';
  const tokens = tokenizeShellWords(cmdMatch[2]);
  if (tokens.length === 0) return null;

  let rawServer: string | null = null;
  let hasHttpsFlag = false;
  let explicitHttpsPath: string | null = null;
  let explicitTarget: string | null = null;
  let reverseIpTarget: string | null = null;
  const explicitTypes: string[] = [];
  const positionals: string[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (!tok) continue;

    // Stop at shell comment or pipe/redirection
    if (tok === '#' || tok === '|' || tok === ';' || tok === '&&' || tok.startsWith('>')) {
      break;
    }

    if (tok.startsWith('@') && tok.length > 1) {
      rawServer = tok.slice(1);
      continue;
    }

    if (tok.startsWith('+')) {
      const lowerPlus = tok.toLowerCase();
      if (lowerPlus === '+https' || lowerPlus === '+doh') {
        hasHttpsFlag = true;
      } else if (lowerPlus.startsWith('+https=')) {
        hasHttpsFlag = true;
        explicitHttpsPath = tok.slice('+https='.length) || null;
      }
      continue;
    }

    // `nslookup` style `-type=MX`, `-querytype=TXT`, `-q=CAA`
    const nslookupTypeMatch = /^-(?:type|querytype|query|q)=(.+)$/i.exec(tok);
    if (nslookupTypeMatch) {
      const candidateType = nslookupTypeMatch[1].toUpperCase();
      if (isRecognizedRrType(candidateType)) {
        explicitTypes.push(candidateType);
      }
      continue;
    }

    if (tok === '-x' && i + 1 < tokens.length) {
      reverseIpTarget = stripIpEndpointWrappers(tokens[++i]).ipCandidate;
      explicitTypes.push('PTR');
      continue;
    }
    if (tok.startsWith('-x') && tok.length > 2) {
      reverseIpTarget = stripIpEndpointWrappers(tok.slice(2)).ipCandidate;
      explicitTypes.push('PTR');
      continue;
    }

    if (tok === '-q' && i + 1 < tokens.length && tool !== 'nslookup') {
      explicitTarget = tokens[++i];
      continue;
    }
    if (tok.startsWith('-q') && tok.length > 2 && !tok.includes('=') && tool !== 'nslookup') {
      explicitTarget = tok.slice(2);
      continue;
    }

    if (tok === '-t' && i + 1 < tokens.length) {
      const nextVal = tokens[++i];
      // `delv -t <unix_epoch>` sets validation clock rather than query RR type
      if (tool === 'delv' && /^\d{8,}$/.test(nextVal)) {
        continue;
      }
      if (isRecognizedRrType(nextVal)) {
        explicitTypes.push(nextVal.toUpperCase());
      }
      continue;
    }
    if (tok.startsWith('-t') && tok.length > 2 && !tok.includes('=')) {
      const sub = tok.slice(2);
      if (!(tool === 'delv' && /^\d{8,}$/.test(sub)) && isRecognizedRrType(sub)) {
        explicitTypes.push(sub.toUpperCase());
      }
      continue;
    }

    if (tool === 'host' && tok === '-a') {
      explicitTypes.push('ANY');
      continue;
    }

    // Options taking a separate argument (`-p 5353`, `-b 0.0.0.0`, `-c IN`, `-k keyfile`, `-y hmac:...`, `delv -a anchor`)
    if (
      (tok === '-p' ||
        tok === '-b' ||
        tok === '-c' ||
        tok === '-k' ||
        tok === '-y' ||
        tok === '-f' ||
        (tool === 'delv' && tok === '-a') ||
        (tool === 'kdig' && tok === '-d')) &&
      i + 1 < tokens.length
    ) {
      i++;
      continue;
    }

    if (tok.startsWith('-')) {
      continue;
    }

    positionals.push(tok);
  }

  let chosenTarget: string | null = reverseIpTarget ?? explicitTarget;

  if (tool === 'nslookup' || tool === 'host') {
    // `nslookup [opts] <target> [server]` or `host [opts] <target> [server]`
    const nonClassPositionals = positionals.filter((p) => !DNS_CLASS_TOKENS.has(p.toUpperCase()));
    if (!chosenTarget && nonClassPositionals.length >= 1) {
      chosenTarget = nonClassPositionals[0];
      if (!rawServer && nonClassPositionals.length >= 2) {
        rawServer = nonClassPositionals[1];
      }
    }
  } else {
    // `dig` / `delv` / `kdig`: positionals can mix `<name>`, `[class]`, and `[type...]` in any order
    const nonTypeNonClass: string[] = [];
    const positionalTypes: string[] = [];
    for (const p of positionals) {
      const upper = p.toUpperCase();
      if (DNS_CLASS_TOKENS.has(upper) && !p.includes('.')) {
        continue;
      }
      if (isRecognizedRrType(upper) && !p.includes('.')) {
        positionalTypes.push(upper);
      } else {
        nonTypeNonClass.push(p);
      }
    }

    if (!chosenTarget) {
      if (nonTypeNonClass.length > 0) {
        chosenTarget = nonTypeNonClass[0];
      } else if (positionalTypes.length > 0) {
        // e.g. `dig md` or `dig key SOA` where first token is a TLD colliding with an RR mnemonic
        chosenTarget = positionalTypes.shift()!.toLowerCase();
      } else if (positionals.length > 0) {
        chosenTarget = positionals[0];
      }
    }
    explicitTypes.push(...positionalTypes);
  }

  const finalTarget = normalizeTargetToken(chosenTarget ?? '.');
  const dedupedTypes = Array.from(new Set(explicitTypes));
  const rrTypes = dedupedTypes.length > 0 ? dedupedTypes : null;

  const { dohEndpoint, dohDisplay, isUntrustedCustomDoh } = rawServer
    ? resolveCliServerToDoh(rawServer, hasHttpsFlag, explicitHttpsPath, savedCustomDohEndpoints)
    : { dohEndpoint: null, dohDisplay: null, isUntrustedCustomDoh: false };

  const parts: string[] = [finalTarget];
  if (rrTypes && rrTypes.length > 0) {
    parts.push(`[${rrTypes.join(', ')}]`);
  }
  if (dohDisplay) {
    parts.push(isUntrustedCustomDoh ? `via custom DoH ${dohDisplay} (confirm required)` : `via ${dohDisplay}`);
  }

  return {
    kind: 'cli-command',
    tool,
    target: finalTarget,
    rrTypes,
    dohEndpoint,
    dohDisplay,
    isUntrustedCustomDoh,
    summaryLabel: `Parsed ${tool} command → ${parts.join(' ')}`,
  };
}

/**
 * Parses and normalizes arbitrary pasted or submitted omnibox text:
 * - RFC 8484 `?dns=...` URLs, `xxd`/DigDeep hex dumps, and raw wire hex packets
 * - `dig`, `delv`, `kdig`, `nslookup`, and `host` CLI commands
 * - RFC 5322 email headers (`Name <user@domain>`), `<user@domain>`, and `mailto:` links
 * - URLs with schemes, credentials, ports, paths, queries, and fragments (`https://host:8443/path?x=1`)
 * - Bracketed IPv6 (`[2606:4700:4700::1111]:443`), IPv6 `%zone` IDs, and IPv4 `:port` literals
 */
export function parseOmniboxInput(
  rawInput: string,
  savedCustomDohEndpoints: string[] = []
): OmniboxParseResult {
  const rawTrimmed = rawInput.trim();
  if (!rawTrimmed) {
    return {
      kind: 'domain',
      target: '.',
      wasTransformed: false,
      summaryLabel: null,
    };
  }

  // 1. Check RFC 8484 DoH `?dns=` URLs, `xxd` hex dumps, and raw DNS wire hex payloads BEFORE URL stripping
  const wireMatch = tryDetectWirePacket(rawTrimmed);
  if (wireMatch) {
    return wireMatch;
  }

  const { value: unquoted, hadOuterQuotes } = stripMatchingOuterQuotes(rawTrimmed);

  // 2. Check `dig` / `delv` / `kdig` / `nslookup` / `host` CLI commands
  const cliMatch = tryParseCliCommand(unquoted, savedCustomDohEndpoints);
  if (cliMatch) {
    return cliMatch;
  }

  // 2b. Check multi-line RFC 5322 raw email headers / `.eml` messages BEFORE whitespace collapse
  const emailHeaderSummary = extractEmailHeaderQuickSummary(rawTrimmed);
  if (emailHeaderSummary) {
    const parts: string[] = [];
    if (emailHeaderSummary.dkimSignatureCount > 0) {
      parts.push(
        `${emailHeaderSummary.dkimSignatureCount} DKIM sig${emailHeaderSummary.dkimSignatureCount === 1 ? '' : 's'}`
      );
    }
    if (emailHeaderSummary.arcSetCount > 0) {
      parts.push(
        `${emailHeaderSummary.arcSetCount} ARC hop${emailHeaderSummary.arcSetCount === 1 ? '' : 's'}`
      );
    }
    const detailSuffix = parts.length > 0 ? ` (${parts.join(' · ')})` : '';
    return {
      kind: 'email-headers',
      rawHeaders: rawInput,
      target: emailHeaderSummary.targetDomain,
      dkimSelectors: emailHeaderSummary.dkimSelectors,
      dkimSignatureCount: emailHeaderSummary.dkimSignatureCount,
      arcSetCount: emailHeaderSummary.arcSetCount,
      fromAddress: emailHeaderSummary.fromAddress,
      summaryLabel: `Detected raw email headers → switched to Mail mode for ${emailHeaderSummary.targetDomain}${detailSuffix} & opened local DKIM/ARC/DMARC verifier`,
    };
  }

  // Collapse accidental multi-line paste whitespace for single-target inputs
  const singleLine = unquoted.replace(/\s+/g, ' ').trim();
  const hadWhitespaceCollapse = singleLine !== rawTrimmed && !hadOuterQuotes;

  // 3. Check RFC 5322 email (`Display Name <user@domain>`, `<user@domain>`, `mailto:...`, or `56hex._openpgpkey...`)
  const parsedEmail = parseEmailDaneInput(singleLine);
  if (parsedEmail) {
    const target = parsedEmail.canonicalInput;
    const wasTransformed = rawTrimmed !== target;
    return {
      kind: 'email',
      target,
      wasTransformed,
      summaryLabel: wasTransformed ? `Normalized email → ${target}` : null,
    };
  }

  // 4. Strip URL scheme, credentials, path, query, fragment, and `:port` if present
  let working = singleLine;
  let hadUrlWrapper = false;
  let hadPortWrapper = false;

  if (working.includes('://')) {
    hadUrlWrapper = true;
    try {
      const u = new URL(working);
      working = u.hostname.replace(/^\[|\]$/g, '');
    } catch {
      working = working
        .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
        .replace(/^[^@/?#]+@/, '')
        .split(/[/?#]/)[0];
    }
  } else if (!working.includes('\\')) {
    if (working.startsWith('//') && working.length > 2) {
      hadUrlWrapper = true;
      working = working.slice(2);
    }
    if (/[/?#]/.test(working)) {
      hadUrlWrapper = true;
      working = working.split(/[/?#]/)[0];
    }
    // Strip URL userinfo (`user:pass@host`) if host contains no spaces
    if (working.includes('@')) {
      const lastAt = working.lastIndexOf('@');
      const afterAt = working.slice(lastAt + 1);
      if (afterAt && !/\s/.test(afterAt)) {
        hadUrlWrapper = true;
        working = afterAt;
      }
    }
  }

  // 5. Check IPv4 / IPv6 (including `[ipv6]:port`, `[ipv6]`, `ipv6%zone`, `ipv4:port`)
  const { ipCandidate, wasWrapped: hadIpWrapper } = stripIpEndpointWrappers(working);
  const parsedIp = parseReverseIpInput(ipCandidate);
  if (parsedIp?.wasRawIpInput) {
    const wasTransformed = hadUrlWrapper || hadIpWrapper || hadOuterQuotes || hadWhitespaceCollapse;
    const target = wasTransformed ? parsedIp.ip : working;
    return {
      kind: 'ip',
      target: parsedIp.ip,
      family: parsedIp.family,
      wasTransformed: wasTransformed || target !== rawInput,
      summaryLabel: wasTransformed
        ? hadUrlWrapper
          ? `Normalized URL → ${parsedIp.ip}`
          : `Normalized IPv${parsedIp.family} → ${parsedIp.ip}`
        : null,
    };
  }

  // 6. Strip `host:port` on domain names (single colon + 1..5 digit port)
  if (!working.includes('\\')) {
    const hostPortMatch = /^([^:]+):(\d{1,5})$/.exec(working);
    if (hostPortMatch) {
      const port = Number.parseInt(hostPortMatch[2], 10);
      if (!Number.isNaN(port) && port >= 0 && port <= 65535) {
        hadPortWrapper = true;
        working = hostPortMatch[1];
      }
    }
  }

  if (working === '.') {
    const wasTransformed = rawInput !== '.';
    return {
      kind: 'domain',
      target: '.',
      wasTransformed,
      summaryLabel: null,
    };
  }

  const hadExplicitTrailingDot = working.endsWith('.') && !hadUrlWrapper && !hadPortWrapper;
  const normFqdn = normalizeFqdn(working);
  const cleanDomain = normFqdn === '.' ? '.' : displayFqdn(normFqdn);
  const target =
    hadExplicitTrailingDot && cleanDomain !== '.' ? `${cleanDomain}.` : cleanDomain;

  const wasTransformed =
    hadUrlWrapper ||
    hadPortWrapper ||
    hadOuterQuotes ||
    hadWhitespaceCollapse ||
    rawInput !== rawTrimmed;

  const summaryLabel = hadUrlWrapper
    ? `Normalized URL → ${target}`
    : hadPortWrapper
      ? `Stripped port → ${target}`
      : null;

  return {
    kind: 'domain',
    target,
    wasTransformed,
    summaryLabel,
  };
}

/**
 * Builds a minimal offline `AnalysisSnapshot` shell around a decoded wire packet so the
 * `ResponsesPanel` Offline Wire Dissector can render even before any live DoH trace has run.
 */
export function buildOfflineWireSnapshot(
  wireResult: Extract<OmniboxParseResult, { kind: 'wire-packet' }>,
  dohEndpoint: string
): AnalysisSnapshot {
  const now = Date.now();
  const syntheticLog = buildSyntheticLogFromDissected(wireResult.dissected);
  const targetFqdn = normalizeFqdn(wireResult.qname);
  const displayDomain = targetFqdn === '.' ? '.' : displayFqdn(targetFqdn);
  return {
    id: `offline-wire-${now}`,
    version: SNAPSHOT_ENGINE_VERSION,
    mode: 'dnssec',
    targetName: targetFqdn,
    displayDomain,
    queryTypes: [wireResult.qtypeName],
    dohEndpoint,
    capturedAt: now,
    validatedAt: now,
    durationMs: 0,
    overallStatus: 'indeterminate',
    overallSummary: `Offline Wire Packet Dissector — decoded ${wireResult.wireSize}-byte DNS ${wireResult.qr ? 'response' : 'query'} locally.`,
    zones: [],
    cnameEdges: [],
    findings: [],
    queries: syntheticLog ? [syntheticLog] : [],
    trustAnchorsUsed: IANA_ROOT_TRUST_ANCHORS.filter((ta) => ta.enabled),
  };
}

/**
 * Deduplicates and ranks saved `localStorage` snapshots for instant omnibox autocomplete.
 */
export function filterHistorySuggestions(
  snapshots: readonly AnalysisSnapshot[],
  rawQuery: string,
  limit = 6
): AnalysisSnapshot[] {
  if (snapshots.length === 0 || limit <= 0) return [];

  // Deduplicate by `(primaryTarget, mode, queryTypes, dohEndpoint)`, keeping newest capture
  const dedupedMap = new Map<string, AnalysisSnapshot>();
  for (const snap of snapshots) {
    const primaryTarget = (snap.queriedEmail ?? snap.queriedIp ?? snap.displayDomain).toLowerCase();
    const mode = snap.mode ?? 'dnssec';
    const typesKey = mode === 'dnssec' ? snap.queryTypes.join(',') : mode;
    const key = `${primaryTarget}|${mode}|${typesKey}|${snap.dohEndpoint}`;
    const existing = dedupedMap.get(key);
    if (!existing || snap.capturedAt > existing.capturedAt) {
      dedupedMap.set(key, snap);
    }
  }

  const unique = Array.from(dedupedMap.values());
  const q = rawQuery.trim().toLowerCase().replace(/\.$/, '');

  if (!q) {
    return unique
      .sort((a, b) => {
        if (Boolean(a.pinned) !== Boolean(b.pinned)) return a.pinned ? -1 : 1;
        return b.capturedAt - a.capturedAt;
      })
      .slice(0, limit);
  }

  const tokens = q.split(/\s+/).filter(Boolean);
  const scored: Array<{ snap: AnalysisSnapshot; score: number }> = [];

  for (const snap of unique) {
    const primary = (snap.queriedEmail ?? snap.queriedIp ?? snap.displayDomain).toLowerCase();
    const domain = snap.displayDomain.toLowerCase();
    const mode = (snap.mode ?? 'dnssec').toLowerCase();
    const types = snap.queryTypes.join(' ').toLowerCase();
    const status =
      snap.overallStatus === 'policy-error'
        ? 'policy-error policy error'
        : snap.overallStatus.toLowerCase();
    const resolver = formatDohShortLabel(snap.dohEndpoint).toLowerCase();
    const haystack = `${primary} ${domain} ${mode} ${types} ${status} ${resolver} ${snap.note?.toLowerCase() ?? ''}`;

    let score = 0;
    if (primary === q || domain === q) {
      score = 100;
    } else if (primary.startsWith(q) || domain.startsWith(q)) {
      score = 80;
    } else if (
      primary.includes(`.${q}`) ||
      primary.includes(`@${q}`) ||
      domain.includes(`.${q}`)
    ) {
      score = 65;
    } else if (primary.includes(q) || domain.includes(q)) {
      score = 50;
    } else if (tokens.every((tok) => haystack.includes(tok))) {
      score = 35;
    }

    if (score > 0) {
      if (snap.pinned) score += 3;
      scored.push({ snap, score });
    }
  }

  return scored
    .sort((a, b) => b.score - a.score || b.snap.capturedAt - a.snap.capturedAt)
    .slice(0, limit)
    .map((entry) => entry.snap);
}

export function filterExampleTraces<
  T extends {
    domain: string;
    mode?: AnalysisMode;
    types: string[];
    badge: string;
    description: string;
  },
>(examples: readonly T[], rawQuery: string, limit = examples.length): T[] {
  const q = rawQuery.trim().toLowerCase().replace(/\.$/, '');
  if (!q) return examples.slice(0, limit);
  const tokens = q.split(/\s+/).filter(Boolean);
  return examples
    .filter((ex) => {
      const hay = `${ex.domain} ${ex.mode ?? 'dnssec'} ${ex.types.join(' ')} ${ex.badge} ${ex.description}`.toLowerCase();
      return tokens.every((tok) => hay.includes(tok));
    })
    .slice(0, limit);
}

/**
 * Formats a snapshot capture timestamp as a compact human-readable relative age (`just now`, `4m ago`, `2h ago`, `3d ago`).
 */
export function formatRelativeTime(capturedAtMs: number, nowMs = Date.now()): string {
  const diffSec = Math.max(0, Math.floor((nowMs - capturedAtMs) / 1000));
  if (diffSec < 10) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDays = Math.floor(diffHr / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return new Date(capturedAtMs).toISOString().slice(0, 10);
}
