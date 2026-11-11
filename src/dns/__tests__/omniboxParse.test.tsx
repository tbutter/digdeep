import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ResponsesPanel } from '../../components/ResponsesPanel';
import { DEFAULT_DOH_ENDPOINT } from '../constants';
import { generateCliReproducerCommands } from '../digFormat';
import { parseEmailDaneInput } from '../emailDane';
import { bytesToBase64Url, bytesToHex, normalizeFqdn } from '../encoding';
import { parseReverseIpInput } from '../ipUtils';
import {
  buildOfflineWireSnapshot,
  filterExampleTraces,
  filterHistorySuggestions,
  formatRelativeTime,
  parseOmniboxInput,
} from '../omniboxParse';
import type { AnalysisSnapshot } from '../types';
import { buildDnsQuery } from '../wire';

function makeMockSnapshot(overrides: Partial<AnalysisSnapshot> & { id: string }): AnalysisSnapshot {
  return {
    version: 5,
    mode: 'dnssec',
    targetName: 'example.com.',
    displayDomain: 'example.com',
    queryTypes: ['A', 'AAAA'],
    dohEndpoint: DEFAULT_DOH_ENDPOINT,
    capturedAt: 1_700_000_000_000,
    validatedAt: 1_700_000_000_000,
    durationMs: 120,
    overallStatus: 'secure',
    overallSummary: 'Mock snapshot',
    zones: [],
    cnameEdges: [],
    findings: [],
    queries: [],
    trustAnchorsUsed: [],
    ...overrides,
  };
}

describe('Smart-Paste Omnibox Normalization, CLI Parser & Offline Wire Detection', () => {
  it('strips URL schemes, credentials, ports, paths, queries, and fragments for domains', () => {
    const httpsFull = parseOmniboxInput('https://Sub.Example.COM:8443/path/to/page?x=1&y=2#top');
    expect(httpsFull).toEqual({
      kind: 'domain',
      target: 'sub.example.com',
      wasTransformed: true,
      summaryLabel: 'Normalized URL → sub.example.com',
    });

    const withAuth = parseOmniboxInput('http://admin:s3cr3t@api.example.org:8080/v1/health');
    expect(withAuth.kind).toBe('domain');
    if (withAuth.kind === 'domain') {
      expect(withAuth.target).toBe('api.example.org');
      expect(withAuth.wasTransformed).toBe(true);
    }

    const schemelessPortPath = parseOmniboxInput('sub.example.com:8443/api?debug=1');
    expect(schemelessPortPath).toEqual({
      kind: 'domain',
      target: 'sub.example.com',
      wasTransformed: true,
      summaryLabel: 'Normalized URL → sub.example.com',
    });

    const hostPortOnly = parseOmniboxInput('sub.example.com:8443');
    expect(hostPortOnly).toEqual({
      kind: 'domain',
      target: 'sub.example.com',
      wasTransformed: true,
      summaryLabel: 'Stripped port → sub.example.com',
    });

    const protocolRelative = parseOmniboxInput('//cdn.example.org/assets/main.js');
    expect(protocolRelative.kind).toBe('domain');
    if (protocolRelative.kind === 'domain') {
      expect(protocolRelative.target).toBe('cdn.example.org');
      expect(protocolRelative.wasTransformed).toBe(true);
    }

    expect(normalizeFqdn('sub.example.com:8443/api')).toBe('sub.example.com.');

    // Plain domains and root '.' remain untransformed
    const plain = parseOmniboxInput('cloudflare.com');
    expect(plain).toEqual({
      kind: 'domain',
      target: 'cloudflare.com',
      wasTransformed: false,
      summaryLabel: null,
    });

    const rootDot = parseOmniboxInput('.');
    expect(rootDot).toEqual({
      kind: 'domain',
      target: '.',
      wasTransformed: false,
      summaryLabel: null,
    });
  });

  it('normalizes bracketed IPv6 + port, IPv6 URLs, IPv6 zone IDs, and IPv4 + port literals', () => {
    const bracketPort = parseOmniboxInput('[2606:4700:4700::1111]:443');
    expect(bracketPort).toEqual({
      kind: 'ip',
      target: '2606:4700:4700::1111',
      family: 6,
      wasTransformed: true,
      summaryLabel: 'Normalized IPv6 → 2606:4700:4700::1111',
    });

    const ipv6Url = parseOmniboxInput('http://[2606:4700:4700::1111]:8080/dns-query');
    expect(ipv6Url).toEqual({
      kind: 'ip',
      target: '2606:4700:4700::1111',
      family: 6,
      wasTransformed: true,
      summaryLabel: 'Normalized URL → 2606:4700:4700::1111',
    });

    const ipv6Zone = parseOmniboxInput('fe80::1%eth0');
    expect(ipv6Zone.kind).toBe('ip');
    if (ipv6Zone.kind === 'ip') {
      expect(ipv6Zone.target).toBe('fe80::1');
      expect(ipv6Zone.family).toBe(6);
      expect(ipv6Zone.wasTransformed).toBe(true);
    }

    const ipv4Port = parseOmniboxInput('1.1.1.1:853');
    expect(ipv4Port).toEqual({
      kind: 'ip',
      target: '1.1.1.1',
      family: 4,
      wasTransformed: true,
      summaryLabel: 'Normalized IPv4 → 1.1.1.1',
    });

    // Direct parseReverseIpInput also accepts bracketed IPv6 + port and IPv4 + port
    expect(parseReverseIpInput('[2606:4700:4700::1111]:443')?.ip).toBe('2606:4700:4700::1111');
    expect(parseReverseIpInput('1.1.1.1:853')?.ip).toBe('1.1.1.1');

    // Bare canonical IPv6 is NOT flagged as transformed and NOT misclassified as hex wire data
    const bareV6 = parseOmniboxInput('2606:4700:4700::1111');
    expect(bareV6).toEqual({
      kind: 'ip',
      target: '2606:4700:4700::1111',
      family: 6,
      wasTransformed: false,
      summaryLabel: null,
    });
  });

  it('normalizes RFC 5322 email headers, angle brackets, and mailto: links while preserving quoted local-parts', () => {
    const rfc5322 = parseOmniboxInput('Paul Wouters <paul@nohats.ca>');
    expect(rfc5322).toEqual({
      kind: 'email',
      target: 'paul@nohats.ca',
      wasTransformed: true,
      summaryLabel: 'Normalized email → paul@nohats.ca',
    });

    const fromHeader = parseOmniboxInput('From: "IETF Secretariat" <iesg@ietf.org>');
    expect(fromHeader).toEqual({
      kind: 'email',
      target: 'iesg@ietf.org',
      wasTransformed: true,
      summaryLabel: 'Normalized email → iesg@ietf.org',
    });

    const mailtoLink = parseOmniboxInput('mailto:paul@nohats.ca?subject=DANE%20Test&body=Hi');
    expect(mailtoLink).toEqual({
      kind: 'email',
      target: 'paul@nohats.ca',
      wasTransformed: true,
      summaryLabel: 'Normalized email → paul@nohats.ca',
    });

    // Quoted RFC 7929 local-part is preserved accurately
    const quotedLocal = parseEmailDaneInput('"john.doe"@example.com');
    expect(quotedLocal?.localPart).toBe('john.doe');

    // Pre-hashed 56-hex OPENPGPKEY owner name is NOT misclassified as raw wire hex
    const openpgpOwner =
      '03575114f1aa3d04f8fb2a2c44f66094d1b006a99402595163626a58._openpgpkey.nohats.ca';
    const ownerParsed = parseOmniboxInput(openpgpOwner);
    expect(ownerParsed.kind).toBe('email');
    if (ownerParsed.kind === 'email') {
      expect(ownerParsed.target).toBe(openpgpOwner);
    }
  });

  it('parses dig, delv, kdig, nslookup, and host CLI commands and enforces untrusted custom DoH confirmation', () => {
    const digCmd = parseOmniboxInput('$ dig @8.8.8.8 cloudflare.com CAA +dnssec +multi');
    expect(digCmd.kind).toBe('cli-command');
    if (digCmd.kind === 'cli-command') {
      expect(digCmd.tool).toBe('dig');
      expect(digCmd.target).toBe('cloudflare.com');
      expect(digCmd.rrTypes).toEqual(['CAA']);
      expect(digCmd.dohEndpoint).toBe('https://8.8.8.8/dns-query');
      expect(digCmd.isUntrustedCustomDoh).toBe(false);
    }

    const digReverse = parseOmniboxInput('sudo dig -x 1.1.1.1 @9.9.9.9 +short');
    expect(digReverse.kind).toBe('cli-command');
    if (digReverse.kind === 'cli-command') {
      expect(digReverse.target).toBe('1.1.1.1');
      expect(digReverse.rrTypes).toEqual(['PTR']);
      expect(digReverse.dohEndpoint).toBe('https://9.9.9.9/dns-query');
    }

    // Round-trip DigDeep's own `generateCliReproducerCommands` (including `delv -t <epoch>`)
    const repro = generateCliReproducerCommands({
      qname: 'www.iana.org.',
      qtypeName: 'AAAA',
      dohEndpoint: 'https://9.9.9.9/dns-query',
      cd: true,
      validatedAt: 1_700_005_000_000,
      capturedAt: 1_700_000_000_000,
    });
    for (const cliText of [repro.dig, repro.delv, repro.kdig]) {
      const parsedRepro = parseOmniboxInput(cliText);
      expect(parsedRepro.kind).toBe('cli-command');
      if (parsedRepro.kind === 'cli-command') {
        expect(parsedRepro.target).toBe('www.iana.org');
        expect(parsedRepro.rrTypes).toEqual(['AAAA']);
        expect(parsedRepro.dohEndpoint).toBe('https://9.9.9.9/dns-query');
        expect(parsedRepro.isUntrustedCustomDoh).toBe(false);
      }
    }

    const nslookupCmd = parseOmniboxInput('nslookup -type=MX ietf.org 8.8.4.4');
    expect(nslookupCmd.kind).toBe('cli-command');
    if (nslookupCmd.kind === 'cli-command') {
      expect(nslookupCmd.target).toBe('ietf.org');
      expect(nslookupCmd.rrTypes).toEqual(['MX']);
      expect(nslookupCmd.dohEndpoint).toBe('https://8.8.8.8/dns-query');
    }

    const hostCmd = parseOmniboxInput('host -t TXT example.org 1.1.1.1');
    expect(hostCmd.kind).toBe('cli-command');
    if (hostCmd.kind === 'cli-command') {
      expect(hostCmd.target).toBe('example.org');
      expect(hostCmd.rrTypes).toEqual(['TXT']);
      expect(hostCmd.dohEndpoint).toBe('https://1.1.1.1/dns-query');
    }

    // Authoritative UDP server `@a.iana-servers.net` is safely ignored as a DoH override
    const authUdp = parseOmniboxInput('dig @a.iana-servers.net iana.org NS');
    expect(authUdp.kind).toBe('cli-command');
    if (authUdp.kind === 'cli-command') {
      expect(authUdp.target).toBe('iana.org');
      expect(authUdp.rrTypes).toEqual(['NS']);
      expect(authUdp.dohEndpoint).toBeNull();
      expect(authUdp.isUntrustedCustomDoh).toBe(false);
    }

    // Unknown third-party HTTPS DoH server requires explicit user confirmation unless saved
    const untrustedCli = parseOmniboxInput(
      'dig @https://doh.untrusted-resolver.example/dns-query example.com A'
    );
    expect(untrustedCli.kind).toBe('cli-command');
    if (untrustedCli.kind === 'cli-command') {
      expect(untrustedCli.dohEndpoint).toBe('https://doh.untrusted-resolver.example/dns-query');
      expect(untrustedCli.isUntrustedCustomDoh).toBe(true);
    }

    const trustedSavedCli = parseOmniboxInput(
      'dig @https://doh.untrusted-resolver.example/dns-query example.com A',
      ['https://doh.untrusted-resolver.example/dns-query']
    );
    expect(trustedSavedCli.kind).toBe('cli-command');
    if (trustedSavedCli.kind === 'cli-command') {
      expect(trustedSavedCli.dohEndpoint).toBe('https://doh.untrusted-resolver.example/dns-query');
      expect(trustedSavedCli.isUntrustedCustomDoh).toBe(false);
    }
  });

  it('detects RFC 8484 ?dns= URLs and wire hex dumps and renders them in Offline Wire Dissector without false positives', () => {
    const wireBytes = buildDnsQuery('example.com.', 1, { cd: true, doBit: true, id: 0x1a2b });
    const b64Url = bytesToBase64Url(wireBytes);

    const dohUrlParsed = parseOmniboxInput(`https://1.1.1.1/dns-query?dns=${b64Url}`);
    expect(dohUrlParsed.kind).toBe('wire-packet');
    if (dohUrlParsed.kind === 'wire-packet') {
      expect(dohUrlParsed.detectedFormat).toBe('doh-url');
      expect(dohUrlParsed.qname).toBe('example.com');
      expect(dohUrlParsed.qtypeName).toBe('A');
      expect(dohUrlParsed.qr).toBe(false);

      const offlineSnap = buildOfflineWireSnapshot(dohUrlParsed, DEFAULT_DOH_ENDPOINT);
      const html = renderToStaticMarkup(
        <ResponsesPanel
          snapshot={{ ...offlineSnap, queries: [] }}
          externalCustomWire={{ payload: dohUrlParsed.wireInput, seq: 1 }}
        />
      );
      expect(html).toContain('Offline Raw DNS Wire Packet Decoder');
      expect(html).toContain('RFC 8484 DoH ?dns= URL');
      expect(html).toContain('example.com');
    }

    const rawHex = bytesToHex(wireBytes).toLowerCase();
    const hexParsed = parseOmniboxInput(rawHex);
    expect(hexParsed.kind).toBe('wire-packet');
    if (hexParsed.kind === 'wire-packet') {
      expect(hexParsed.detectedFormat).toBe('hex');
      expect(hexParsed.qname).toBe('example.com');
    }

    // Random 64-hex SHA-256 digest does NOT parse as a valid DNS wire packet -> never misclassified
    const sha256Empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(parseOmniboxInput(sha256Empty).kind).toBe('domain');
  });

  it('deduplicates, ranks, and formats local-history autocomplete suggestions', () => {
    const snaps: AnalysisSnapshot[] = [
      makeMockSnapshot({
        id: 'old-iana',
        targetName: 'www.iana.org.',
        displayDomain: 'www.iana.org',
        capturedAt: 1_700_000_000_000,
      }),
      makeMockSnapshot({
        id: 'new-iana',
        targetName: 'www.iana.org.',
        displayDomain: 'www.iana.org',
        capturedAt: 1_700_000_600_000,
      }),
      makeMockSnapshot({
        id: 'ietf-mail',
        mode: 'mail',
        targetName: 'ietf.org.',
        displayDomain: 'ietf.org',
        queryTypes: ['MX', 'TXT'],
        capturedAt: 1_700_000_300_000,
      }),
      makeMockSnapshot({
        id: 'quad9-rdns',
        targetName: '9.9.9.9.in-addr.arpa.',
        displayDomain: '9.9.9.9.in-addr.arpa',
        queriedIp: '9.9.9.9',
        queryTypes: ['PTR'],
        capturedAt: 1_700_000_500_000,
        pinned: true,
      }),
    ];

    // Empty query deduplicates `www.iana.org` and puts pinned snapshot first
    const recent = filterHistorySuggestions(snaps, '');
    expect(recent.map((s) => s.id)).toEqual(['quad9-rdns', 'new-iana', 'ietf-mail']);

    // Label match finds `www.iana.org` from `iana`
    const ianaMatches = filterHistorySuggestions(snaps, 'iana');
    expect(ianaMatches.map((s) => s.id)).toEqual(['new-iana']);

    // Multi-token mode search finds `ietf.org` Mail snapshot
    const mailMatches = filterHistorySuggestions(snaps, 'ietf mail');
    expect(mailMatches.map((s) => s.id)).toEqual(['ietf-mail']);

    // Queried IP matches `9.9`
    const ipMatches = filterHistorySuggestions(snaps, '9.9');
    expect(ipMatches.map((s) => s.id)).toEqual(['quad9-rdns']);

    // Example trace filter
    const exFiltered = filterExampleTraces(
      [
        { domain: 'ietf.org', mode: 'mail', types: ['MX'], badge: 'Mail', description: 'SMTP DANE' },
        { domain: 'cloudflare.com', mode: 'web', types: ['HTTPS'], badge: 'Web', description: 'ECH' },
      ],
      'ech'
    );
    expect(exFiltered).toHaveLength(1);
    expect(exFiltered[0].domain).toBe('cloudflare.com');

    // Relative time formatting
    const baseNow = 1_700_001_000_000;
    expect(formatRelativeTime(baseNow - 4_000, baseNow)).toBe('just now');
    expect(formatRelativeTime(baseNow - 45_000, baseNow)).toBe('45s ago');
    expect(formatRelativeTime(baseNow - 5 * 60_000, baseNow)).toBe('5m ago');
    expect(formatRelativeTime(baseNow - 3 * 3_600_000, baseNow)).toBe('3h ago');
    expect(formatRelativeTime(baseNow - 4 * 86_400_000, baseNow)).toBe('4d ago');
  });
});
