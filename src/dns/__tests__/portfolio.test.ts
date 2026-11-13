import { describe, expect, it } from 'vitest';
import { importSnapshotsFromJson } from '../../storage/historyStore';
import { reverifySnapshot } from '../analyzer';
import { RR_TYPES } from '../constants';
import { DohSession } from '../doh';
import {
  computePortfolioAsnConcentration,
  createPortfolioBatchRunner,
  detectMultiDomainPaste,
  extractPortfolioPosture,
  formatPortfolioCsv,
  formatPortfolioJsonBundle,
  formatPortfolioMarkdown,
  MAX_PORTFOLIO_DOMAINS,
  parsePortfolioDomainList,
  sortPortfolioRows,
  type PortfolioDomainRow,
} from '../portfolioAnalyzer';
import type { AnalysisSnapshot, DohQueryLog } from '../types';
import { buildDnsQuery } from '../wire';

// Minimal localStorage shim for JSON bundle round-trip import test
const memStorage = new Map<string, string>();
if (typeof globalThis.localStorage === 'undefined') {
  Object.defineProperty(globalThis, 'localStorage', {
    value: {
      get length() {
        return memStorage.size;
      },
      clear: () => memStorage.clear(),
      getItem: (k: string) => memStorage.get(k) ?? null,
      key: (i: number) => Array.from(memStorage.keys())[i] ?? null,
      removeItem: (k: string) => {
        memStorage.delete(k);
      },
      setItem: (k: string, v: string) => {
        memStorage.set(k, v);
      },
    },
    configurable: true,
  });
}

function makeSyntheticPortfolioSnapshot(
  domain: string,
  overrides: {
    dnssecStatus?: AnalysisSnapshot['overallStatus'];
    algorithm?: number;
    remainingSec?: number | null;
    asns?: Array<{ asn: number; asName?: string }>;
    dmarcPolicy?: 'reject' | 'quarantine' | 'none' | 'missing';
    spfVerdict?: 'strict-fail' | 'soft-fail' | 'pass-all' | 'none';
    daneStatus?: 'all-valid' | 'not-deployed' | 'bogus';
    echEnabled?: boolean;
    caaEnforced?: boolean;
    errorCount?: number;
  } = {}
): AnalysisSnapshot {
  const fqdn = `${domain.toLowerCase()}.`;
  const dnssecStatus = overrides.dnssecStatus ?? 'secure';
  const zoneStatus = dnssecStatus === 'policy-error' ? 'secure' : dnssecStatus;
  const asns = overrides.asns ?? [{ asn: 13335, asName: 'CLOUDFLARENET' }];
  const remainingSec =
    overrides.remainingSec !== undefined
      ? overrides.remainingSec
      : dnssecStatus === 'insecure'
        ? null
        : 86400 * 14;
  const dmarcPolicy = overrides.dmarcPolicy ?? 'reject';
  const spfVerdict = overrides.spfVerdict ?? 'strict-fail';
  const daneStatus = overrides.daneStatus ?? 'not-deployed';
  const echEnabled = overrides.echEnabled ?? false;
  const caaEnforced = overrides.caaEnforced ?? true;
  const errorCount = overrides.errorCount ?? 0;

  return {
    id: `snap-synth-${domain}`,
    version: 3,
    mode: 'dnssec',
    targetName: fqdn,
    displayDomain: domain.toLowerCase(),
    queryTypes: ['A', 'AAAA', 'MX', 'TXT', 'HTTPS', 'CAA'],
    dohEndpoint: 'https://cloudflare-dns.com/dns-query',
    capturedAt: 1_780_000_000_000,
    validatedAt: 1_780_000_000_000,
    durationMs: 250,
    overallStatus: dnssecStatus,
    overallSummary: `Synthetic snapshot for ${domain}`,
    zones: [
      {
        zoneName: fqdn,
        parentZone: 'com.',
        depth: 2,
        status: zoneStatus,
        statusReason: 'Synthetic',
        nsecMode: dnssecStatus === 'insecure' ? 'UNSIGNED' : 'NSEC',
        dnskeys:
          dnssecStatus === 'insecure'
            ? []
            : [
                {
                  id: `dnskey-${fqdn}-12345`,
                  zone: fqdn,
                  keyTag: 12345,
                  flags: 257,
                  algorithm: overrides.algorithm ?? 13,
                  protocol: 3,
                  keySizeInfo: '256-bit ECDSA',
                  publicKeyBase64: 'AA==',
                  isSep: true,
                  isZoneKey: true,
                  isRevoked: false,
                  role: 'ksk',
                  signsTypes: ['DNSKEY', 'A'],
                  matchedByParentDs: true,
                  status: 'secure',
                  statusReason: 'OK',
                },
              ],
        dsVerifications: [],
        trustAnchorMatches: [],
        rrsets:
          remainingSec === null
            ? []
            : [
                {
                  id: `rrset-${fqdn}-A`,
                  zone: fqdn,
                  name: fqdn,
                  type: RR_TYPES.A,
                  typeName: 'A',
                  ttl: 300,
                  section: 'answer',
                  records: [],
                  rrsigs: [
                    {
                      id: `rrsig-${fqdn}-A-12345`,
                      rrsig: {
                        kind: 'RRSIG',
                        typeCovered: RR_TYPES.A,
                        typeCoveredName: 'A',
                        algorithm: overrides.algorithm ?? 13,
                        labels: 2,
                        originalTtl: 300,
                        expiration: 1_780_000_000 + remainingSec,
                        inception: 1_779_990_000,
                        keyTag: 12345,
                        signerName: fqdn,
                        signatureBase64: 'AA==',
                        signedHeaderBase64: 'AA==',
                      },
                      rrsigTtl: 300,
                      signerKeyTag: 12345,
                      signerFound: true,
                      cryptoValid: true,
                      timeValid: remainingSec > 0,
                      notYetValid: false,
                      expired: remainingSec <= 0,
                      remainingSeconds: remainingSec,
                      wildcardSynthesized: false,
                      ttlMismatch: false,
                      status: remainingSec > 0 ? 'secure' : 'bogus',
                      reason: 'Synthetic RRSIG',
                    },
                  ],
                  isQueryTarget: true,
                  status: remainingSec > 0 ? 'secure' : 'bogus',
                  statusReason: 'Synthetic RRset',
                },
              ],
        negativeNodes: [],
        nameservers: [
          {
            hostname: `ns1.${domain}.`,
            ipv4: ['198.51.100.1'],
            ipv6: ['2001:db8::1'],
          },
          {
            hostname: `ns2.${domain}.`,
            ipv4: ['198.51.100.2'],
            ipv6: ['2001:db8::2'],
          },
        ],
        nsDiversity: {
          nameserverCount: 2,
          probedCount: 2,
          uniqueAsns: asns,
          uniquePrefixes: ['198.51.100.0/24'],
          hasIpv4: true,
          hasIpv6: true,
          ipv4NsCount: 2,
          ipv6NsCount: 2,
          dualStackNsCount: 2,
          dualStackReady: true,
          danglingHosts: [],
          singleAsn: asns.length === 1,
          singlePrefix: true,
          status: asns.length === 1 ? 'single-asn' : 'diverse',
          summary: 'Synthetic NS diversity',
        },
      },
    ],
    cnameEdges: [],
    findings: Array.from({ length: errorCount }, (_, idx) => ({
      id: `err-${domain}-${idx}`,
      severity: 'error' as const,
      code: 'SYNTH_ERR',
      title: 'Synthetic error',
      detail: 'Synthetic error detail',
    })),
    queries: [],
    trustAnchorsUsed: [],
    mailAnalysis: {
      mxStatus: 'valid',
      mxDnssecStatus: 'secure',
      mxHosts: [
        {
          preference: 10,
          exchange: `mail.${domain}.`,
          displayExchange: `mail.${domain}`,
          isNullMx: false,
          isIpLiteral: false,
          cnameChain: [],
          addresses: [{ ip: '198.51.100.10', family: 4, isPublic: true }],
          ipv4Status: 'secure',
          ipv6Status: 'insecure',
          addressRrsetIds: [],
          dane: {
            qname: `_25._tcp.mail.${domain}.`,
            resolvedOwner: `_25._tcp.mail.${domain}.`,
            cnameChain: [],
            status: daneStatus === 'all-valid' ? 'dane-valid' : 'no-tlsa-unsigned',
            dnssecStatus: daneStatus === 'all-valid' ? 'secure' : 'insecure',
            records: [],
            rolloverReady: false,
            summary: 'Synthetic DANE',
          },
        },
      ],
      daneStatus,
      daneSummary: 'Synthetic DANE',
      spf: {
        present: spfVerdict !== 'none',
        verdict: spfVerdict,
        dnsLookupCount: 3,
        dnsLookupLimit: 10,
        voidLookupCount: 0,
        voidLookupLimit: 2,
        dnssecStatus: 'secure',
        allSpfRecords: spfVerdict === 'none' ? [] : ['v=spf1 -all'],
        legacySpfRecords: [],
        effectiveAllQualifier:
          spfVerdict === 'strict-fail'
            ? '-'
            : spfVerdict === 'soft-fail'
              ? '~'
              : spfVerdict === 'pass-all'
                ? '+'
                : undefined,
        rootNode: {
          domain: fqdn,
          displayDomain: domain,
          via: 'root',
          depth: 0,
          spfRecords: [],
          terms: [],
        },
        summary: 'Synthetic SPF',
      },
      dmarc: {
        present: dmarcPolicy !== 'missing',
        verdict:
          dmarcPolicy === 'reject'
            ? 'reject'
            : dmarcPolicy === 'quarantine'
              ? 'quarantine'
              : dmarcPolicy === 'none'
                ? 'monitor-only'
                : 'none',
        queriedOwner: `_dmarc.${fqdn}`,
        effectiveOwner: `_dmarc.${fqdn}`,
        cnameChain: [],
        usedOrgFallback: false,
        dnssecStatus: 'secure',
        allDmarcRecords: [],
        policy: dmarcPolicy === 'missing' ? undefined : dmarcPolicy,
        adkim: 'r',
        aspf: 'r',
        pct: 100,
        rua: [],
        ruf: [],
        fo: '0',
        ri: 86400,
        tags: [],
        issues: [],
        summary: 'Synthetic DMARC',
      },
      dkim: {
        status: 'not-found',
        probedSelectors: [],
        customSelectors: [],
        selectors: [],
        summary: 'Skipped in batch',
      },
      mtaSts: {
        present: false,
        status: 'not-deployed',
        qname: `_mta-sts.${fqdn}`,
        resolvedOwner: `_mta-sts.${fqdn}`,
        cnameChain: [],
        dnssecStatus: 'insecure',
        allStsRecords: [],
        extensions: [],
        policyUrl: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
        issues: [],
        summary: 'No MTA-STS',
      },
      tlsRpt: {
        present: false,
        status: 'not-deployed',
        qname: `_smtp._tls.${fqdn}`,
        resolvedOwner: `_smtp._tls.${fqdn}`,
        cnameChain: [],
        dnssecStatus: 'insecure',
        allTlsRptRecords: [],
        rua: [],
        extensions: [],
        issues: [],
        summary: 'No TLS-RPT',
      },
      bimi: {
        present: false,
        status: 'not-deployed',
        selector: 'default',
        qname: `default._bimi.${fqdn}`,
        resolvedOwner: `default._bimi.${fqdn}`,
        cnameChain: [],
        dnssecStatus: 'insecure',
        allBimiRecords: [],
        dmarcEligible: false,
        dmarcEligibilityReason: '',
        issues: [],
        summary: 'No BIMI',
      },
      fcrdnsSummary: {
        checkedIpCount: 0,
        validCount: 0,
        noPtrCount: 0,
        mismatchCount: 0,
        status: 'unchecked',
        summary: 'Unchecked',
      },
    },
    webAnalysis: {
      targetDomain: fqdn,
      displayDomain: domain,
      cnameChain: [],
      ipv4Addresses: ['198.51.100.20'],
      ipv6Addresses: ['2001:db8::20'],
      addressDnssecStatus: 'secure',
      httpsStatus: echEnabled ? 'ech-enabled' : 'not-deployed',
      httpsDnssecStatus: 'secure',
      httpsRecords: echEnabled
        ? [
            {
              ownerName: fqdn,
              rrtypeName: 'HTTPS',
              ttl: 300,
              priority: 1,
              isAliasMode: false,
              target: '.',
              params: [],
              alpns: ['h3', 'h2'],
              hasH3: true,
              hasH2: true,
              noDefaultAlpn: false,
              ipv4Hints: [],
              ipv6Hints: [],
              ipv4HintsMatched: [],
              ipv4HintsDrifted: [],
              ipv6HintsMatched: [],
              ipv6HintsDrifted: [],
              echConfigs: [],
              issues: [],
            },
          ]
        : [],
      svcbRecords: [],
      supportsHttp3: echEnabled,
      supportsHttp2: echEnabled,
      echEnabled,
      echPublicNames: echEnabled ? ['cloudflare-ech.com'] : [],
      ipHintStatus: 'not-used',
      httpsSummary: 'Synthetic HTTPS',
      caa: {
        status: caaEnforced ? 'enforced' : 'unprotected',
        effectiveOwner: caaEnforced ? fqdn : undefined,
        dnssecStatus: 'secure',
        hops: [],
        issueCas: caaEnforced ? ['letsencrypt.org'] : [],
        issuewildCas: [],
        iodefUris: [],
        hasAcmeAccountBinding: false,
        hasCriticalUnknownTag: false,
        issues: [],
        summary: 'Synthetic CAA',
      },
      webDane: {
        qname: `_443._tcp.${fqdn}`,
        resolvedOwner: `_443._tcp.${fqdn}`,
        cnameChain: [],
        status: 'no-tlsa-unsigned',
        dnssecStatus: 'insecure',
        records: [],
        rolloverReady: false,
        summary: 'No Web DANE',
      },
      sshfp: {
        present: false,
        status: 'not-deployed',
        dnssecStatus: 'insecure',
        records: [],
        summary: 'No SSHFP',
      },
    },
  };
}

describe('Multi-Domain Portfolio Security Triage Engine (#34)', () => {
  it('parses multi-line, CSV, Markdown bullets, URLs, emails, and wildcard CT SANs up to 50 domains', () => {
    const mixedInput = [
      '# Production domain inventory',
      '- https://www.cloudflare.com:443/dns/',
      '1. ietf.org # standards body',
      'postmaster@nlnetlabs.nl, *.api.github.com; CLOUDFLARE.COM.',
      '192.0.2.10',
      'not_a_domain',
    ].join('\n');

    const parsed = parsePortfolioDomainList(mixedInput);
    expect(parsed.domains).toEqual([
      'www.cloudflare.com',
      'ietf.org',
      'nlnetlabs.nl',
      'api.github.com',
      'cloudflare.com',
    ]);
    expect(parsed.skippedTokens).toContain('192.0.2.10');
    expect(parsed.skippedTokens).toContain('not_a_domain');
    expect(parsed.truncatedCount).toBe(0);

    // Structured CSV with header row
    const csvInput = [
      'Domain,Environment,Owner',
      'example.com,prod,platform',
      '*.staging.example.org,staging,web',
      'example.com,duplicate,platform',
    ].join('\n');
    const parsedCsv = parsePortfolioDomainList(csvInput);
    expect(parsedCsv.domains).toEqual(['example.com', 'staging.example.org']);

    // Enforce 50-domain cap
    const sixtyDomains = Array.from({ length: 60 }, (_, i) => `host-${i + 1}.example.com`).join(
      '\n'
    );
    const capped = parsePortfolioDomainList(sixtyDomains);
    expect(capped.domains.length).toBe(MAX_PORTFOLIO_DOMAINS);
    expect(capped.totalValidBeforeCap).toBe(60);
    expect(capped.truncatedCount).toBe(10);
  });

  it('detects multi-domain Omnibox pastes without false-triggering on CLI commands, email headers, or single domains', () => {
    expect(detectMultiDomainPaste('cloudflare.com\nietf.org\ngithub.com')).toEqual([
      'cloudflare.com',
      'ietf.org',
      'github.com',
    ]);
    expect(detectMultiDomainPaste('cloudflare.com, ietf.org')).toEqual([
      'cloudflare.com',
      'ietf.org',
    ]);

    // Must NOT trigger on single domains, dig CLI commands, raw email headers, wire URLs, or prose
    expect(detectMultiDomainPaste('cloudflare.com')).toBeNull();
    expect(detectMultiDomainPaste('dig @1.1.1.1 cloudflare.com ietf.org +dnssec')).toBeNull();
    expect(detectMultiDomainPaste('cloudflare.com +dnssec')).toBeNull();
    expect(
      detectMultiDomainPaste(
        'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=ietf.org; dmarc=pass'
      )
    ).toBeNull();
    expect(
      detectMultiDomainPaste('https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE')
    ).toBeNull();
    expect(
      detectMultiDomainPaste('Please check why our server failed yesterday morning in production')
    ).toBeNull();
  });

  it('deduplicates cross-session root/TLD/ASN DoH fetches via sharedQueryCache while isolating per-session logs', async () => {
    let networkFetchCalls = 0;
    const wireResponse = buildDnsQuery('.', RR_TYPES.DNSKEY, { cd: true, doBit: true });

    const mockFetch: typeof fetch = async () => {
      networkFetchCalls += 1;
      await new Promise((r) => setTimeout(r, 15));
      return new Response(new Uint8Array(wireResponse), {
        status: 200,
        headers: { 'content-type': 'application/dns-message' },
      });
    };

    const sharedCache = new Map<string, Promise<DohQueryLog>>();
    const sessionA = new DohSession({
      endpoint: 'https://cloudflare-dns.com/dns-query',
      fetchImpl: mockFetch,
      sharedQueryCache: sharedCache,
    });
    const sessionB = new DohSession({
      endpoint: 'https://cloudflare-dns.com/dns-query',
      fetchImpl: mockFetch,
      sharedQueryCache: sharedCache,
    });

    let completedA = 0;
    let completedB = 0;
    sessionA.onQueryCompleted = (n) => {
      completedA = n;
    };
    sessionB.onQueryCompleted = (n) => {
      completedB = n;
    };

    const [logA, logB] = await Promise.all([
      sessionA.query('.', RR_TYPES.DNSKEY, { cd: true, doBit: true, purpose: 'Session A Root' }),
      sessionB.query('.', RR_TYPES.DNSKEY, { cd: true, doBit: true, purpose: 'Session B Root' }),
    ]);

    expect(networkFetchCalls).toBe(1);
    expect(logA.purpose).toBe('Session A Root');
    expect(logB.purpose).toBe('Session B Root');
    expect(sessionA.getLogs()).toHaveLength(1);
    expect(sessionB.getLogs()).toHaveLength(1);
    expect(completedA).toBe(1);
    expect(completedB).toBe(1);
  });

  it('enforces strict bounded concurrency, Pause/Resume gating, and immediate Cancel in createPortfolioBatchRunner', async () => {
    const domains = Array.from({ length: 10 }, (_, i) => `d${i + 1}.example.com`);
    let activeWorkers = 0;
    let maxObservedConcurrency = 0;

    const runner = createPortfolioBatchRunner({
      domains,
      concurrency: 3,
      probeFn: async (domain, opts) => {
        activeWorkers += 1;
        maxObservedConcurrency = Math.max(maxObservedConcurrency, activeWorkers);
        opts.onQueryProgress?.(4, `Probing ${domain}`);
        await new Promise((r) => setTimeout(r, 20));
        activeWorkers -= 1;
        return makeSyntheticPortfolioSnapshot(domain);
      },
    });

    const finalState = await runner.start();
    expect(maxObservedConcurrency).toBe(3);
    expect(finalState.status).toBe('completed');
    expect(finalState.completedDomains).toBe(10);
    expect(finalState.rows.every((r) => r.status === 'done')).toBe(true);

    // Verify Pause & Resume
    let releaseFirstBatch!: () => void;
    const firstBatchGate = new Promise<void>((resolve) => {
      releaseFirstBatch = resolve;
    });
    let startedCount = 0;

    const pauseRunner = createPortfolioBatchRunner({
      domains: ['p1.example.com', 'p2.example.com', 'p3.example.com', 'p4.example.com'],
      concurrency: 2,
      probeFn: async (domain) => {
        startedCount += 1;
        if (startedCount <= 2) {
          await firstBatchGate;
        }
        return makeSyntheticPortfolioSnapshot(domain);
      },
    });

    const pausePromise = pauseRunner.start();
    await new Promise((r) => setTimeout(r, 10));
    expect(startedCount).toBe(2);

    pauseRunner.pause();
    expect(pauseRunner.getState().status).toBe('paused');
    releaseFirstBatch();
    await new Promise((r) => setTimeout(r, 25));

    // Workers finished p1 & p2, and must NOT have started p3 or p4 while paused!
    expect(pauseRunner.getState().completedDomains).toBe(2);
    expect(startedCount).toBe(2);

    pauseRunner.resume();
    const resumedFinal = await pausePromise;
    expect(resumedFinal.status).toBe('completed');
    expect(resumedFinal.completedDomains).toBe(4);
    expect(startedCount).toBe(4);

    // Verify Cancel aborts in-flight probes and marks remaining queued rows 'canceled'
    const cancelRunner = createPortfolioBatchRunner({
      domains: ['c1.example.com', 'c2.example.com', 'c3.example.com', 'c4.example.com'],
      concurrency: 1,
      probeFn: async (domain, opts) => {
        if (domain === 'c1.example.com') {
          return makeSyntheticPortfolioSnapshot(domain);
        }
        return await new Promise<AnalysisSnapshot>((_resolve, reject) => {
          opts.signal?.addEventListener('abort', () => reject(new Error('Aborted')), {
            once: true,
          });
        });
      },
    });

    const cancelPromise = cancelRunner.start();
    await new Promise((r) => setTimeout(r, 20));
    cancelRunner.cancel();
    const canceledFinal = await cancelPromise;

    expect(canceledFinal.status).toBe('canceled');
    expect(canceledFinal.rows[0]?.status).toBe('done');
    expect(canceledFinal.rows[1]?.status).toBe('canceled');
    expect(canceledFinal.rows[2]?.status).toBe('canceled');
    expect(canceledFinal.rows[3]?.status).toBe('canceled');
  });

  it('computes cross-portfolio BGP ASN concentration, sorts posture rows, and exports RFC 4180 CSV, GFM Markdown & re-importable JSON bundles', () => {
    const snapA = makeSyntheticPortfolioSnapshot('alpha.example', {
      dnssecStatus: 'secure',
      remainingSec: 3600 * 12, // 12h expiring soon!
      asns: [{ asn: 13335, asName: 'CLOUDFLARENET' }],
      dmarcPolicy: 'reject',
      spfVerdict: 'strict-fail',
      daneStatus: 'all-valid',
      echEnabled: true,
      caaEnforced: true,
    });
    const snapB = makeSyntheticPortfolioSnapshot('bravo.example', {
      dnssecStatus: 'insecure',
      asns: [{ asn: 13335, asName: 'CLOUDFLARENET' }],
      dmarcPolicy: 'missing',
      spfVerdict: 'pass-all',
      daneStatus: 'not-deployed',
      echEnabled: false,
      caaEnforced: false,
    });
    const snapC = makeSyntheticPortfolioSnapshot('charlie.example', {
      dnssecStatus: 'bogus',
      remainingSec: -120, // expired!
      asns: [
        { asn: 13335, asName: 'CLOUDFLARENET' },
        { asn: 16509, asName: 'AMAZON-02' },
      ],
      dmarcPolicy: 'none',
      spfVerdict: 'soft-fail',
      errorCount: 2,
    });
    const snapD = makeSyntheticPortfolioSnapshot('delta.example', {
      dnssecStatus: 'secure',
      remainingSec: 86400 * 21,
      asns: [{ asn: 16509, asName: 'AMAZON-02' }],
      dmarcPolicy: 'quarantine',
      spfVerdict: 'strict-fail',
    });

    const rows: PortfolioDomainRow[] = [snapA, snapB, snapC, snapD].map((s, index) => ({
      index,
      domain: s.displayDomain,
      status: 'done',
      completedQueries: 20,
      durationMs: s.durationMs,
      snapshot: s,
      posture: extractPortfolioPosture(s),
    }));

    const concentration = computePortfolioAsnConcentration(rows);
    expect(concentration[0]?.asn).toBe(13335);
    expect(concentration[0]?.domainCount).toBe(3);
    expect(concentration[0]?.sharePercent).toBe(75);
    expect(concentration[0]?.soleSpofDomainCount).toBe(2); // alpha & bravo are 1-ASN on AS13335
    expect(concentration[0]?.concentrationRisk).toBe('critical');

    // Sort by risk descending -> bogus charlie first!
    const byRisk = sortPortfolioRows(rows, 'risk', 'desc');
    expect(byRisk[0]?.domain).toBe('charlie.example');

    // Sort by shortest RRSIG ascending -> expired charlie (-120s), then alpha (12h), then delta (21d), then unsigned bravo
    const byRrsig = sortPortfolioRows(rows, 'rrsig', 'asc');
    expect(byRrsig.map((r) => r.domain)).toEqual([
      'charlie.example',
      'alpha.example',
      'delta.example',
      'bravo.example',
    ]);

    // CSV export + formula injection check
    const csv = formatPortfolioCsv(rows, concentration);
    const csvLines = csv.split('\n');
    expect(csvLines).toHaveLength(5);
    expect(csvLines[0]).toContain('shortest_rrsig_remaining_sec');
    expect(csvLines[0]).toContain('ns_max_portfolio_asn_share_pct');
    expect(csv).toContain('AS13335 (CLOUDFLARENET)');
    expect(csv).toContain('strict-fail (-all)');
    expect(csv).toContain('pass-all (+all)');
    // Negative numeric seconds (-120) should remain numeric, not single-quote prefixed
    expect(csv).toContain(',-120,EXPIRED,');

    // Markdown export
    const md = formatPortfolioMarkdown(rows, concentration, {
      sourceLabel: 'Unit Suite',
      exportedAt: 1_780_000_000_000,
    });
    expect(md).toContain('# DigDeep Portfolio DNS Security & Resilience Triage Report');
    expect(md).toContain('## Cross-Portfolio Authoritative NS BGP ASN Concentration');
    expect(md).toContain('CRITICAL SPOF');
    expect(md).toContain('`alpha.example`');
    expect(md).toContain('HTTPS + ECH ✓');

    // JSON bundle export + History Store round-trip import
    memStorage.clear();
    const jsonBundle = formatPortfolioJsonBundle(rows, concentration);
    const parsedBundle = JSON.parse(jsonBundle);
    expect(parsedBundle.kind).toBe('digdeep-portfolio-bundle');
    expect(parsedBundle.snapshots).toHaveLength(4);

    const imported = importSnapshotsFromJson(jsonBundle);
    expect(imported).toHaveLength(4);
    expect(imported.map((s) => s.displayDomain).sort()).toEqual([
      'alpha.example',
      'bravo.example',
      'charlie.example',
      'delta.example',
    ]);
  });

  it(
    'audits a live portfolio batch (cloudflare.com, ietf.org, github.com) via client-side DoH and preserves Mail/Web posture on reverifySnapshot',
    async () => {
      const runner = createPortfolioBatchRunner({
        domains: ['cloudflare.com', 'ietf.org', 'github.com'],
        concurrency: 2,
        skipExternalHttp: true,
      });

      const state = await runner.start();
      expect(state.status).toBe('completed');
      expect(state.completedDomains).toBe(3);
      expect(state.failedDomains).toBe(0);
      expect(state.asnConcentration.length).toBeGreaterThanOrEqual(2);

      const cf = state.rows.find((r) => r.domain === 'cloudflare.com')!;
      expect(cf.posture?.dnssecStatus).toBe('secure');
      expect(cf.posture?.dnssecAlgorithmLabel).toContain('ECDSAP256SHA256');
      expect(cf.posture?.shortestRrsigRemainingSec).toBeGreaterThan(0);
      expect(cf.posture?.nsAsns.some((a) => a.asn === 13335)).toBe(true);
      expect(cf.posture?.hasHttps).toBe(true);
      expect(cf.posture?.supportsHttp3).toBe(true);
      expect(cf.posture?.caaStatus).toBe('enforced');
      expect(cf.posture?.dmarcPolicy).toBe('reject');

      const ietf = state.rows.find((r) => r.domain === 'ietf.org')!;
      expect(ietf.posture?.dnssecStatus).toBe('secure');
      expect(ietf.posture?.daneStatus).toBe('all-valid');
      expect(ietf.posture?.spfPresent).toBe(true);

      const gh = state.rows.find((r) => r.domain === 'github.com')!;
      expect(gh.posture?.dnssecStatus).toBe('insecure');
      expect(gh.posture?.dnssecAlgorithmLabel).toBe('UNSIGNED');
      expect(gh.posture?.shortestRrsigRemainingSec).toBeNull();
      expect(gh.posture?.spfPresent).toBe(true);
      expect(gh.posture?.dmarcPresent).toBe(true);

      // Verify offline Time-Travel reverifySnapshot preserves both mailAnalysis and webAnalysis on unified portfolio snapshots
      const reverifiedCf = await reverifySnapshot(cf.snapshot!);
      expect(reverifiedCf.mailAnalysis?.dmarc.policy).toBe('reject');
      expect(reverifiedCf.webAnalysis?.supportsHttp3).toBe(true);
      expect(reverifiedCf.webAnalysis?.caa.status).toBe('enforced');
    },
    45000
  );
});
