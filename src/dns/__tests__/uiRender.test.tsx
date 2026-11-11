import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { AuditPanel } from '../../components/AuditPanel';
import { ChainGraphView, prepareExportSvgElement } from '../../components/ChainGraphView';
import { ConsensusView } from '../../components/ConsensusView';
import { GraphInspector } from '../../components/GraphInspector';
import { HistoryPanel } from '../../components/HistoryPanel';
import {
  ensureIpAsnInfoLoaded,
  getCachedOrInitialIpInfo,
  IpAsnHoverCardContent,
  IpHoverBadge,
  parseIpToken,
  seedIpAsnCacheFromSnapshot,
} from '../../components/IpHoverBadge';
import { MailAnalysisView } from '../../components/MailAnalysisView';
import { ResponsesPanel } from '../../components/ResponsesPanel';
import { ReverseDnsCard } from '../../components/ReverseDnsCard';
import { SettingsModal } from '../../components/SettingsModal';
import { WebAnalysisView } from '../../components/WebAnalysisView';
import { WirePacketDissectorView } from '../../components/WireDissectorView';
import { ZonesPanel } from '../../components/ZonesPanel';
import { buildChainGraph } from '../../graph/layout';
import { DEFAULT_USER_SETTINGS, saveSnapshot } from '../../storage/historyStore';
import {
  buildDeepLinkSearch,
  buildShareUrl,
  parseDeepLinkParams,
} from '../../urlState';
import { runDnsvizAnalysis } from '../analyzer';
import { runConsensusAnalysis } from '../consensusAnalyzer';
import { base64ToBytes } from '../encoding';
import { runMailAnalysis } from '../mailAnalyzer';
import { runWebAnalysis } from '../webAnalyzer';
import { dissectDnsWirePacket } from '../wireDissector';

// Minimal localStorage shim for HistoryPanel stats
const mem = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    get length() {
      return mem.size;
    },
    clear: () => mem.clear(),
    getItem: (k: string) => mem.get(k) ?? null,
    key: (i: number) => Array.from(mem.keys())[i] ?? null,
    removeItem: (k: string) => mem.delete(k),
    setItem: (k: string, v: string) => mem.set(k, String(v)),
  },
  configurable: true,
});

describe('UI Component Rendering on Real 1.1.1.1 Snapshots', () => {
  it(
    'renders ChainGraphView, AuditPanel, ResponsesPanel, ZonesPanel, HistoryPanel, and SettingsModal cleanly',
    async () => {
      const [cfSnap, bogusSnap] = await Promise.all([
        runDnsvizAnalysis('www.iana.org', { queryTypes: ['A'] }),
        runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] }),
      ]);

      const graphHtml = renderToStaticMarkup(
        <ChainGraphView
          snapshot={cfSnap}
          theme="dark"
          filters={{ showSoaAndNs: true, showStandbyKeys: true }}
          onChangeFilters={() => {}}
        />
      );
      expect(graphHtml).toContain('<svg');
      expect(graphHtml).toContain('iana.org.');
      expect(graphHtml).toContain('cloudflare.net.');
      expect(graphHtml).toContain('lg:flex-1');
      expect(graphHtml).toMatch(/min-height:\d+px/);

      const bogusGraphHtml = renderToStaticMarkup(
        <ChainGraphView
          snapshot={bogusSnap}
          theme="light"
          filters={{ showSoaAndNs: false, showStandbyKeys: true }}
          onChangeFilters={() => {}}
        />
      );
      expect(bogusGraphHtml).toContain('MISSING KEY');

      const auditHtml = renderToStaticMarkup(
        <AuditPanel snapshot={bogusSnap} onJumpToGraphTarget={() => {}} />
      );
      expect(auditHtml).toContain('DS_NO_MATCHING_DNSKEY');

      const responsesHtml = renderToStaticMarkup(<ResponsesPanel snapshot={cfSnap} />);
      expect(responsesHtml).toContain('HEADER');
      expect(responsesHtml).toContain('application/dns-message');
      expect(responsesHtml).toContain('Zonefile (.zone)');
      expect(responsesHtml).toContain('Export .zone');
      expect(responsesHtml).toContain('dig +dnssec +multi');
      expect(responsesHtml).toContain('Decode ?dns= / Hex');

      const compressedQuery =
        cfSnap.queries.find(
          (q) => dissectDnsWirePacket(base64ToBytes(q.wireBase64)).compressionJumps.length > 0
        ) ?? cfSnap.queries[0];
      const dissectedLive = dissectDnsWirePacket(base64ToBytes(compressedQuery.wireBase64));
      const dissectorHtml = renderToStaticMarkup(
        <WirePacketDissectorView dissected={dissectedLive} packetLabel="Live Response Wire" />
      );
      expect(dissectorHtml).toContain('16-Bit Header Flags Register');
      expect(dissectorHtml).toContain('Decoded Packet Structure');
      expect(dissectorHtml).toContain('Copy ?dns= Base64url');
      expect(dissectorHtml).toContain('RFC 1035 §4.1.4 Compression Pointer Jumps');
      expect(dissectorHtml).toContain('0xC0xx pointer');

      const zonesHtml = renderToStaticMarkup(<ZonesPanel snapshot={cfSnap} />);
      expect(zonesHtml).toContain('. (Root Zone)');
      expect(zonesHtml).toContain('RFC 1912 / 2308 OK');
      expect(zonesHtml).toContain('IN SYNC WITH PARENT DS');
      expect(zonesHtml).toContain('AS13335');
      expect(zonesHtml).toContain('RFC 1035 Master Zonefile Export');
      expect(zonesHtml).toContain('Export Zonefile (.zone)');

      const inspectorHtml = renderToStaticMarkup(
        <GraphInspector
          selection={{ kind: 'zone', zone: cfSnap.zones[0] }}
          dohEndpoint={cfSnap.dohEndpoint}
          capturedAt={cfSnap.capturedAt}
          validatedAt={cfSnap.validatedAt}
          onClose={() => {}}
        />
      );
      expect(inspectorHtml).toContain('CLI Reproducer');
      expect(inspectorHtml).toContain('dig +dnssec +multi');

      const historyHtml = renderToStaticMarkup(
        <HistoryPanel
          snapshots={[cfSnap, bogusSnap]}
          activeSnapshotId={cfSnap.id}
          onSelectSnapshot={() => {}}
          onReprobe={() => {}}
          onTogglePin={() => {}}
          onDelete={() => {}}
          onClearUnpinned={() => {}}
          onImportJson={() => {}}
        />
      );
      expect(historyHtml).toContain('Compare Snapshots');

      const settingsHtml = renderToStaticMarkup(
        <SettingsModal
          open={true}
          settings={DEFAULT_USER_SETTINGS}
          activeSnapshot={cfSnap}
          onClose={() => {}}
          onSaveSettings={() => {}}
          onReverifyAtTime={() => {}}
        />
      );
      expect(settingsHtml).toContain('IANA Root KSK-2024 (#38696)');
    },
    25000
  );

  it('ships valid PWA manifest, icons, service worker, and offline-ready App shell', () => {
    const fs = (
      globalThis as unknown as {
        process: {
          getBuiltinModule: (id: string) => {
            existsSync: (p: URL) => boolean;
            readFileSync: (p: URL, enc?: string) => string | Uint8Array;
          };
        };
      }
    ).process.getBuiltinModule('node:fs');

    const manifestUrl = new URL('../../../public/manifest.webmanifest', import.meta.url);
    expect(fs.existsSync(manifestUrl)).toBe(true);

    const manifest = JSON.parse(fs.readFileSync(manifestUrl, 'utf8') as string) as {
      name: string;
      short_name: string;
      start_url: string;
      scope: string;
      display: string;
      icons: Array<{ src: string; sizes: string; type: string; purpose: string }>;
    };
    expect(manifest.short_name).toBe('DigDeep');
    expect(manifest.display).toBe('standalone');
    expect(manifest.start_url).toBe('./');
    expect(manifest.scope).toBe('./');
    expect(manifest.icons.length).toBeGreaterThanOrEqual(4);

    for (const icon of manifest.icons) {
      const rel = icon.src.replace(/^\.\//, '');
      const iconUrl = new URL(`../../../public/${rel}`, import.meta.url);
      expect(fs.existsSync(iconUrl)).toBe(true);
      const bytes = fs.readFileSync(iconUrl) as Uint8Array;
      expect(bytes.byteLength).toBeGreaterThan(100);
      if (icon.type === 'image/png') {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        expect(view.getUint32(0, false)).toBe(0x89504e47);
        const width = view.getUint32(16, false);
        const height = view.getUint32(20, false);
        expect(`${width}x${height}`).toBe(icon.sizes);
      }
    }

    const indexHtml = fs.readFileSync(new URL('../../../index.html', import.meta.url), 'utf8') as string;
    expect(indexHtml).toContain('rel="manifest" href="./manifest.webmanifest"');
    expect(indexHtml).toContain('name="theme-color"');

    const swCode = fs.readFileSync(new URL('../../../public/sw.js', import.meta.url), 'utf8') as string;
    expect(swCode).toContain('digdeep-shell-v22');
    expect(swCode).toContain('application/dns-message');

    // Verify App renders offline badge when navigator.onLine is false
    Object.defineProperty(globalThis, 'window', {
      value: {
        location: { search: '', href: 'https://example.test/' },
        matchMedia: () => ({ matches: false }),
        addEventListener: () => {},
        removeEventListener: () => {},
      },
      configurable: true,
    });
    const prevOnline = Object.getOwnPropertyDescriptor(globalThis.navigator, 'onLine');
    Object.defineProperty(globalThis.navigator, 'onLine', {
      value: false,
      configurable: true,
    });
    try {
      const appHtml = renderToStaticMarkup(<App />);
      expect(appHtml).toContain('Offline · Local History');
      expect(appHtml).toContain('value="digdeep.butter.eu"');
      expect(appHtml).toContain('data-testid="search-public-suffix"');
      expect(appHtml).toContain('>eu</span>');
      expect(appHtml).not.toContain('Presets:');
    } finally {
      if (prevOnline) {
        Object.defineProperty(globalThis.navigator, 'onLine', prevOnline);
      }
    }
  });

  it(
    'appends DigDeep · digdeep.fyi attribution footer to exported SVG/PNG diagrams without overlapping graph',
    async () => {
      const snap = await runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] });
      const filters = { showSoaAndNs: false, showStandbyKeys: true };
      const graph = buildChainGraph(snap, filters);

      const html = renderToStaticMarkup(
        <ChainGraphView
          snapshot={snap}
          theme="dark"
          filters={filters}
          onChangeFilters={() => {}}
        />
      );
      const { JSDOM } = (await import('jsdom' as string)) as {
        JSDOM: new (markup: string) => { window: { document: Document } };
      };
      const dom = new JSDOM(html);
      const svgEl = dom.window.document.querySelector('svg') as unknown as SVGSVGElement;
      expect(svgEl).toBeTruthy();

      const { clone, exportWidth, exportHeight } = prepareExportSvgElement(
        svgEl,
        snap,
        graph,
        'dark'
      );
      expect(exportWidth).toBeGreaterThanOrEqual(graph.width);
      expect(exportHeight).toBe(graph.height + 42);

      const serialized = clone.outerHTML;
      expect(serialized).toContain('data-export-attribution="true"');
      expect(serialized).toContain('DigDeep');
      expect(serialized).toContain('digdeep.fyi');
      expect(serialized).toContain('dnssec-failed.org [A]');
      expect(serialized).toContain('BOGUS');
      expect(serialized).toContain('1.1.1.1 DoH');
    },
    20000
  );

  it('parses and builds deep-link URLs, guards untrusted DoH params, and renders Copy Link UI', async () => {
    const shareUrl = buildShareUrl('https://digdeep.fyi/', {
      name: 'dnssec-failed.org',
      types: ['A', 'AAAA'],
      dohEndpoint: 'https://9.9.9.9/dns-query',
      tab: 'audit',
      focus: 'zone:dnssec-failed.org.',
      showSoaAndNs: true,
      showStandbyKeys: false,
    });
    expect(shareUrl).toBe(
      'https://digdeep.fyi/?name=dnssec-failed.org&types=A,AAAA&doh=9.9.9.9&tab=audit'
    );

    const graphShareUrl = buildShareUrl('https://digdeep.fyi/', {
      name: 'www.iana.org',
      types: ['A'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'graph',
      focus: 'zone:iana.org.',
      showSoaAndNs: true,
      showStandbyKeys: false,
    });
    expect(graphShareUrl).toBe(
      'https://digdeep.fyi/?name=www.iana.org&types=A&doh=1.1.1.1&focus=zone%3Aiana.org.&soa=1&standby=0'
    );

    // History tab normalizes to graph in shared URLs while preserving clean default address bar
    const historyShare = buildShareUrl('https://digdeep.fyi/', {
      name: 'cloudflare.com',
      types: ['A'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'history',
    });
    expect(historyShare).toBe('https://digdeep.fyi/?name=cloudflare.com&types=A&doh=1.1.1.1');

    const addressBarDefault = buildDeepLinkSearch({
      name: 'cloudflare.com',
      types: ['A', 'AAAA'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'graph',
    });
    expect(addressBarDefault).toBe('?name=cloudflare.com&types=A,AAAA');

    // Mail mode deep links omit types and default to 'mail' tab cleanly
    const mailBarDefault = buildDeepLinkSearch({
      name: 'ietf.org',
      mode: 'mail',
      types: ['MX', 'TXT'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'mail',
    });
    expect(mailBarDefault).toBe('?name=ietf.org&mode=mail');

    const mailShare = buildShareUrl('https://digdeep.fyi/', {
      name: 'ietf.org',
      mode: 'mail',
      types: ['MX', 'TXT'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'history',
    });
    expect(mailShare).toBe('https://digdeep.fyi/?name=ietf.org&mode=mail&doh=1.1.1.1');

    const parsedMail = parseDeepLinkParams('?name=ietf.org&mode=mail&tab=graph');
    expect(parsedMail.mode).toBe('mail');
    expect(parsedMail.tab).toBe('graph');

    // Web mode deep links round-trip cleanly
    const webBarDefault = buildDeepLinkSearch({
      name: 'cloudflare.com',
      mode: 'web',
      types: ['A', 'AAAA', 'HTTPS', 'CAA'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'web',
    });
    expect(webBarDefault).toBe('?name=cloudflare.com&mode=web');

    const parsedWeb = parseDeepLinkParams('?name=cloudflare.com&tab=web');
    expect(parsedWeb.mode).toBe('web');
    expect(parsedWeb.tab).toBe('web');

    // Consensus mode deep links round-trip cleanly
    const consensusBarDefault = buildDeepLinkSearch({
      name: 'dnssec-failed.org',
      mode: 'consensus',
      types: ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'consensus',
    });
    expect(consensusBarDefault).toBe('?name=dnssec-failed.org&mode=consensus');

    const parsedConsensus = parseDeepLinkParams('?name=dnssec-failed.org&tab=consensus');
    expect(parsedConsensus.mode).toBe('consensus');
    expect(parsedConsensus.tab).toBe('consensus');

    // Custom DKIM selectors imply mail mode and round-trip in share URLs
    const parsedDkim = parseDeepLinkParams('?name=ietf.org&dkim=ietf1,mail');
    expect(parsedDkim.mode).toBe('mail');
    expect(parsedDkim.dkimSelectors).toEqual(['ietf1', 'mail']);

    const dkimShare = buildShareUrl('https://digdeep.fyi/', {
      name: 'ietf.org',
      mode: 'mail',
      types: ['MX', 'TXT'],
      dkimSelectors: ['ietf1', 'mail'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      tab: 'mail',
    });
    expect(dkimShare).toBe('https://digdeep.fyi/?name=ietf.org&mode=mail&dkim=ietf1,mail&doh=1.1.1.1');

    // Parse preset DoH shortLabel
    const parsedPreset = parseDeepLinkParams(
      '?name=dnssec-failed.org&types=a,dnskey&doh=unfiltered.joindns4.eu&tab=audit'
    );
    expect(parsedPreset.name).toBe('dnssec-failed.org');
    expect(parsedPreset.types).toEqual(['A', 'DNSKEY']);
    expect(parsedPreset.dohEndpoint).toBe('https://unfiltered.joindns4.eu/dns-query');
    expect(parsedPreset.isUntrustedCustomDoh).toBe(false);
    expect(parsedPreset.tab).toBe('audit');

    // Flag unknown external HTTPS DoH as untrusted; reject loopback/private hosts
    const parsedExternal = parseDeepLinkParams('?name=example.com&doh=https://doh.example.net/dns-query');
    expect(parsedExternal.dohEndpoint).toBe('https://doh.example.net/dns-query');
    expect(parsedExternal.isUntrustedCustomDoh).toBe(true);

    const parsedSaved = parseDeepLinkParams(
      '?name=example.com&doh=https://doh.example.net/dns-query',
      ['https://doh.example.net/dns-query']
    );
    expect(parsedSaved.isUntrustedCustomDoh).toBe(false);

    const parsedLoopback = parseDeepLinkParams('?name=example.com&doh=https://127.0.0.1/dns-query');
    expect(parsedLoopback.dohEndpoint).toBeNull();

    // Render App with saved snapshot + deep-link query params -> shows Copy Link button and active resolver
    const snap = await runDnsvizAnalysis('www.iana.org', { queryTypes: ['A'] });
    mem.clear();
    saveSnapshot(snap);

    Object.defineProperty(globalThis, 'window', {
      value: {
        location: {
          search: '?name=www.iana.org&types=A&doh=9.9.9.9&tab=responses',
          href: 'https://digdeep.fyi/?name=www.iana.org&types=A&doh=9.9.9.9&tab=responses',
        },
        matchMedia: () => ({ matches: false }),
        addEventListener: () => {},
        removeEventListener: () => {},
      },
      configurable: true,
    });

    const appHtml = renderToStaticMarkup(<App />);
    expect(appHtml).toContain('Copy Link');
    expect(appHtml).toContain('9.9.9.9 DoH');
    expect(appHtml).toContain('application/dns-message');

    // Render App with untrusted custom DoH -> shows confirmation prompt
    Object.defineProperty(globalThis, 'window', {
      value: {
        location: {
          search: '?name=www.iana.org&doh=https://custom-doh.example/dns-query',
          href: 'https://digdeep.fyi/?name=www.iana.org&doh=https://custom-doh.example/dns-query',
        },
        matchMedia: () => ({ matches: false }),
        addEventListener: () => {},
        removeEventListener: () => {},
      },
      configurable: true,
    });
    const untrustedHtml = renderToStaticMarkup(<App />);
    expect(untrustedHtml).toContain('https://custom-doh.example/dns-query');
    expect(untrustedHtml).toContain('Use &amp; Run Trace');
  }, 20000);

  it('ships complete SEO metadata, 1200x630 OpenGraph card, JSON-LD schema, robots.txt, sitemap.xml, and opensearch.xml', () => {
    const fs = (
      globalThis as unknown as {
        process: {
          getBuiltinModule: (id: string) => {
            existsSync: (p: URL) => boolean;
            readFileSync: (p: URL, enc?: string) => string | Uint8Array;
          };
        };
      }
    ).process.getBuiltinModule('node:fs');

    // Validate 1200x630 OpenGraph PNG image
    const ogCardUrl = new URL('../../../public/og-card.png', import.meta.url);
    expect(fs.existsSync(ogCardUrl)).toBe(true);
    const ogBytes = fs.readFileSync(ogCardUrl) as Uint8Array;
    const ogView = new DataView(ogBytes.buffer, ogBytes.byteOffset, ogBytes.byteLength);
    expect(ogView.getUint32(0, false)).toBe(0x89504e47);
    expect(ogView.getUint32(16, false)).toBe(1200);
    expect(ogView.getUint32(20, false)).toBe(630);

    // Validate index.html SEO, OpenGraph, Twitter Card, JSON-LD, and crawlable shell
    const indexHtml = fs.readFileSync(
      new URL('../../../index.html', import.meta.url),
      'utf8'
    ) as string;
    expect(indexHtml).toContain('rel="canonical" href="https://digdeep.fyi/"');
    expect(indexHtml).toContain('property="og:image" content="https://digdeep.fyi/og-card.png"');
    expect(indexHtml).toContain('property="og:image:width" content="1200"');
    expect(indexHtml).toContain('property="og:image:height" content="630"');
    expect(indexHtml).toContain('name="twitter:card" content="summary_large_image"');
    expect(indexHtml).toContain('type="application/opensearchdescription+xml"');
    expect(indexHtml).toContain('<h1');

    const jsonLdMatch = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(indexHtml);
    expect(jsonLdMatch).toBeTruthy();
    const schema = JSON.parse(jsonLdMatch![1]) as {
      '@type': string;
      url: string;
      potentialAction: { '@type': string; target: string };
    };
    expect(schema['@type']).toBe('WebApplication');
    expect(schema.url).toBe('https://digdeep.fyi/');
    expect(schema.potentialAction.target).toBe('https://digdeep.fyi/?name={search_term_string}');

    // Validate robots.txt, sitemap.xml, and opensearch.xml
    const robotsTxt = fs.readFileSync(
      new URL('../../../public/robots.txt', import.meta.url),
      'utf8'
    ) as string;
    expect(robotsTxt).toContain('Sitemap: https://digdeep.fyi/sitemap.xml');

    const sitemapXml = fs.readFileSync(
      new URL('../../../public/sitemap.xml', import.meta.url),
      'utf8'
    ) as string;
    expect(sitemapXml).toContain('<loc>https://digdeep.fyi/</loc>');
    expect(sitemapXml).toContain('dnssec-failed.org');

    const openSearchXml = fs.readFileSync(
      new URL('../../../public/opensearch.xml', import.meta.url),
      'utf8'
    ) as string;
    expect(openSearchXml).toContain('https://digdeep.fyi/?name={searchTerms}');
  });

  it(
    'renders MailAnalysisView and multi-branch ChainGraphView on live ietf.org Mail + DANE + SPF snapshot',
    async () => {
      const mailSnap = await runMailAnalysis('ietf.org');
      expect(mailSnap.mode).toBe('mail');
      expect(mailSnap.mailAnalysis).toBeDefined();

      const mailHtml = renderToStaticMarkup(
        <MailAnalysisView
          snapshot={mailSnap}
          onJumpToGraphTarget={() => {}}
          onOpenChainGraph={() => {}}
        />
      );
      expect(mailHtml).toContain('SMTP DANE (RFC 7672)');
      expect(mailHtml).toContain('SPF Policy (RFC 7208)');
      expect(mailHtml).toContain('DKIM Keys (RFC 6376)');
      expect(mailHtml).toContain('DMARC Policy (RFC 7489)');
      expect(mailHtml).toContain('_mta-sts.ietf.org');
      expect(mailHtml).toContain('_smtp._tls.ietf.org');
      expect(mailHtml).toContain('default._bimi.ietf.org');
      expect(mailHtml).toContain('v=BIMI1');
      expect(mailHtml).toContain('_25._tcp.');
      expect(mailHtml).toContain('v=spf1');
      expect(mailHtml).toContain('Interactive SPF Sender IP Evaluator');
      expect(mailHtml).toContain('Test Sender IPv4 / IPv6 Address');
      expect(mailHtml).toContain('_dmarc.ietf.org');
      expect(mailHtml).toContain('mail._domainkey.ietf.org');

      const graphHtml = renderToStaticMarkup(
        <ChainGraphView
          snapshot={mailSnap}
          theme="dark"
          filters={{ showSoaAndNs: false, showStandbyKeys: true }}
          onChangeFilters={() => {}}
        />
      );
      expect(graphHtml).toContain('<svg');
      expect(graphHtml).toContain('TLSA');

      const rdnsSnap = await runDnsvizAnalysis('1.1.1.1');
      expect(rdnsSnap.reverseDns).toBeDefined();
      const rdnsHtml = renderToStaticMarkup(
        <ReverseDnsCard
          reverseDns={rdnsSnap.reverseDns!}
          onJumpToGraphTarget={() => {}}
          onTraceHostname={() => {}}
        />
      );
      expect(rdnsHtml).toContain('1.1.1.1.in-addr.arpa');
      expect(rdnsHtml).toContain('one.one.one.one');
      expect(rdnsHtml).toContain('FCrDNS VERIFIED ✓');
      expect(rdnsHtml).toContain('AS13335');
      expect(rdnsHtml).toContain('1.1.1.0/24');
      expect(rdnsHtml).toContain('RPKI VALID ✓');

      const webSnap = await runWebAnalysis('cloudflare.com');
      expect(webSnap.mode).toBe('web');
      expect(webSnap.webAnalysis).toBeDefined();
      const tracedSubdomains: string[] = [];
      const webHtml = renderToStaticMarkup(
        <WebAnalysisView
          snapshot={webSnap}
          onJumpToGraphTarget={() => {}}
          onOpenChainGraph={() => {}}
          onTraceDomain={(d) => tracedSubdomains.push(d)}
        />
      );
      expect(webHtml).toContain('HTTPS / SVCB &amp; ECH');
      expect(webHtml).toContain('CAA Policy (RFC 8659)');
      expect(webHtml).toContain(
        'Certificate Transparency (CT) ↔ CAA Policy Cross-Check &amp; Subdomain Discovery'
      );
      expect(webHtml).toContain('Web DANE (_443._tcp)');
      expect(webHtml).toContain('SSHFP (RFC 4255)');
      expect(webHtml).toContain('HTTPS Priority 1');
      expect(webHtml).toContain('h3');
      if (webSnap.ctLogFetch?.ok) {
        expect(webHtml).toContain('CT ↔ CAA COMPLIANT');
        expect(webHtml).toContain('CAA AUTHORIZED ✓');
      }

      const consensusSnap = await runConsensusAnalysis('iana.org');
      expect(consensusSnap.mode).toBe('consensus');
      expect(consensusSnap.consensusAnalysis).toBeDefined();
      const consensusHtml = renderToStaticMarkup(
        <ConsensusView
          snapshot={consensusSnap}
          onOpenChainGraph={() => {}}
          onOpenWireResponses={() => {}}
        />
      );
      expect(consensusHtml).toContain('Multi-Resolver DoH Matrix for');
      expect(consensusHtml).toContain('Protective Filtering &amp; EDE');
      expect(consensusHtml).toContain('SOA Serial Propagation');
      expect(consensusHtml).toContain('DNSKEY &amp; Answer Sync');
      expect(consensusHtml).toContain('1.1.1.1');
      expect(consensusHtml).toContain('8.8.8.8');
      expect(consensusHtml).toContain('9.9.9.9');

      // Verify IP hover card cache seeding, live DoH lookup, and rendering
      seedIpAsnCacheFromSnapshot(rdnsSnap);
      const tok1111 = parseIpToken('1.1.1.1')!;
      expect(tok1111).toBeTruthy();
      expect(tok1111.canonicalIp).toBe('1.1.1.1');
      const seededInfo = getCachedOrInitialIpInfo(tok1111);
      expect(seededInfo.status).toBe('ready');
      expect(seededInfo.asns.some((a) => a.asn === 13335)).toBe(true);

      const spfCidrTok = parseIpToken('ip4:192.0.2.0/24')!;
      expect(spfCidrTok).toBeTruthy();
      expect(spfCidrTok.canonicalIp).toBe('192.0.2.0');
      expect(spfCidrTok.cidrSuffix).toBe('/24');
      expect(spfCidrTok.isPublic).toBe(false);

      const liveQuad9Tok = parseIpToken('9.9.9.9')!;
      const fetchedQuad9 = await ensureIpAsnInfoLoaded(liveQuad9Tok);
      expect(fetchedQuad9.status).toBe('ready');
      expect(fetchedQuad9.asns.some((a) => a.asn === 19281)).toBe(true);

      const hoverCardHtml = renderToStaticMarkup(
        <IpAsnHoverCardContent
          entries={[
            { token: tok1111, info: seededInfo },
            { token: spfCidrTok, info: getCachedOrInitialIpInfo(spfCidrTok) },
          ]}
          titleLabel="www.iana.org · A RRset"
        />
      );
      expect(hoverCardHtml).toContain('AS13335');
      expect(hoverCardHtml).toContain('1.1.1.0/24');
      expect(hoverCardHtml).toContain('RPKI VALID ✓');
      expect(hoverCardHtml).toContain('SPECIAL RANGE');

      const badgeHtml = renderToStaticMarkup(<IpHoverBadge ip="1.1.1.1" />);
      expect(badgeHtml).toContain('1.1.1.1');
      expect(badgeHtml).toContain('cursor-help');
    },
    35000
  );
});
