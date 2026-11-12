import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { AuditPanel } from '../../components/AuditPanel';
import { ChainGraphView, prepareExportSvgElement } from '../../components/ChainGraphView';
import { ConsensusView } from '../../components/ConsensusView';
import { EmailDaneCard } from '../../components/EmailDaneCard';
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
import {
  resetWireGridWidthPreference,
  WirePacketDissectorView,
} from '../../components/WireDissectorView';
import { isHealthyIntermediateParentZone, ZonesPanel } from '../../components/ZonesPanel';
import { buildChainGraph } from '../../graph/layout';
import { DEFAULT_USER_SETTINGS, saveSnapshot } from '../../storage/historyStore';
import {
  buildDeepLinkSearch,
  buildShareUrl,
  parseDeepLinkParams,
} from '../../urlState';
import { runDnsvizAnalysis } from '../analyzer';
import { runConsensusAnalysis } from '../consensusAnalyzer';
import { base64ToBytes, hexToBytes } from '../encoding';
import { runMailAnalysis } from '../mailAnalyzer';
import type { AnalysisSnapshot, ZoneAnalysis } from '../types';
import { runWebAnalysis } from '../webAnalyzer';
import { dissectDnsWirePacket } from '../wireDissector';
import {
  computeWireQueryCategoryCounts,
  filterDohQueryLogs,
  findAuditFindingWireQuery,
  findConsensusResolverWireQuery,
  findEcsRegionWireQueries,
  findGraphSelectionWireQuery,
} from '../wireQueryFilter';

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
        <AuditPanel
          snapshot={bogusSnap}
          onJumpToGraphTarget={() => {}}
          onInspectWireQuery={() => {}}
        />
      );
      expect(auditHtml).toContain('DS_NO_MATCHING_DNSKEY');
      expect(auditHtml).toContain('Inspect CD=0 Wire Packet');
      expect(auditHtml).toContain('Inspect Wire');

      const responsesHtml = renderToStaticMarkup(<ResponsesPanel snapshot={cfSnap} />);
      expect(responsesHtml).toContain('HEADER');
      expect(responsesHtml).toContain('application/dns-message');
      expect(responsesHtml).toContain('Zonefile (.zone)');
      expect(responsesHtml).toContain('Export .zone');
      expect(responsesHtml).toContain('dig +dnssec +multi');
      expect(responsesHtml).toContain('Decode ?dns= / Hex');
      expect(responsesHtml).toContain('data-testid="wire-query-search"');
      expect(responsesHtml).toContain('data-testid="wire-filter-pill-all"');
      expect(responsesHtml).toContain('data-testid="wire-filter-pill-target"');
      expect(responsesHtml).toContain('data-testid="wire-filter-pill-dnssec"');
      expect(responsesHtml).toContain('data-testid="wire-filter-pill-errors"');

      const dnskeyQuery =
        cfSnap.queries.find((q) => q.qtypeName === 'DNSKEY' && q.qname === 'iana.org.') ??
        cfSnap.queries[0];
      const focusedHexHtml = renderToStaticMarkup(
        <ResponsesPanel
          snapshot={cfSnap}
          focusedQuery={{ queryId: dnskeyQuery.id, mode: 'hex-resp', seq: 1 }}
        />
      );
      expect(focusedHexHtml).toContain(
        `DNS Response Wire — ${dnskeyQuery.qname} ${dnskeyQuery.qtypeName}`
      );
      expect(focusedHexHtml).toContain('16-Bit Header Flags Register');

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
      expect(dissectorHtml).toContain('data-testid="wire-inspector-banner"');
      expect(dissectorHtml).toContain('sticky top-0 z-20');
      expect(dissectorHtml).toContain('data-wire-sizer="candidate"');
      expect(dissectorHtml).toContain('Pointer Trace:');
      expect(dissectorHtml).toContain('data-testid="wire-hex-grid"');
      expect(dissectorHtml).toContain('data-bytes-per-row="16"');
      expect(dissectorHtml).toContain('data-testid="wire-grid-width-8"');
      expect(dissectorHtml).toContain('data-testid="wire-grid-width-16"');
      expect(dissectorHtml).toContain('data-testid="wire-grid-ruler"');

      const zonesHtml = renderToStaticMarkup(<ZonesPanel snapshot={cfSnap} />);
      expect(zonesHtml).toContain('. (Root Zone)');
      expect(zonesHtml).toContain('RFC 1912 / 2308 OK');
      expect(zonesHtml).toContain('IN SYNC WITH PARENT DS');
      expect(zonesHtml).toContain('AS13335');
      expect(zonesHtml).toContain('RFC 1035 Master Zonefile Export');
      expect(zonesHtml).toContain('Export Zonefile (.zone)');
      expect(zonesHtml).toContain('data-testid="zones-jump-bar"');
      expect(zonesHtml).toContain('data-testid="zone-jump-chip-root"');
      expect(zonesHtml).toContain('data-testid="zones-toggle-all"');
      expect(zonesHtml).toContain('data-testid="zone-toggle-root"');

      const inspectorHtml = renderToStaticMarkup(
        <GraphInspector
          selection={{ kind: 'zone', zone: cfSnap.zones[0] }}
          dohEndpoint={cfSnap.dohEndpoint}
          capturedAt={cfSnap.capturedAt}
          validatedAt={cfSnap.validatedAt}
          queries={cfSnap.queries}
          onInspectWireQuery={() => {}}
          onClose={() => {}}
        />
      );
      expect(inspectorHtml).toContain('CLI Reproducer');
      expect(inspectorHtml).toContain('dig +dnssec +multi');
      expect(inspectorHtml).toContain('Recorded DoH Wire Packet');
      expect(inspectorHtml).toContain('Inspect dig');
      expect(inspectorHtml).toContain('Dissect Hex');

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
    expect(swCode).toContain('digdeep-shell-v30');
    expect(swCode).toContain('application/dns-message');

    // Verify App renders offline badge, clear button, and synchronized PSL overlay when navigator.onLine is false
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
      expect(appHtml).toContain('data-testid="omnibox-clear-button"');
      expect(appHtml).toContain('aria-label="Clear search input"');
      expect(appHtml).toContain('data-testid="search-public-suffix"');
      expect(appHtml).toContain('>eu</span>');
      expect(appHtml).not.toContain('data-testid="omnibox-dropdown"');
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
    expect(indexHtml).toContain('<noscript>');
    expect(indexHtml).toContain('OPENPGPKEY');
    expect(indexHtml).toContain('SMIMEA');
    expect(indexHtml).toContain('Certificate Transparency');
    expect(indexHtml).toContain('0xC0xx');

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
      expect(mailHtml).toContain('data-testid="mail-scorecard-jump-mx-dane"');
      expect(mailHtml).toContain('data-testid="mail-scorecard-jump-dane"');
      expect(mailHtml).toContain('data-testid="mail-scorecard-jump-spf"');
      expect(mailHtml).toContain('data-testid="mail-scorecard-jump-dkim"');
      expect(mailHtml).toContain('data-testid="mail-scorecard-jump-dmarc"');
      expect(mailHtml).toContain('data-testid="mail-section-jump-bar"');
      expect(mailHtml).toContain('data-testid="mail-toggle-all-sections"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-mx-dane"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-spf"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-dmarc"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-dkim"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-mta-sts"');
      expect(mailHtml).toContain('data-testid="mail-section-toggle-srv"');

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

      const emailSnap = await runDnsvizAnalysis('paul@nohats.ca');
      expect(emailSnap.emailDane).toBeDefined();
      const emailHtml = renderToStaticMarkup(
        <EmailDaneCard
          emailDane={emailSnap.emailDane!}
          onJumpToGraphTarget={() => {}}
          onInspectDomainMail={() => {}}
        />
      );
      expect(emailHtml).toContain('DANE Email Identity');
      expect(emailHtml).toContain('paul@nohats.ca');
      expect(emailHtml).toContain('0357513deb903a056e74a7e475247fc1ffe31d8be4c1d4a31f58dd47');
      expect(emailHtml).toContain('OPENPGPKEY');
      expect(emailHtml).toContain('SMIMEA');
      expect(emailHtml).toContain('DANE USABLE ✓');
      expect(emailHtml).toContain('Copy .asc');

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
      expect(webHtml).toContain('data-testid="web-scorecard-jump-https"');
      expect(webHtml).toContain('data-testid="web-scorecard-jump-caa"');
      expect(webHtml).toContain('data-testid="web-scorecard-jump-dane"');
      expect(webHtml).toContain('data-testid="web-scorecard-jump-sshfp"');
      expect(webHtml).toContain('data-testid="web-section-jump-bar"');
      expect(webHtml).toContain('data-testid="web-toggle-all-sections"');
      expect(webHtml).toContain('data-testid="web-section-toggle-https"');
      expect(webHtml).toContain('data-testid="web-section-toggle-caa"');
      expect(webHtml).toContain('data-testid="web-section-toggle-ct"');
      expect(webHtml).toContain('data-testid="web-section-toggle-dane"');
      expect(webHtml).toContain('data-testid="web-section-toggle-sshfp"');
      if (webSnap.ctLogFetch?.ok) {
        expect(webHtml).toContain('CT ↔ CAA COMPLIANT');
        expect(webHtml).toContain('CAA AUTHORIZED ✓');
      }

      const consensusSnap = await runConsensusAnalysis('iana.org');
      expect(consensusSnap.mode).toBe('consensus');
      expect(consensusSnap.consensusAnalysis).toBeDefined();
      expect(consensusSnap.consensusAnalysis?.ecsGeo).toBeDefined();
      const consensusHtml = renderToStaticMarkup(
        <ConsensusView
          snapshot={consensusSnap}
          onOpenChainGraph={() => {}}
          onOpenWireResponses={() => {}}
          onInspectWireQuery={() => {}}
        />
      );
      expect(consensusHtml).toContain('Multi-Resolver DoH Matrix for');
      expect(consensusHtml).toContain('Protective Filtering &amp; EDE');
      expect(consensusHtml).toContain('SOA Serial Propagation');
      expect(consensusHtml).toContain('DNSKEY &amp; Answer Sync');
      expect(consensusHtml).toContain('EDNS Client Subnet (ECS — RFC 7871)');
      expect(consensusHtml).toContain('71.252.0.0/24');
      expect(consensusHtml).toContain('0.0.0.0/0');
      expect(consensusHtml).toContain('Interactive Custom ECS Subnet Probe');
      expect(consensusHtml).toContain('Latency &amp; Wire');
      expect(consensusHtml).toContain('1.1.1.1');
      expect(consensusHtml).toContain('8.8.8.8');
      expect(consensusHtml).toContain('9.9.9.9');

      // Verify DoH Wire Waterfall category counts, search filters, and cross-tab query resolvers on Consensus snapshot
      const consensusResponsesHtml = renderToStaticMarkup(
        <ResponsesPanel snapshot={consensusSnap} />
      );
      expect(consensusResponsesHtml).toContain('data-testid="wire-filter-pill-consensus"');
      expect(consensusResponsesHtml).toContain('data-testid="wire-filter-pill-ecs"');

      const counts = computeWireQueryCategoryCounts(consensusSnap.queries);
      expect(counts.all).toBe(consensusSnap.queries.length);
      expect(counts.ecs).toBeGreaterThanOrEqual(14);
      expect(counts.consensus).toBeGreaterThan(0);
      expect(counts.dnssec).toBeGreaterThan(0);
      expect(counts.target).toBeGreaterThan(0);

      const ecsFiltered = filterDohQueryLogs(consensusSnap.queries, 'ecs', '71.252.0.0/24');
      expect(ecsFiltered.length).toBe(1);
      expect(ecsFiltered[0].ecsSubnet).toBe('71.252.0.0/24');

      const reachableSecondary = consensusSnap.consensusAnalysis!.resolvers.find(
        (r) => r.reachable && r.endpoint !== consensusSnap.dohEndpoint
      );
      expect(reachableSecondary).toBeDefined();
      const secondaryFiltered = filterDohQueryLogs(
        consensusSnap.queries,
        'consensus',
        `${reachableSecondary!.shortLabel} a`
      );
      expect(secondaryFiltered.length).toBeGreaterThanOrEqual(1);
      const providerFiltered = filterDohQueryLogs(
        consensusSnap.queries,
        'consensus',
        reachableSecondary!.provider
      );
      expect(providerFiltered.length).toBeGreaterThanOrEqual(1);

      const firstResolverRow = consensusSnap.consensusAnalysis!.resolvers[0];
      expect(findConsensusResolverWireQuery(firstResolverRow, consensusSnap)).toBeDefined();

      const firstEcsRow = consensusSnap.consensusAnalysis!.ecsGeo!.regions[0];
      const ecsRowQueries = findEcsRegionWireQueries(firstEcsRow, consensusSnap.queries);
      expect(ecsRowQueries.ipv4).toBeDefined();
      expect(ecsRowQueries.ipv6).toBeDefined();

      const graphBuilt = buildChainGraph(consensusSnap, {
        showSoaAndNs: true,
        showStandbyKeys: true,
      });
      const firstRrsetNode = graphBuilt.nodes.find((n) => n.kind === 'rrset');
      if (firstRrsetNode) {
        expect(
          findGraphSelectionWireQuery(
            { kind: 'node', node: firstRrsetNode },
            consensusSnap.queries
          )
        ).toBeDefined();
      }
      if (consensusSnap.findings.length > 0) {
        const anyMatchedFinding = consensusSnap.findings.some((f) =>
          Boolean(findAuditFindingWireQuery(f, consensusSnap))
        );
        expect(anyMatchedFinding).toBe(true);
      }

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
    45000
  );

  it('renders sticky wire-inspector-banner, auto-selects 8B compact hex grid on narrow mobile viewports, and toggles 8B/16B & byte pins cleanly', async () => {
    // 68-byte compressed DNS response for `www.example.org. IN A`
    const packetHex =
      '1a2b81a00001000200000000' +
      '03777777076578616d706c65036f72670000010001' +
      'c00c0005000100000e1000070465646765c010' +
      'c02d000100010000012c00045db8d822';
    const dissected = dissectDnsWirePacket(hexToBytes(packetHex));
    expect(dissected.wireSize).toBe(68);

    const prevWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    resetWireGridWidthPreference();
    try {
      // 1. Wide viewport (matchMedia matches: false) -> defaults to 16B/row (5 rows for 68 bytes)
      Object.defineProperty(globalThis, 'window', {
        value: {
          matchMedia: () => ({ matches: false }),
        },
        configurable: true,
      });
      const wideHtml = renderToStaticMarkup(
        <WirePacketDissectorView dissected={dissected} packetLabel="Wide Wire" />
      );
      expect(wideHtml).toContain('data-bytes-per-row="16"');
      expect(wideHtml).toContain('68 OCTETS · 16B/ROW');
      expect(wideHtml).toContain('data-row-offset="0000"');
      expect(wideHtml).toContain('data-row-offset="0010"');
      expect(wideHtml).toContain('data-row-offset="0040"');
      expect(wideHtml).not.toContain('data-row-offset="0008"');
      expect((wideHtml.match(/data-row-offset="/g) ?? []).length).toBe(5);

      // 2. Narrow mobile viewport (< 640px, matchMedia matches: true) -> auto-selects 8B/row (9 rows for 68 bytes)
      Object.defineProperty(globalThis, 'window', {
        value: {
          matchMedia: (q: string) => ({ matches: q.includes('639px') }),
        },
        configurable: true,
      });
      const mobileHtml = renderToStaticMarkup(
        <WirePacketDissectorView dissected={dissected} packetLabel="Mobile Wire" />
      );
      expect(mobileHtml).toContain('data-bytes-per-row="8"');
      expect(mobileHtml).toContain('68 OCTETS · 8B/ROW');
      expect(mobileHtml).toContain('data-row-offset="0000"');
      expect(mobileHtml).toContain('data-row-offset="0008"');
      expect(mobileHtml).toContain('data-row-offset="0018"');
      expect(mobileHtml).toContain('data-row-offset="0040"');
      expect((mobileHtml.match(/data-row-offset="/g) ?? []).length).toBe(9);

      // Verify ruler only renders columns 00..07 in 8B mode
      const { JSDOM } = (await import('jsdom' as string)) as {
        JSDOM: new (markup?: string) => { window: Window & typeof globalThis };
      };
      const mobileDom = new JSDOM(mobileHtml);
      const mobileBanner = mobileDom.window.document.querySelector(
        '[data-testid="wire-inspector-banner"]'
      )!;
      expect(mobileBanner.className).toContain('sticky');
      expect(mobileBanner.className).toContain('top-0');
      expect(mobileBanner.className).toContain('z-20');
      expect(
        mobileBanner.querySelectorAll('[data-wire-sizer="candidate"]').length
      ).toBeGreaterThan(0);

      const rulerCols = Array.from(
        mobileDom.window.document.querySelectorAll('[data-testid="wire-grid-ruler"] div span')
      ).map((el) => el.textContent);
      expect(rulerCols).toEqual(['00', '01', '02', '03', '04', '05', '06', '07', 'ASCII']);

      // 3. Interactive JSDOM mount: toggle 16B <-> 8B and pin/step/clear individual hex bytes
      const liveDom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>');
      Object.defineProperty(globalThis, 'window', {
        value: liveDom.window,
        configurable: true,
      });
      Object.defineProperty(globalThis, 'document', {
        value: liveDom.window.document,
        configurable: true,
      });
      (liveDom.window as unknown as { matchMedia: (q: string) => { matches: boolean } }).matchMedia =
        () => ({ matches: false });
      (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
        true;

      const { act } = await import('react');
      const { createRoot } = await import('react-dom/client');
      const container = liveDom.window.document.getElementById('root')!;
      const root = createRoot(container);

      await act(async () => {
        root.render(<WirePacketDissectorView dissected={dissected} packetLabel="Interactive Wire" />);
      });

      const gridEl = container.querySelector('[data-testid="wire-hex-grid"]')!;
      const btn8 = container.querySelector('[data-testid="wire-grid-width-8"]') as HTMLButtonElement;
      const btn16 = container.querySelector('[data-testid="wire-grid-width-16"]') as HTMLButtonElement;
      expect(gridEl.getAttribute('data-bytes-per-row')).toBe('16');
      expect(btn16.getAttribute('aria-pressed')).toBe('true');
      expect(container.querySelectorAll('[data-row-offset]').length).toBe(5);

      await act(async () => {
        btn8.click();
      });
      expect(gridEl.getAttribute('data-bytes-per-row')).toBe('8');
      expect(btn8.getAttribute('aria-pressed')).toBe('true');
      expect(container.querySelectorAll('[data-row-offset]').length).toBe(9);

      // Tap byte 0x000C (0x03 length prefix of "www"), then tap adjacent byte 0x000D ('w' = 0x77)
      const byte0c = container.querySelector(
        'button[title^="0x000C:"]'
      ) as HTMLButtonElement;
      const byte0d = container.querySelector(
        'button[title^="0x000D:"]'
      ) as HTMLButtonElement;
      expect(byte0c).toBeTruthy();
      expect(byte0d).toBeTruthy();

      await act(async () => {
        byte0c.click();
      });
      const liveBanner = container.querySelector('[data-testid="wire-inspector-banner"]')!;
      expect(liveBanner.textContent).toContain('Byte @0x000C = 0x03');
      expect(liveBanner.textContent).toContain('Pinned (clear)');

      await act(async () => {
        byte0d.click();
      });
      expect(liveBanner.textContent).toContain('Byte @0x000D = 0x77');
      expect(liveBanner.textContent).toContain('Pinned (clear)');

      // Tap same byte 0x000D again -> unpins cleanly
      await act(async () => {
        byte0d.click();
      });
      expect(liveBanner.textContent).not.toContain('Byte @0x000D = 0x77');
      expect(liveBanner.textContent).toContain('Tap or hover any hex byte');

      await act(async () => {
        btn16.click();
      });
      expect(gridEl.getAttribute('data-bytes-per-row')).toBe('16');

      await act(async () => {
        root.unmount();
      });
    } finally {
      resetWireGridWidthPreference();
      if (prevWindow) {
        Object.defineProperty(globalThis, 'window', prevWindow);
      } else {
        Reflect.deleteProperty(globalThis, 'window');
      }
      Reflect.deleteProperty(globalThis, 'document');
    }
  });

  it('supports mobile auto-collapse of healthy parent zones in ZonesPanel and tap-to-jump / accordion toggles in Mail, Web, and Zones views', async () => {
    const makeZone = (
      zoneName: string,
      parentZone: string | null,
      depth: number,
      overrides: Partial<ZoneAnalysis> = {}
    ): ZoneAnalysis => ({
      zoneName,
      parentZone,
      depth,
      status: 'secure',
      statusReason: 'Validated DNSSEC chain',
      nsecMode: 'NSEC',
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [],
      negativeNodes: [],
      nameservers: [
        {
          hostname: `a.ns.${zoneName === '.' ? 'iana.org.' : zoneName}`,
          ipv4: ['192.0.2.53'],
          ipv6: [],
          status: 'ok',
        },
      ],
      ...overrides,
    });

    const zonesFixture: AnalysisSnapshot = {
      id: 'snap-mobile-51',
      version: 1,
      mode: 'dnssec',
      targetName: 'www.example.org.',
      displayDomain: 'www.example.org',
      queryTypes: ['A'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      capturedAt: 1700000000000,
      validatedAt: 1700000000000,
      durationMs: 120,
      overallStatus: 'secure',
      overallSummary: 'Secure delegation chain',
      zones: [
        makeZone('.', null, 0),
        makeZone('org.', '.', 1),
        makeZone('example.org.', 'org.', 2),
        // CNAME branch where intermediate net. has a SOA timer warning -> must NOT auto-collapse!
        makeZone('net.', '.', 1, {
          soaAudit: {
            valid: false,
            issues: [
              {
                parameter: 'expire',
                value: 3600,
                severity: 'warning',
                message: 'SOA expire below RFC 1912 minimum',
                rfc: 'RFC 1912',
              },
            ],
            summary: 'SOA timer warning',
          },
        }),
        makeZone('cloudflare.net.', 'net.', 2),
      ],
      cnameEdges: [],
      findings: [],
      queries: [],
      trustAnchorsUsed: [],
      mailAnalysis: {
        mxStatus: 'valid',
        mxDnssecStatus: 'secure',
        mxHosts: [
          {
            preference: 10,
            exchange: 'mail.example.org.',
            displayExchange: 'mail.example.org',
            isNullMx: false,
            isIpLiteral: false,
            cnameChain: [],
            addresses: [{ ip: '192.0.2.25', family: 4, isPublic: false }],
            ipv4Status: 'secure',
            ipv6Status: 'insecure',
            addressRrsetIds: [],
            dane: {
              qname: '_25._tcp.mail.example.org.',
              resolvedOwner: '_25._tcp.mail.example.org.',
              cnameChain: [],
              status: 'no-tlsa-secure',
              dnssecStatus: 'secure',
              records: [],
              rolloverReady: false,
              summary: 'No _25._tcp TLSA published',
            },
          },
        ],
        daneStatus: 'not-deployed',
        daneSummary: 'No DANE TLSA; MTA-STS enforce active.',
        spf: {
          present: true,
          verdict: 'strict-fail',
          dnsLookupCount: 1,
          dnsLookupLimit: 10,
          voidLookupCount: 0,
          voidLookupLimit: 2,
          dnssecStatus: 'secure',
          rawRecord: 'v=spf1 mx -all',
          allSpfRecords: ['v=spf1 mx -all'],
          legacySpfRecords: [],
          effectiveAllQualifier: '-',
          rootNode: {
            domain: 'example.org.',
            displayDomain: 'example.org',
            via: 'root',
            depth: 0,
            spfRecords: ['v=spf1 mx -all'],
            dnssecStatus: 'secure',
            terms: [
              { raw: 'v=spf1', kind: 'version', countsTowardLookupLimit: false, syntaxValid: true },
              {
                raw: 'mx',
                kind: 'mechanism',
                qualifier: '+',
                mechanism: 'mx',
                countsTowardLookupLimit: true,
                syntaxValid: true,
              },
              {
                raw: '-all',
                kind: 'mechanism',
                qualifier: '-',
                mechanism: 'all',
                countsTowardLookupLimit: false,
                syntaxValid: true,
              },
            ],
          },
          summary: 'Strict -all SPF policy (1/10 lookups).',
        },
        dmarc: {
          present: true,
          verdict: 'reject',
          queriedOwner: '_dmarc.example.org.',
          effectiveOwner: '_dmarc.example.org.',
          cnameChain: [],
          usedOrgFallback: false,
          dnssecStatus: 'secure',
          rawRecord: 'v=DMARC1; p=reject;',
          allDmarcRecords: ['v=DMARC1; p=reject;'],
          policy: 'reject',
          adkim: 'r',
          aspf: 'r',
          pct: 100,
          rua: [],
          ruf: [],
          fo: '0',
          ri: 86400,
          tags: [
            { tag: 'v', value: 'DMARC1', known: true, valid: true },
            { tag: 'p', value: 'reject', known: true, valid: true },
          ],
          issues: [],
          summary: 'Strict p=reject DMARC policy.',
        },
        dkim: {
          status: 'verified',
          probedSelectors: ['selector1'],
          customSelectors: [],
          selectors: [
            {
              selector: 'selector1',
              source: 'auto',
              qname: 'selector1._domainkey.example.org.',
              resolvedOwner: 'selector1._domainkey.example.org.',
              cnameChain: [],
              present: true,
              status: 'valid',
              dnssecStatus: 'secure',
              rawRecord: 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
              allRecords: ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='],
              version: 'DKIM1',
              keyType: 'ed25519',
              keyBits: 256,
              flags: [],
              isTestingMode: false,
              isStrictSubdomain: false,
              issues: [],
              summary: 'Valid Ed25519 DKIM key',
            },
          ],
          summary: '1 active DKIM selector verified.',
        },
        mtaSts: {
          present: true,
          status: 'enforce',
          qname: '_mta-sts.example.org.',
          resolvedOwner: '_mta-sts.example.org.',
          cnameChain: [],
          dnssecStatus: 'secure',
          rawRecord: 'v=STSv1; id=20261112;',
          allStsRecords: ['v=STSv1; id=20261112;'],
          version: 'STSv1',
          policyId: '20261112',
          extensions: [],
          policyUrl: 'https://mta-sts.example.org/.well-known/mta-sts.txt',
          policy: {
            version: 'STSv1',
            mode: 'enforce',
            maxAge: 604800,
            mxPatterns: ['mail.example.org'],
            matchedMxHosts: ['mail.example.org'],
            unmatchedMxHosts: [],
            valid: true,
            issues: [],
          },
          issues: [],
          summary: 'MTA-STS enforce mode active.',
        },
        tlsRpt: {
          present: true,
          status: 'valid',
          qname: '_smtp._tls.example.org.',
          resolvedOwner: '_smtp._tls.example.org.',
          cnameChain: [],
          dnssecStatus: 'secure',
          rawRecord: 'v=TLSRPTv1; rua=mailto:tlsrpt@example.org',
          allTlsRptRecords: ['v=TLSRPTv1; rua=mailto:tlsrpt@example.org'],
          version: 'TLSRPTv1',
          rua: [
            {
              raw: 'mailto:tlsrpt@example.org',
              uri: 'mailto:tlsrpt@example.org',
              scheme: 'mailto',
              syntaxValid: true,
            },
          ],
          extensions: [],
          issues: [],
          summary: 'TLS-RPT configured.',
        },
        bimi: {
          present: false,
          status: 'not-deployed',
          selector: 'default',
          qname: 'default._bimi.example.org.',
          resolvedOwner: 'default._bimi.example.org.',
          cnameChain: [],
          dnssecStatus: 'secure',
          allBimiRecords: [],
          dmarcEligible: true,
          dmarcEligibilityReason: 'DMARC p=reject (100%)',
          issues: [],
          summary: 'No BIMI record published.',
        },
        fcrdnsSummary: {
          checkedIpCount: 1,
          validCount: 1,
          noPtrCount: 0,
          mismatchCount: 0,
          status: 'all-valid',
          summary: '1/1 FCrDNS verified',
        },
        srvDiscovery: {
          probedCount: 1,
          activeCount: 1,
          disabledCount: 0,
          services: [
            {
              prefix: '_submissions._tcp',
              qname: '_submissions._tcp.example.org.',
              label: 'SMTPS Submission',
              category: 'mail-submission',
              rfc: 'RFC 8314',
              present: true,
              status: 'active',
              dnssecStatus: 'secure',
              records: [{ priority: 0, weight: 1, port: 465, target: 'mail.example.org.', isNullService: false }],
            },
          ],
          summary: '1 active SRV endpoint discovered.',
        },
      },
      webAnalysis: {
        targetDomain: 'www.example.org.',
        displayDomain: 'www.example.org',
        cnameChain: ['www.example.org.cdn.cloudflare.net.'],
        ipv4Addresses: ['192.0.2.80'],
        ipv6Addresses: [],
        addressDnssecStatus: 'secure',
        httpsStatus: 'ech-enabled',
        httpsDnssecStatus: 'secure',
        httpsRecords: [
          {
            ownerName: 'www.example.org.',
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
            ipv4Hints: ['192.0.2.80'],
            ipv6Hints: [],
            ipv4HintsMatched: ['192.0.2.80'],
            ipv4HintsDrifted: [],
            ipv6HintsMatched: [],
            ipv6HintsDrifted: [],
            echConfigs: [],
            issues: [],
          },
        ],
        svcbRecords: [],
        supportsHttp3: true,
        supportsHttp2: true,
        echEnabled: true,
        echPublicNames: ['cloudflare-ech.com'],
        ipHintStatus: 'matched',
        httpsSummary: 'HTTPS Priority 1 with HTTP/3 and ECH.',
        caa: {
          status: 'enforced',
          effectiveOwner: 'example.org.',
          dnssecStatus: 'secure',
          hops: [
            {
              name: 'www.example.org.',
              displayName: 'www.example.org',
              depth: 0,
              dnssecStatus: 'secure',
              records: [],
              isEffectivePolicySource: false,
            },
            {
              name: 'example.org.',
              displayName: 'example.org',
              depth: 1,
              dnssecStatus: 'secure',
              records: [
                {
                  ownerName: 'example.org.',
                  flags: 0,
                  critical: false,
                  tag: 'issue',
                  rawValue: 'letsencrypt.org',
                  caDomain: 'letsencrypt.org',
                  parameters: [],
                  recognizedTag: true,
                  valid: true,
                  issues: [],
                },
              ],
              isEffectivePolicySource: true,
            },
          ],
          issueCas: ['letsencrypt.org'],
          issuewildCas: [],
          iodefUris: [],
          hasAcmeAccountBinding: false,
          hasCriticalUnknownTag: false,
          issues: [],
          summary: 'CAA policy inherited from example.org restricts issuance to letsencrypt.org.',
        },
        webDane: {
          qname: '_443._tcp.www.example.org.',
          resolvedOwner: '_443._tcp.www.example.org.',
          cnameChain: [],
          status: 'dane-valid',
          dnssecStatus: 'secure',
          records: [
            {
              ownerName: '_443._tcp.www.example.org.',
              ttl: 3600,
              usage: 3,
              usageMnemonic: 'DANE-EE',
              usageDescription: 'Domain-issued certificate',
              selector: 1,
              selectorMnemonic: 'SPKI',
              matchingType: 1,
              matchingTypeMnemonic: 'SHA2-256',
              certAssociationHex: 'a'.repeat(64),
              smtpRecommended: true,
              rdataValid: true,
              issues: [],
            },
          ],
          rolloverReady: false,
          summary: 'DANE-EE (3 1 1) TLSA active.',
        },
        sshfp: {
          present: true,
          status: 'secure',
          dnssecStatus: 'secure',
          records: [
            {
              ownerName: 'www.example.org.',
              ttl: 3600,
              algorithm: 4,
              algorithmName: 'Ed25519',
              fpType: 2,
              fpTypeName: 'SHA-256',
              fingerprintHex: 'b'.repeat(64),
              deprecated: false,
              valid: true,
              issues: [],
            },
          ],
          summary: '1 DNSSEC-validated SSHFP record.',
        },
        ctAnalysis: {
          status: 'caa-compliant',
          source: 'certspotter',
          queriedDomain: 'www.example.org',
          totalEntries: 1,
          activeCertCount: 1,
          expiredCertCount: 0,
          mismatchedActiveCertCount: 0,
          issuers: [
            {
              friendlyName: "Let's Encrypt",
              mappedCaaDomains: ['letsencrypt.org'],
              activeCertCount: 1,
              wildcardCertCount: 0,
              latestNotBefore: '2026-10-01T00:00:00Z',
              caaAuthorized: true,
              authorizedForIssue: true,
              authorizedForWildcard: false,
            },
          ],
          certificates: [],
          discoveredSubdomains: ['api.www.example.org'],
          tlsaMatchedCertCount: 1,
          summary: "1 active certificate issued by Let's Encrypt matches CAA policy.",
        },
      },
    };

    // Pure predicate verification:
    expect(isHealthyIntermediateParentZone(zonesFixture.zones[0], zonesFixture)).toBe(true); // .
    expect(isHealthyIntermediateParentZone(zonesFixture.zones[1], zonesFixture)).toBe(true); // org.
    expect(isHealthyIntermediateParentZone(zonesFixture.zones[2], zonesFixture)).toBe(false); // example.org. (leaf)
    expect(isHealthyIntermediateParentZone(zonesFixture.zones[3], zonesFixture)).toBe(false); // net. (SOA warning!)
    expect(isHealthyIntermediateParentZone(zonesFixture.zones[4], zonesFixture)).toBe(false); // cloudflare.net. (leaf)

    const prevWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    try {
      const { JSDOM } = (await import('jsdom' as string)) as {
        JSDOM: new (markup?: string) => { window: Window & typeof globalThis };
      };
      const liveDom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>');
      Object.defineProperty(globalThis, 'window', {
        value: liveDom.window,
        configurable: true,
      });
      Object.defineProperty(globalThis, 'document', {
        value: liveDom.window.document,
        configurable: true,
      });
      // Simulate narrow mobile (< 640px) viewport
      (liveDom.window as unknown as { matchMedia: (q: string) => { matches: boolean } }).matchMedia =
        (q: string) => ({ matches: q.includes('639px') });
      (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
        true;

      const scrolledIds: string[] = [];
      liveDom.window.HTMLElement.prototype.scrollIntoView = function (this: HTMLElement) {
        scrolledIds.push(this.id);
      };

      const { act } = await import('react');
      const { createRoot } = await import('react-dom/client');
      const container = liveDom.window.document.getElementById('root')!;
      const root = createRoot(container);

      // 1. ZonesPanel on narrow viewport: `.` and `org.` auto-collapsed; `example.org.`, `net.` (SOA warning), `cloudflare.net.` stay expanded!
      await act(async () => {
        root.render(<ZonesPanel snapshot={zonesFixture} />);
      });
      expect(
        container.querySelector('[data-testid="zone-card-root"]')?.getAttribute('data-collapsed')
      ).toBe('true');
      expect(
        container.querySelector('[data-testid="zone-card-org"]')?.getAttribute('data-collapsed')
      ).toBe('true');
      expect(
        container
          .querySelector('[data-testid="zone-card-example.org"]')
          ?.getAttribute('data-collapsed')
      ).toBe('false');
      expect(
        container.querySelector('[data-testid="zone-card-net"]')?.getAttribute('data-collapsed')
      ).toBe('false');
      expect(
        container
          .querySelector('[data-testid="zone-card-cloudflare.net"]')
          ?.getAttribute('data-collapsed')
      ).toBe('false');

      // Ensure no nested <button> inside <button> anywhere in ZonesPanel
      expect(container.querySelectorAll('button button').length).toBe(0);

      // Tap zone jump chip for Root -> auto-expands Root and scrolls #zone-card-root into view
      const rootChip = container.querySelector(
        '[data-testid="zone-jump-chip-root"]'
      ) as HTMLButtonElement;
      await act(async () => {
        rootChip.click();
        await new Promise((r) => setTimeout(r, 15));
      });
      expect(
        container.querySelector('[data-testid="zone-card-root"]')?.getAttribute('data-collapsed')
      ).toBe('false');
      expect(scrolledIds).toContain('zone-card-root');

      // Tap Expand All (since org. is still collapsed) -> expands every zone
      const zonesToggleAll = container.querySelector(
        '[data-testid="zones-toggle-all"]'
      ) as HTMLButtonElement;
      expect(zonesToggleAll.textContent).toContain('Expand All');
      await act(async () => {
        zonesToggleAll.click();
      });
      expect(
        container.querySelector('[data-testid="zone-card-org"]')?.getAttribute('data-collapsed')
      ).toBe('false');
      expect(zonesToggleAll.textContent).toContain('Collapse All');

      // 2. MailAnalysisView: Collapse All, then tap Scorecard SPF & Scorecard DANE (which routes to MTA-STS when DANE is not-deployed + MTA-STS present)
      scrolledIds.length = 0;
      await act(async () => {
        root.render(
          <MailAnalysisView
            snapshot={zonesFixture}
            onJumpToGraphTarget={() => {}}
            onOpenChainGraph={() => {}}
          />
        );
      });
      expect(container.querySelectorAll('button button').length).toBe(0);

      const mailToggleAll = container.querySelector(
        '[data-testid="mail-toggle-all-sections"]'
      ) as HTMLButtonElement;
      expect(mailToggleAll.textContent).toContain('Collapse All');
      await act(async () => {
        mailToggleAll.click();
      });
      expect(mailToggleAll.textContent).toContain('Expand All');
      expect(
        container
          .querySelector('[data-testid="mail-section-toggle-spf"]')
          ?.getAttribute('aria-expanded')
      ).toBe('false');
      expect(container.textContent).not.toContain('Interactive SPF Sender IP Evaluator');

      // Tap SPF scorecard card -> auto-expands SPF section and scrolls #mail-section-spf
      const spfScorecardBtn = container.querySelector(
        '[data-testid="mail-scorecard-jump-spf"]'
      ) as HTMLButtonElement;
      await act(async () => {
        spfScorecardBtn.click();
        await new Promise((r) => setTimeout(r, 15));
      });
      expect(
        container
          .querySelector('[data-testid="mail-section-toggle-spf"]')
          ?.getAttribute('aria-expanded')
      ).toBe('true');
      expect(container.textContent).toContain('Interactive SPF Sender IP Evaluator');
      expect(scrolledIds).toContain('mail-section-spf');

      // Tap DANE & MTA-STS scorecard card -> auto-expands #mail-section-mta-sts (since DANE is not-deployed and MTA-STS is active)
      const daneScorecardBtn = container.querySelector(
        '[data-testid="mail-scorecard-jump-dane"]'
      ) as HTMLButtonElement;
      await act(async () => {
        daneScorecardBtn.click();
        await new Promise((r) => setTimeout(r, 15));
      });
      expect(
        container
          .querySelector('[data-testid="mail-section-toggle-mta-sts"]')
          ?.getAttribute('aria-expanded')
      ).toBe('true');
      expect(scrolledIds).toContain('mail-section-mta-sts');

      // 3. WebAnalysisView: Collapse All, then tap CAA scorecard card & CT jump chip -> auto-expands & scrolls
      scrolledIds.length = 0;
      await act(async () => {
        root.render(
          <WebAnalysisView
            snapshot={zonesFixture}
            onJumpToGraphTarget={() => {}}
            onOpenChainGraph={() => {}}
          />
        );
      });
      expect(container.querySelectorAll('button button').length).toBe(0);

      const webToggleAll = container.querySelector(
        '[data-testid="web-toggle-all-sections"]'
      ) as HTMLButtonElement;
      expect(webToggleAll.textContent).toContain('Collapse All');
      await act(async () => {
        webToggleAll.click();
      });
      expect(webToggleAll.textContent).toContain('Expand All');
      expect(
        container
          .querySelector('[data-testid="web-section-toggle-caa"]')
          ?.getAttribute('aria-expanded')
      ).toBe('false');
      expect(container.textContent).not.toContain('RFC 8659 §3 Climb Order:');

      const caaScorecardBtn = container.querySelector(
        '[data-testid="web-scorecard-jump-caa"]'
      ) as HTMLButtonElement;
      await act(async () => {
        caaScorecardBtn.click();
        await new Promise((r) => setTimeout(r, 15));
      });
      expect(
        container
          .querySelector('[data-testid="web-section-toggle-caa"]')
          ?.getAttribute('aria-expanded')
      ).toBe('true');
      expect(container.textContent).toContain('RFC 8659 §3 Climb Order:');
      expect(scrolledIds).toContain('web-section-caa');

      const ctJumpChip = container.querySelector(
        '[data-testid="web-jump-chip-ct"]'
      ) as HTMLButtonElement;
      await act(async () => {
        ctJumpChip.click();
        await new Promise((r) => setTimeout(r, 15));
      });
      expect(
        container
          .querySelector('[data-testid="web-section-toggle-ct"]')
          ?.getAttribute('aria-expanded')
      ).toBe('true');
      expect(scrolledIds).toContain('web-section-ct');

      await act(async () => {
        root.unmount();
      });
    } finally {
      if (prevWindow) {
        Object.defineProperty(globalThis, 'window', prevWindow);
      } else {
        Reflect.deleteProperty(globalThis, 'window');
      }
      Reflect.deleteProperty(globalThis, 'document');
    }
  });
});
