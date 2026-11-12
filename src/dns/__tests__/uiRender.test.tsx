import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { AuditPanel } from '../../components/AuditPanel';
import { ChainGraphView, prepareExportSvgElement } from '../../components/ChainGraphView';
import { ConsensusView } from '../../components/ConsensusView';
import { CryptoBlob, formatMiddleEllipsis } from '../../components/CryptoBlob';
import { EmailDaneCard } from '../../components/EmailDaneCard';
import { EmailHeaderVerifierCard } from '../../components/EmailHeaderVerifierCard';
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
import { ReportExportModal } from '../../components/ReportExportModal';
import { ResponsesPanel } from '../../components/ResponsesPanel';
import { ReverseDnsCard } from '../../components/ReverseDnsCard';
import { SettingsModal } from '../../components/SettingsModal';
import { StatusBadge } from '../../components/StatusBadge';
import { WebAnalysisView } from '../../components/WebAnalysisView';
import {
  resetWireGridWidthPreference,
  WirePacketDissectorView,
} from '../../components/WireDissectorView';
import { isHealthyIntermediateParentZone, ZonesPanel } from '../../components/ZonesPanel';
import { buildChainGraph } from '../../graph/layout';
import { DEFAULT_USER_SETTINGS, loadSnapshots, saveSnapshot } from '../../storage/historyStore';
import {
  buildDeepLinkSearch,
  buildShareUrl,
  parseDeepLinkParams,
} from '../../urlState';
import { runDnsvizAnalysis } from '../analyzer';
import { runConsensusAnalysis } from '../consensusAnalyzer';
import { base64ToBytes, bytesToBase64, hexToBytes } from '../encoding';
import { runMailAnalysis } from '../mailAnalyzer';
import type { AnalysisSnapshot, DohQueryLog, ZoneAnalysis } from '../types';
import { runWebAnalysis } from '../webAnalyzer';
import { buildDnsQuery, parseDnsPacket } from '../wire';
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
    expect(indexHtml).toContain('viewport-fit=cover');

    const indexCss = fs.readFileSync(new URL('../../index.css', import.meta.url), 'utf8') as string;
    expect(indexCss).toContain('env(safe-area-inset-top');
    expect(indexCss).toContain('env(safe-area-inset-bottom');

    const swCode = fs.readFileSync(new URL('../../../public/sw.js', import.meta.url), 'utf8') as string;
    expect(swCode).toContain('digdeep-shell-v37');
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
      expect(appHtml).toContain('safe-area-header');
      expect(appHtml).toContain('safe-area-footer');
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

  it('renders concise mobile navigation tab labels (< sm) and tap-to-expand + 1-tap Copy cryptographic blobs (#53)', async () => {
    // 1. Unit-verify formatMiddleEllipsis
    expect(formatMiddleEllipsis('00', 12, 10)).toEqual({ truncated: false, preview: '00' });
    const sampleSha256 = '0123456789abcdef'.repeat(4); // 64 hex chars
    const ellipsized = formatMiddleEllipsis(sampleSha256, 12, 10);
    expect(ellipsized.truncated).toBe(true);
    expect(ellipsized.preview).toBe('0123456789ab…6789abcdef');

    // 2. Verify App navigation tabs render concise < sm short labels alongside full sm:+ titles across Mail, Web & Consensus snapshots
    const baseSnap: AnalysisSnapshot = {
      id: 'snap-tabs-mail',
      version: 1,
      mode: 'mail',
      targetName: 'example.org.',
      displayDomain: 'example.org',
      queryTypes: ['MX', 'TXT'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      capturedAt: 1700000000000,
      validatedAt: 1700000000000,
      durationMs: 95,
      overallStatus: 'secure',
      overallSummary: 'Validated chain',
      zones: [
        {
          zoneName: '.',
          parentZone: null,
          depth: 0,
          status: 'secure',
          statusReason: 'Root KSK verified',
          nsecMode: 'NSEC',
          dnskeys: [
            {
              id: 'dnskey-root-20326',
              zone: '.',
              keyTag: 20326,
              flags: 257,
              algorithm: 8,
              protocol: 3,
              keySizeInfo: '2048-bit',
              publicKeyBase64:
                'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=',
              isSep: true,
              isZoneKey: true,
              isRevoked: false,
              role: 'trust-anchor',
              signsTypes: ['DNSKEY'],
              matchedByParentDs: true,
              status: 'secure',
              statusReason: 'Matches IANA trust anchor',
            },
          ],
          dsVerifications: [
            {
              id: 'ds-org-26974',
              ds: {
                kind: 'DS',
                keyTag: 26974,
                algorithm: 8,
                digestType: 2,
                digestHex: sampleSha256,
              },
              dsTtl: 86400,
              matchedKeyTag: 26974,
              targetKeyFound: true,
              computedDigestHex: sampleSha256,
              digestValid: true,
              status: 'secure',
              reason: 'Matches child SEP DNSKEY',
            },
          ],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [],
          zonemd: {
            present: true,
            status: 'valid-sync',
            dnssecStatus: 'secure',
            soaSerial: 2026111200,
            records: [
              {
                serial: 2026111200,
                scheme: 1,
                schemeName: 'SIMPLE',
                hashAlgorithm: 1,
                hashAlgorithmName: 'SHA-384',
                digestHex: 'ab'.repeat(48),
                digestByteLength: 48,
                digestLengthValid: true,
                serialMatchesSoa: true,
              },
            ],
            summary: 'Root ZONEMD SHA-384 matches SOA serial',
          },
        },
      ],
      cnameEdges: [],
      findings: [],
      queries: [],
      trustAnchorsUsed: [],
    };

    const prevWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    const prevClipboard = Object.getOwnPropertyDescriptor(globalThis.navigator, 'clipboard');
    try {
      mem.clear();
      saveSnapshot(baseSnap);
      Object.defineProperty(globalThis, 'window', {
        value: {
          location: { search: '', href: 'https://example.test/' },
          matchMedia: () => ({ matches: false }),
          addEventListener: () => {},
          removeEventListener: () => {},
        },
        configurable: true,
      });

      const mailAppHtml = renderToStaticMarkup(<App />);
      expect(mailAppHtml).toContain('data-testid="nav-tab-short-mail"');
      expect(mailAppHtml).toContain('>Mail</span>');
      expect(mailAppHtml).toContain('data-testid="nav-tab-full-mail"');
      expect(mailAppHtml).toContain('>Mail, DANE, SPF, DKIM &amp; DMARC</span>');
      expect(mailAppHtml).toContain('>Graph</span>');
      expect(mailAppHtml).toContain('>Audit</span>');
      expect(mailAppHtml).toContain('>Wire</span>');
      expect(mailAppHtml).toContain('>Zones</span>');
      expect(mailAppHtml).toContain('>History</span>');

      mem.clear();
      saveSnapshot({ ...baseSnap, id: 'snap-tabs-web', mode: 'web' });
      const webAppHtml = renderToStaticMarkup(<App />);
      expect(webAppHtml).toContain('data-testid="nav-tab-short-web"');
      expect(webAppHtml).toContain('>Web</span>');
      expect(webAppHtml).toContain('>Web, HTTPS/SVCB, ECH, CAA &amp; DANE</span>');

      mem.clear();
      saveSnapshot({ ...baseSnap, id: 'snap-tabs-consensus', mode: 'consensus' });
      const consensusAppHtml = renderToStaticMarkup(<App />);
      expect(consensusAppHtml).toContain('data-testid="nav-tab-short-consensus"');
      expect(consensusAppHtml).toContain('>Consensus</span>');
      expect(consensusAppHtml).toContain('>Multi-Resolver DoH Consensus &amp; EDE</span>');
      mem.clear();

      // 3. Interactive JSDOM test: tap-to-expand + 1-tap Copy on CryptoBlob & ZonesPanel / EmailDaneCard
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
      (liveDom.window as unknown as { matchMedia: (q: string) => { matches: boolean } }).matchMedia =
        () => ({ matches: false });
      (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
        true;

      const copiedTexts: string[] = [];
      Object.defineProperty(globalThis.navigator, 'clipboard', {
        value: {
          writeText: async (txt: string) => {
            copiedTexts.push(txt);
          },
        },
        configurable: true,
      });

      const { act } = await import('react');
      const { createRoot } = await import('react-dom/client');
      const container = liveDom.window.document.getElementById('root')!;
      const root = createRoot(container);

      await act(async () => {
        root.render(
          <div>
            <ZonesPanel snapshot={baseSnap} />
            <CryptoBlob
              value={sampleSha256}
              headChars={12}
              tailChars={10}
              copyLabel="Copy Digest"
              testId="crypto-unit-blob"
            />
            <EmailDaneCard
              emailDane={{
                inputKind: 'email',
                email: 'alice@example.org',
                localPart: 'alice',
                domain: 'example.org.',
                exactHashHex: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e88',
                smimea: {
                  protocol: 'SMIMEA',
                  rfc: 'RFC 8162',
                  queriedOwner:
                    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e88._smimecert.example.org.',
                  resolvedOwner:
                    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e88._smimecert.example.org.',
                  usedLowercaseFallback: false,
                  cnameChain: [],
                  status: 'present',
                  dnssecStatus: 'secure',
                  daneUsable: true,
                  records: [
                    {
                      index: 0,
                      ttl: 3600,
                      usage: 3,
                      usageMnemonic: 'DANE-EE',
                      usageName: 'Domain-issued certificate',
                      selector: 1,
                      selectorMnemonic: 'SPKI',
                      selectorName: 'SubjectPublicKeyInfo',
                      matchingType: 1,
                      matchingMnemonic: 'SHA2-256',
                      matchingName: 'SHA-256 hash',
                      certAssociationHex: sampleSha256,
                      byteLength: 32,
                      digestLengthValid: true,
                    },
                  ],
                  cliVerifyCommand: 'dig +dnssec SMIMEA',
                },
                summary: 'DNSSEC-validated SMIMEA record.',
              }}
            />
          </div>
        );
      });

      // Ensure zero nested <button> inside <button>
      expect(container.querySelectorAll('button button').length).toBe(0);

      // Verify ZonesPanel DNSKEY public key blob starts collapsed even on desktop (`collapseOnDesktop`), expands on click, and copies full Base64 key
      const dnskeyBlob = container.querySelector('[data-testid="crypto-dnskey-root-20326"]')!;
      expect(dnskeyBlob.getAttribute('data-expanded')).toBe('false');
      expect(dnskeyBlob.textContent).toContain('AwEAAagAIK…Uk1ihz0=');

      const dnskeyToggle = container.querySelector(
        '[data-testid="crypto-dnskey-root-20326-toggle"]'
      ) as HTMLButtonElement;
      await act(async () => {
        dnskeyToggle.click();
      });
      expect(dnskeyBlob.getAttribute('data-expanded')).toBe('true');
      expect(
        container.querySelector('[data-testid="crypto-dnskey-root-20326-expanded-full"]')
          ?.textContent
      ).toBe(baseSnap.zones[0].dnskeys[0].publicKeyBase64);

      const dnskeyCopy = container.querySelector(
        '[data-testid="crypto-dnskey-root-20326-copy"]'
      ) as HTMLButtonElement;
      await act(async () => {
        dnskeyCopy.click();
      });
      expect(copiedTexts.at(-1)).toBe(baseSnap.zones[0].dnskeys[0].publicKeyBase64);
      expect(dnskeyCopy.textContent).toContain('Copied');

      // Verify responsive CryptoBlob (< sm middle-ellipsis toggle + 1-tap Copy) expands & collapses cleanly
      const unitBlob = container.querySelector('[data-testid="crypto-unit-blob"]')!;
      const unitToggle = container.querySelector(
        '[data-testid="crypto-unit-blob-toggle"]'
      ) as HTMLButtonElement;
      expect(unitBlob.getAttribute('data-expanded')).toBe('false');
      expect(unitToggle.getAttribute('aria-expanded')).toBe('false');
      expect(unitToggle.textContent).toContain('0123456789ab…6789abcdef');

      await act(async () => {
        unitToggle.click();
      });
      expect(unitBlob.getAttribute('data-expanded')).toBe('true');
      expect(
        container.querySelector('[data-testid="crypto-unit-blob-expanded-full"]')?.textContent
      ).toBe(sampleSha256);

      // Collapse back
      const unitCollapseBtn = container.querySelector(
        '[data-testid="crypto-unit-blob-toggle"]'
      ) as HTMLButtonElement;
      expect(unitCollapseBtn.getAttribute('aria-expanded')).toBe('true');
      await act(async () => {
        unitCollapseBtn.click();
      });
      expect(unitBlob.getAttribute('data-expanded')).toBe('false');

      // Verify EmailDaneCard SMIMEA digest association CryptoBlob copy
      const smimeaCopyBtn = container.querySelector(
        '[data-testid="crypto-smimea-assoc-0-copy"]'
      ) as HTMLButtonElement;
      await act(async () => {
        smimeaCopyBtn.click();
      });
      expect(copiedTexts.at(-1)).toBe(sampleSha256);

      await act(async () => {
        root.unmount();
      });
    } finally {
      mem.clear();
      if (prevClipboard) {
        Object.defineProperty(globalThis.navigator, 'clipboard', prevClipboard);
      } else {
        Reflect.deleteProperty(globalThis.navigator, 'clipboard');
      }
      if (prevWindow) {
        Object.defineProperty(globalThis, 'window', prevWindow);
      } else {
        Reflect.deleteProperty(globalThis, 'window');
      }
      Reflect.deleteProperty(globalThis, 'document');
    }
  });

  it('supports mobile master-detail view switching and sticky Prev/Next packet navigation in ResponsesPanel', async () => {
    const { JSDOM } = (await import('jsdom' as string)) as {
      JSDOM: new (markup?: string) => { window: Window & typeof globalThis };
    };
    const { createRoot } = await import('react-dom/client');
    const { act } = await import('react');

    const makeLog = (
      id: string,
      qname: string,
      qtype: number,
      qtypeName: string,
      purpose: string,
      latencyMs: number
    ): DohQueryLog => {
      const reqBytes = buildDnsQuery(qname, qtype, { id: 0x1234 });
      const respBytes = new Uint8Array(reqBytes);
      respBytes[2] = 0x81; // QR=1, RD=1
      respBytes[3] = 0xa0; // RA=1, AD=1, RCODE=0
      const packet = parseDnsPacket(respBytes);
      return {
        id,
        qname,
        qtype,
        qtypeName,
        cd: false,
        doBit: true,
        endpoint: 'https://cloudflare-dns.com/dns-query',
        startedAt: 1700000000000,
        latencyMs,
        httpStatus: 200,
        wireBase64: bytesToBase64(respBytes),
        requestWireBase64: bytesToBase64(reqBytes),
        packet,
        purpose,
      };
    };

    const queries: DohQueryLog[] = [
      makeLog('q-1', 'example.org.', 1, 'A', 'Target RRset query', 18),
      makeLog('q-2', 'example.org.', 48, 'DNSKEY', 'Zone DNSKEY query', 24),
      makeLog('q-3', 'example.org.', 43, 'DS', 'Parent DS delegation query', 21),
      makeLog('q-4', 'example.org.', 28, 'AAAA', 'Target IPv6 RRset query', 15),
    ];

    const snap: AnalysisSnapshot = {
      id: 'snap-wire-master-detail-test',
      version: 1,
      capturedAt: 1700000000000,
      validatedAt: 1700000000000,
      durationMs: 42,
      targetName: 'example.org.',
      displayDomain: 'example.org',
      mode: 'dnssec',
      queryTypes: ['A', 'AAAA'],
      dohEndpoint: 'https://cloudflare-dns.com/dns-query',
      overallStatus: 'secure',
      overallSummary: 'DNSSEC chain verified',
      zones: [],
      cnameEdges: [],
      findings: [],
      queries,
      trustAnchorsUsed: [],
    };

    // 1. SSR checks: default browse starts in mobile 'list' pane; focusedQuery starts in 'detail' pane
    const defaultSsr = renderToStaticMarkup(<ResponsesPanel snapshot={snap} />);
    expect(defaultSsr).toContain('data-mobile-pane="list"');
    expect(defaultSsr).toContain('data-testid="wire-mobile-nav-bar"');
    expect(defaultSsr).toContain('All Queries (1/4)');

    const focusedSsr = renderToStaticMarkup(
      <ResponsesPanel
        snapshot={snap}
        focusedQuery={{ queryId: 'q-3', mode: 'hex-resp', seq: 1 }}
      />
    );
    expect(focusedSsr).toContain('data-mobile-pane="detail"');
    expect(focusedSsr).toContain('All Queries (3/4)');

    const customWireSsr = renderToStaticMarkup(
      <ResponsesPanel
        snapshot={snap}
        externalCustomWire={{ payload: '1a2b81a000010000000000000000010001', seq: 1 }}
      />
    );
    expect(customWireSsr).toContain('data-mobile-pane="detail"');

    // 2. Interactive JSDOM flow: Waterfall list -> tap row -> Prev/Next steppers -> Back -> Filtered Prev/Next
    const prevWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    try {
      const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>');
      (globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;
      Object.defineProperty(globalThis, 'window', { value: dom.window, configurable: true });
      Object.defineProperty(globalThis, 'document', {
        value: dom.window.document,
        configurable: true,
      });

      const container = dom.window.document.getElementById('root')!;
      const root = createRoot(container);

      await act(async () => {
        root.render(<ResponsesPanel snapshot={snap} resetToListSeq={0} />);
      });

      const getPanel = () => container.querySelector('[data-testid="wire-responses-panel"]')!;
      const getWaterfallPane = () =>
        container.querySelector('[data-testid="wire-waterfall-pane"]')!;
      const getDetailPane = () => container.querySelector('[data-testid="wire-detail-pane"]')!;
      const getBackBtn = () =>
        container.querySelector('[data-testid="wire-mobile-back"]') as HTMLButtonElement;
      const getPrevBtn = () =>
        container.querySelector('[data-testid="wire-mobile-prev"]') as HTMLButtonElement;
      const getNextBtn = () =>
        container.querySelector('[data-testid="wire-mobile-next"]') as HTMLButtonElement;
      const getSummary = () => container.querySelector('[data-testid="wire-mobile-active-summary"]');

      // Starts on mobile waterfall list
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('list');
      expect(getWaterfallPane().classList.contains('flex')).toBe(true);
      expect(getWaterfallPane().classList.contains('hidden')).toBe(false);
      expect(getDetailPane().classList.contains('hidden')).toBe(true);
      expect(getDetailPane().classList.contains('lg:flex')).toBe(true);

      // Tap query row q-2 (DNSKEY) -> switches to mobile detail pane at (2/4)
      const row2 = container.querySelector('[data-query-id="q-2"]') as HTMLButtonElement;
      await act(async () => {
        row2.click();
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('detail');
      expect(getWaterfallPane().classList.contains('hidden')).toBe(true);
      expect(getWaterfallPane().classList.contains('lg:flex')).toBe(true);
      expect(getDetailPane().classList.contains('flex')).toBe(true);
      expect(getDetailPane().classList.contains('hidden')).toBe(false);
      expect(getBackBtn().textContent).toContain('All Queries (2/4)');
      expect(getSummary()?.textContent).toContain('DNSKEY');
      expect(getPrevBtn().disabled).toBe(false);
      expect(getNextBtn().disabled).toBe(false);

      // Step Next -> (3/4) DS -> (4/4) AAAA (Next becomes disabled)
      await act(async () => {
        getNextBtn().click();
      });
      expect(getBackBtn().textContent).toContain('All Queries (3/4)');
      expect(getSummary()?.textContent).toContain('DS');

      await act(async () => {
        getNextBtn().click();
      });
      expect(getBackBtn().textContent).toContain('All Queries (4/4)');
      expect(getSummary()?.textContent).toContain('AAAA');
      expect(getNextBtn().disabled).toBe(true);
      expect(getPrevBtn().disabled).toBe(false);

      // Step Prev back to (1/4) -> Prev becomes disabled
      for (let i = 0; i < 3; i += 1) {
        await act(async () => {
          getPrevBtn().click();
        });
      }
      expect(getBackBtn().textContent).toContain('All Queries (1/4)');
      expect(getPrevBtn().disabled).toBe(true);

      // Tap "All Queries (1/4)" back button -> returns to Waterfall list
      await act(async () => {
        getBackBtn().click();
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('list');

      // Filter waterfall to DNSSEC (q-2 DNSKEY & q-3 DS), tap q-2, and verify (1/2) -> (2/2) stepping
      const dnssecPill = container.querySelector(
        '[data-testid="wire-filter-pill-dnssec"]'
      ) as HTMLButtonElement;
      await act(async () => {
        dnssecPill.click();
      });
      const filteredRow2 = container.querySelector('[data-query-id="q-2"]') as HTMLButtonElement;
      await act(async () => {
        filteredRow2.click();
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('detail');
      expect(getBackBtn().textContent).toContain('All Queries (1/2)');
      expect(getPrevBtn().disabled).toBe(true);
      expect(getNextBtn().disabled).toBe(false);

      await act(async () => {
        getNextBtn().click();
      });
      expect(getBackBtn().textContent).toContain('All Queries (2/2)');
      expect(getSummary()?.textContent).toContain('DS');
      expect(getNextBtn().disabled).toBe(true);

      // Return to list, open offline decoder via mobile quick button, then reset via resetToListSeq
      await act(async () => {
        getBackBtn().click();
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('list');

      const openDecoderBtn = container.querySelector(
        '[data-testid="wire-mobile-open-decoder"]'
      ) as HTMLButtonElement;
      await act(async () => {
        openDecoderBtn.click();
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('detail');
      expect(container.textContent).toContain('Offline Raw DNS Wire Packet Decoder');

      await act(async () => {
        root.render(<ResponsesPanel snapshot={snap} resetToListSeq={1} />);
      });
      expect(getPanel().getAttribute('data-mobile-pane')).toBe('list');

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

  it('distinguishes POLICY ERROR from DNSSEC BOGUS in StatusBadge, App title/banner, and legacy snapshot loading', async () => {
    const policyBadgeHtml = renderToStaticMarkup(<StatusBadge status="policy-error" size="md" />);
    expect(policyBadgeHtml).toContain('POLICY ERROR');
    expect(policyBadgeHtml).not.toContain('BOGUS');

    const bogusBadgeHtml = renderToStaticMarkup(<StatusBadge status="bogus" size="md" />);
    expect(bogusBadgeHtml).toContain('BOGUS');

    const unsignedZone: ZoneAnalysis = {
      zoneName: 'example.com.',
      parentZone: 'com.',
      depth: 2,
      status: 'insecure',
      statusReason: 'Provably unsigned delegation',
      nsecMode: 'UNSIGNED',
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [],
      negativeNodes: [],
      nameservers: [],
    };

    const legacySpfPermerrorSnap: AnalysisSnapshot = {
      id: 'snap-legacy-spf-permerror',
      version: 1,
      mode: 'mail',
      targetName: 'example.com.',
      displayDomain: 'example.com',
      queryTypes: ['MX', 'TXT'],
      dohEndpoint: 'https://cloudflare-dns.com/dns-query',
      capturedAt: 1700000001000,
      validatedAt: 1700000001000,
      durationMs: 65,
      // Simulate a pre-fix snapshot stored in localStorage with overallStatus: 'bogus' despite unsigned DNSSEC
      overallStatus: 'bogus',
      overallSummary: 'Mail policy/DNS check failed: SPF policy exceeds 10-DNS-lookup limit (11 / 10 lookups).',
      zones: [unsignedZone],
      cnameEdges: [],
      findings: [
        {
          id: 'spf-limit-exceeded',
          severity: 'error',
          code: 'SPF_DNS_LOOKUP_LIMIT_EXCEEDED',
          title: 'SPF policy exceeds 10-DNS-lookup limit (11 / 10 lookups)',
          detail: 'RFC 7208 §4.6.4 limits SPF to 10 DNS-interactive lookups.',
          rfc: 'RFC 7208 §4.6.4',
        },
      ],
      queries: [],
      trustAnchorsUsed: [],
    };

    const realDnssecBogusSnap: AnalysisSnapshot = {
      ...legacySpfPermerrorSnap,
      id: 'snap-real-dnssec-bogus',
      capturedAt: 1700000000500,
      zones: [{ ...unsignedZone, status: 'bogus', statusReason: 'RRSIG verification failed' }],
    };

    const { JSDOM } = (await import('jsdom' as string)) as {
      JSDOM: new (
        markup?: string,
        options?: { url?: string }
      ) => { window: Window & typeof globalThis };
    };
    const { createRoot } = await import('react-dom/client');
    const { act } = await import('react');

    const prevWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    try {
      mem.clear();
      // Write raw pre-fix JSON directly into localStorage to verify loadSnapshots() migration
      globalThis.localStorage.setItem(
        'digdeep:history:v1',
        JSON.stringify([legacySpfPermerrorSnap, realDnssecBogusSnap])
      );
      const loaded = loadSnapshots();
      expect(loaded.find((s) => s.id === 'snap-legacy-spf-permerror')?.overallStatus).toBe(
        'policy-error'
      );
      expect(loaded.find((s) => s.id === 'snap-real-dnssec-bogus')?.overallStatus).toBe('bogus');

      const dom = new JSDOM(
        '<!doctype html><html><head><title></title></head><body><div id="root"></div></body></html>',
        { url: 'https://digdeep.fyi/' }
      );
      (dom.window as unknown as { matchMedia: (q: string) => { matches: boolean } }).matchMedia =
        () => ({ matches: false });
      (globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;
      Object.defineProperty(globalThis, 'window', { value: dom.window, configurable: true });
      Object.defineProperty(globalThis, 'document', {
        value: dom.window.document,
        configurable: true,
      });

      const container = dom.window.document.getElementById('root')!;
      const root = createRoot(container);

      await act(async () => {
        root.render(<App />);
      });

      expect(dom.window.document.title).toContain('example.com (POLICY ERROR)');
      expect(dom.window.document.title).not.toContain('example.com (BOGUS)');
      expect(container.textContent).toContain('POLICY ERROR');

      // Verify 1-Click Copy MD & CI / Report modal (#36)
      let copiedText = '';
      Object.defineProperty(globalThis.navigator, 'clipboard', {
        value: {
          writeText: async (txt: string) => {
            copiedText = txt;
          },
        },
        configurable: true,
      });

      const copyMdBtn = container.querySelector(
        '[data-testid="copy-markdown-report-btn"]'
      ) as HTMLButtonElement | null;
      expect(copyMdBtn).not.toBeNull();
      await act(async () => {
        copyMdBtn!.click();
      });
      expect(copiedText).toContain('# 🛑 DNS Diagnostic Report: `example.com` (POLICY ERROR)');
      expect(copiedText).toContain('SPF_DNS_LOOKUP_LIMIT_EXCEEDED');
      expect(container.textContent).toContain('Copied MD!');

      const openCiModalBtn = container.querySelector(
        '[data-testid="open-report-ci-modal-btn"]'
      ) as HTMLButtonElement | null;
      expect(openCiModalBtn).not.toBeNull();
      await act(async () => {
        openCiModalBtn!.click();
      });

      const modal = container.querySelector('[data-testid="report-export-modal"]');
      expect(modal).not.toBeNull();
      const preview = container.querySelector('[data-testid="report-modal-preview"]');
      expect(preview?.textContent).toContain('#!/usr/bin/env sh');

      // Switch to GitHub Actions (.yml) tab inside ReportExportModal
      const wfTab = container.querySelector(
        '[data-testid="report-modal-tab-workflow"]'
      ) as HTMLButtonElement | null;
      expect(wfTab).not.toBeNull();
      await act(async () => {
        wfTab!.click();
      });
      expect(preview?.textContent).toContain('name: "DNS Security Check (example.com)"');
      expect(preview?.textContent).toContain('workflow_dispatch:');

      // Switch to Incident Report (.md) tab and verify SSR rendering of ReportExportModal too
      const mdTab = container.querySelector(
        '[data-testid="report-modal-tab-markdown"]'
      ) as HTMLButtonElement | null;
      await act(async () => {
        mdTab!.click();
      });
      expect(preview?.textContent).toContain('## Audit Findings');

      const ssrModalHtml = renderToStaticMarkup(
        <ReportExportModal
          open={true}
          snapshot={realDnssecBogusSnap}
          initialTab="shell"
          onClose={() => {}}
        />
      );
      expect(ssrModalHtml).toContain('Incident Report &amp; CI Regression Check');
      expect(ssrModalHtml).toContain('RRSIG &gt;=');

      // Verify EmailHeaderVerifierCard SSR rendering with externalRawEmail expanded state
      const ssrVerifierHtml = renderToStaticMarkup(
        <EmailHeaderVerifierCard
          snapshot={realDnssecBogusSnap}
          externalRawEmail={{
            payload: 'From: test@example.com\nSubject: Hello',
            seq: 1,
          }}
        />
      );
      expect(ssrVerifierHtml).toContain('100% Local WebCrypto · Zero Upload');
      expect(ssrVerifierHtml).toContain('data-testid="email-verifier-textarea"');
      expect(ssrVerifierHtml).toContain('Verify DKIM / ARC / DMARC');
      expect(ssrVerifierHtml).toContain('text-base sm:text-xs');

      // Verify #44 mobile input zoom prevention & DNS keyboard attributes on App omnibox + PSL overlay
      const omniboxInput = container.querySelector(
        'input[aria-label="Search domain, URL, email, IP, CLI command, or DNS wire packet"]'
      ) as HTMLInputElement | null;
      expect(omniboxInput).not.toBeNull();
      expect(omniboxInput!.className).toContain('text-base sm:text-sm');
      expect(omniboxInput!.getAttribute('autocapitalize')).toBe('none');
      expect(omniboxInput!.getAttribute('autocorrect')).toBe('off');
      expect(omniboxInput!.getAttribute('spellcheck')).toBe('false');
      expect(omniboxInput!.getAttribute('enterkeyhint')).toBe('search');
      const pslOverlay = container.querySelector('[data-testid="search-psl-overlay"]');
      if (pslOverlay) {
        expect(pslOverlay.className).toContain('text-base sm:text-sm');
      }

      // Verify #50 native Web Share Sheet buttons when navigator.share is available
      const prevShare = Object.getOwnPropertyDescriptor(globalThis.navigator, 'share');
      let sharedPayload: { title?: string; text?: string; url?: string } | null = null;
      Object.defineProperty(globalThis.navigator, 'share', {
        value: async (data: { title?: string; text?: string; url?: string }) => {
          sharedPayload = data;
        },
        configurable: true,
      });
      try {
        const shareGraphHtml = renderToStaticMarkup(
          <ChainGraphView
            snapshot={realDnssecBogusSnap}
            theme="dark"
            filters={{ showSoaAndNs: false, showStandbyKeys: false }}
            onChangeFilters={() => {}}
          />
        );
        expect(shareGraphHtml).toContain('data-testid="share-png-diagram-btn"');

        // Re-render mounted App to expose share-deep-link-btn and invoke it
        await act(async () => {
          root.render(<App />);
        });
        const shareBtn = container.querySelector(
          '[data-testid="share-deep-link-btn"]'
        ) as HTMLButtonElement | null;
        expect(shareBtn).not.toBeNull();
        await act(async () => {
          shareBtn!.click();
        });
        expect(sharedPayload).not.toBeNull();
        expect(sharedPayload!.url).toContain('name=example.com');
      } finally {
        if (prevShare) {
          Object.defineProperty(globalThis.navigator, 'share', prevShare);
        } else {
          Reflect.deleteProperty(globalThis.navigator, 'share');
        }
      }

      // Verify #48 compact mobile action row, unclipped DohChooser popover, single-row RR Types, and tab scroll-fade hints
      const actionRow = container.querySelector('[data-testid="omnibox-action-row"]');
      expect(actionRow).not.toBeNull();
      const dohTrigger = actionRow!.querySelector('button[title^="Active DoH server:"]') as HTMLButtonElement | null;
      expect(dohTrigger).not.toBeNull();
      await act(async () => {
        dohTrigger!.click();
      });
      const dohPopover = container.querySelector('[data-testid="doh-chooser-popover"]');
      expect(dohPopover).not.toBeNull();
      expect(dohPopover!.className).toContain('left-0 sm:left-auto sm:right-0');
      await act(async () => {
        dohTrigger!.click();
      });

      const navScrollWrapper = container.querySelector('[data-testid="nav-tabs-scroll-wrapper"]');
      expect(navScrollWrapper).not.toBeNull();
      const navScrollInner = navScrollWrapper!.querySelector('.overflow-x-auto') as HTMLDivElement | null;
      expect(navScrollInner).not.toBeNull();
      Object.defineProperty(navScrollInner!, 'scrollWidth', {
        value: 780,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(navScrollInner!, 'clientWidth', {
        value: 340,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(navScrollInner!, 'scrollLeft', {
        value: 60,
        writable: true,
        configurable: true,
      });
      await act(async () => {
        navScrollInner!.dispatchEvent(new dom.window.Event('scroll', { bubbles: true }));
      });
      expect(container.querySelector('[data-testid="nav-tabs-fade-left"]')).not.toBeNull();
      expect(container.querySelector('[data-testid="nav-tabs-fade-right"]')).not.toBeNull();

      // Verify #54 bottom-sheet SettingsModal, dvh sizing, backdrop/Escape dismissal, and Back-gesture (popstate) dismissal
      const openSettingsBtn = container.querySelector(
        '[data-testid="open-settings-btn"]'
      ) as HTMLButtonElement | null;
      expect(openSettingsBtn).not.toBeNull();
      await act(async () => {
        openSettingsBtn!.click();
      });
      const settingsBackdrop = container.querySelector(
        '[data-testid="settings-modal"]'
      ) as HTMLDivElement | null;
      const settingsSheet = container.querySelector(
        '[data-testid="settings-modal-sheet"]'
      ) as HTMLDivElement | null;
      expect(settingsBackdrop).not.toBeNull();
      expect(settingsSheet).not.toBeNull();
      expect(settingsBackdrop!.className).toContain('items-end sm:items-center');
      expect(settingsSheet!.className).toContain('max-h-[92dvh]');
      expect(settingsSheet!.className).toContain('rounded-t-2xl sm:rounded-2xl');

      // Simulate mobile Back gesture (popstate): closes SettingsModal while keeping active snapshot intact
      await act(async () => {
        dom.window.dispatchEvent(new dom.window.PopStateEvent('popstate'));
      });
      expect(container.querySelector('[data-testid="settings-modal"]')).toBeNull();
      expect(container.textContent).toContain('example.com');

      // Re-open SettingsModal and dismiss via backdrop click
      await act(async () => {
        openSettingsBtn!.click();
      });
      const reopenedBackdrop = container.querySelector(
        '[data-testid="settings-modal"]'
      ) as HTMLDivElement | null;
      expect(reopenedBackdrop).not.toBeNull();
      await act(async () => {
        reopenedBackdrop!.click();
      });
      expect(container.querySelector('[data-testid="settings-modal"]')).toBeNull();

      // Verify #55 floating mobile quick-return / tab pill on deep scrolls (> 420px)
      expect(container.querySelector('[data-testid="mobile-floating-nav-pill"]')).toBeNull();
      let scrolledToTop = false;
      Object.defineProperty(dom.window, 'scrollY', { value: 600, configurable: true });
      Object.defineProperty(dom.window, 'scrollTo', {
        value: (opts?: ScrollToOptions | number) => {
          if (typeof opts === 'object' && opts?.top === 0) scrolledToTop = true;
        },
        configurable: true,
      });
      await act(async () => {
        dom.window.dispatchEvent(new dom.window.Event('scroll'));
      });
      const floatingPill = container.querySelector('[data-testid="mobile-floating-nav-pill"]');
      expect(floatingPill).not.toBeNull();
      const floatingTopBtn = floatingPill!.querySelector(
        '[data-testid="floating-scroll-top-btn"]'
      ) as HTMLButtonElement | null;
      expect(floatingTopBtn).not.toBeNull();
      await act(async () => {
        floatingTopBtn!.click();
      });
      expect(scrolledToTop).toBe(true);

      // Switch to History tab via floating pill and verify #55 full-card tap target + stopPropagation on action buttons
      const floatingHistoryBtn = floatingPill!.querySelector(
        '[data-testid="floating-tab-history"]'
      ) as HTMLButtonElement | null;
      expect(floatingHistoryBtn).not.toBeNull();
      await act(async () => {
        floatingHistoryBtn!.click();
      });
      const historyCard = container.querySelector(
        '[data-testid="history-snapshot-card"]'
      ) as HTMLDivElement | null;
      expect(historyCard).not.toBeNull();
      const pinBtn = historyCard!.querySelector(
        '[data-testid="history-pin-btn"]'
      ) as HTMLButtonElement | null;
      expect(pinBtn).not.toBeNull();
      expect(pinBtn!.className).toContain('min-w-[40px] min-h-[40px]');

      // Clicking Pin must NOT select/leave the History tab (stopPropagation)
      await act(async () => {
        pinBtn!.click();
      });
      expect(container.querySelector('[data-testid="history-snapshot-card"]')).not.toBeNull();

      // Clicking the snapshot card body itself selects the snapshot and navigates out of History tab
      await act(async () => {
        historyCard!.click();
      });
      expect(container.querySelector('[data-testid="history-snapshot-card"]')).toBeNull();

      await act(async () => {
        root.unmount();
      });
    } finally {
      mem.clear();
      if (prevWindow) {
        Object.defineProperty(globalThis, 'window', prevWindow);
      } else {
        Reflect.deleteProperty(globalThis, 'window');
      }
      Reflect.deleteProperty(globalThis, 'document');
    }
  });

  it('renders #6 RFC 2181 §10.3 CNAME alias, bogon IP, RFC 3901 dual-stack readiness, and intra-zone NS RRset skew in ZonesPanel and AuditPanel', () => {
    const nsAuditSnap: AnalysisSnapshot = {
      id: 'snap-ns-audit-6',
      version: 17,
      mode: 'dnssec',
      targetName: 'app.sub.example.com.',
      displayDomain: 'app.sub.example.com',
      queryTypes: ['A'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      capturedAt: 1700000000000,
      validatedAt: 1700000000000,
      durationMs: 95,
      overallStatus: 'secure',
      overallSummary: 'DNSSEC chain verified',
      zones: [
        {
          zoneName: '.',
          parentZone: null,
          depth: 0,
          status: 'secure',
          statusReason: 'Trusted root',
          nsecMode: 'NSEC',
          dnskeys: [],
          dsVerifications: [],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [{ hostname: 'a.root-servers.net.', ipv4: [], ipv6: [] }],
        },
        {
          // Intermediate zone with NS hygiene issues -> must NOT be considered a healthy auto-collapsible parent!
          zoneName: 'example.com.',
          parentZone: '.',
          depth: 2,
          status: 'secure',
          statusReason: 'Validated via DS',
          nsecMode: 'NSEC3',
          dnskeys: [],
          dsVerifications: [],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [
            {
              hostname: 'ns1.example.com.',
              ipv4: ['93.184.216.34'],
              ipv6: [],
              status: 'ok',
              addressStack: 'ipv4-only',
              cnameChain: ['alias-ns1.example.net.'],
            },
            {
              hostname: 'ns2.example.com.',
              ipv4: ['10.0.0.53'],
              ipv6: ['2606:2800:220:1:248:1893:25c8:1946'],
              status: 'ok',
              addressStack: 'ipv6-only',
              bogonIps: [{ ip: '10.0.0.53', family: 4, reason: 'Private-use IPv4 (RFC 1918)' }],
            },
          ],
          nsDiversity: {
            nameserverCount: 2,
            probedCount: 2,
            uniqueAsns: [],
            uniquePrefixes: [],
            hasIpv4: true,
            hasIpv6: true,
            ipv4NsCount: 1,
            ipv6NsCount: 1,
            dualStackNsCount: 0,
            dualStackReady: false,
            ipv4OnlyHosts: ['ns1.example.com.'],
            ipv6OnlyHosts: ['ns2.example.com.'],
            cnameHosts: ['ns1.example.com.'],
            bogonHosts: ['ns2.example.com.'],
            danglingHosts: [],
            singleAsn: false,
            singlePrefix: false,
            status: 'diverse',
            summary: '2 authoritative nameservers (1/2 IPv4, 1/2 IPv6).',
          },
          nsConsistency: {
            authoritativeNs: ['ns1.example.com.', 'ns2.example.com.'],
            checkedObservations: 2,
            consistent: false,
            divergentObservations: [
              {
                sourceQueryId: 'q-skew-1',
                qname: 'example.com.',
                qtypeName: 'SOA',
                section: 'authority',
                endpoint: 'https://1.1.1.1/dns-query',
                nsTargets: ['ns1.example.com.', 'ns3-stale.example.com.'],
                missingTargets: ['ns2.example.com.'],
                extraTargets: ['ns3-stale.example.com.'],
                matchesAuthoritative: false,
              },
            ],
            summary: 'NS RRset skew detected across 1 of 2 observations.',
          },
        },
        {
          zoneName: 'sub.example.com.',
          parentZone: 'example.com.',
          depth: 3,
          status: 'secure',
          statusReason: 'Validated via DS',
          nsecMode: 'NSEC3',
          dnskeys: [],
          dsVerifications: [],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [
            {
              hostname: 'ns1.sub.example.com.',
              ipv4: ['93.184.216.34'],
              ipv6: ['2606:2800:220:1:248:1893:25c8:1946'],
              status: 'ok',
              addressStack: 'dual-stack',
            },
            {
              hostname: 'ns2.sub.example.com.',
              ipv4: ['93.184.216.35'],
              ipv6: ['2606:2800:220:1:248:1893:25c8:1947'],
              status: 'ok',
              addressStack: 'dual-stack',
            },
          ],
          nsDiversity: {
            nameserverCount: 2,
            probedCount: 2,
            uniqueAsns: [],
            uniquePrefixes: [],
            hasIpv4: true,
            hasIpv6: true,
            ipv4NsCount: 2,
            ipv6NsCount: 2,
            dualStackNsCount: 2,
            dualStackReady: true,
            ipv4OnlyHosts: [],
            ipv6OnlyHosts: [],
            cnameHosts: [],
            bogonHosts: [],
            danglingHosts: [],
            singleAsn: false,
            singlePrefix: false,
            status: 'diverse',
            summary: '2 authoritative nameservers (2/2 IPv4, 2/2 IPv6, RFC 3901 dual-stack ready).',
          },
          nsConsistency: {
            authoritativeNs: ['ns1.sub.example.com.', 'ns2.sub.example.com.'],
            checkedObservations: 3,
            consistent: true,
            divergentObservations: [],
            summary: 'Authoritative NS RRset (2 servers) is consistent across 3 additional observations.',
          },
        },
      ],
      cnameEdges: [],
      findings: [
        {
          id: 'warn-ns-cname-example.com.-ns1.example.com.',
          severity: 'warning',
          code: 'NS_TARGET_IS_CNAME',
          title: 'Authoritative NS ns1.example.com in example.com. is a CNAME alias',
          detail: 'RFC 2181 §10.3 forbids NS records from pointing to an alias.',
          rfc: 'RFC 2181 §10.3',
          zone: 'example.com.',
        },
        {
          id: 'warn-ns-bogon-example.com.-ns2.example.com.',
          severity: 'warning',
          code: 'NS_BOGON_IP',
          title: 'Authoritative NS ns2.example.com in example.com. resolves to non-public bogon IP (10.0.0.53)',
          detail: 'Private-use IPv4 (RFC 1918)',
          rfc: 'RFC 1918 / RFC 6598 / RFC 4193',
          zone: 'example.com.',
        },
        {
          id: 'warn-ns-inconsistent-example.com.',
          severity: 'warning',
          code: 'NS_RRSET_INCONSISTENT',
          title: 'Inconsistent NS RRset observed for example.com. across 1 response',
          detail: 'NS RRset skew detected.',
          rfc: 'RFC 2181 §5 / RFC 1912 §2.8',
          zone: 'example.com.',
        },
      ],
      queries: [],
      trustAnchorsUsed: [],
    };

    expect(isHealthyIntermediateParentZone(nsAuditSnap.zones[0], nsAuditSnap)).toBe(true);
    expect(isHealthyIntermediateParentZone(nsAuditSnap.zones[1], nsAuditSnap)).toBe(false);

    const zonesHtml = renderToStaticMarkup(
      <ZonesPanel snapshot={nsAuditSnap} defaultMobileCollapse={true} />
    );
    expect(zonesHtml).toContain('Partial Dual-Stack (1v4 / 1v6)');
    expect(zonesHtml).toContain('Dual-Stack Ready (2v4 / 2v6 ✓)');
    expect(zonesHtml).toContain('NS Set Skew (1)');
    expect(zonesHtml).toContain('NS Set Consistent (3 obs ✓)');
    expect(zonesHtml).toContain('CNAME ALIAS');
    expect(zonesHtml).toContain('alias-ns1.example.net');
    expect(zonesHtml).toContain('BOGON IP');
    expect(zonesHtml).toContain('Private-use IPv4 (RFC 1918)');
    expect(zonesHtml).toContain('IPv4-only');
    expect(zonesHtml).toContain('IPv6-only');
    expect(zonesHtml).toContain('+ns3-stale.example.com');
    expect(zonesHtml).toContain('-ns2.example.com');

    const auditHtml = renderToStaticMarkup(
      <AuditPanel snapshot={nsAuditSnap} onJumpToGraphTarget={() => {}} />
    );
    expect(auditHtml).toContain('NS_TARGET_IS_CNAME');
    expect(auditHtml).toContain('NS_BOGON_IP');
    expect(auditHtml).toContain('NS_RRSET_INCONSISTENT');
  });
});
