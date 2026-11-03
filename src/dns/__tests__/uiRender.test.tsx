import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../../App';
import { AuditPanel } from '../../components/AuditPanel';
import { ChainGraphView } from '../../components/ChainGraphView';
import { HistoryPanel } from '../../components/HistoryPanel';
import { ResponsesPanel } from '../../components/ResponsesPanel';
import { SettingsModal } from '../../components/SettingsModal';
import { ZonesPanel } from '../../components/ZonesPanel';
import { DEFAULT_USER_SETTINGS } from '../../storage/historyStore';
import { runDnsvizAnalysis } from '../analyzer';

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

      const zonesHtml = renderToStaticMarkup(<ZonesPanel snapshot={cfSnap} />);
      expect(zonesHtml).toContain('. (Root Zone)');

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
    expect(swCode).toContain('digdeep-shell-v1');
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
    } finally {
      if (prevOnline) {
        Object.defineProperty(globalThis.navigator, 'onLine', prevOnline);
      }
    }
  });
});
