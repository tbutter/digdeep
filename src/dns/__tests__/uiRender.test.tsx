import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
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
});
