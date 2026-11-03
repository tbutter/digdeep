import { beforeEach, describe, expect, it } from 'vitest';
import {
  buildChainGraph,
  computeDefaultCanvasHeight,
  computeDefaultGraphTransform,
  computeFitAllGraphTransform,
} from '../../graph/layout';
import {
  clearUnpinnedSnapshots,
  deleteSnapshot,
  diffSnapshots,
  getStorageStats,
  importSnapshotsFromJson,
  loadSnapshots,
  saveSnapshot,
  updateSnapshotMeta,
} from '../../storage/historyStore';
import { runDnsvizAnalysis } from '../analyzer';

// Provide a standard Web Storage API shim in Node test runtime
const store = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null;
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string) {
      store.delete(key);
    },
    setItem(key: string, value: string) {
      store.set(key, String(value));
    },
  },
  configurable: true,
});

describe('Graph Layout Engine & LocalStorage History Store', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it(
    'builds non-overlapping zone/node DAG and persists/diffs snapshots in localStorage',
    async () => {
      const snap1 = await runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A'] });
      const graph = buildChainGraph(snap1, { showSoaAndNs: true, showStandbyKeys: true });

      expect(graph.zones.length).toBe(3);
      expect(graph.nodes.length).toBeGreaterThanOrEqual(5);
      expect(graph.edges.length).toBeGreaterThanOrEqual(4);

      // Verify zero pairwise bounding-box overlap among nodes
      for (let i = 0; i < graph.nodes.length; i++) {
        for (let j = i + 1; j < graph.nodes.length; j++) {
          const a = graph.nodes[i];
          const b = graph.nodes[j];
          const overlapX = a.x < b.x + b.width && a.x + a.width > b.x;
          const overlapY = a.y < b.y + b.height && a.y + a.height > b.y;
          expect(overlapX && overlapY).toBe(false);
        }
      }

      // Verify default zoom scales widest box to 90% width and standard canvas height fits full graph
      const allBoxes = [...graph.zones, ...graph.nodes];
      const widestBox = allBoxes.reduce((best, item) =>
        item.width > best.width ? item : best
      );
      for (const vpWidth of [1400, 390] as const) {
        const canvasHeight = computeDefaultCanvasHeight(graph, vpWidth);
        const defaultTx = computeDefaultGraphTransform(graph, vpWidth, canvasHeight);
        expect(widestBox.width * defaultTx.scale).toBeCloseTo(vpWidth * 0.9, 5);
        const renderedLeft = defaultTx.x + widestBox.x * defaultTx.scale;
        expect(Math.abs(renderedLeft - vpWidth * 0.05)).toBeLessThanOrEqual(1);

        // Every zone & node must fit cleanly inside [0, canvasHeight] at default zoom
        for (const box of allBoxes) {
          const topPx = defaultTx.y + box.y * defaultTx.scale;
          const bottomPx = defaultTx.y + (box.y + box.height) * defaultTx.scale;
          expect(topPx).toBeGreaterThanOrEqual(24);
          expect(bottomPx).toBeLessThanOrEqual(canvasHeight - 20);
        }
      }

      const fitAllTx = computeFitAllGraphTransform(graph, 1400, 800);
      expect(graph.width * fitAllTx.scale).toBeLessThanOrEqual(1400);
      expect(graph.height * fitAllTx.scale).toBeLessThanOrEqual(800);

      // Persist in localStorage
      saveSnapshot(snap1);
      expect(loadSnapshots()).toHaveLength(1);
      expect(getStorageStats().usedBytes).toBeGreaterThan(1000);

      // Pin snap1 and save a second snapshot (dnssec-failed.org)
      updateSnapshotMeta(snap1.id, { pinned: true });
      const snap2 = await runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] });
      saveSnapshot(snap2);
      expect(loadSnapshots()).toHaveLength(2);

      // Diff two snapshots
      const diff = diffSnapshots(snap1, snap2);
      expect(diff.statusChanged).toBe(true);
      expect(diff.zoneChanges.some((z) => z.change !== 'unchanged')).toBe(true);

      // Clear unpinned leaves pinned snap1 intact
      const afterClear = clearUnpinnedSnapshots();
      expect(afterClear).toHaveLength(1);
      expect(afterClear[0].id).toBe(snap1.id);

      // Export & re-import JSON
      const exported = JSON.stringify([snap2]);
      const afterImport = importSnapshotsFromJson(exported);
      expect(afterImport).toHaveLength(2);

      deleteSnapshot(snap1.id);
      expect(loadSnapshots()).toHaveLength(1);
    },
    25000
  );
});
