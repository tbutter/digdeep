import { describe, expect, it } from 'vitest';
import { DEFAULT_USER_SETTINGS } from '../../storage/historyStore';
import { runDnsvizAnalysis } from '../analyzer';
import {
  buildCommandPaletteItems,
  filterCommandPaletteItems,
  scoreCommandItem,
} from '../commandPalette';

describe('Global Command Palette Indexing & Fuzzy Ranking (#64)', () => {
  it(
    'dynamically indexes zones, #keyTags, RRsets, audit findings, wire packets, resolvers, and history with sharp fuzzy ranking',
    async () => {
      const [secureSnap, bogusSnap] = await Promise.all([
        runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A', 'AAAA'] }),
        runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] }),
      ]);

      const settings = {
        ...DEFAULT_USER_SETTINGS,
        customDohEndpoints: ['https://doh.corp.example/dns-query'],
      };

      const items = buildCommandPaletteItems({
        activeSnapshot: secureSnap,
        snapshots: [secureSnap, bogusSnap],
        activeTab: 'graph',
        analysisMode: 'dnssec',
        domainInput: 'cloudflare.com',
        settings,
        theme: 'dark',
        isOffline: false,
        isViewingFrozenSnapshot: true,
        nowMs: secureSnap.capturedAt + 30_000,
      });

      // 1. Verify empty-query default view is curated and grouped cleanly
      const initialList = filterCommandPaletteItems(items, '');
      expect(initialList.length).toBeGreaterThan(15);
      expect(initialList.some((i) => i.id === 'snap-zone-cloudflare.com.')).toBe(true);
      expect(initialList.some((i) => i.id === 'action-compare-frozen-live')).toBe(true);
      // Raw wire logs stay hidden when query is empty to avoid cluttering initial list
      expect(initialList.some((i) => i.id.startsWith('snap-wire-'))).toBe(false);

      // 2. Searching by #keyTag (#2371 for Cloudflare KSK) ranks that DNSKEY #1
      const keyMatches = filterCommandPaletteItems(items, '#2371');
      expect(keyMatches.length).toBeGreaterThan(0);
      expect(keyMatches[0]!.title).toContain('DNSKEY #2371');
      expect(keyMatches[0]!.action).toEqual({
        type: 'focus-graph',
        targetId: expect.stringContaining('2371'),
        ensureStandbyVisible: false,
      });

      // 3. Searching DoH resolver by IP or provider name
      const quad9Unfiltered = filterCommandPaletteItems(items, 'quad9 9.9.9.10');
      expect(quad9Unfiltered.length).toBeGreaterThan(0);
      expect(quad9Unfiltered[0]!.id).toBe('resolver-preset-9.9.9.10');
      expect(quad9Unfiltered[0]!.action).toEqual({
        type: 'switch-resolver',
        endpoint: 'https://9.9.9.10/dns-query',
        reprobe: true,
      });

      // Custom DoH endpoint is also indexed
      const customDoh = filterCommandPaletteItems(items, 'doh.corp.example');
      expect(customDoh[0]!.id).toBe('resolver-custom-https://doh.corp.example/dns-query');

      // 4. Searching wire packets surfaces hidden-by-default wire items
      const wireResults = filterCommandPaletteItems(items, 'wire cloudflare.com AAAA');
      expect(wireResults.some((i) => i.id.startsWith('snap-wire-'))).toBe(true);

      // 5. Searching Audit Finding codes on bogus snapshot (dnssec-failed.org)
      const bogusItems = buildCommandPaletteItems({
        activeSnapshot: bogusSnap,
        snapshots: [bogusSnap, secureSnap],
        activeTab: 'graph',
        analysisMode: 'dnssec',
        domainInput: 'dnssec-failed.org',
        settings,
        theme: 'dark',
        isOffline: false,
        isViewingFrozenSnapshot: false,
      });
      const findingMatches = filterCommandPaletteItems(bogusItems, 'DS_NO_MATCHING_DNSKEY');
      expect(findingMatches.length).toBeGreaterThan(0);
      expect(findingMatches[0]!.category).toBe('snapshot');
      expect(findingMatches[0]!.severity).toBe('error');

      // 6. Category filter pills isolate exact categories
      const historyOnly = filterCommandPaletteItems(bogusItems, '', 'history');
      expect(historyOnly.length).toBe(2);
      expect(historyOnly.every((i) => i.category === 'history')).toBe(true);

      // 7. Non-matching gibberish returns null / empty array cleanly
      expect(scoreCommandItem('zzzz_no_such_dns_entity_99999', items[0]!)).toBeNull();
      expect(filterCommandPaletteItems(items, 'zzzz_no_such_dns_entity_99999')).toEqual([]);
    },
    30_000
  );
});
