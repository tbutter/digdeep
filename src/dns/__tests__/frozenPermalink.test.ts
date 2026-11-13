import { describe, expect, it, vi } from 'vitest';
import { runDnsvizAnalysis } from '../analyzer';
import { IANA_ROOT_TRUST_ANCHORS } from '../constants';
import { bytesToBase64Url, concatBytes } from '../encoding';
import {
  buildFrozenPermalink,
  buildFrozenSnapshotFilename,
  decodeFrozenPermalinkHash,
  decodeFrozenSnapshotBytes,
  encodeFrozenSnapshotBytes,
  extractFrozenSnapshotToken,
  FrozenSnapshotError,
  hasFrozenSnapshotHash,
  MAX_DECOMPRESSED_FROZEN_BYTES,
  MAX_SAFE_FROZEN_FRAGMENT_CHARS,
} from '../frozenPermalink';
import { runWebAnalysis } from '../webAnalyzer';

async function gzipRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  const reader = cs.readable.getReader();
  const writeTask = (async () => {
    await writer.write(bytes as unknown as BufferSource);
    await writer.close();
  })();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  await writeTask;
  return concatBytes(...chunks);
}

describe('Zero-Server Frozen Incident Permalinks (#snap=) & .digdeep.gz Codec (#62)', () => {
  it(
    'round-trips live Secure (cloudflare.com) and Bogus (dnssec-failed.org) DNSSEC wire snapshots with zero network requests',
    async () => {
      const [secureSnap, bogusSnap] = await Promise.all([
        runDnsvizAnalysis('cloudflare.com', { queryTypes: ['A', 'AAAA'] }),
        runDnsvizAnalysis('dnssec-failed.org', { queryTypes: ['A'] }),
      ]);

      expect(secureSnap.overallStatus).toBe('secure');
      expect(bogusSnap.overallStatus).toBe('bogus');

      const secureBuilt = await buildFrozenPermalink(
        'https://digdeep.fyi/',
        secureSnap,
        {
          name: secureSnap.displayDomain,
          mode: secureSnap.mode,
          types: secureSnap.queryTypes,
          dohEndpoint: secureSnap.dohEndpoint,
          tab: 'graph',
          focus: 'zone:cloudflare.com.',
          showSoaAndNs: false,
          showStandbyKeys: true,
        }
      );

      expect(secureBuilt.fitsInUrl).toBe(true);
      expect(secureBuilt.url).toBeDefined();
      expect(secureBuilt.url).toContain('?name=cloudflare.com');
      expect(secureBuilt.url).toContain('#snap=');
      expect(secureBuilt.encodedFragmentLength).toBeLessThan(MAX_SAFE_FROZEN_FRAGMENT_CHARS);
      expect(secureBuilt.compressedByteLength).toBeLessThan(12_000);
      expect(secureBuilt.suggestedFilename).toMatch(
        /^digdeep-cloudflare\.com-\d{8}-\d{6}Z\.digdeep\.gz$/
      );

      const bogusWithNote = {
        ...bogusSnap,
        note: 'Incident #402: broken DS rollover',
      };
      const bogusBuilt = await buildFrozenPermalink(
        'https://digdeep.fyi/',
        bogusWithNote,
        {
          name: bogusWithNote.displayDomain,
          types: bogusWithNote.queryTypes,
          dohEndpoint: bogusWithNote.dohEndpoint,
          tab: 'audit',
        }
      );
      expect(bogusBuilt.fitsInUrl).toBe(true);
      expect(bogusBuilt.url).toContain('#snap=');

      // Block all network requests during decode to prove 100% zero-server offline reconstruction
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Network fetch MUST NOT be called during frozen decode'));

      try {
        const { snapshot: decodedSecure, compressedByteLength } = await decodeFrozenPermalinkHash(
          secureBuilt.url!
        );
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(compressedByteLength).toBe(secureBuilt.compressedByteLength);
        expect(decodedSecure.id).toBe(secureSnap.id);
        expect(decodedSecure.overallStatus).toBe('secure');
        expect(decodedSecure.targetName).toBe(secureSnap.targetName);
        expect(decodedSecure.displayDomain).toBe('cloudflare.com');
        expect(decodedSecure.capturedAt).toBe(secureSnap.capturedAt);
        expect(decodedSecure.validatedAt).toBe(secureSnap.validatedAt);
        expect(decodedSecure.queries.length).toBe(secureSnap.queries.length);
        for (let i = 0; i < secureSnap.queries.length; i++) {
          expect(decodedSecure.queries[i]!.wireBase64).toBe(secureSnap.queries[i]!.wireBase64);
          expect(decodedSecure.queries[i]!.qname).toBe(secureSnap.queries[i]!.qname);
          expect(decodedSecure.queries[i]!.qtype).toBe(secureSnap.queries[i]!.qtype);
          expect(decodedSecure.queries[i]!.purpose).toBe(secureSnap.queries[i]!.purpose);
        }
        expect(decodedSecure.zones.map((z) => z.zoneName)).toEqual(
          secureSnap.zones.map((z) => z.zoneName)
        );

        const { snapshot: decodedBogus } = await decodeFrozenPermalinkHash(bogusBuilt.url!);
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(decodedBogus.overallStatus).toBe('bogus');
        expect(decodedBogus.note).toBe('Incident #402: broken DS rollover');
        expect(decodedBogus.findings.map((f) => f.code)).toContain('DS_NO_MATCHING_DNSKEY');

        // Verify original validatedAt pinning: decoding without override stays 'secure',
        // whereas overriding validationTimeMs 15 years into the future detects expired RRSIGs
        const farFutureMs = secureSnap.validatedAt + 15 * 365 * 24 * 3600 * 1000;
        const { snapshot: expiredDecode } = await decodeFrozenPermalinkHash(secureBuilt.url!, {
          validationTimeMs: farFutureMs,
        });
        expect(expiredDecode.overallStatus).toBe('bogus');
      } finally {
        fetchSpy.mockRestore();
      }
    },
    30_000
  );

  it(
    'preserves Web mode CT metadata, trims oversized CT entries to fit URL budget, and falls back to .digdeep.gz when over budget',
    async () => {
      const webSnap = await runWebAnalysis('cloudflare.com');
      const syntheticCtEntries = Array.from({ length: 80 }, (_, idx) => ({
        id: `ct-${100_000 + idx}`,
        dnsNames: [
          `sub-${idx}-${Math.sin(idx + 1).toString(36).slice(2)}.cloudflare.com`,
          `alt-${idx}-${Math.cos(idx + 1).toString(36).slice(2)}.cloudflare.com`,
        ],
        issuerFriendlyName: `Example CA ${idx % 7}`,
        issuerDn: `C=US, O=Example CA ${idx}, CN=Example Intermediate R${idx % 7}`,
        notBefore: '2026-01-01T00:00:00Z',
        notAfter: '2027-12-31T23:59:59Z',
        revoked: false,
        certSha256: `${idx.toString(16).padStart(64, 'a')}`,
      }));

      const customAnchors = IANA_ROOT_TRUST_ANCHORS.map((ta, idx) =>
        idx === 0 ? { ...ta, enabled: false } : ta
      );
      const richWebSnap = {
        ...webSnap,
        trustAnchorsUsed: customAnchors,
        ctLogFetch: {
          source: 'crt.sh' as const,
          url: 'https://crt.sh/?q=cloudflare.com&output=json',
          fetchedAt: webSnap.capturedAt,
          ok: true,
          httpStatus: 200,
          includeSubdomains: true,
          entries: syntheticCtEntries,
        },
      };

      const fullBytes = await encodeFrozenSnapshotBytes(richWebSnap);
      const trimmedProbe = await encodeFrozenSnapshotBytes(richWebSnap, { maxCtEntries: 12 });
      const fullFragLen = `#snap=${bytesToBase64Url(fullBytes)}`.length;
      const trimmedFragLen = `#snap=${bytesToBase64Url(trimmedProbe)}`.length;
      expect(trimmedFragLen).toBeLessThan(fullFragLen);

      // Set budget between trimmedFragLen and fullFragLen -> triggers automatic CT entry trimming
      const midBudget = Math.floor((trimmedFragLen + fullFragLen) / 2);
      const trimmedResult = await buildFrozenPermalink(
        'https://digdeep.fyi/',
        richWebSnap,
        {
          name: richWebSnap.displayDomain,
          mode: 'web',
          types: richWebSnap.queryTypes,
          dohEndpoint: richWebSnap.dohEndpoint,
          tab: 'web',
        },
        { maxFragmentChars: midBudget }
      );
      expect(trimmedResult.fitsInUrl).toBe(true);
      expect(trimmedResult.trimmedCtEntries).toBe(true);
      expect(trimmedResult.url).toBeDefined();

      // Offline decode of trimmed Web snapshot reconstructs WebAnalysis & 12 CT entries
      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('No network allowed'));
      try {
        const { snapshot: decodedWeb } = await decodeFrozenPermalinkHash(trimmedResult.url!);
        expect(decodedWeb.mode).toBe('web');
        expect(decodedWeb.webAnalysis).toBeDefined();
        expect(decodedWeb.ctLogFetch?.entries.length).toBe(12);
      } finally {
        fetchSpy.mockRestore();
      }

      // Set tiny budget (512 chars) -> cleanly reports fitsInUrl: false and provides gzipBytes + filename
      const fallbackResult = await buildFrozenPermalink(
        'https://digdeep.fyi/',
        richWebSnap,
        {
          name: richWebSnap.displayDomain,
          mode: 'web',
          types: richWebSnap.queryTypes,
          dohEndpoint: richWebSnap.dohEndpoint,
          tab: 'web',
        },
        { maxFragmentChars: 512 }
      );
      expect(fallbackResult.fitsInUrl).toBe(false);
      expect(fallbackResult.url).toBeUndefined();
      expect(fallbackResult.gzipBytes.byteLength).toBeGreaterThan(100);
      expect(buildFrozenSnapshotFilename(richWebSnap)).toBe(fallbackResult.suggestedFilename);
    },
    30_000
  );

  it('detects #snap= hashes and rejects corrupted, truncated, or oversized streams cleanly without crashing', async () => {
    expect(hasFrozenSnapshotHash('')).toBe(false);
    expect(hasFrozenSnapshotHash('#tab=graph')).toBe(false);
    expect(hasFrozenSnapshotHash('#snap=')).toBe(true);
    expect(hasFrozenSnapshotHash('https://digdeep.fyi/?name=example.com#foo=1&snap=abc123')).toBe(
      true
    );
    expect(extractFrozenSnapshotToken('#foo=1&snap=abc_123')).toBe('abc_123');
    expect(extractFrozenSnapshotToken('#snap=')).toBe('');
    expect(extractFrozenSnapshotToken('#other=1')).toBeNull();

    await expect(decodeFrozenPermalinkHash('#other=1')).rejects.toThrow(FrozenSnapshotError);
    await expect(decodeFrozenPermalinkHash('#snap=')).rejects.toThrow(/empty/i);
    await expect(decodeFrozenPermalinkHash('#snap=bad!chars@here')).rejects.toThrow(
      /invalid Base64url/i
    );
    await expect(
      decodeFrozenPermalinkHash('#snap=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo')
    ).rejects.toThrow(/Invalid gzip header/i);

    // Truncated gzip stream
    const validGzip = await gzipRaw(new TextEncoder().encode('DDP1-short-test-payload'));
    const truncatedGzip = validGzip.subarray(0, validGzip.byteLength - 6);
    await expect(decodeFrozenSnapshotBytes(truncatedGzip)).rejects.toThrow(FrozenSnapshotError);

    // Valid gzip but wrong container magic
    const wrongMagicGzip = await gzipRaw(new TextEncoder().encode('NOPE0000{}'));
    await expect(decodeFrozenSnapshotBytes(wrongMagicGzip)).rejects.toThrow(
      /expected DDP1/i
    );

    // Valid DDP1 magic but out-of-bounds header length
    const badLenRaw = new Uint8Array(16);
    badLenRaw.set([0x44, 0x44, 0x50, 0x31], 0);
    new DataView(badLenRaw.buffer).setUint32(4, 999_999, false);
    const badLenGzip = await gzipRaw(badLenRaw);
    await expect(decodeFrozenSnapshotBytes(badLenGzip)).rejects.toThrow(
      /Corrupted DDP1 header length/i
    );

    // Decompression bomb guard (> MAX_DECOMPRESSED_FROZEN_BYTES)
    const oversizedZeros = new Uint8Array(MAX_DECOMPRESSED_FROZEN_BYTES + 64 * 1024);
    const bombGzip = await gzipRaw(oversizedZeros);
    expect(bombGzip.byteLength).toBeLessThan(32_768);
    await expect(decodeFrozenSnapshotBytes(bombGzip)).rejects.toThrow(
      /exceeds maximum safe decompressed size/i
    );
  });
});
