# DigDeep — Client-Side DNSSEC Visualizer (`1.1.1.1` DoH)

A modern, client-side re-imagining of **DNSViz** that performs all DNS resolution, RFC 4034/4035/5155 cryptographic verification, chain-of-trust graph layout, and historical snapshot management directly in the browser.

## Highlights

- **100% Client-Side DNSSEC Validation**: Uses WebCrypto (`SubtleCrypto`) in the browser to cryptographically verify `DS` → `DNSKEY` digests (SHA-1, SHA-256, SHA-384) and canonical wireformat `RRSIG` signatures (`RSASHA1`, `RSASHA256`, `RSASHA512`, `ECDSAP256SHA256`, `ECDSAP384SHA384`, `ED25519`), wildcard synthesis, and `NSEC` / `NSEC3` (including Opt-Out and Compact Denial of Existence) proofs.
- **Cloudflare `1.1.1.1` DoH Wireformat**: Speaks RFC 8484 (`application/dns-message`) directly to `https://1.1.1.1/dns-query` with `DO=1` and `CD=1` (plus a side-by-side `CD=0` `AD`-bit & RFC 8914 Extended DNS Error check).
- **Interactive Chain-of-Trust Graph**: Pan/zoom hierarchical zone containers, double-ring SEP/KSK/Trust Anchor capsules, phantom missing-key nodes (e.g. `dnssec-failed.org`), cross-zone CNAME arcs (e.g. `www.iana.org`), deep cryptographic node/edge inspector, and standalone **SVG / PNG** diagram export.
- **Browser `localStorage` History & Snapshot Diff**: Automatically archives historical analyses in `localStorage` with pin protection, storage quota meter, JSON export/import, offline RRSIG time-travel re-validation, and side-by-side snapshot diffing (SOA serial bumps, DNSKEY/DS rollovers, RRset changes).

## Quick Start

```bash
npm install
npm run dev
```

Run the test suite and production build:

```bash
npm test
npm run build
```
