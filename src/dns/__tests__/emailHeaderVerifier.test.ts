import { describe, expect, it } from 'vitest';
import { RR_TYPES } from '../constants';
import { toArrayBuffer } from '../crypto';
import {
  buildArcSealSigningInput,
  buildDkimSigningInput,
  canonicalizeDkimBody,
  canonicalizeDkimHeader,
  evaluateDmarcAlignment,
  looksLikeRawEmailHeaders,
  parseRawEmailMessage,
  stripSignatureBValue,
  verifyEmailMessageCryptographically,
} from '../emailHeaderVerifier';
import { bytesToBase64, concatBytes, normalizeFqdn } from '../encoding';
import { clearPublicSuffixCache, seedPublicSuffixCache } from '../mailAnalyzer';
import { parseOmniboxInput } from '../omniboxParse';
import type { AnalysisSnapshot, DohQueryLog } from '../types';
import { encodeDnsName, parseDnsPacket } from '../wire';

function buildDnsResponsePacket(params: {
  qname: string;
  qtype: number;
  rcode?: number;
  ad?: boolean;
  answers?: Array<{ name: string; type: number; ttl?: number; rdata: Uint8Array }>;
}) {
  const { qname, qtype, rcode = 0, ad = true, answers = [] } = params;
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  view.setUint16(0, 0x2468, false);
  const flags = 0x8180 | (ad ? 0x0020 : 0) | (rcode & 0x000f);
  view.setUint16(2, flags, false);
  view.setUint16(4, 1, false);
  view.setUint16(6, answers.length, false);

  const qWire = concatBytes(
    encodeDnsName(qname),
    new Uint8Array([(qtype >> 8) & 0xff, qtype & 0xff, 0, 1])
  );

  const ansChunks = answers.map((a) => {
    const ownerWire = encodeDnsName(a.name);
    const meta = new Uint8Array(10);
    const mv = new DataView(meta.buffer);
    mv.setUint16(0, a.type, false);
    mv.setUint16(2, 1, false);
    mv.setUint32(4, a.ttl ?? 300, false);
    mv.setUint16(8, a.rdata.length, false);
    return concatBytes(ownerWire, meta, a.rdata);
  });

  return parseDnsPacket(concatBytes(header, qWire, ...ansChunks));
}

function encodeTxtRdata(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  const parts: Uint8Array[] = [];
  for (let off = 0; off < bytes.length; off += 255) {
    const chunk = bytes.subarray(off, Math.min(bytes.length, off + 255));
    parts.push(concatBytes(new Uint8Array([chunk.length]), chunk));
  }
  return parts.length > 0 ? concatBytes(...parts) : new Uint8Array([0]);
}

function makeTxtLog(qname: string, txtStrings: string[], cd = true): DohQueryLog {
  const norm = normalizeFqdn(qname);
  const packet = buildDnsResponsePacket({
    qname: norm,
    qtype: RR_TYPES.TXT,
    ad: true,
    answers: txtStrings.map((t) => ({
      name: norm,
      type: RR_TYPES.TXT,
      rdata: encodeTxtRdata(t),
    })),
  });
  return {
    id: `mock-${norm}-TXT-${cd ? 1 : 0}`,
    qname: norm,
    qtype: RR_TYPES.TXT,
    qtypeName: 'TXT',
    cd,
    doBit: true,
    endpoint: 'https://1.1.1.1/dns-query',
    startedAt: 1_700_000_000_000,
    latencyMs: 3,
    httpStatus: 200,
    wireBase64: '',
    requestWireBase64: '',
    packet,
    purpose: `Mail target (${norm} TXT)`,
  };
}

/**
 * Mock DoH responder returning deterministic wire packets from an in-memory TXT map
 * (and clean NODATA for unconfigured DNSKEY/DS/SOA/NS lookups) with zero network access.
 */
function createInMemoryDohFetch(txtRecordsByOwner: Record<string, string[]>): typeof fetch {
  const normalizedMap = new Map<string, string[]>();
  for (const [owner, txts] of Object.entries(txtRecordsByOwner)) {
    normalizedMap.set(normalizeFqdn(owner), txts);
  }

  return async (input: RequestInfo | URL): Promise<Response> => {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const u = new URL(urlStr);
    const dnsParam = u.searchParams.get('dns') ?? '';
    const b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const reqBytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) reqBytes[i] = bin.charCodeAt(i);
    const reqPkt = parseDnsPacket(reqBytes);
    const q = reqPkt.questions[0];
    const qname = normalizeFqdn(q?.name ?? '.');
    const qtype = q?.type ?? RR_TYPES.TXT;

    const txts = qtype === RR_TYPES.TXT ? normalizedMap.get(qname) : undefined;
    const rcode = qtype === RR_TYPES.TXT && !txts && qname.includes('._domainkey.') ? 3 : 0;

    const header = new Uint8Array(12);
    const hv = new DataView(header.buffer);
    hv.setUint16(0, reqPkt.id, false);
    hv.setUint16(2, 0x8180 | (rcode & 0x0f), false);
    hv.setUint16(4, 1, false);
    hv.setUint16(6, txts ? txts.length : 0, false);

    const qWire = concatBytes(
      encodeDnsName(qname),
      new Uint8Array([(qtype >> 8) & 0xff, qtype & 0xff, 0, 1])
    );
    const ansWires = (txts ?? []).map((t) => {
      const rdata = encodeTxtRdata(t);
      const ownerWire = encodeDnsName(qname);
      const meta = new Uint8Array(10);
      const mv = new DataView(meta.buffer);
      mv.setUint16(0, RR_TYPES.TXT, false);
      mv.setUint16(2, 1, false);
      mv.setUint32(4, 300, false);
      mv.setUint16(8, rdata.length, false);
      return concatBytes(ownerWire, meta, rdata);
    });
    const wire = concatBytes(header, qWire, ...ansWires);
    return new Response(toArrayBuffer(wire), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' },
    });
  };
}

async function signMessageWithRsaOrEd25519(params: {
  rawHeadersTopToBottom: string[];
  rawBodyCrlf: string;
  headerName?: 'DKIM-Signature' | 'ARC-Message-Signature';
  headerPrefixTags: string; // e.g. `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; t=1700000000; h=from:to:subject:date`
  algorithm: 'rsa-sha256' | 'rsa-sha1' | 'ed25519-sha256';
  bodyCanon: 'simple' | 'relaxed';
  bodyLengthLimit?: number;
  privateKey: CryptoKey;
}): Promise<string> {
  const {
    rawHeadersTopToBottom,
    rawBodyCrlf,
    headerName = 'DKIM-Signature',
    headerPrefixTags,
    algorithm,
    bodyCanon,
    bodyLengthLimit,
    privateKey,
  } = params;

  const canonBody = canonicalizeDkimBody(rawBodyCrlf, bodyCanon);
  const fullBodyBytes = new TextEncoder().encode(canonBody);
  const slicedBody =
    bodyLengthLimit !== undefined ? fullBodyBytes.subarray(0, bodyLengthLimit) : fullBodyBytes;
  const hashAlg = algorithm === 'rsa-sha1' ? 'SHA-1' : 'SHA-256';
  const bhBuf = await crypto.subtle.digest(hashAlg, toArrayBuffer(slicedBody));
  const bhB64 = bytesToBase64(new Uint8Array(bhBuf));

  const templateHeader = `${headerName}: ${headerPrefixTags};${
    bodyLengthLimit !== undefined ? ` l=${bodyLengthLimit};` : ''
  }\r\n\tbh=${bhB64};\r\n\tb=`;

  const tempMsg = `${[templateHeader, ...rawHeadersTopToBottom].join('\r\n')}\r\n\r\n${rawBodyCrlf}`;
  const parsed = parseRawEmailMessage(tempMsg);
  const sigObj =
    headerName === 'DKIM-Signature' ? parsed.dkimSignatures[0] : parsed.arcMessageSignatures[0];
  const { signingBytes } = buildDkimSigningInput(parsed.headers, sigObj);

  let sigBuf: ArrayBuffer;
  if (algorithm === 'ed25519-sha256') {
    const headerDigest = await crypto.subtle.digest('SHA-256', toArrayBuffer(signingBytes));
    sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, headerDigest);
  } else {
    sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, toArrayBuffer(signingBytes));
  }

  const bB64 = bytesToBase64(new Uint8Array(sigBuf));
  return `${templateHeader}${bB64}`;
}

describe('RFC 5322 / 6376 / 8301 / 8463 / 8617 / 7489 Local Email Header & .eml Verifier', () => {
  it('canonicalizes headers and bodies identically to RFC 6376 §3.4.5 test vectors', async () => {
    // RFC 6376 §3.4.5 Example 1 (relaxed/relaxed)
    expect(canonicalizeDkimHeader('A: X', 'relaxed')).toBe('a:X');
    expect(canonicalizeDkimHeader('B : Y\t\r\n\tZ  ', 'relaxed')).toBe('b:Y Z');
    expect(canonicalizeDkimHeader('B : Y\t\r\n\tZ  ', 'simple')).toBe('B : Y\t\r\n\tZ  ');

    const exampleBody = ' C \r\nD \t E\r\n\r\n\r\n';
    expect(canonicalizeDkimBody(exampleBody, 'relaxed')).toBe(' C\r\nD E\r\n');
    expect(canonicalizeDkimBody(exampleBody, 'simple')).toBe(' C \r\nD \t E\r\n');

    // Empty body edge cases (RFC 6376 §3.4.3 & §3.4.4)
    expect(canonicalizeDkimBody('', 'simple')).toBe('\r\n');
    expect(canonicalizeDkimBody('\r\n\r\n\r\n', 'simple')).toBe('\r\n');
    expect(canonicalizeDkimBody('', 'relaxed')).toBe('');
    expect(canonicalizeDkimBody('  \t \r\n\r\n', 'relaxed')).toBe('');

    const emptySimpleSha256 = bytesToBase64(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', toArrayBuffer(new TextEncoder().encode('\r\n')))
      )
    );
    expect(emptySimpleSha256).toBe('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');

    const emptyRelaxedSha256 = bytesToBase64(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new ArrayBuffer(0)))
    );
    expect(emptyRelaxedSha256).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');

    // Ensure stripSignatureBValue removes folded b= value without corrupting bh=
    const rawSig =
      'DKIM-Signature: v=1; a=rsa-sha256; bh=AbCdEfGh1234==;\r\n\tb=XyZ987\r\n\t  654321==; x=1900000000';
    const stripped = stripSignatureBValue(rawSig);
    expect(stripped).toBe(
      'DKIM-Signature: v=1; a=rsa-sha256; bh=AbCdEfGh1234==;\r\n\tb=; x=1900000000'
    );
  });

  it('verifies dual-signed RSA-2048 (rsa-sha256) + Ed25519 (RFC 8463 ed25519-sha256) .eml, headers-only paste, tampering, l= truncation, and RFC 8301 rsa-sha1', async () => {
    const rsaPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );
    const rsaSpkiB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('spki', rsaPair.publicKey))
    );

    const edPair = (await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const edRawB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('raw', edPair.publicKey))
    );

    const baseHeaders = [
      'Return-Path: <bounce@mail.example.com>',
      'Received: from mail.example.com (mail.example.com [198.51.100.42])\r\n\tby mx.example.net with ESMTPS id abc123;\r\n\tWed, 15 May 2024 12:00:05 +0000',
      'Received: from [10.0.0.15] (internal.corp [10.0.0.15])\r\n\tby mail.example.com with ESMTPSA;\r\n\tWed, 15 May 2024 12:00:01 +0000',
      'From: "Alice Security" <alice@example.com>',
      'To: Bob <bob@example.net>',
      'Subject:   Quarterly   DNSSEC  &  DKIM   Review  ',
      'Date: Wed, 15 May 2024 12:00:00 +0000',
      'Message-ID: <msg-20240515@example.com>',
    ];
    const bodyCrlf = 'Hello Bob,\r\n\r\nHere is the signed report.\r\n\r\n';

    const rsaSigHeader = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: baseHeaders,
      rawBodyCrlf: bodyCrlf,
      headerPrefixTags:
        'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=rsa2024; t=1715774400; x=1715860800; h=from:to:subject:date:message-id:received:received:from',
      algorithm: 'rsa-sha256',
      bodyCanon: 'relaxed',
      privateKey: rsaPair.privateKey,
    });

    const edSigHeader = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: baseHeaders,
      rawBodyCrlf: bodyCrlf,
      headerPrefixTags:
        'v=1; a=ed25519-sha256; c=simple/simple; d=example.com; s=ed2024; t=1715774400; h=from:to:subject:date:message-id',
      algorithm: 'ed25519-sha256',
      bodyCanon: 'simple',
      privateKey: edPair.privateKey,
    });

    const authResHeader =
      'Authentication-Results: mx.example.net;\r\n\tdkim=pass header.d=example.com header.s=rsa2024;\r\n\tdkim=pass header.d=example.com header.s=ed2024;\r\n\tspf=pass (mx.example.net: domain of bounce@mail.example.com designates 198.51.100.42 as permitted sender) smtp.mailfrom=bounce@mail.example.com;\r\n\tdmarc=pass (p=reject) header.from=example.com';

    const fullEml = `${[authResHeader, edSigHeader, rsaSigHeader, ...baseHeaders].join('\r\n')}\r\n\r\n${bodyCrlf}`;

    const mockFetch = createInMemoryDohFetch({
      'rsa2024._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaSpkiB64}`],
      'ed2024._domainkey.example.com': [`v=DKIM1; k=ed25519; p=${edRawB64}`],
      '_dmarc.example.com': ['v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc@example.com'],
      'mail.example.com': ['v=spf1 ip4:198.51.100.0/24 -all'],
      'example.com.psl.digdeep.fyi': ['com'],
      'mail.example.com.psl.digdeep.fyi': ['com'],
    });

    // 1. Full .eml verification (evaluated in 2026: after x=1715860800, but valid at Date 2024!)
    const now2026Ms = Date.UTC(2026, 10, 12, 12, 0, 0);
    const report = await verifyEmailMessageCryptographically(fullEml, {
      fetchImpl: mockFetch,
      trustAnchors: [],
      nowMs: now2026Ms,
    });

    expect(report.overallVerdict).toBe('pass');
    expect(report.dkimResults).toHaveLength(2);
    expect(report.dkimResults[0].signature.algorithm).toBe('ed25519-sha256');
    expect(report.dkimResults[0].verdict).toBe('pass');
    expect(report.dkimResults[0].headerCryptoValid).toBe(true);
    expect(report.dkimResults[0].bodyHashStatus).toBe('match');

    expect(report.dkimResults[1].signature.algorithm).toBe('rsa-sha256');
    expect(report.dkimResults[1].verdict).toBe('pass');
    expect(report.dkimResults[1].timestampEvaluation.expiredNow).toBe(true);
    expect(report.dkimResults[1].timestampEvaluation.expiredAtReceipt).toBe(false);
    expect(report.dkimResults[1].matchedSignedHeaders.some((m) => m.oversigned)).toBe(true);

    // Verify connectingHop skipped RFC 1918 10.0.0.15 and selected external 198.51.100.42
    expect(report.parsed.connectingHop?.ip).toBe('198.51.100.42');
    expect(report.spfReplay.disposition).toBe('pass');
    expect(report.spfReplay.dmarcAligned?.aligned).toBe(true);
    expect(report.spfReplay.dmarcAligned?.matchKind).toBe('org-domain');
    expect(report.dmarcReplay.verdict).toBe('pass');
    expect(report.dmarcReplay.appliedPolicy).toBe('reject');
    expect(report.authResultsDiff.every((d) => d.status === 'match')).toBe(true);

    // 2. Headers-only paste (even with trailing blank line) verifies header b= without false bh= failure
    const headersOnlyPaste = `${[authResHeader, edSigHeader, rsaSigHeader, ...baseHeaders].join('\n')}\n\n`;
    const headersOnlyReport = await verifyEmailMessageCryptographically(headersOnlyPaste, {
      fetchImpl: mockFetch,
      trustAnchors: [],
      nowMs: now2026Ms,
    });
    expect(headersOnlyReport.parsed.bodyMode).toBe('headers-only');
    expect(headersOnlyReport.dkimResults[0].verdict).toBe('headers-verified-only');
    expect(headersOnlyReport.dkimResults[0].headerCryptoValid).toBe(true);
    expect(headersOnlyReport.dkimResults[0].bodyHashStatus).toBe('unchecked-no-body');

    // 3. Mailing-list / forwarder hop prepends a top Received header (unauthorized IP 203.0.113.99)
    //    and appends a body footer: headerCryptoValid stays true while bh= mismatches and DMARC fails
    const forwarderReceived =
      'Received: from list.example.org (list.example.org [203.0.113.99])\r\n\tby final-mx.example.net with ESMTPS;\r\n\tWed, 15 May 2024 12:00:10 +0000';
    const modifiedBodyEml = `${[forwarderReceived, authResHeader, rsaSigHeader, ...baseHeaders].join('\r\n')}\r\n\r\n${bodyCrlf}-- Mailing list footer\r\n`;
    const tamperedBodyReport = await verifyEmailMessageCryptographically(modifiedBodyEml, {
      fetchImpl: mockFetch,
      trustAnchors: [],
      nowMs: now2026Ms,
    });
    expect(tamperedBodyReport.dkimResults[0].headerCryptoValid).toBe(true);
    expect(tamperedBodyReport.dkimResults[0].bodyHashStatus).toBe('mismatch');
    expect(tamperedBodyReport.dkimResults[0].verdict).toBe('fail');
    expect(tamperedBodyReport.dmarcReplay.verdict).toBe('fail');
    expect(tamperedBodyReport.dmarcReplay.effectiveDisposition).toBe('reject');
    expect(tamperedBodyReport.authResultsDiff.some((d) => d.status === 'drift')).toBe(true);

    // 4. Body length limit tag l= signs prefix and warns on unsigned appended bytes (RFC 6376 §8.2)
    const truncatedSigHeader = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: baseHeaders,
      rawBodyCrlf: 'Trusted text.\r\n',
      headerPrefixTags:
        'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=rsa2024; h=from:to:subject:date',
      algorithm: 'rsa-sha256',
      bodyCanon: 'relaxed',
      bodyLengthLimit: 15,
      privateKey: rsaPair.privateKey,
    });
    const lTagEml = `${[truncatedSigHeader, ...baseHeaders].join('\r\n')}\r\n\r\nTrusted text.\r\nUNSIGNED ATTACKER FOOTER\r\n`;
    const lTagReport = await verifyEmailMessageCryptographically(lTagEml, {
      fetchImpl: mockFetch,
      trustAnchors: [],
      nowMs: now2026Ms,
    });
    expect(lTagReport.dkimResults[0].verdict).toBe('pass');
    expect(lTagReport.dkimResults[0].unsignedTrailingBodyBytes).toBeGreaterThan(10);
    expect(
      lTagReport.dkimResults[0].warnings.some((w) => w.includes('RFC 6376 §8.2'))
    ).toBe(true);

    // 5. Deprecated rsa-sha1 is cryptographically checked yet strictly rejected per RFC 8301 §3.1
    const sha1KeyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['sign', 'verify']
    );
    const sha1SpkiB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('spki', sha1KeyPair.publicKey))
    );
    const sha1SigHeader = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: baseHeaders,
      rawBodyCrlf: bodyCrlf,
      headerPrefixTags:
        'v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=legacy1; h=from:to:subject:date',
      algorithm: 'rsa-sha1',
      bodyCanon: 'relaxed',
      privateKey: sha1KeyPair.privateKey,
    });
    const sha1Eml = `${[sha1SigHeader, ...baseHeaders].join('\r\n')}\r\n\r\n${bodyCrlf}`;
    const sha1Report = await verifyEmailMessageCryptographically(sha1Eml, {
      fetchImpl: createInMemoryDohFetch({
        'legacy1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${sha1SpkiB64}`],
        '_dmarc.example.com': ['v=DMARC1; p=reject'],
        'mail.example.com': ['v=spf1 -all'],
      }),
      trustAnchors: [],
      nowMs: now2026Ms,
    });
    expect(sha1Report.dkimResults[0].headerCryptoValid).toBe(true);
    expect(sha1Report.dkimResults[0].deprecatedAlgorithm).toBe(true);
    expect(sha1Report.dkimResults[0].verdict).toBe('policy-fail');
    expect(sha1Report.dmarcReplay.verdict).toBe('fail');

    // 6. Multiple RFC 5322 From: headers trigger spoofing failure per RFC 7489 §6.6.1
    const doubleFromEml = `${[edSigHeader, 'From: "Fake CEO" <ceo@attacker.example.org>', ...baseHeaders].join('\r\n')}\r\n\r\n${bodyCrlf}`;
    const doubleFromReport = await verifyEmailMessageCryptographically(doubleFromEml, {
      fetchImpl: mockFetch,
      trustAnchors: [],
      nowMs: now2026Ms,
    });
    expect(doubleFromReport.parsed.multipleFromHeaderCount).toBe(2);
    expect(doubleFromReport.dmarcReplay.verdict).toBe('fail');
    expect(doubleFromReport.overallVerdict).toBe('fail');

    // 7. Stripped Root DNSKEY (DNSSEC BOGUS) causes DKIM verification to return temperror
    const bogusDnssecReport = await verifyEmailMessageCryptographically(fullEml, {
      fetchImpl: mockFetch,
      nowMs: now2026Ms,
    });
    expect(bogusDnssecReport.dkimResults[0].dnssecStatus).toBe('bogus');
    expect(bogusDnssecReport.dkimResults[0].verdict).toBe('temperror');
  });

  it('verifies multi-hop RFC 8617 ARC chain (i=1 -> i=2) across forwarding modification and catches seal tampering', async () => {
    const hop1Key = (await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const hop1PubB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('raw', hop1Key.publicKey))
    );

    const hop2Key = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );
    const hop2PubB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('spki', hop2Key.publicKey))
    );

    const origHeaders = [
      'From: Alice <alice@example.com>',
      'To: list@lists.example.org',
      'Subject: Original Topic',
      'Date: Thu, 16 May 2024 10:00:00 +0000',
      'Message-ID: <arc-test-1@example.com>',
    ];
    const origBody = 'Original body before list footer.\r\n';

    // Hop 1 (ingress at lists.example.org) stamps AAR(1), AMS(1), AS(1) with cv=none
    const aar1 =
      'ARC-Authentication-Results: i=1; lists.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com';
    const ams1 = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: origHeaders,
      rawBodyCrlf: origBody,
      headerName: 'ARC-Message-Signature',
      headerPrefixTags:
        'i=1; a=ed25519-sha256; c=relaxed/relaxed; d=lists.example.org; s=arc-ed1; h=from:to:subject:date:message-id',
      algorithm: 'ed25519-sha256',
      bodyCanon: 'relaxed',
      privateKey: hop1Key.privateKey,
    });
    const as1Prefix = 'ARC-Seal: i=1; a=ed25519-sha256; cv=none; d=lists.example.org; s=arc-ed1; b=';
    const tempHop1 = parseRawEmailMessage(
      `${[as1Prefix, ams1, aar1, ...origHeaders].join('\r\n')}\r\n\r\n${origBody}`
    );
    const seal1Input = buildArcSealSigningInput(
      new Map([
        [
          1,
          {
            aar: tempHop1.arcAuthResults[0],
            ams: tempHop1.arcMessageSignatures[0],
            seal: tempHop1.arcSeals[0],
          },
        ],
      ]),
      1
    )!;
    const seal1Digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(seal1Input));
    const seal1SigB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, hop1Key.privateKey, seal1Digest))
    );
    const as1 = `${as1Prefix}${seal1SigB64}`;

    // Mailing list modifies Subject & appends footer, then Hop 2 (relay.example.net) stamps AAR(2), AMS(2), AS(2) with cv=pass
    const forwardedHeaders = [
      'Return-Path: <list-bounces@lists.example.org>',
      'Received: from lists.example.org (lists.example.org [198.51.100.88]) by mx.recipient.org; Thu, 16 May 2024 10:00:10 +0000',
      as1,
      ams1,
      aar1,
      'From: Alice <alice@example.com>',
      'To: list@lists.example.org',
      'Subject: [List] Original Topic',
      'Date: Thu, 16 May 2024 10:00:00 +0000',
      'Message-ID: <arc-test-1@example.com>',
    ];
    const forwardedBody = `${origBody}--\r\nMailing list footer\r\n`;

    const aar2 =
      'ARC-Authentication-Results: i=2; relay.example.net; spf=pass smtp.mailfrom=lists.example.org; arc=pass (i=1)';
    const ams2 = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: forwardedHeaders,
      rawBodyCrlf: forwardedBody,
      headerName: 'ARC-Message-Signature',
      headerPrefixTags:
        'i=2; a=rsa-sha256; c=relaxed/relaxed; d=relay.example.net; s=arc-rsa2; h=from:to:subject:date:message-id',
      algorithm: 'rsa-sha256',
      bodyCanon: 'relaxed',
      privateKey: hop2Key.privateKey,
    });
    const as2Prefix = 'ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=relay.example.net; s=arc-rsa2; b=';
    const tempHop2 = parseRawEmailMessage(
      `${[as2Prefix, ams2, aar2, ...forwardedHeaders].join('\r\n')}\r\n\r\n${forwardedBody}`
    );
    const seal2Input = buildArcSealSigningInput(
      new Map([
        [
          1,
          {
            aar: tempHop2.arcAuthResults.find((x) => x.arcInstance === 1)!,
            ams: tempHop2.arcMessageSignatures.find((x) => x.instance === 1)!,
            seal: tempHop2.arcSeals.find((x) => x.instance === 1)!,
          },
        ],
        [
          2,
          {
            aar: tempHop2.arcAuthResults.find((x) => x.arcInstance === 2)!,
            ams: tempHop2.arcMessageSignatures.find((x) => x.instance === 2)!,
            seal: tempHop2.arcSeals.find((x) => x.instance === 2)!,
          },
        ],
      ]),
      2
    )!;
    const seal2SigB64 = bytesToBase64(
      new Uint8Array(
        await crypto.subtle.sign('RSASSA-PKCS1-v1_5', hop2Key.privateKey, toArrayBuffer(seal2Input))
      )
    );
    const as2 = `${as2Prefix}${seal2SigB64}`;

    const fullArcEml = `${[as2, ams2, aar2, ...forwardedHeaders].join('\r\n')}\r\n\r\n${forwardedBody}`;
    const arcDoh = createInMemoryDohFetch({
      'arc-ed1._domainkey.lists.example.org': [`v=DKIM1; k=ed25519; p=${hop1PubB64}`],
      'arc-rsa2._domainkey.relay.example.net': [`v=DKIM1; k=rsa; p=${hop2PubB64}`],
      '_dmarc.example.com': ['v=DMARC1; p=reject'],
      'lists.example.org': ['v=spf1 ip4:198.51.100.88 -all'],
    });

    const arcReport = await verifyEmailMessageCryptographically(fullArcEml, {
      fetchImpl: arcDoh,
      trustAnchors: [],
      nowMs: Date.UTC(2024, 4, 16, 10, 5, 0),
    });

    expect(arcReport.arc.present).toBe(true);
    expect(arcReport.arc.verdict).toBe('pass');
    expect(arcReport.arc.sets).toHaveLength(2);
    expect(arcReport.arc.sets[0].amsModifiedDownstream).toBe(true);
    expect(arcReport.arc.sets[0].seal?.verdict).toBe('pass');
    expect(arcReport.arc.sets[1].ams?.verdict).toBe('pass');
    expect(arcReport.arc.sets[1].seal?.verdict).toBe('pass');
    // Forwarded message failed direct DMARC (lists.example.org != example.com), but valid ARC preserved upstream dmarc=pass!
    expect(arcReport.dmarcReplay.verdict).toBe('fail');
    expect(arcReport.dmarcReplay.arcOverrideCandidate).toBe(true);

    // Tampering with AAR(1) breaks BOTH AS(1) and AS(2) seals!
    const forgedAarEml = fullArcEml.replace('dmarc=pass', 'dmarc=none');
    const forgedReport = await verifyEmailMessageCryptographically(forgedAarEml, {
      fetchImpl: arcDoh,
      trustAnchors: [],
      nowMs: Date.UTC(2024, 4, 16, 10, 5, 0),
    });
    expect(forgedReport.arc.verdict).toBe('fail');
    expect(forgedReport.arc.sets[0].seal?.verdict).toBe('fail');
    expect(forgedReport.arc.sets[1].seal?.verdict).toBe('fail');

    // RFC 8617 §4.1.3: h= tag inside ARC-Seal MUST fail with permerror
    const illegalHSealEml = fullArcEml.replace('cv=pass;', 'cv=pass; h=from:to;');
    const illegalHReport = await verifyEmailMessageCryptographically(illegalHSealEml, {
      fetchImpl: arcDoh,
      trustAnchors: [],
    });
    expect(illegalHReport.arc.sets[1].seal?.verdict).toBe('permerror');
  });

  it('enforces PSL-aware strict (s) vs relaxed (r) DMARC organizational alignment and reuses cached snapshot queries', async () => {
    clearPublicSuffixCache();
    seedPublicSuffixCache('sub.example.co.uk', 'co.uk');
    seedPublicSuffixCache('mailer.example.co.uk', 'co.uk');
    seedPublicSuffixCache('evil.co.uk', 'co.uk');

    const pslLogs = [
      makeTxtLog('sub.example.co.uk.psl.digdeep.fyi', ['co.uk'], false),
      makeTxtLog('mailer.example.co.uk.psl.digdeep.fyi', ['co.uk'], false),
      makeTxtLog('evil.co.uk.psl.digdeep.fyi', ['co.uk'], false),
    ];

    // Relaxed alignment across sibling subdomains under .co.uk -> ALIGNED (example.co.uk)
    const relaxedSibling = evaluateDmarcAlignment({
      candidateDomain: 'mailer.example.co.uk',
      fromDomain: 'sub.example.co.uk',
      mode: 'r',
      queries: pslLogs,
    });
    expect(relaxedSibling.aligned).toBe(true);
    expect(relaxedSibling.matchKind).toBe('org-domain');
    expect(relaxedSibling.fromOrgDomain).toBe('example.co.uk');

    // Strict alignment across sibling subdomains -> UNALIGNED
    const strictSibling = evaluateDmarcAlignment({
      candidateDomain: 'mailer.example.co.uk',
      fromDomain: 'sub.example.co.uk',
      mode: 's',
      queries: pslLogs,
    });
    expect(strictSibling.aligned).toBe(false);

    // Different registrable orgs under multi-label PSL co.uk -> NEVER aligned even in relaxed mode!
    const cousinCoUk = evaluateDmarcAlignment({
      candidateDomain: 'evil.co.uk',
      fromDomain: 'sub.example.co.uk',
      mode: 'r',
      queries: pslLogs,
    });
    expect(cousinCoUk.aligned).toBe(false);

    // Verify DohSession initialLogs reuse from existing AnalysisSnapshot (0 network queries when cached)
    const edPair = (await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const edRawB64 = bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey('raw', edPair.publicKey))
    );
    const hdrs = [
      'From: ops@example.com',
      'To: user@example.org',
      'Subject: Snapshot Cache Test',
      'Date: Fri, 17 May 2024 08:00:00 +0000',
    ];
    const body = 'Cached snapshot verification.\r\n';
    const dkimHdr = await signMessageWithRsaOrEd25519({
      rawHeadersTopToBottom: hdrs,
      rawBodyCrlf: body,
      headerPrefixTags:
        'v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=edcache; h=from:to:subject:date',
      algorithm: 'ed25519-sha256',
      bodyCanon: 'relaxed',
      privateKey: edPair.privateKey,
    });
    const cachedSnap: AnalysisSnapshot = {
      id: 'snap-cached',
      version: 16,
      mode: 'mail',
      targetName: 'example.com.',
      displayDomain: 'example.com',
      queryTypes: ['MX', 'TXT'],
      dohEndpoint: 'https://1.1.1.1/dns-query',
      capturedAt: 1_715_900_000_000,
      validatedAt: 1_715_900_000_000,
      durationMs: 50,
      overallStatus: 'insecure',
      overallSummary: 'Cached mail snapshot',
      zones: [],
      cnameEdges: [],
      findings: [],
      queries: [
        makeTxtLog('edcache._domainkey.example.com', [`v=DKIM1; k=ed25519; p=${edRawB64}`], true),
        makeTxtLog('_dmarc.example.com', ['v=DMARC1; p=quarantine'], true),
        makeTxtLog('example.com.psl.digdeep.fyi', ['com'], false),
      ],
      trustAnchorsUsed: [],
    };

    const cachedReport = await verifyEmailMessageCryptographically(
      `${[dkimHdr, ...hdrs].join('\r\n')}\r\n\r\n${body}`,
      {
        snapshot: cachedSnap,
        fetchImpl: createInMemoryDohFetch({}),
      }
    );
    expect(cachedReport.reusedSnapshotQueries).toBe(3);
    expect(cachedReport.dkimResults[0].verdict).toBe('pass');
    expect(cachedReport.dmarcReplay.verdict).toBe('pass');
  });

  it('detects raw email headers in omnibox smart-paste without false-triggering on domains, URLs, IPs, or CLI commands', () => {
    const pastedHeaders = [
      'Delivered-To: user@example.net',
      'Authentication-Results: mx.example.net; dkim=pass header.d=ietf.org header.s=ietf1; spf=pass; dmarc=pass',
      'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=ietf.org; s=ietf1; bh=abc=; b=xyz=',
      'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=lists.ietf.org; s=arc1; b=123=',
      'From: IETF Secretariat <agenda@ietf.org>',
      'Subject: IETF 120 Agenda',
    ].join('\n');

    expect(looksLikeRawEmailHeaders(pastedHeaders)).toBe(true);
    const parsed = parseOmniboxInput(pastedHeaders);
    expect(parsed.kind).toBe('email-headers');
    if (parsed.kind === 'email-headers') {
      expect(parsed.target).toBe('ietf.org');
      expect(parsed.dkimSelectors).toEqual(['ietf1']);
      expect(parsed.dkimSignatureCount).toBe(1);
      expect(parsed.arcSetCount).toBe(1);
      expect(parsed.fromAddress).toBe('agenda@ietf.org');
    }

    // Must never false-trigger on plain email addresses, URLs, IPv6, or dig commands
    expect(looksLikeRawEmailHeaders('Alice <alice@ietf.org>')).toBe(false);
    expect(looksLikeRawEmailHeaders('https://ietf.org:8443/agenda')).toBe(false);
    expect(looksLikeRawEmailHeaders('2001:4860:4860::8888')).toBe(false);
    expect(parseOmniboxInput('Alice <alice@ietf.org>').kind).toBe('email');
    expect(parseOmniboxInput('dig @1.1.1.1 ietf.org MX').kind).toBe('cli-command');
  });
});
