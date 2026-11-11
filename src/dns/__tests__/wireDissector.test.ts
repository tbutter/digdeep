import { describe, expect, it } from 'vitest';
import { RR_TYPES } from '../constants';
import { formatPacketAsDig, formatWireHexDump } from '../digFormat';
import { bytesToBase64, bytesToBase64Url, hexToBytes } from '../encoding';
import { buildDnsQuery } from '../wire';
import {
  buildHeaderBitFields,
  buildSyntheticLogFromDissected,
  decodeUserWireInput,
  decodeWireNameWithTrace,
  dissectDnsWirePacket,
} from '../wireDissector';

// 68-byte DNS response for `www.example.org. IN A` with CNAME + A records and 3 compression pointers
const COMPRESSED_RESPONSE_HEX =
  '1a2b81a00001000200000000' +
  '03777777076578616d706c65036f72670000010001' +
  'c00c0005000100000e1000070465646765c010' +
  'c02d000100010000012c00045db8d822';

describe('Byte-Level DNS Wire Dissector & Compression Pointer Tracer', () => {
  it('dissects header bitfields, contiguous section spans, and direct + chained 0xC0xx pointers', () => {
    const buf = hexToBytes(COMPRESSED_RESPONSE_HEX);
    expect(buf.length).toBe(68);

    const dissected = dissectDnsWirePacket(buf);
    expect(dissected.parseWarning).toBeUndefined();
    expect(dissected.id).toBe(0x1a2b);
    expect(dissected.flagWord).toBe(0x81a0);
    expect(dissected.flagWordHex).toBe('0x81A0');
    expect(dissected.counts).toEqual({
      qdCount: 1,
      anCount: 2,
      nsCount: 0,
      arCount: 0,
    });

    // Verify 16-bit header flags breakdown
    const bitByName = Object.fromEntries(dissected.headerBits.map((b) => [b.name, b]));
    expect(bitByName.QR.numericValue).toBe(1);
    expect(bitByName.RD.numericValue).toBe(1);
    expect(bitByName.RA.numericValue).toBe(1);
    expect(bitByName.AD.numericValue).toBe(1);
    expect(bitByName.CD.numericValue).toBe(0);
    expect(bitByName.RCODE.numericValue).toBe(0);

    // Verify contiguous byte coverage from 0..68 across Header + Question + 2 Answers
    expect(dissected.spans).toHaveLength(4);
    expect(dissected.spans[0].startOffset).toBe(0);
    expect(dissected.spans[0].endOffset).toBe(12);
    expect(dissected.spans[1].startOffset).toBe(12);
    expect(dissected.spans[1].endOffset).toBe(33);
    expect(dissected.spans[2].startOffset).toBe(33);
    expect(dissected.spans[2].endOffset).toBe(52);
    expect(dissected.spans[3].startOffset).toBe(52);
    expect(dissected.spans[3].endOffset).toBe(68);

    // Verify all 3 compression pointer jumps (including 2-hop chained pointer)
    expect(dissected.compressionJumps).toHaveLength(3);

    const [jump1, jump2, jump3] = dissected.compressionJumps;
    // Jump 1: Answer #1 Owner NAME `0x0021 [0xC00C] -> 0x000C` ("www.example.org.")
    expect(jump1.pointerOffset).toBe(0x21);
    expect(jump1.targetOffset).toBe(0x0c);
    expect(jump1.fullName).toBe('www.example.org.');
    expect(jump1.inlineBytes).toBe(2);
    expect(jump1.uncompressedBytes).toBe(17);
    expect(jump1.savedBytes).toBe(15);
    expect(jump1.hops).toHaveLength(1);

    // Jump 2: Answer #1 CNAME Target `\x04edge` at 0x2D + `0x0032 [0xC010] -> 0x0010` ("example.org.")
    expect(jump2.nameStartOffset).toBe(0x2d);
    expect(jump2.pointerOffset).toBe(0x32);
    expect(jump2.targetOffset).toBe(0x10);
    expect(jump2.fullName).toBe('edge.example.org.');
    expect(jump2.resolvedSuffix).toBe('example.org.');
    expect(jump2.inlineBytes).toBe(7);
    expect(jump2.uncompressedBytes).toBe(18);
    expect(jump2.savedBytes).toBe(11);

    // Jump 3: Chained pointer `0x0034 [0xC02D] -> 0x002D -> 0x0010` ("edge.example.org.")
    expect(jump3.pointerOffset).toBe(0x34);
    expect(jump3.targetOffset).toBe(0x2d);
    expect(jump3.fullName).toBe('edge.example.org.');
    expect(jump3.hops).toHaveLength(2);
    expect(jump3.hops[0].pointerHex).toBe('0xC02D');
    expect(jump3.hops[1].pointerHex).toBe('0xC010');
    expect(jump3.savedBytes).toBe(16);

    // Total wire savings: 15 + 11 + 16 = 42 bytes saved
    expect(dissected.compressionStats).toEqual({
      pointerCount: 3,
      compressedWireSize: 68,
      uncompressedEquivalentSize: 110,
      totalSavedBytes: 42,
      savingsPercent: 38.2,
    });

    // Verify synthetic dig output generation for offline packets
    const syntheticLog = buildSyntheticLogFromDissected(dissected);
    expect(syntheticLog).not.toBeNull();
    const digOut = formatPacketAsDig(syntheticLog!);
    expect(digOut).toContain('status: NOERROR');
    expect(digOut).toContain('edge.example.org.');
    expect(digOut).toContain('93.184.216.34');
  });

  it('dissects EDNS0 OPT pseudo-RR with Extended DNS Error (RFC 8914 Option 15) and extended RCODE', () => {
    const queryWire = buildDnsQuery('example.org', RR_TYPES.DNSKEY, { cd: true, doBit: true, id: 0x4242 });
    const reqDissected = dissectDnsWirePacket(queryWire);
    expect(reqDissected.counts).toEqual({ qdCount: 1, anCount: 0, nsCount: 0, arCount: 1 });
    const ednsSection = reqDissected.spans.find((s) => s.category === 'edns');
    expect(ednsSection).toBeDefined();
    expect(ednsSection?.title).toContain('DO=1');

    // Craft response with EDNS0 OPT + EDE code 6 (DNSSEC Bogus: "signature expired")
    const edePacketHex =
      '424281920001000000000001' + // ID=0x4242, Flags=0x8192 (QR=1, RD=1, RA=1, CD=1, RCODE=SERVFAIL)
      '076578616d706c65036f72670000300001' + // example.org. IN DNSKEY
      '00002904d000008000' + // OPT root=0x00, type=41, udp=1232, extRcode=0, ver=0, flags=0x8000 (DO=1)
      '0009' + // RDLENGTH = 9
      '000f00050006626164'; // Option 15 (EDE), len 5, infoCode=6 (DNSSEC Bogus), extra="bad"
    const edeDissected = dissectDnsWirePacket(hexToBytes(edePacketHex));
    expect(edeDissected.parseWarning).toBeUndefined();
    const optSpan = edeDissected.spans.find((s) => s.category === 'edns')!;
    const edeField = optSpan.fields.find((f) => f.label.includes('Option 15'));
    expect(edeField).toBeDefined();
    expect(edeField?.valueSummary).toContain('EDE 6 (DNSSEC Bogus): "bad"');

    // Verify extended RCODE (e.g. BADVERS = 16 when extRcode=1, baseRcode=0)
    const extBits = buildHeaderBitFields(0x8180, 1);
    const rcodeField = extBits.find((b) => b.name === 'RCODE')!;
    expect(rcodeField.numericValue).toBe(16);
    expect(rcodeField.summary).toContain('16');
  });

  it('auto-detects and decodes DoH ?dns= URLs, Base64url, raw hex, and offset hex dumps offline', () => {
    const expectedBytes = hexToBytes(COMPRESSED_RESPONSE_HEX);
    const b64Url = bytesToBase64Url(expectedBytes);
    const b64Std = bytesToBase64(expectedBytes);

    // 1. Full RFC 8484 DoH URL
    const fromUrl = decodeUserWireInput(`https://cloudflare-dns.com/dns-query?dns=${b64Url}`);
    expect(fromUrl.detectedFormat).toBe('doh-url');
    expect(fromUrl.bytes).toEqual(expectedBytes);

    // 2. Raw Base64url / Base64
    const fromB64Url = decodeUserWireInput(b64Url);
    expect(fromB64Url.detectedFormat).toBe('base64url');
    expect(fromB64Url.bytes).toEqual(expectedBytes);

    // 3. DigDeep / xxd multi-line offset hex dump
    const dumpLines = formatWireHexDump(b64Std)
      .map((r) => `${r.offsetHex}  ${r.hexGroups}  |${r.ascii}|`)
      .join('\n');
    const fromHexDump = decodeUserWireInput(dumpLines);
    expect(fromHexDump.detectedFormat).toBe('hex-dump');
    expect(fromHexDump.bytes).toEqual(expectedBytes);

    // 4. Colon-delimited and plain hex
    const colonHex = Array.from(expectedBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':');
    const fromColonHex = decodeUserWireInput(colonHex);
    expect(fromColonHex.detectedFormat).toBe('hex');
    expect(fromColonHex.bytes).toEqual(expectedBytes);
  });

  it('guards against compression pointer loops and out-of-bounds pointer targets without hanging', () => {
    // Self-referencing compression pointer `0xC00C` at offset 0x000C
    const loopHex = '123481800001000000000000c00c00010001';
    const loopBytes = hexToBytes(loopHex);
    expect(() => decodeWireNameWithTrace(loopBytes, 12)).toThrow(/loop detected/i);

    const dissectedLoop = dissectDnsWirePacket(loopBytes);
    expect(dissectedLoop.parseWarning).toMatch(/loop detected/i);

    // Out-of-bounds compression pointer `0xC07F` in an 18-byte packet
    const oobHex = '123481800001000000000000c07f00010001';
    const dissectedOob = dissectDnsWirePacket(hexToBytes(oobHex));
    expect(dissectedOob.parseWarning).toMatch(/out-of-bounds/i);
  });
});
