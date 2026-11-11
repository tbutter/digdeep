import { describe, expect, it } from 'vitest';
import { runDnsvizAnalysis } from '../analyzer';
import { RR_TYPES } from '../constants';
import {
  armorOpenPgpPublicKey,
  computeDaneLocalPartHash,
  computeOpenPgpCrc24,
  decodeOpenPgpTransferablePublicKey,
  decodeX509CertificateDer,
  deriveEmailDaneTargets,
  evaluateEmailDaneFromSnapshotData,
  parseEmailDaneInput,
} from '../emailDane';
import { bytesToBase64, bytesToHex, hexToBytes } from '../encoding';
import { splitDomainByPublicSuffix } from '../mailAnalyzer';
import type { AnalyzedRrset, ZoneAnalysis } from '../types';

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function pgpNewPacket(tag: number, body: Uint8Array): Uint8Array {
  const ctb = 0xc0 | (tag & 0x3f);
  if (body.length < 192) {
    return concatBytes(new Uint8Array([ctb, body.length]), body);
  }
  const b0 = ((body.length - 192) >> 8) + 192;
  const b1 = (body.length - 192) & 0xff;
  return concatBytes(new Uint8Array([ctb, b0, b1]), body);
}

function derTlv(tag: number, content: Uint8Array): Uint8Array {
  if (content.length < 128) {
    return concatBytes(new Uint8Array([tag, content.length]), content);
  }
  if (content.length < 256) {
    return concatBytes(new Uint8Array([tag, 0x81, content.length]), content);
  }
  return concatBytes(
    new Uint8Array([tag, 0x82, (content.length >> 8) & 0xff, content.length & 0xff]),
    content
  );
}

function derOid(hexStr: string): Uint8Array {
  return derTlv(0x06, hexToBytes(hexStr));
}

function derUtf8(str: string): Uint8Array {
  return derTlv(0x0c, new TextEncoder().encode(str));
}

function derIa5(str: string): Uint8Array {
  return derTlv(0x16, new TextEncoder().encode(str));
}

function derRdn(oidHex: string, valEl: Uint8Array): Uint8Array {
  return derTlv(0x31, derTlv(0x30, concatBytes(derOid(oidHex), valEl)));
}

function buildTestSmimeCertDer(): Uint8Array {
  // Version v3 ([0] EXPLICIT INTEGER 2)
  const version = derTlv(0xa0, derTlv(0x02, new Uint8Array([0x02])));
  // Serial 0x12345678
  const serial = derTlv(0x02, new Uint8Array([0x12, 0x34, 0x56, 0x78]));
  // ecdsa-with-SHA256 (1.2.840.10045.4.3.2 -> 2a8648ce3d040302)
  const sigAlg = derTlv(0x30, derOid('2a8648ce3d040302'));
  // Issuer: CN=Example S/MIME CA, O=Example Org
  const issuer = derTlv(
    0x30,
    concatBytes(
      derRdn('550403', derUtf8('Example S/MIME CA')),
      derRdn('55040a', derUtf8('Example Org'))
    )
  );
  // Validity: 2025-01-01T00:00:00Z .. 2029-01-01T00:00:00Z
  const notBefore = derTlv(0x17, new TextEncoder().encode('250101000000Z'));
  const notAfter = derTlv(0x17, new TextEncoder().encode('290101000000Z'));
  const validity = derTlv(0x30, concatBytes(notBefore, notAfter));
  // Subject: CN=Alice Example, emailAddress=alice@example.org
  const subject = derTlv(
    0x30,
    concatBytes(
      derRdn('550403', derUtf8('Alice Example')),
      derRdn('2a864886f70d010901', derIa5('alice@example.org'))
    )
  );
  // SPKI: id-ecPublicKey (2a8648ce3d0201) + prime256v1 (2a8648ce3d030107) + 65B uncompressed EC point
  const ecPoint = new Uint8Array(66);
  ecPoint[0] = 0x00; // 0 unused bits in BIT STRING
  ecPoint[1] = 0x04;
  ecPoint.fill(0xab, 2);
  const spki = derTlv(
    0x30,
    concatBytes(
      derTlv(0x30, concatBytes(derOid('2a8648ce3d0201'), derOid('2a8648ce3d030107'))),
      derTlv(0x03, ecPoint)
    )
  );

  // Extensions: subjectAltName (2.5.29.17 -> 551d11) with [1] rfc822Name "alice@example.org"
  // + extKeyUsage (2.5.29.37 -> 551d25) with id-kp-emailProtection (1.3.6.1.5.5.7.3.4 -> 2b06010505070304)
  const sanValue = derTlv(0x30, derTlv(0x81, new TextEncoder().encode('alice@example.org')));
  const sanExt = derTlv(0x30, concatBytes(derOid('551d11'), derTlv(0x04, sanValue)));
  const ekuValue = derTlv(0x30, derOid('2b06010505070304'));
  const ekuExt = derTlv(0x30, concatBytes(derOid('551d25'), derTlv(0x04, ekuValue)));
  const extensions = derTlv(0xa3, derTlv(0x30, concatBytes(sanExt, ekuExt)));

  const tbs = derTlv(
    0x30,
    concatBytes(version, serial, sigAlg, issuer, validity, subject, spki, extensions)
  );
  const dummySig = derTlv(0x03, new Uint8Array([0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
  return derTlv(0x30, concatBytes(tbs, sigAlg, dummySig));
}

describe('RFC 7929 (OPENPGPKEY) & RFC 8162 (SMIMEA) Email DANE Identity Engine', () => {
  it('derives RFC 7929 §3 SHA-256-224 local-part hashes, case-sensitive + lowercase fallbacks, and PSL splits', async () => {
    // Official RFC 7929 §3 test vector: hugh@example.com
    const hughHash = await computeDaneLocalPartHash('hugh');
    expect(hughHash).toBe('c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6');

    const hughTargets = await deriveEmailDaneTargets('hugh@example.com');
    expect(hughTargets).not.toBeNull();
    expect(hughTargets?.inputKind).toBe('email');
    expect(hughTargets?.domain).toBe('example.com.');
    expect(hughTargets?.openpgpkeyQname).toBe(
      'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com.'
    );
    expect(hughTargets?.smimeaQname).toBe(
      'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com.'
    );
    expect(hughTargets?.lowercaseHashHex).toBeUndefined();

    // Mixed-case local-part generates both exact-case and RFC 7929 §4 lowercase fallback QNAMEs
    const mixedTargets = await deriveEmailDaneTargets('<mailto:Hugh@Example.COM>');
    expect(mixedTargets?.canonicalInput).toBe('Hugh@example.com');
    expect(mixedTargets?.exactHashHex).not.toBe(hughHash);
    expect(mixedTargets?.lowercaseHashHex).toBe(hughHash);
    expect(mixedTargets?.lowercaseOpenpgpkeyQname).toBe(
      'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com.'
    );

    // Quoted RFC 5322 local-part removes surrounding quotes before hashing
    const quoted = parseEmailDaneInput('"hugh"@example.com');
    expect(quoted?.localPart).toBe('hugh');

    // Pre-hashed owner detection
    const preHashed = parseEmailDaneInput(
      'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com'
    );
    expect(preHashed?.inputKind).toBe('openpgpkey-owner');
    expect(preHashed?.domain).toBe('example.com.');

    // Search bar Public Suffix alignment on email inputs
    const split = splitDomainByPublicSuffix('paul@nohats.ca');
    expect(split).not.toBeNull();
    expect(split?.prefix).toBe('paul@nohats.');
    expect(split?.publicSuffix).toBe('ca');
  });

  it('decodes OpenPGP v4 & v6 Transferable Public Keys, subkeys, User IDs, expirations, and CRC24 armor', async () => {
    const createdSec = 1735689600; // 2025-01-01T00:00:00Z
    // Primary key: v4 (4), createdSec, alg 22 (EdDSA), OID len 9 (2B06010401DA470F01 = Ed25519), MPI
    const primaryBody = concatBytes(
      new Uint8Array([
        4,
        (createdSec >>> 24) & 0xff,
        (createdSec >>> 16) & 0xff,
        (createdSec >>> 8) & 0xff,
        createdSec & 0xff,
        22,
        9,
      ]),
      hexToBytes('2B06010401DA470F01'),
      new Uint8Array([0x01, 0x07, 0x40, ...new Uint8Array(32).fill(0x11)])
    );

    const uidBody = new TextEncoder().encode('Alice Example <alice@example.org>');

    // Self-signature (v4, sigType 0x13 Positive Certification):
    // Hashed subpackets: sigCreationTime (type 2) + keyExpiration +31536000s (type 9) + keyFlags 0x03 Certify|Sign (type 27)
    const expRel = 31536000; // +365 days -> expires 2026-01-01
    const hashedSub = new Uint8Array([
      5, 2, (createdSec >>> 24) & 0xff, (createdSec >>> 16) & 0xff, (createdSec >>> 8) & 0xff, createdSec & 0xff,
      5, 9, (expRel >>> 24) & 0xff, (expRel >>> 16) & 0xff, (expRel >>> 8) & 0xff, expRel & 0xff,
      2, 27, 0x03,
    ]);
    const selfSigBody = concatBytes(
      new Uint8Array([4, 0x13, 22, 8, 0, hashedSub.length]),
      hashedSub,
      new Uint8Array([0, 0, 0xaa, 0xbb])
    );

    // Encryption Subkey: v4, createdSec, alg 18 (ECDH), OID len 10 (Curve25519)
    const subkeyBody = concatBytes(
      new Uint8Array([
        4,
        (createdSec >>> 24) & 0xff,
        (createdSec >>> 16) & 0xff,
        (createdSec >>> 8) & 0xff,
        createdSec & 0xff,
        18,
        10,
      ]),
      hexToBytes('2B060104019755010501'),
      new Uint8Array([0x01, 0x07, 0x40, ...new Uint8Array(32).fill(0x22), 0x03, 0x01, 0x08, 0x07])
    );
    const subSigHashed = new Uint8Array([
      5, 2, (createdSec >>> 24) & 0xff, (createdSec >>> 16) & 0xff, (createdSec >>> 8) & 0xff, createdSec & 0xff,
      2, 27, 0x0c, // Encrypt Comm | Encrypt Storage
    ]);
    const subSigBody = concatBytes(
      new Uint8Array([4, 0x18, 22, 8, 0, subSigHashed.length]),
      subSigHashed,
      new Uint8Array([0, 0, 0xcc, 0xdd])
    );

    const tpkBytes = concatBytes(
      pgpNewPacket(6, primaryBody),
      pgpNewPacket(13, uidBody),
      pgpNewPacket(2, selfSigBody),
      pgpNewPacket(14, subkeyBody),
      pgpNewPacket(2, subSigBody)
    );

    const decoded = await decodeOpenPgpTransferablePublicKey(tpkBytes, {
      queriedEmail: 'alice@example.org',
      validationTimeSec: createdSec + 86400, // Valid (day 1)
    });
    expect(decoded.version).toBe(4);
    expect(decoded.algorithmName).toContain('EdDSA');
    expect(decoded.curveOrBits).toBe('Ed25519');
    expect(decoded.fingerprintHex).toHaveLength(40);
    expect(decoded.keyIdHex).toBe(decoded.fingerprintHex.slice(-16));
    expect(decoded.userIds).toEqual(['Alice Example <alice@example.org>']);
    expect(decoded.matchesQueriedEmail).toBe(true);
    expect(decoded.keyFlags).toEqual(['Certify', 'Sign']);
    expect(decoded.isExpired).toBe(false);
    expect(decoded.subkeys).toHaveLength(1);
    expect(decoded.subkeys[0].curveOrBits).toContain('Curve25519');
    expect(decoded.subkeys[0].keyFlags).toEqual(['Encrypt Comm', 'Encrypt Storage']);
    expect(decoded.armoredPublicKey).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');

    // Time-travel past expiration marks key expired
    const decodedExpired = await decodeOpenPgpTransferablePublicKey(tpkBytes, {
      queriedEmail: 'other@example.org',
      validationTimeSec: createdSec + expRel + 3600,
    });
    expect(decodedExpired.isExpired).toBe(true);
    expect(decodedExpired.matchesQueriedEmail).toBe(false);

    // Verify RFC 9580 v6 Ed25519 key (alg 27) produces 64-hex SHA-256 fingerprint
    const v6Body = concatBytes(
      new Uint8Array([
        6,
        (createdSec >>> 24) & 0xff,
        (createdSec >>> 16) & 0xff,
        (createdSec >>> 8) & 0xff,
        createdSec & 0xff,
        27,
        0, 0, 0, 32,
      ]),
      new Uint8Array(32).fill(0x55)
    );
    const v6Decoded = await decodeOpenPgpTransferablePublicKey(pgpNewPacket(6, v6Body));
    expect(v6Decoded.version).toBe(6);
    expect(v6Decoded.algorithmName).toContain('Ed25519');
    expect(v6Decoded.fingerprintHex).toHaveLength(64);
    expect(v6Decoded.keyIdHex).toBe(v6Decoded.fingerprintHex.slice(0, 16));

    // Verify CRC24 checksum on "123456789"
    const crc = computeOpenPgpCrc24(new TextEncoder().encode('123456789'));
    expect(crc).toBe(0x21cf02);
    expect(armorOpenPgpPublicKey(new Uint8Array([1, 2, 3]))).toContain('-----END PGP PUBLIC KEY BLOCK-----');
  });

  it('decodes SMIMEA full X.509 DER certificates and enforces mandatory DNSSEC on unsigned zones', async () => {
    const certDer = buildTestSmimeCertDer();
    const validMidpointSec = Math.floor(Date.UTC(2026, 5, 1) / 1000);
    const cert = await decodeX509CertificateDer(certDer, {
      queriedEmail: 'alice@example.org',
      validationTimeSec: validMidpointSec,
    });

    expect(cert.version).toBe(3);
    expect(cert.serialHex).toBe('12:34:56:78');
    expect(cert.signatureAlgorithm).toBe('ecdsa-with-SHA256');
    expect(cert.subject).toContain('CN=Alice Example');
    expect(cert.subjectEmailAddresses).toEqual(['alice@example.org']);
    expect(cert.sanRfc822Names).toEqual(['alice@example.org']);
    expect(cert.issuer).toContain('CN=Example S/MIME CA');
    expect(cert.publicKeyAlgorithm).toBe('ECDSA / EC');
    expect(cert.publicKeyBitsOrCurve).toBe('NIST P-256');
    expect(cert.hasEmailProtectionEku).toBe(true);
    expect(cert.isExpired).toBe(false);
    expect(cert.matchesQueriedEmail).toBe(true);
    expect(cert.pem).toContain('-----BEGIN CERTIFICATE-----');

    // Enforce RFC 8162 §5 / RFC 7929 §5 warning when SMIMEA is published in an UNSIGNED (insecure) zone!
    const derived = (await deriveEmailDaneTargets('alice@example.org'))!;
    const smimeaOwner = derived.smimeaQname!;
    const certHex = bytesToHex(certDer);
    const rawRdata = concatBytes(new Uint8Array([3, 0, 0]), certDer);

    const unsignedSmimeaRrset: AnalyzedRrset = {
      id: `rrset-example.org.-${smimeaOwner}-SMIMEA`,
      zone: 'example.org.',
      name: smimeaOwner,
      type: RR_TYPES.SMIMEA,
      typeName: 'SMIMEA',
      ttl: 3600,
      section: 'answer',
      isQueryTarget: true,
      records: [
        {
          name: smimeaOwner,
          type: RR_TYPES.SMIMEA,
          typeName: 'SMIMEA',
          rrclass: 1,
          ttl: 3600,
          rdataBase64: bytesToBase64(rawRdata),
          canonicalRdataBase64: bytesToBase64(rawRdata),
          rdataText: `3 0 0 ${certHex}`,
          section: 'answer',
          parsed: {
            kind: 'TLSA',
            usage: 3,
            selector: 0,
            matchingType: 0,
            certAssociationHex: certHex,
          },
        },
      ],
      rrsigs: [],
      status: 'insecure',
      statusReason: 'Zone example.org. is unsigned',
    };

    const unsignedZone: ZoneAnalysis = {
      zoneName: 'example.org.',
      parentZone: 'org.',
      depth: 2,
      dnskeys: [],
      dsVerifications: [],
      trustAnchorMatches: [],
      rrsets: [unsignedSmimeaRrset],
      negativeNodes: [],
      nameservers: [],
      nsecMode: 'UNSIGNED',
      status: 'insecure',
      statusReason: 'Unsigned delegation',
    };

    const evalRes = await evaluateEmailDaneFromSnapshotData({
      derivedTargets: derived,
      queries: [],
      zones: [unsignedZone],
      cnameEdges: [],
      dohEndpoint: 'https://cloudflare-dns.com/dns-query',
      validatedAt: validMidpointSec * 1000,
    });

    expect(evalRes.emailDane.smimea?.status).toBe('present');
    expect(evalRes.emailDane.smimea?.dnssecStatus).toBe('insecure');
    expect(evalRes.emailDane.smimea?.daneUsable).toBe(false);
    expect(evalRes.emailDane.smimea?.records[0]?.decodedCert?.sanRfc822Names).toEqual([
      'alice@example.org',
    ]);
    expect(evalRes.findings.some((f) => f.code === 'EMAIL_DANE_UNSIGNED_IGNORE')).toBe(true);
    expect(evalRes.overallStatusOverride).toBe('warning');
  });

  it(
    'resolves, validates DNSSEC, and decodes live RFC 7929 OPENPGPKEY for paul@nohats.ca via 1.1.1.1 DoH',
    async () => {
      const snap = await runDnsvizAnalysis('paul@nohats.ca');
      expect(snap.queriedEmail).toBe('paul@nohats.ca');
      expect(snap.targetName).toBe('nohats.ca.');
      expect(snap.emailDane).toBeDefined();
      expect(snap.emailDane?.exactHashHex).toBe(
        '0357513deb903a056e74a7e475247fc1ffe31d8be4c1d4a31f58dd47'
      );

      const pgp = snap.emailDane?.openpgpkey;
      expect(pgp).toBeDefined();
      expect(pgp?.status).toBe('present');
      expect(pgp?.dnssecStatus).toBe('secure');
      expect(pgp?.daneUsable).toBe(true);
      expect(pgp?.records.length).toBeGreaterThanOrEqual(1);

      const dk = pgp?.records[0]?.decodedKey;
      expect(dk).toBeDefined();
      expect(dk?.version).toBe(4);
      expect(dk?.fingerprintHex).toHaveLength(40);
      expect(dk?.userIds.some((u) => u.toLowerCase().includes('paul@nohats.ca'))).toBe(true);
      expect(dk?.matchesQueriedEmail).toBe(true);
    },
    25000
  );
});
