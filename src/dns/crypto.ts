import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from './constants';
import {
  base64ToBytes,
  bytesToBase32Hex,
  bytesToBase64Url,
  bytesToHex,
  compareBytes,
  compareCanonicalDnsNames,
  concatBytes,
  countDnsLabels,
  getDomainHierarchy,
  hexToBytes,
  isSubdomainOrEqual,
  normalizeFqdn,
  splitPresentationLabels,
} from './encoding';
import type {
  DnsRecord,
  DnskeyRdata,
  DsRdata,
  DsVerification,
  NegativeProofVerification,
  NsecProofItem,
  RrsigRdata,
  RrsigVerification,
} from './types';
import { encodeDnsName } from './wire';

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) {
    i++;
  }
  return bytes.subarray(i);
}

/**
 * Computes DS digest (HEX uppercase) of a DNSKEY record per RFC 4034 §5.1.4 & RFC 4509 / RFC 6605:
 * digest = HASH(canonical_owner_wire || DNSKEY_RDATA)
 */
export async function computeDsDigest(
  ownerName: string,
  dnskeyCanonicalRdata: Uint8Array,
  digestType: number
): Promise<string | null> {
  const algName =
    digestType === 1 ? 'SHA-1' : digestType === 2 ? 'SHA-256' : digestType === 4 ? 'SHA-384' : null;
  if (!algName) return null;

  const ownerWire = encodeDnsName(normalizeFqdn(ownerName), true);
  const data = concatBytes(ownerWire, dnskeyCanonicalRdata);
  const hashBuf = await crypto.subtle.digest(algName, toArrayBuffer(data));
  return bytesToHex(new Uint8Array(hashBuf));
}

/**
 * Verifies a parent DS record against candidate DNSKEY records in the child zone.
 */
export async function verifyDsAgainstZoneKeys(
  childZone: string,
  dsRecord: DnsRecord,
  childDnskeyRecords: DnsRecord[]
): Promise<DsVerification> {
  const ds = dsRecord.parsed as DsRdata;
  const id = `ds-${normalizeFqdn(childZone)}-${ds.keyTag}-${ds.digestType}-${ds.digestHex.slice(0, 12)}`;

  const digestMeta = DS_DIGEST_TYPES[ds.digestType];
  const algMeta = DNSSEC_ALGORITHMS[ds.algorithm];
  const digestWarning =
    digestMeta?.deprecated || ds.digestType === 1
      ? `DS uses ${digestMeta?.name ?? `digest ${ds.digestType}`} (RFC 8624: ${digestMeta?.rfc8624 ?? 'NOT RECOMMENDED'})`
      : undefined;
  const algorithmWarning = algMeta?.deprecated
    ? `Algorithm ${ds.algorithm} (${algMeta.mnemonic}) is ${algMeta.rfc8624} per RFC 8624`
    : undefined;

  const candidates = childDnskeyRecords.filter((rec) => {
    if (rec.parsed.kind !== 'DNSKEY') return false;
    return rec.parsed.keyTag === ds.keyTag && rec.parsed.algorithm === ds.algorithm;
  });

  if (candidates.length === 0) {
    return {
      id,
      ds,
      dsTtl: dsRecord.ttl,
      targetKeyFound: false,
      digestValid: false,
      digestWarning,
      algorithmWarning,
      status: 'bogus',
      reason: `No DNSKEY with key tag #${ds.keyTag} (alg ${ds.algorithm}) found in ${childZone}`,
    };
  }

  let lastComputed: string | undefined;
  for (const keyRec of candidates) {
    const keyRdata = base64ToBytes(keyRec.canonicalRdataBase64);
    const computed = await computeDsDigest(childZone, keyRdata, ds.digestType);
    if (computed === null) {
      return {
        id,
        ds,
        dsTtl: dsRecord.ttl,
        matchedKeyTag: ds.keyTag,
        targetKeyFound: true,
        digestValid: false,
        digestWarning,
        algorithmWarning,
        status: 'indeterminate',
        reason: `Unsupported DS digest type ${ds.digestType} (${digestMeta?.name ?? 'unknown'})`,
      };
    }
    lastComputed = computed;
    if (computed.toUpperCase() === ds.digestHex.toUpperCase()) {
      const parsedKey = keyRec.parsed as DnskeyRdata;
      if (!parsedKey.isZoneKey) {
        return {
          id,
          ds,
          dsTtl: dsRecord.ttl,
          matchedKeyTag: ds.keyTag,
          targetKeyFound: true,
          computedDigestHex: computed,
          digestValid: true,
          digestWarning,
          algorithmWarning,
          status: 'bogus',
          reason: `Matched DNSKEY #${ds.keyTag} does not have the Zone Key bit set (RFC 4034 §5.2)`,
        };
      }
      const hasWarn = Boolean(digestWarning || algorithmWarning);
      return {
        id,
        ds,
        dsTtl: dsRecord.ttl,
        matchedKeyTag: ds.keyTag,
        targetKeyFound: true,
        computedDigestHex: computed,
        digestValid: true,
        digestWarning,
        algorithmWarning,
        status: hasWarn ? 'warning' : 'secure',
        reason: `Digest verified against ${childZone} DNSKEY #${ds.keyTag}`,
      };
    }
  }

  return {
    id,
    ds,
    dsTtl: dsRecord.ttl,
    matchedKeyTag: ds.keyTag,
    targetKeyFound: true,
    computedDigestHex: lastComputed,
    digestValid: false,
    digestWarning,
    algorithmWarning,
    status: 'bogus',
    reason: `DS digest mismatch for ${childZone} DNSKEY #${ds.keyTag}`,
  };
}

/**
 * Reconstructs canonical signed data buffer per RFC 4034 §3.1.8.1 & §6.2.
 */
export function buildSignedRrsetBuffer(
  rrset: DnsRecord[],
  rrsig: RrsigRdata
): { signedData: Uint8Array; wildcardSynthesized: boolean; wildcardClosestEncloser?: string } {
  if (rrset.length === 0) {
    throw new Error('Cannot build signed buffer for empty RRset');
  }
  const owner = normalizeFqdn(rrset[0].name);
  const fqdnLabels = splitPresentationLabels(owner);
  const actualLabelCount = countDnsLabels(owner, true);

  let signedOwner = owner;
  let wildcardSynthesized = false;
  let wildcardClosestEncloser: string | undefined;

  if (rrsig.labels < actualLabelCount) {
    wildcardSynthesized = true;
    const suffixLabels = rrsig.labels === 0 ? [] : fqdnLabels.slice(fqdnLabels.length - rrsig.labels);
    wildcardClosestEncloser = suffixLabels.length === 0 ? '.' : `${suffixLabels.join('.')}.`;
    signedOwner = suffixLabels.length === 0 ? '*.' : `*.${suffixLabels.join('.')}.`;
  }

  const ownerWire = encodeDnsName(signedOwner, true);
  const sortedRdatas = rrset
    .map((r) => base64ToBytes(r.canonicalRdataBase64))
    .sort(compareBytes);

  // Deduplicate identical canonical RDATAs per RFC 4034 §6.3
  const uniqueRdatas: Uint8Array[] = [];
  for (const rdata of sortedRdatas) {
    if (
      uniqueRdatas.length === 0 ||
      compareBytes(uniqueRdatas[uniqueRdatas.length - 1], rdata) !== 0
    ) {
      uniqueRdatas.push(rdata);
    }
  }

  const rrChunks: Uint8Array[] = [base64ToBytes(rrsig.signedHeaderBase64)];
  const rrtype = rrset[0].type;
  const rrclass = rrset[0].rrclass;

  for (const rdata of uniqueRdatas) {
    const fixed = new Uint8Array(10);
    const view = new DataView(fixed.buffer);
    view.setUint16(0, rrtype, false);
    view.setUint16(2, rrclass, false);
    view.setUint32(4, rrsig.originalTtl, false);
    view.setUint16(8, rdata.length, false);
    rrChunks.push(ownerWire, fixed, rdata);
  }

  return {
    signedData: concatBytes(...rrChunks),
    wildcardSynthesized,
    wildcardClosestEncloser,
  };
}

async function verifySignatureBytes(
  algorithm: number,
  publicKey: Uint8Array,
  signature: Uint8Array,
  signedData: Uint8Array
): Promise<{ supported: boolean; valid: boolean; error?: string }> {
  try {
    // RSA algorithms: 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1), 8 (RSASHA256), 10 (RSASHA512)
    if (algorithm === 5 || algorithm === 7 || algorithm === 8 || algorithm === 10) {
      if (publicKey.length < 3) {
        return { supported: true, valid: false, error: 'Malformed RSA public key' };
      }
      let expLen = publicKey[0];
      let offset = 1;
      if (expLen === 0) {
        expLen = (publicKey[1] << 8) | publicKey[2];
        offset = 3;
      }
      if (offset + expLen >= publicKey.length) {
        return { supported: true, valid: false, error: 'RSA exponent length exceeds DNSKEY RDATA' };
      }
      const expBytes = stripLeadingZeros(publicKey.subarray(offset, offset + expLen));
      const modBytes = stripLeadingZeros(publicKey.subarray(offset + expLen));
      const hashName =
        algorithm === 5 || algorithm === 7 ? 'SHA-1' : algorithm === 8 ? 'SHA-256' : 'SHA-512';
      const jwkAlg =
        algorithm === 5 || algorithm === 7 ? 'RS1' : algorithm === 8 ? 'RS256' : 'RS512';

      const cryptoKey = await crypto.subtle.importKey(
        'jwk',
        {
          kty: 'RSA',
          n: bytesToBase64Url(modBytes),
          e: bytesToBase64Url(expBytes),
          alg: jwkAlg,
          ext: true,
        },
        { name: 'RSASSA-PKCS1-v1_5', hash: hashName },
        false,
        ['verify']
      );

      const valid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        toArrayBuffer(signature),
        toArrayBuffer(signedData)
      );
      return { supported: true, valid };
    }

    // ECDSA: 13 (ECDSAP256SHA256), 14 (ECDSAP384SHA384)
    if (algorithm === 13 || algorithm === 14) {
      const expectedLen = algorithm === 13 ? 64 : 96;
      if (publicKey.length !== expectedLen || signature.length !== expectedLen) {
        return {
          supported: true,
          valid: false,
          error: `Invalid ECDSA key/signature length (${publicKey.length}/${signature.length}, expected ${expectedLen})`,
        };
      }
      const rawPoint = new Uint8Array(1 + publicKey.length);
      rawPoint[0] = 0x04; // Uncompressed ANSI X9.62 point
      rawPoint.set(publicKey, 1);

      const namedCurve = algorithm === 13 ? 'P-256' : 'P-384';
      const hash = algorithm === 13 ? 'SHA-256' : 'SHA-384';
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        toArrayBuffer(rawPoint),
        { name: 'ECDSA', namedCurve },
        false,
        ['verify']
      );
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash },
        cryptoKey,
        toArrayBuffer(signature),
        toArrayBuffer(signedData)
      );
      return { supported: true, valid };
    }

    // Ed25519: 15
    if (algorithm === 15) {
      if (publicKey.length !== 32 || signature.length !== 64) {
        return {
          supported: true,
          valid: false,
          error: `Invalid Ed25519 key/signature length (${publicKey.length}/${signature.length})`,
        };
      }
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        toArrayBuffer(publicKey),
        { name: 'Ed25519' },
        false,
        ['verify']
      );
      const valid = await crypto.subtle.verify(
        { name: 'Ed25519' },
        cryptoKey,
        toArrayBuffer(signature),
        toArrayBuffer(signedData)
      );
      return { supported: true, valid };
    }

    return {
      supported: false,
      valid: false,
      error: `Algorithm ${algorithm} is not supported by browser WebCrypto`,
    };
  } catch (err) {
    return {
      supported: true,
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * RFC 1982 32-bit serial number arithmetic comparison: returns true if s1 <= s2.
 */
function serialLessOrEqual(s1: number, s2: number): boolean {
  if (s1 === s2) return true;
  const diff = (s2 - s1) >>> 0;
  return diff < 0x80000000;
}

/**
 * Verifies an RRSIG record covering an RRset against the zone's DNSKEY RRset.
 */
export async function verifyRrsigForRrset(
  rrset: DnsRecord[],
  rrsigRecord: DnsRecord,
  zoneDnskeyRecords: DnsRecord[],
  validationEpochSec: number
): Promise<RrsigVerification> {
  const rrsig = rrsigRecord.parsed as RrsigRdata;
  const id = `rrsig-${normalizeFqdn(rrset[0]?.name ?? '.')}-${rrsig.typeCoveredName}-${rrsig.keyTag}-${rrsig.signatureBase64.slice(0, 10)}`;

  const notYetValid = !serialLessOrEqual(rrsig.inception, validationEpochSec);
  const expired = !serialLessOrEqual(validationEpochSec, rrsig.expiration);
  const timeValid = !notYetValid && !expired;
  const remainingSeconds = rrsig.expiration - validationEpochSec;

  const algMeta = DNSSEC_ALGORITHMS[rrsig.algorithm];
  const algorithmWarning = algMeta?.deprecated
    ? `RRSIG uses ${algMeta.mnemonic} (RFC 8624: ${algMeta.rfc8624})`
    : undefined;

  const { signedData, wildcardSynthesized, wildcardClosestEncloser } = buildSignedRrsetBuffer(
    rrset,
    rrsig
  );

  const ttlMismatch = rrset.some((r) => r.ttl > rrsig.originalTtl);

  // Match candidate DNSKEYs by keyTag + algorithm + Zone Key bit + not revoked
  const candidateKeys = zoneDnskeyRecords.filter((rec) => {
    if (rec.parsed.kind !== 'DNSKEY') return false;
    return (
      rec.parsed.keyTag === rrsig.keyTag &&
      rec.parsed.algorithm === rrsig.algorithm &&
      rec.parsed.isZoneKey &&
      !rec.parsed.isRevoked
    );
  });

  if (candidateKeys.length === 0) {
    return {
      id,
      rrsig,
      rrsigTtl: rrsigRecord.ttl,
      signerKeyTag: rrsig.keyTag,
      signerFound: false,
      cryptoValid: false,
      timeValid,
      notYetValid,
      expired,
      remainingSeconds,
      wildcardSynthesized,
      wildcardClosestEncloser,
      ttlMismatch,
      algorithmWarning,
      status: 'bogus',
      reason: `Signing DNSKEY #${rrsig.keyTag} (alg ${rrsig.algorithm}) not present in ${rrsig.signerName}`,
    };
  }

  const sigBytes = base64ToBytes(rrsig.signatureBase64);
  let unsupportedError: string | undefined;
  let lastError: string | undefined;

  for (const keyRec of candidateKeys) {
    const keyParsed = keyRec.parsed as DnskeyRdata;
    const pubKeyBytes = base64ToBytes(keyParsed.publicKeyBase64);
    const res = await verifySignatureBytes(rrsig.algorithm, pubKeyBytes, sigBytes, signedData);
    if (!res.supported) {
      unsupportedError = res.error;
      continue;
    }
    if (res.valid) {
      if (!timeValid) {
        return {
          id,
          rrsig,
          rrsigTtl: rrsigRecord.ttl,
          signerKeyTag: rrsig.keyTag,
          signerFound: true,
          cryptoValid: true,
          timeValid: false,
          notYetValid,
          expired,
          remainingSeconds,
          wildcardSynthesized,
          wildcardClosestEncloser,
          ttlMismatch,
          algorithmWarning,
          status: 'bogus',
          reason: expired
            ? `Signature expired (${Math.abs(Math.round(remainingSeconds / 3600))}h ago)`
            : 'Signature inception timestamp is in the future',
        };
      }
      // Align RRSIG expiration warnings with RFC 4035 §5.3.1 / §5.3.3 and DNSViz:
      // - Warn if cached TTL can outlive the signature (remainingSeconds < minTtl, TTL_BEYOND_EXPIRATION)
      // - Warn if within 5-minute clock-skew window (remainingSeconds <= 300)
      // - Warn on multi-day offline signatures (> 48h total validity window) with < 24h left,
      //   without false-alarming on short-lived online signers (e.g. AWS Route 53 2h window, Cloudflare 25-48h window).
      const minTtl = Math.min(rrsig.originalTtl, rrsigRecord.ttl, ...rrset.map((r) => r.ttl));
      const validityWindowSec = (rrsig.expiration - rrsig.inception) >>> 0;
      const ttlBeyondExpiration = remainingSeconds < minTtl;
      const withinClockSkew = remainingSeconds <= 300;
      const offlineExpiringSoon = validityWindowSec > 172800 && remainingSeconds < 86400;
      const expiringSoon = ttlBeyondExpiration || withinClockSkew || offlineExpiringSoon;
      const expirationWarning = ttlBeyondExpiration
        ? `RRSIG expires in ${Math.max(0, Math.round(remainingSeconds / 60))}m, before RRset/RRSIG TTL (${minTtl}s) expires in caches`
        : withinClockSkew
          ? `RRSIG expires in ${Math.max(0, remainingSeconds)}s (within 5-minute RFC 4035 clock-skew window)`
          : offlineExpiringSoon
            ? `Long-lived RRSIG (${Math.round(validityWindowSec / 86400)}d validity window) has less than 24h remaining (${Math.max(1, Math.round(remainingSeconds / 3600))}h left)`
            : undefined;
      const hasWarning = Boolean(algorithmWarning || expiringSoon || ttlMismatch);
      return {
        id,
        rrsig,
        rrsigTtl: rrsigRecord.ttl,
        signerKeyTag: rrsig.keyTag,
        signerFound: true,
        cryptoValid: true,
        timeValid: true,
        notYetValid: false,
        expired: false,
        remainingSeconds,
        wildcardSynthesized,
        wildcardClosestEncloser,
        ttlMismatch,
        algorithmWarning,
        expirationWarning,
        status: hasWarning ? 'warning' : 'secure',
        reason: expiringSoon
          ? `Cryptographically verified with DNSKEY #${rrsig.keyTag} (expires in ${
              remainingSeconds < 3600
                ? `${Math.max(1, Math.round(remainingSeconds / 60))}m`
                : `${Math.max(1, Math.round(remainingSeconds / 3600))}h`
            })`
          : `Cryptographically verified with DNSKEY #${rrsig.keyTag}`,
      };
    }
    lastError = res.error;
  }

  if (unsupportedError) {
    return {
      id,
      rrsig,
      rrsigTtl: rrsigRecord.ttl,
      signerKeyTag: rrsig.keyTag,
      signerFound: true,
      cryptoValid: false,
      timeValid,
      notYetValid,
      expired,
      remainingSeconds,
      wildcardSynthesized,
      wildcardClosestEncloser,
      ttlMismatch,
      algorithmWarning,
      status: 'indeterminate',
      reason: unsupportedError,
    };
  }

  return {
    id,
    rrsig,
    rrsigTtl: rrsigRecord.ttl,
    signerKeyTag: rrsig.keyTag,
    signerFound: true,
    cryptoValid: false,
    timeValid,
    notYetValid,
    expired,
    remainingSeconds,
    wildcardSynthesized,
    wildcardClosestEncloser,
    ttlMismatch,
    algorithmWarning,
    status: 'bogus',
    reason: lastError
      ? `Cryptographic signature check failed (${lastError})`
      : `Cryptographic signature mismatch for DNSKEY #${rrsig.keyTag}`,
  };
}

/**
 * RFC 5155 §5 NSEC3 iterated salted SHA-1 hash -> Base32hex (uppercase, no padding).
 */
export async function computeNsec3Hash(
  fqdn: string,
  saltHex: string,
  iterations: number
): Promise<string | null> {
  if (iterations > 2500) return null; // RFC 9276 DoS protection
  const wire = encodeDnsName(normalizeFqdn(fqdn), true);
  const salt = saltHex ? hexToBytes(saltHex) : new Uint8Array(0);

  let buf = await crypto.subtle.digest('SHA-1', toArrayBuffer(concatBytes(wire, salt)));
  let current = new Uint8Array(buf);
  for (let i = 0; i < iterations; i++) {
    buf = await crypto.subtle.digest('SHA-1', toArrayBuffer(concatBytes(current, salt)));
    current = new Uint8Array(buf);
  }
  return bytesToBase32Hex(current);
}

function nsecIntervalCovers(owner: string, next: string, target: string, zoneApex: string): boolean {
  const cOwnerTarget = compareCanonicalDnsNames(owner, target);
  if (cOwnerTarget >= 0) return false;
  const cOwnerNext = compareCanonicalDnsNames(owner, next);
  if (cOwnerNext < 0) {
    // Normal forward interval: owner < target < next
    return compareCanonicalDnsNames(target, next) < 0;
  }
  // Wrap-around last NSEC in zone (next points back to zoneApex or earlier)
  return isSubdomainOrEqual(target, zoneApex);
}

function nsec3IntervalCovers(ownerHash: string, nextHash: string, targetHash: string): boolean {
  const o = ownerHash.toUpperCase();
  const n = nextHash.toUpperCase();
  const t = targetHash.toUpperCase();
  if (o === t || n === t) return false;
  if (o < n) {
    return o < t && t < n;
  }
  // Hash ring wrap-around at end of zone
  return t > o || t < n;
}

/**
 * Evaluates NSEC / NSEC3 authenticated denial-of-existence proofs for:
 * - NXDOMAIN
 * - NODATA
 * - INSECURE_DELEGATION (proving absence of DS at child delegation point)
 */
export async function verifyNegativeProof(params: {
  kind: 'NXDOMAIN' | 'NODATA' | 'INSECURE_DELEGATION';
  zoneApex: string;
  qname: string;
  qtype?: string;
  nsecRecords: DnsRecord[];
  nsec3Records: DnsRecord[];
}): Promise<NegativeProofVerification> {
  const { kind, qtype, nsecRecords, nsec3Records } = params;
  const zoneApex = normalizeFqdn(params.zoneApex);
  const qname = normalizeFqdn(params.qname);

  // Case 1: NSEC (RFC 4035 §5.4)
  if (nsecRecords.length > 0) {
    const items: NsecProofItem[] = [];
    let matchedExact = false;
    let coveredQname = false;
    let coveredWildcard = false;
    let typeAbsentAtExact = false;

    for (const rec of nsecRecords) {
      if (rec.parsed.kind !== 'NSEC') continue;
      const owner = normalizeFqdn(rec.name);
      const next = normalizeFqdn(rec.parsed.nextDomainName);
      const types = rec.parsed.typeNames;
      let role = 'Auxiliary NSEC';
      let coversName: string | undefined;
      let matchesName: string | undefined;

      if (owner === qname) {
        matchedExact = true;
        matchesName = qname;
        if (kind === 'INSECURE_DELEGATION') {
          typeAbsentAtExact = !types.includes('DS') && !types.includes('SOA');
          role = typeAbsentAtExact
            ? 'Proves DS absent at delegation point'
            : 'Exact owner NSEC (unexpected DS/SOA bit)';
        } else if (kind === 'NODATA' && qtype) {
          typeAbsentAtExact = !types.includes(qtype) && !types.includes('CNAME');
          role = typeAbsentAtExact
            ? `Proves ${qtype} absent at ${qname}`
            : `Exact owner NSEC at ${qname}`;
        } else {
          role = `Exact owner NSEC at ${qname}`;
        }
      } else if (nsecIntervalCovers(owner, next, qname, zoneApex)) {
        coveredQname = true;
        coversName = qname;
        role = `Covers non-existence of ${qname}`;
      }

      // Check wildcard coverage along ancestor chain inside zone
      const hierarchy = getDomainHierarchy(qname).filter((d) => isSubdomainOrEqual(d, zoneApex));
      for (const anc of hierarchy) {
        const wc = `*.${anc}`;
        if (nsecIntervalCovers(owner, next, wc, zoneApex)) {
          coveredWildcard = true;
          if (!coversName) {
            coversName = wc;
            role = `Proves no wildcard ${wc}`;
          }
        }
      }

      items.push({
        kind: 'NSEC',
        owner,
        next,
        types,
        coversName,
        matchesName,
        role,
      });
    }

    let valid = false;
    let summary = '';
    if (kind === 'INSECURE_DELEGATION') {
      valid = matchedExact && typeAbsentAtExact;
      summary = valid
        ? `NSEC at ${qname} proves no DS record exists (unsigned delegation)`
        : `NSEC records did not conclusively prove DS absence for ${qname}`;
    } else if (kind === 'NODATA') {
      valid = (matchedExact && typeAbsentAtExact) || coveredQname;
      summary = valid
        ? `NSEC proves ${qtype ?? 'requested RRset'} does not exist at ${qname}`
        : `Incomplete NSEC NODATA proof for ${qname}`;
    } else {
      valid = coveredQname && (coveredWildcard || items.length >= 1);
      summary = valid
        ? `NSEC proves ${qname} does not exist (${coveredWildcard ? 'including wildcard denial' : 'name interval covered'})`
        : `Incomplete NSEC NXDOMAIN proof for ${qname}`;
    }

    return {
      kind,
      qname,
      qtype,
      protocol: 'NSEC',
      valid,
      optOutUsed: false,
      items,
      status: valid ? 'secure' : 'bogus',
      summary,
    };
  }

  // Case 2: NSEC3 (RFC 5155)
  if (nsec3Records.length > 0) {
    const firstParsed = nsec3Records[0].parsed;
    if (firstParsed.kind === 'NSEC3' && firstParsed.hashAlgorithm === 1) {
      const { saltHex, iterations } = firstParsed;
      const computedHashes: { label: string; name: string; hash: string }[] = [];

      // Compute hashes for QNAME and ancestors within zoneApex
      const ancestors = getDomainHierarchy(qname).filter((d) => isSubdomainOrEqual(d, zoneApex));
      const hashByDomain = new Map<string, string>();
      for (const dom of ancestors) {
        const h = await computeNsec3Hash(dom, saltHex, iterations);
        if (h) {
          hashByDomain.set(dom, h);
          computedHashes.push({
            label: dom === qname ? 'Target QNAME' : 'Ancestor',
            name: dom,
            hash: h,
          });
        }
      }

      const nsec3Entries = nsec3Records
        .filter((r) => r.parsed.kind === 'NSEC3')
        .map((r) => {
          const p = r.parsed as Extract<typeof r.parsed, { kind: 'NSEC3' }>;
          const ownerHash = normalizeFqdn(r.name).split('.')[0].toUpperCase();
          return {
            record: r,
            owner: normalizeFqdn(r.name),
            ownerHash,
            nextHash: p.nextHashedOwnerBase32.toUpperCase(),
            types: p.typeNames,
            optOut: p.optOut,
            iterations: p.iterations,
            saltHex: p.saltHex,
          };
        });

      const qnameHash = hashByDomain.get(qname);
      let optOutUsed = false;
      let exactQnameMatch: (typeof nsec3Entries)[number] | undefined;
      if (qnameHash) {
        exactQnameMatch = nsec3Entries.find((e) => e.ownerHash === qnameHash);
      }

      // Find Closest Encloser (deepest ancestor whose hash matches an NSEC3 ownerHash)
      let closestEncloser: string | undefined;
      let nextCloser: string | undefined;
      for (let i = ancestors.length - 1; i >= 0; i--) {
        const anc = ancestors[i];
        if (anc === qname && kind === 'NXDOMAIN') continue;
        const h = hashByDomain.get(anc);
        if (h && nsec3Entries.some((e) => e.ownerHash === h)) {
          closestEncloser = anc;
          if (i + 1 < ancestors.length) {
            nextCloser = ancestors[i + 1];
          }
          break;
        }
      }

      let wildcardHash: string | undefined;
      if (closestEncloser) {
        const wcName = `*.${closestEncloser}`;
        const wh = await computeNsec3Hash(wcName, saltHex, iterations);
        if (wh) {
          wildcardHash = wh;
          computedHashes.push({ label: 'Wildcard at CE', name: wcName, hash: wh });
        }
      }

      const nextCloserHash = nextCloser ? hashByDomain.get(nextCloser) : undefined;
      const items: NsecProofItem[] = [];
      let coversNextCloser = false;
      let coversQname = false;
      let coversWildcard = false;

      for (const e of nsec3Entries) {
        if (e.optOut) optOutUsed = true;
        const roles: string[] = [];
        let matchesName: string | undefined;
        let matchesHash: string | undefined;
        let coversName: string | undefined;
        let coversHash: string | undefined;

        if (qnameHash && e.ownerHash === qnameHash) {
          matchesName = qname;
          matchesHash = qnameHash;
          roles.push(`Matches QNAME (${qname})`);
        }
        if (closestEncloser && hashByDomain.get(closestEncloser) === e.ownerHash) {
          matchesName = matchesName ?? closestEncloser;
          matchesHash = matchesHash ?? e.ownerHash;
          roles.push(`Closest Encloser (${closestEncloser})`);
        }
        if (qnameHash && nsec3IntervalCovers(e.ownerHash, e.nextHash, qnameHash)) {
          coversQname = true;
          coversName = qname;
          coversHash = qnameHash;
          roles.push(`Covers QNAME hash (${qname})`);
        }
        if (nextCloser && nextCloserHash && nsec3IntervalCovers(e.ownerHash, e.nextHash, nextCloserHash)) {
          coversNextCloser = true;
          coversName = coversName ?? nextCloser;
          coversHash = coversHash ?? nextCloserHash;
          roles.push(
            e.optOut
              ? `Covers Next Closer (${nextCloser}) with Opt-Out`
              : `Covers Next Closer (${nextCloser})`
          );
        }
        if (wildcardHash && nsec3IntervalCovers(e.ownerHash, e.nextHash, wildcardHash)) {
          coversWildcard = true;
          roles.push(`Covers Wildcard (*.${closestEncloser})`);
        }

        items.push({
          kind: 'NSEC3',
          owner: e.ownerHash,
          next: e.nextHash,
          types: e.types,
          optOut: e.optOut,
          iterations: e.iterations,
          saltHex: e.saltHex,
          coversName,
          coversHash,
          matchesName,
          matchesHash,
          role: roles.length > 0 ? roles.join(' · ') : 'NSEC3 chain record',
        });
      }

      let valid = false;
      let summary = '';

      if (kind === 'INSECURE_DELEGATION') {
        if (exactQnameMatch && !exactQnameMatch.types.includes('DS') && !exactQnameMatch.types.includes('SOA')) {
          valid = true;
          summary = `NSEC3 exact hash match (${qnameHash?.slice(0, 12)}…) proves no DS exists at ${qname}`;
        } else if ((coversQname || coversNextCloser) && optOutUsed) {
          valid = true;
          summary = `NSEC3 Opt-Out interval covers ${qname} — provably unsigned delegation (RFC 5155 §7.2.7)`;
        } else {
          summary = `NSEC3 records did not prove DS non-existence for ${qname}`;
        }
      } else if (kind === 'NODATA') {
        if (exactQnameMatch && (!qtype || (!exactQnameMatch.types.includes(qtype) && !exactQnameMatch.types.includes('CNAME')))) {
          valid = true;
          summary = `NSEC3 exact hash match (${qnameHash?.slice(0, 12)}…) proves ${qtype ?? 'RRset'} absent at ${qname}`;
        } else if ((coversQname || coversNextCloser) && optOutUsed) {
          valid = true;
          summary = `NSEC3 Opt-Out interval covers ${qname} NODATA`;
        } else {
          summary = `Incomplete NSEC3 NODATA proof for ${qname}`;
        }
      } else {
        // NXDOMAIN per RFC 5155 §7.2.2: closest encloser + next closer covered + wildcard covered
        valid = Boolean(closestEncloser && coversNextCloser && (coversWildcard || optOutUsed));
        if (!valid && coversQname) {
          valid = true;
        }
        summary = valid
          ? `NSEC3 proves ${qname} does not exist (CE: ${closestEncloser ?? zoneApex})`
          : `Incomplete NSEC3 NXDOMAIN proof for ${qname}`;
      }

      return {
        kind,
        qname,
        qtype,
        protocol: 'NSEC3',
        valid,
        optOutUsed,
        computedHashes,
        items,
        status: valid ? 'secure' : 'bogus',
        summary,
      };
    }
  }

  return {
    kind,
    qname,
    qtype,
    protocol: 'NONE',
    valid: false,
    optOutUsed: false,
    items: [],
    status: 'bogus',
    summary: `No NSEC or NSEC3 authenticated denial-of-existence records returned for ${qname}`,
  };
}
