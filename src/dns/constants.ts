export const RR_TYPES: Record<string, number> = {
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  SIG: 24,
  KEY: 25,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  SRV: 33,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  DNAME: 39,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  CAA: 257,
  ANY: 255,
};

export const RR_TYPE_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(RR_TYPES).map(([k, v]) => [v, k])
);

export function rrTypeToString(type: number): string {
  return RR_TYPE_NAMES[type] ?? `TYPE${type}`;
}

export function stringToRrType(name: string): number {
  const upper = name.trim().toUpperCase();
  if (RR_TYPES[upper] !== undefined) return RR_TYPES[upper];
  if (upper.startsWith('TYPE')) {
    const n = Number.parseInt(upper.slice(4), 10);
    if (!Number.isNaN(n) && n >= 0 && n <= 65535) return n;
  }
  return RR_TYPES.A;
}

export const QUERYABLE_RR_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'NS',
  'SOA',
  'CAA',
  'HTTPS',
  'SVCB',
  'DNSKEY',
  'DS',
  'SRV',
  'TLSA',
  'PTR',
  'SSHFP',
  'NAPTR',
] as const;

export const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
  6: 'YXDOMAIN',
  7: 'YXRRSET',
  8: 'NXRRSET',
  9: 'NOTAUTH',
  10: 'NOTZONE',
  16: 'BADVERS',
};

export function rcodeToString(rcode: number): string {
  return RCODE_NAMES[rcode] ?? `RCODE${rcode}`;
}

export interface DnssecAlgorithmInfo {
  id: number;
  mnemonic: string;
  name: string;
  rfc8624: 'MUST' | 'RECOMMENDED' | 'OPTIONAL' | 'NOT RECOMMENDED' | 'MUST NOT';
  deprecated?: boolean;
}

export const DNSSEC_ALGORITHMS: Record<number, DnssecAlgorithmInfo> = {
  1: { id: 1, mnemonic: 'RSAMD5', name: 'RSA/MD5', rfc8624: 'MUST NOT', deprecated: true },
  3: { id: 3, mnemonic: 'DSA', name: 'DSA/SHA-1', rfc8624: 'MUST NOT', deprecated: true },
  5: { id: 5, mnemonic: 'RSASHA1', name: 'RSA/SHA-1', rfc8624: 'NOT RECOMMENDED', deprecated: true },
  6: { id: 6, mnemonic: 'DSA-NSEC3-SHA1', name: 'DSA-NSEC3-SHA1', rfc8624: 'MUST NOT', deprecated: true },
  7: {
    id: 7,
    mnemonic: 'RSASHA1-NSEC3-SHA1',
    name: 'RSA/SHA-1 (NSEC3)',
    rfc8624: 'NOT RECOMMENDED',
    deprecated: true,
  },
  8: { id: 8, mnemonic: 'RSASHA256', name: 'RSA/SHA-256', rfc8624: 'MUST' },
  10: { id: 10, mnemonic: 'RSASHA512', name: 'RSA/SHA-512', rfc8624: 'NOT RECOMMENDED' },
  12: { id: 12, mnemonic: 'ECC-GOST', name: 'GOST R 34.10-2001', rfc8624: 'MUST NOT', deprecated: true },
  13: { id: 13, mnemonic: 'ECDSAP256SHA256', name: 'ECDSA P-256/SHA-256', rfc8624: 'MUST' },
  14: { id: 14, mnemonic: 'ECDSAP384SHA384', name: 'ECDSA P-384/SHA-384', rfc8624: 'RECOMMENDED' },
  15: { id: 15, mnemonic: 'ED25519', name: 'Ed25519', rfc8624: 'RECOMMENDED' },
  16: { id: 16, mnemonic: 'ED448', name: 'Ed448', rfc8624: 'OPTIONAL' },
};

export function formatAlgorithm(alg: number): string {
  const info = DNSSEC_ALGORITHMS[alg];
  return info ? `${alg} (${info.mnemonic})` : `ALG-${alg}`;
}

export interface DsDigestInfo {
  id: number;
  name: string;
  rfc8624: 'MUST' | 'RECOMMENDED' | 'NOT RECOMMENDED' | 'MUST NOT';
  deprecated?: boolean;
}

export const DS_DIGEST_TYPES: Record<number, DsDigestInfo> = {
  1: { id: 1, name: 'SHA-1', rfc8624: 'NOT RECOMMENDED', deprecated: true },
  2: { id: 2, name: 'SHA-256', rfc8624: 'MUST' },
  3: { id: 3, name: 'GOST R 34.11-94', rfc8624: 'MUST NOT', deprecated: true },
  4: { id: 4, name: 'SHA-384', rfc8624: 'RECOMMENDED' },
};

export function formatDigestType(dt: number): string {
  const info = DS_DIGEST_TYPES[dt];
  return info ? `${dt} (${info.name})` : `DIGEST-${dt}`;
}

/**
 * RFC 8914 Extended DNS Error Codes (EDNS0 Option 15)
 */
export const EDE_CODES: Record<number, { name: string; description: string }> = {
  0: { name: 'Other Error', description: 'Unclassified extended error from resolver' },
  1: { name: 'Unsupported DNSKEY Algorithm', description: 'DNSKEY algorithm is not supported by validator' },
  2: { name: 'Unsupported DS Digest Type', description: 'DS digest algorithm is not supported by validator' },
  3: { name: 'Stale Answer', description: 'Answer served from stale cache after upstream timeout' },
  4: { name: 'Forged Answer', description: 'Policy-forged or rewritten DNS answer' },
  5: { name: 'DNSSEC Indeterminate', description: 'DNSSEC validation state could not be determined' },
  6: { name: 'DNSSEC Bogus', description: 'Resolver determined the response failed DNSSEC validation' },
  7: { name: 'Signature Expired', description: 'RRSIG validity period has expired' },
  8: { name: 'Signature Not Yet Valid', description: 'RRSIG inception timestamp is in the future' },
  9: { name: 'DNSKEY Missing', description: 'No SEP DNSKEY matching the parent DS record was found in the zone' },
  10: { name: 'RRSIGs Missing', description: 'Expected RRSIG records covering the RRset were missing' },
  11: { name: 'No Zone Key Bit Set', description: 'DNSKEY lacks the Zone Key flag (bit 7) required by RFC 4034' },
  12: { name: 'NSEC Missing', description: 'Missing NSEC/NSEC3 authenticated denial-of-existence record' },
  13: { name: 'Cached Error', description: 'Cached SERVFAIL or upstream validation failure' },
  14: { name: 'Not Ready', description: 'Server is not ready to serve queries' },
  15: { name: 'Blocked', description: 'Domain blocked by resolver policy' },
  16: { name: 'Censored', description: 'Response filtered due to external mandate' },
  17: { name: 'Filtered', description: 'Response filtered by subscriber configuration' },
  18: { name: 'Prohibited', description: 'Client is not authorized for this query' },
  19: { name: 'Stale NXDOMAIN Answer', description: 'Stale NXDOMAIN served from cache' },
  20: { name: 'Not Authoritative', description: 'Server is not authoritative for the queried zone' },
  21: { name: 'Not Supported', description: 'Requested operation or query parameter is unsupported' },
  22: { name: 'No Reachable Authority', description: 'None of the authoritative nameservers responded' },
  23: { name: 'Network Error', description: 'Network error communicating with upstream nameserver' },
  24: { name: 'Invalid Data', description: 'Zone data is malformed or invalid' },
};

export interface TrustAnchor {
  id: string;
  zone: string; // e.g. "."
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string; // uppercase hex
  label: string;
  builtin?: boolean;
  enabled: boolean;
}

/**
 * Official IANA Root Zone Trust Anchors (root-anchors.xml)
 * Includes both KSK-2017 (#20326) and KSK-2024 (#38696, active root signer).
 */
export const IANA_ROOT_TRUST_ANCHORS: TrustAnchor[] = [
  {
    id: 'iana-ksk-2024-38696',
    zone: '.',
    keyTag: 38696,
    algorithm: 8,
    digestType: 2,
    digest: '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
    label: 'IANA Root KSK-2024 (#38696)',
    builtin: true,
    enabled: true,
  },
  {
    id: 'iana-ksk-2017-20326',
    zone: '.',
    keyTag: 20326,
    algorithm: 8,
    digestType: 2,
    digest: 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
    label: 'IANA Root KSK-2017 (#20326)',
    builtin: true,
    enabled: true,
  },
];

export const DEFAULT_DOH_ENDPOINT = 'https://1.1.1.1/dns-query';

export interface PresetDomain {
  domain: string;
  types: string[];
  label: string;
  badge: 'secure' | 'bogus' | 'insecure' | 'cname';
  description: string;
}

export const PRESET_DOMAINS: PresetDomain[] = [
  {
    domain: 'cloudflare.com',
    types: ['A', 'AAAA'],
    label: 'cloudflare.com',
    badge: 'secure',
    description: 'ECDSAP256SHA256 (Alg 13) signed zone',
  },
  {
    domain: 'www.iana.org',
    types: ['A', 'AAAA'],
    label: 'www.iana.org',
    badge: 'cname',
    description: 'Cross-zone signed CNAME chain into cloudflare.net',
  },
  {
    domain: 'nlnetlabs.nl',
    types: ['A', 'AAAA', 'TXT'],
    label: 'nlnetlabs.nl',
    badge: 'secure',
    description: 'RSA/SHA-256 DNSSEC research pioneer zone',
  },
  {
    domain: 'dnssec-failed.org',
    types: ['A'],
    label: 'dnssec-failed.org',
    badge: 'bogus',
    description: 'Broken DS delegation — missing SEP DNSKEY (EDE 9)',
  },
  {
    domain: 'sigfail.verteiltesysteme.net',
    types: ['A', 'AAAA'],
    label: 'sigfail.verteiltesysteme.net',
    badge: 'bogus',
    description: 'Corrupted RRSIG cryptographic signature test',
  },
  {
    domain: 'github.com',
    types: ['A', 'MX'],
    label: 'github.com',
    badge: 'insecure',
    description: 'Provably unsigned delegation (NSEC3 Opt-Out)',
  },
];
