import type { TrustAnchor } from './constants';

export type ValidationStatus = 'secure' | 'insecure' | 'bogus' | 'warning' | 'indeterminate';

export interface DnsHeaderFlags {
  qr: boolean;
  opcode: number;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  z: number;
  ad: boolean;
  cd: boolean;
  rcode: number;
}

export interface DnsQuestion {
  name: string;
  type: number;
  typeName: string;
  qclass: number;
}

export interface EdeEntry {
  infoCode: number;
  name: string;
  extraText: string;
}

export interface EdnsInfo {
  udpPayloadSize: number;
  extendedRcode: number;
  version: number;
  doBit: boolean;
  flags: number;
  ede: EdeEntry[];
}

export interface DnskeyRdata {
  kind: 'DNSKEY';
  flags: number;
  protocol: number;
  algorithm: number;
  publicKeyBase64: string;
  publicKeyHex: string;
  keyTag: number;
  isZoneKey: boolean;
  isSep: boolean;
  isRevoked: boolean;
  keySizeInfo: string;
}

export interface DsRdata {
  kind: 'DS';
  keyTag: number;
  algorithm: number;
  digestType: number;
  digestHex: string;
}

export interface RrsigRdata {
  kind: 'RRSIG';
  typeCovered: number;
  typeCoveredName: string;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number; // unix epoch seconds
  inception: number; // unix epoch seconds
  keyTag: number;
  signerName: string;
  signatureBase64: string;
  /** Raw RRSIG RDATA prefix (18 bytes + canonical lowercased signer wire bytes) Base64 */
  signedHeaderBase64: string;
}

export interface NsecRdata {
  kind: 'NSEC';
  nextDomainName: string;
  types: number[];
  typeNames: string[];
}

export interface Nsec3Rdata {
  kind: 'NSEC3';
  hashAlgorithm: number;
  flags: number;
  optOut: boolean;
  iterations: number;
  saltHex: string;
  nextHashedOwnerBase32: string;
  types: number[];
  typeNames: string[];
}

export interface Nsec3ParamRdata {
  kind: 'NSEC3PARAM';
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  saltHex: string;
}

export interface SoaRdata {
  kind: 'SOA';
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

export interface MxRdata {
  kind: 'MX';
  preference: number;
  exchange: string;
}

export interface SrvRdata {
  kind: 'SRV';
  priority: number;
  weight: number;
  port: number;
  target: string;
}

export interface CaaRdata {
  kind: 'CAA';
  flags: number;
  tag: string;
  value: string;
}

export interface GenericRdata {
  kind: 'GENERIC';
  target?: string;
}

export type ParsedRdata =
  | DnskeyRdata
  | DsRdata
  | RrsigRdata
  | NsecRdata
  | Nsec3Rdata
  | Nsec3ParamRdata
  | SoaRdata
  | MxRdata
  | SrvRdata
  | CaaRdata
  | GenericRdata;

export interface DnsRecord {
  name: string; // normalized FQDN ("." or "example.com.")
  type: number;
  typeName: string;
  rrclass: number;
  ttl: number;
  rdataBase64: string;
  /** RFC 4034 §6.2 uncompressed & canonicalized RDATA for signature verification */
  canonicalRdataBase64: string;
  rdataText: string;
  parsed: ParsedRdata;
  section: 'answer' | 'authority' | 'additional';
}

export interface DnsPacket {
  id: number;
  flags: DnsHeaderFlags;
  questions: DnsQuestion[];
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
  edns?: EdnsInfo;
  wireSize: number;
}

export interface DohQueryLog {
  id: string;
  qname: string;
  qtype: number;
  qtypeName: string;
  cd: boolean;
  doBit: boolean;
  endpoint: string;
  startedAt: number;
  latencyMs: number;
  httpStatus: number;
  wireBase64: string;
  requestWireBase64: string;
  packet: DnsPacket;
  purpose: string;
}

export interface RrsigVerification {
  id: string;
  rrsig: RrsigRdata;
  rrsigTtl: number;
  signerKeyTag: number;
  signerFound: boolean;
  cryptoValid: boolean;
  timeValid: boolean;
  notYetValid: boolean;
  expired: boolean;
  remainingSeconds: number;
  wildcardSynthesized: boolean;
  wildcardClosestEncloser?: string;
  ttlMismatch: boolean;
  algorithmWarning?: string;
  expirationWarning?: string;
  status: ValidationStatus;
  reason: string;
}

export interface DsVerification {
  id: string;
  ds: DsRdata;
  dsTtl: number;
  matchedKeyTag?: number;
  targetKeyFound: boolean;
  computedDigestHex?: string;
  digestValid: boolean;
  digestWarning?: string;
  algorithmWarning?: string;
  status: ValidationStatus;
  reason: string;
}

export interface NsecProofItem {
  kind: 'NSEC' | 'NSEC3';
  owner: string;
  next: string;
  types: string[];
  optOut?: boolean;
  iterations?: number;
  saltHex?: string;
  coversName?: string;
  coversHash?: string;
  matchesName?: string;
  matchesHash?: string;
  role: string;
}

export interface NegativeProofVerification {
  kind: 'NXDOMAIN' | 'NODATA' | 'INSECURE_DELEGATION' | 'WILDCARD';
  qname: string;
  qtype?: string;
  protocol: 'NSEC' | 'NSEC3' | 'NONE';
  valid: boolean;
  optOutUsed: boolean;
  computedHashes?: { label: string; name: string; hash: string }[];
  items: NsecProofItem[];
  status: ValidationStatus;
  summary: string;
}

export type DnskeyRole =
  | 'trust-anchor'
  | 'ksk'
  | 'zsk'
  | 'csk'
  | 'standby'
  | 'revoked'
  | 'missing';

export interface AnalyzedDnskey {
  id: string;
  zone: string;
  keyTag: number;
  flags: number;
  algorithm: number;
  protocol: number;
  keySizeInfo: string;
  publicKeyBase64: string;
  isSep: boolean;
  isZoneKey: boolean;
  isRevoked: boolean;
  role: DnskeyRole;
  trustAnchorLabel?: string;
  computedSha256?: string;
  computedSha384?: string;
  signsTypes: string[];
  matchedByParentDs: boolean;
  status: ValidationStatus;
  statusReason: string;
}

export interface AnalyzedRrset {
  id: string;
  zone: string;
  name: string;
  type: number;
  typeName: string;
  ttl: number;
  section: 'answer' | 'authority';
  records: DnsRecord[];
  rrsigs: RrsigVerification[];
  isQueryTarget: boolean;
  status: ValidationStatus;
  statusReason: string;
}

export interface NegativeNode {
  id: string;
  zone: string;
  qname: string;
  qtypeName: string;
  kind: 'NXDOMAIN' | 'NODATA';
  proof: NegativeProofVerification;
  coveringRrsetIds: string[];
  status: ValidationStatus;
}

export interface NameserverEntry {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
}

export interface ZoneAnalysis {
  zoneName: string; // "." or "com." or "cloudflare.com."
  parentZone: string | null;
  depth: number;
  status: ValidationStatus;
  statusReason: string;
  nsecMode: 'NSEC' | 'NSEC3' | 'NSEC3-OPTOUT' | 'UNSIGNED';
  dnskeys: AnalyzedDnskey[];
  /** DS records in the PARENT zone delegating to THIS zone */
  parentDsRrsetId?: string;
  dsVerifications: DsVerification[];
  /** Trust anchor match(es) if this zone is anchored directly (e.g. root ".") */
  trustAnchorMatches: {
    anchorId: string;
    label: string;
    keyTag: number;
    matched: boolean;
    computedDigestHex?: string;
    expectedDigestHex: string;
  }[];
  /** If parent zone has no DS, the NSEC/NSEC3 proof of insecure delegation from parent */
  insecureDelegationProof?: NegativeProofVerification;
  rrsets: AnalyzedRrset[];
  negativeNodes: NegativeNode[];
  nameservers: NameserverEntry[];
  soa?: SoaRdata;
}

export interface CnameEdge {
  id: string;
  fromRrsetId: string;
  fromName: string;
  toName: string;
  toRrsetId?: string;
  toNegativeNodeId?: string;
  qtypeName: string;
}

export interface AuditFinding {
  id: string;
  severity: 'error' | 'warning' | 'info';
  code: string;
  title: string;
  detail: string;
  rfc?: string;
  zone?: string;
  targetId?: string;
}

export interface ResolverVerdict {
  qname: string;
  qtypeName: string;
  rcode: number;
  rcodeName: string;
  adBit: boolean;
  ede: EdeEntry[];
  latencyMs: number;
}

export interface AnalysisSnapshot {
  id: string;
  version: number;
  targetName: string; // normalized FQDN e.g. "cloudflare.com."
  displayDomain: string; // clean display e.g. "cloudflare.com" or "."
  queryTypes: string[];
  dohEndpoint: string;
  capturedAt: number; // ms epoch
  validatedAt: number; // ms epoch used for RRSIG timestamp checks
  durationMs: number;
  overallStatus: ValidationStatus;
  overallSummary: string;
  resolverVerdict?: ResolverVerdict;
  zones: ZoneAnalysis[];
  cnameEdges: CnameEdge[];
  findings: AuditFinding[];
  queries: DohQueryLog[];
  trustAnchorsUsed: TrustAnchor[];
  pinned?: boolean;
  note?: string;
}

export interface AnalysisProgress {
  phase: 'zone-cuts' | 'targets' | 'security-records' | 'nameservers' | 'validating';
  message: string;
  completedQueries: number;
}
