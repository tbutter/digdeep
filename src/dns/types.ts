import type { TrustAnchor } from './constants';

export type ValidationStatus = 'secure' | 'insecure' | 'bogus' | 'warning' | 'indeterminate';

export type AnalysisMode = 'dnssec' | 'mail' | 'web';

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

export interface TxtRdata {
  kind: 'TXT';
  /** Individual <character-string> chunks inside this single TXT/SPF resource record */
  strings: string[];
  /** RFC 7208 §3.3 concatenated string without spaces (`strings.join('')`) */
  joinedText: string;
}

export interface TlsaRdata {
  kind: 'TLSA';
  usage: number;
  selector: number;
  matchingType: number;
  certAssociationHex: string;
}

export interface CsyncRdata {
  kind: 'CSYNC';
  soaSerial: number;
  flags: number;
  immediate: boolean;
  soaMinimum: boolean;
  types: number[];
  typeNames: string[];
}

export interface EchCipherSuite {
  kdfId: number;
  kdfName: string;
  aeadId: number;
  aeadName: string;
}

export interface EchConfigEntry {
  version: number;
  versionHex: string;
  configId: number;
  kemId: number;
  kemName: string;
  publicKeyLength: number;
  publicKeyHex: string;
  cipherSuites: EchCipherSuite[];
  maximumNameLength: number;
  publicName: string;
}

export interface SvcParamEntry {
  key: number;
  keyName: string;
  rawHex: string;
  valueText: string;
  mandatoryKeys?: string[];
  alpns?: string[];
  port?: number;
  ipv4Hints?: string[];
  ipv6Hints?: string[];
  echConfigListBase64?: string;
  echConfigs?: EchConfigEntry[];
  dohPath?: string;
}

export interface SvcbRdata {
  kind: 'SVCB';
  rrtypeName: 'SVCB' | 'HTTPS';
  priority: number;
  isAliasMode: boolean;
  target: string;
  params: SvcParamEntry[];
}

export interface SshfpRdata {
  kind: 'SSHFP';
  algorithm: number;
  algorithmName: string;
  fpType: number;
  fpTypeName: string;
  fingerprintHex: string;
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
  | TxtRdata
  | TlsaRdata
  | CsyncRdata
  | SvcbRdata
  | SshfpRdata
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
  status?: 'ok' | 'dangling' | 'nodata';
  asns?: BgpAsnOrganization[];
  bgpPrefixes?: string[];
  country?: string;
  rir?: string;
}

export interface CdsRecordDetail {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digestHex: string;
  isDeleteSignal: boolean;
  matchesParentDs: boolean;
  matchesChildDnskey: boolean;
}

export interface CdnskeyRecordDetail {
  keyTag: number;
  flags: number;
  protocol: number;
  algorithm: number;
  publicKeyBase64: string;
  isDeleteSignal: boolean;
  matchesChildDnskey: boolean;
}

export interface CdsRolloverAnalysis {
  present: boolean;
  status: 'in-sync' | 'rollover-pending' | 'delete-signal' | 'unsigned-invalid' | 'not-published';
  cdsRecords: CdsRecordDetail[];
  cdnskeyRecords: CdnskeyRecordDetail[];
  cdsDnssecStatus?: ValidationStatus;
  cdnskeyDnssecStatus?: ValidationStatus;
  signedByKsk: boolean;
  parentDsKeyTags: number[];
  childCdsKeyTags: number[];
  summary: string;
}

export interface SoaTimerIssue {
  parameter: 'refresh' | 'retry' | 'expire' | 'minimum';
  value: number;
  severity: 'warning' | 'info';
  message: string;
  rfc: string;
}

export interface SoaAuditSummary {
  valid: boolean;
  issues: SoaTimerIssue[];
  summary: string;
}

export interface NsDiversityAnalysis {
  nameserverCount: number;
  uniqueAsns: BgpAsnOrganization[];
  uniquePrefixes: string[];
  hasIpv4: boolean;
  hasIpv6: boolean;
  danglingHosts: string[];
  singleAsn: boolean;
  singlePrefix: boolean;
  status: 'diverse' | 'single-asn' | 'single-prefix' | 'dangling' | 'insufficient';
  summary: string;
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
  soaAudit?: SoaAuditSummary;
  cdsRollover?: CdsRolloverAnalysis;
  nsDiversity?: NsDiversityAnalysis;
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

export type DaneHostStatus =
  | 'dane-valid'
  | 'dane-warning'
  | 'dane-unsigned-ignored'
  | 'dane-bogus'
  | 'no-tlsa-secure'
  | 'no-tlsa-unsigned';

export interface TlsaRecordDetail {
  ownerName: string;
  ttl: number;
  usage: number;
  usageMnemonic: string;
  usageDescription: string;
  selector: number;
  selectorMnemonic: string;
  matchingType: number;
  matchingTypeMnemonic: string;
  certAssociationHex: string;
  smtpRecommended: boolean;
  rdataValid: boolean;
  issues: string[];
}

export type FcrdnsStatus = 'valid' | 'ptr-mismatch' | 'no-ptr' | 'temperror' | 'unchecked';

export interface MxAddressEntry {
  ip: string;
  family: 4 | 6;
  isPublic: boolean;
  note?: string;
  ptrQname?: string;
  ptrTargets?: string[];
  ptrDnssecStatus?: ValidationStatus;
  ptrRrsetId?: string;
  ptrNegativeNodeId?: string;
  fcrdnsStatus?: FcrdnsStatus;
  fcrdnsMatchedNames?: string[];
}

export interface MxHostAnalysis {
  preference: number;
  exchange: string;
  displayExchange: string;
  isNullMx: boolean;
  isIpLiteral: boolean;
  cnameChain: string[];
  addresses: MxAddressEntry[];
  ipv4Status: ValidationStatus;
  ipv6Status: ValidationStatus;
  addressRrsetIds: string[];
  dane: {
    qname: string;
    resolvedOwner: string;
    cnameChain: string[];
    status: DaneHostStatus;
    dnssecStatus: ValidationStatus;
    rrsetId?: string;
    negativeNodeId?: string;
    records: TlsaRecordDetail[];
    rolloverReady: boolean;
    summary: string;
  };
}

export type SpfQualifier = '+' | '-' | '~' | '?';

export interface SpfTerm {
  raw: string;
  kind: 'version' | 'mechanism' | 'modifier' | 'unknown';
  qualifier?: SpfQualifier;
  mechanism?: 'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';
  modifier?: string;
  value?: string;
  cidr4?: number;
  cidr6?: number;
  countsTowardLookupLimit: boolean;
  syntaxValid: boolean;
  error?: string;
  warning?: string;
  resolvedIps?: string[];
  isVoidLookup?: boolean;
  unreachableAfterAll?: boolean;
  childNode?: SpfDomainNode;
}

export interface SpfDomainNode {
  domain: string;
  displayDomain: string;
  via: 'root' | 'include' | 'redirect';
  depth: number;
  spfRecords: string[];
  legacySpfType99Records?: string[];
  dnssecStatus?: ValidationStatus;
  adBit?: boolean;
  rcodeName?: string;
  terms: SpfTerm[];
  error?: string;
  loopDetected?: boolean;
}

export type SpfPolicyVerdict =
  | 'strict-fail'
  | 'soft-fail'
  | 'neutral'
  | 'pass-all'
  | 'no-default'
  | 'permerror'
  | 'temperror'
  | 'none';

export type DmarcPolicyValue = 'none' | 'quarantine' | 'reject';

export type DmarcVerdict =
  | 'reject'
  | 'quarantine'
  | 'monitor-only'
  | 'invalid'
  | 'temperror'
  | 'none';

export interface DmarcUriDetail {
  raw: string;
  uri: string;
  scheme: string;
  addressOrHost?: string;
  reportDomain?: string;
  maxSizeSpec?: string;
  syntaxValid: boolean;
  isExternalDomain: boolean;
  externalAuthorized?: 'authorized' | 'unauthorized' | 'unchecked';
  externalVerifyQname?: string;
  error?: string;
}

export interface DmarcTagItem {
  tag: string;
  value: string;
  known: boolean;
  valid: boolean;
  note?: string;
}

export interface DmarcAnalysis {
  present: boolean;
  verdict: DmarcVerdict;
  queriedOwner: string;
  effectiveOwner: string;
  cnameChain: string[];
  usedOrgFallback: boolean;
  orgDomain?: string;
  dnssecStatus: ValidationStatus;
  txtRrsetId?: string;
  negativeNodeId?: string;
  rawRecord?: string;
  allDmarcRecords: string[];
  policy?: DmarcPolicyValue;
  subdomainPolicy?: DmarcPolicyValue;
  nonExistentSubdomainPolicy?: DmarcPolicyValue;
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  pct: number;
  rua: DmarcUriDetail[];
  ruf: DmarcUriDetail[];
  fo: string;
  ri: number;
  tags: DmarcTagItem[];
  issues: string[];
  summary: string;
}

export type DkimKeyStatus = 'valid' | 'warning' | 'revoked' | 'weak' | 'invalid' | 'missing';

export interface DkimSelectorResult {
  selector: string;
  source: 'custom' | 'auto';
  qname: string;
  resolvedOwner: string;
  cnameChain: string[];
  present: boolean;
  status: DkimKeyStatus;
  dnssecStatus: ValidationStatus;
  txtRrsetId?: string;
  negativeNodeId?: string;
  rawRecord?: string;
  allRecords: string[];
  version?: string;
  keyType: string;
  keyBits?: number;
  rsaExponent?: number;
  publicKeyBase64?: string;
  hashAlgorithms?: string[];
  serviceTypes?: string[];
  flags: string[];
  notesTag?: string;
  isTestingMode: boolean;
  isStrictSubdomain: boolean;
  issues: string[];
  summary: string;
}

export interface DkimAnalysis {
  status: 'verified' | 'warning' | 'broken' | 'not-found';
  probedSelectors: string[];
  customSelectors: string[];
  selectors: DkimSelectorResult[];
  summary: string;
}

export interface MtaStsPolicyFetchResult {
  url: string;
  fetchedAt: number;
  ok: boolean;
  httpStatus?: number;
  contentType?: string;
  rawBody?: string;
  corsOrNetworkError?: string;
}

export type MtaStsMode = 'enforce' | 'testing' | 'none';

export interface MtaStsPolicyData {
  version?: string;
  mode?: MtaStsMode;
  maxAge?: number;
  mxPatterns: string[];
  matchedMxHosts: string[];
  unmatchedMxHosts: string[];
  valid: boolean;
  issues: string[];
}

export interface MtaStsAnalysis {
  present: boolean;
  status: 'enforce' | 'testing' | 'dns-only' | 'none-mode' | 'invalid' | 'not-deployed';
  qname: string;
  resolvedOwner: string;
  cnameChain: string[];
  dnssecStatus: ValidationStatus;
  txtRrsetId?: string;
  negativeNodeId?: string;
  rawRecord?: string;
  allStsRecords: string[];
  version?: string;
  policyId?: string;
  extensions: { key: string; value: string }[];
  policyUrl: string;
  policyFetch?: MtaStsPolicyFetchResult;
  policy?: MtaStsPolicyData;
  issues: string[];
  summary: string;
}

export interface TlsRptUriDetail {
  raw: string;
  uri: string;
  scheme: string;
  syntaxValid: boolean;
  error?: string;
}

export interface TlsRptAnalysis {
  present: boolean;
  status: 'valid' | 'warning' | 'invalid' | 'not-deployed';
  qname: string;
  resolvedOwner: string;
  cnameChain: string[];
  dnssecStatus: ValidationStatus;
  txtRrsetId?: string;
  negativeNodeId?: string;
  rawRecord?: string;
  allTlsRptRecords: string[];
  version?: string;
  rua: TlsRptUriDetail[];
  extensions: { key: string; value: string }[];
  issues: string[];
  summary: string;
}

export interface BimiAnalysis {
  present: boolean;
  status: 'valid' | 'declined' | 'dmarc-ineligible' | 'warning' | 'invalid' | 'not-deployed';
  selector: string;
  qname: string;
  resolvedOwner: string;
  cnameChain: string[];
  dnssecStatus: ValidationStatus;
  txtRrsetId?: string;
  negativeNodeId?: string;
  rawRecord?: string;
  allBimiRecords: string[];
  version?: string;
  logoUrl?: string;
  authorityUrl?: string;
  dmarcEligible: boolean;
  dmarcEligibilityReason: string;
  issues: string[];
  summary: string;
}

export interface MailAnalysisResult {
  mxStatus: 'valid' | 'null-mx' | 'implicit-a' | 'warning' | 'broken' | 'none';
  mxDnssecStatus: ValidationStatus;
  mxRrsetId?: string;
  mxAtCname?: string;
  mxHosts: MxHostAnalysis[];
  implicitFallbackAddresses?: MxAddressEntry[];
  daneStatus:
    | 'all-valid'
    | 'partial'
    | 'unsigned-ignored'
    | 'bogus'
    | 'not-deployed'
    | 'not-applicable';
  daneSummary: string;
  spf: {
    present: boolean;
    verdict: SpfPolicyVerdict;
    dnsLookupCount: number;
    dnsLookupLimit: number;
    voidLookupCount: number;
    voidLookupLimit: number;
    dnssecStatus: ValidationStatus;
    txtRrsetId?: string;
    rawRecord?: string;
    allSpfRecords: string[];
    legacySpfRecords: string[];
    effectiveAllQualifier?: SpfQualifier;
    rootNode: SpfDomainNode;
    summary: string;
  };
  dmarc: DmarcAnalysis;
  dkim: DkimAnalysis;
  mtaSts: MtaStsAnalysis;
  tlsRpt: TlsRptAnalysis;
  bimi: BimiAnalysis;
  fcrdnsSummary: {
    checkedIpCount: number;
    validCount: number;
    noPtrCount: number;
    mismatchCount: number;
    status: 'all-valid' | 'partial' | 'broken' | 'not-applicable' | 'unchecked';
    summary: string;
  };
}

export interface ReversePtrTargetEntry {
  hostname: string;
  displayHostname: string;
  forwardStatus: 'match' | 'mismatch' | 'nxdomain' | 'nodata' | 'temperror' | 'unchecked';
  forwardIpv4: string[];
  forwardIpv6: string[];
  forwardDnssecStatus: ValidationStatus;
}

export interface BgpAsnOrganization {
  asn: number;
  asName?: string;
  country?: string;
  rir?: string;
  allocatedDate?: string;
}

export interface ReverseIpBgpInfo {
  originQueryName: string;
  bgpPrefix?: string;
  country?: string;
  rir?: string;
  allocatedDate?: string;
  asns: BgpAsnOrganization[];
  rawOriginTxt?: string;
}

export interface ReverseDnsAnalysis {
  ip: string;
  family: 4 | 6;
  arpaFqdn: string;
  displayArpa: string;
  isPublic: boolean;
  specialRangeNote?: string;
  ptrStatus: 'resolved' | 'nxdomain' | 'nodata' | 'servfail';
  ptrDnssecStatus: ValidationStatus;
  ptrRrsetId?: string;
  ptrNegativeNodeId?: string;
  cnameChain: string[];
  isRfc2317ClasslessDelegation: boolean;
  targets: ReversePtrTargetEntry[];
  fcrdnsStatus: 'valid' | 'partial' | 'ptr-mismatch' | 'no-ptr' | 'temperror' | 'not-applicable';
  fcrdnsSummary: string;
  bgp?: ReverseIpBgpInfo;
}

export interface WebSvcbRecordDetail {
  ownerName: string;
  rrtypeName: 'HTTPS' | 'SVCB';
  ttl: number;
  priority: number;
  isAliasMode: boolean;
  target: string;
  params: SvcParamEntry[];
  alpns: string[];
  hasH3: boolean;
  hasH2: boolean;
  noDefaultAlpn: boolean;
  port?: number;
  ipv4Hints: string[];
  ipv6Hints: string[];
  ipv4HintsMatched: string[];
  ipv4HintsDrifted: string[];
  ipv6HintsMatched: string[];
  ipv6HintsDrifted: string[];
  echConfigs: EchConfigEntry[];
  issues: string[];
}

export interface CaaRecordEntry {
  ownerName: string;
  flags: number;
  critical: boolean;
  tag: string;
  rawValue: string;
  caDomain?: string;
  parameters: { key: string; value: string }[];
  recognizedTag: boolean;
  valid: boolean;
  issues: string[];
}

export interface CaaTreeHop {
  name: string;
  displayName: string;
  depth: number;
  dnssecStatus: ValidationStatus;
  rrsetId?: string;
  negativeNodeId?: string;
  records: CaaRecordEntry[];
  isEffectivePolicySource: boolean;
}

export interface WebCaaAnalysis {
  status: 'enforced' | 'inherited' | 'permissive' | 'unprotected' | 'invalid';
  effectiveOwner?: string;
  dnssecStatus: ValidationStatus;
  hops: CaaTreeHop[];
  issueCas: string[];
  issuewildCas: string[];
  iodefUris: string[];
  hasAcmeAccountBinding: boolean;
  hasCriticalUnknownTag: boolean;
  issues: string[];
  summary: string;
}

export interface SshfpRecordDetail {
  ownerName: string;
  ttl: number;
  algorithm: number;
  algorithmName: string;
  fpType: number;
  fpTypeName: string;
  fingerprintHex: string;
  deprecated: boolean;
  valid: boolean;
  issues: string[];
}

export interface WebAnalysisResult {
  targetDomain: string;
  displayDomain: string;
  cnameChain: string[];
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  addressDnssecStatus: ValidationStatus;
  httpsStatus: 'ech-enabled' | 'valid' | 'alias-mode' | 'warning' | 'not-deployed' | 'bogus';
  httpsDnssecStatus: ValidationStatus;
  httpsRrsetId?: string;
  httpsNegativeNodeId?: string;
  httpsRecords: WebSvcbRecordDetail[];
  svcbRecords: WebSvcbRecordDetail[];
  supportsHttp3: boolean;
  supportsHttp2: boolean;
  echEnabled: boolean;
  echPublicNames: string[];
  ipHintStatus: 'matched' | 'drift-detected' | 'not-used';
  httpsSummary: string;
  caa: WebCaaAnalysis;
  webDane: {
    qname: string;
    resolvedOwner: string;
    cnameChain: string[];
    status: DaneHostStatus;
    dnssecStatus: ValidationStatus;
    rrsetId?: string;
    negativeNodeId?: string;
    records: TlsaRecordDetail[];
    rolloverReady: boolean;
    summary: string;
  };
  sshfp: {
    present: boolean;
    status: 'secure' | 'insecure-ignored' | 'warning' | 'bogus' | 'not-deployed';
    dnssecStatus: ValidationStatus;
    rrsetId?: string;
    negativeNodeId?: string;
    records: SshfpRecordDetail[];
    summary: string;
  };
}

export interface AnalysisSnapshot {
  id: string;
  version: number;
  mode?: AnalysisMode;
  targetName: string; // normalized FQDN e.g. "cloudflare.com."
  displayDomain: string; // clean display e.g. "cloudflare.com" or "."
  queriedIp?: string; // canonical IP when reverse-DNS trace was initiated for an IPv4/IPv6 address
  queryTypes: string[];
  customDkimSelectors?: string[];
  mtaStsPolicyFetch?: MtaStsPolicyFetchResult;
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
  mailAnalysis?: MailAnalysisResult;
  webAnalysis?: WebAnalysisResult;
  reverseDns?: ReverseDnsAnalysis;
  pinned?: boolean;
  note?: string;
}

export interface AnalysisProgress {
  phase:
    | 'zone-cuts'
    | 'targets'
    | 'security-records'
    | 'nameservers'
    | 'validating'
    | 'mail-mx'
    | 'mail-dane'
    | 'mail-spf'
    | 'mail-dmarc'
    | 'mail-dkim'
    | 'mail-transport'
    | 'web-https'
    | 'web-caa'
    | 'web-dane';
  message: string;
  completedQueries: number;
}
