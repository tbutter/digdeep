import { RR_TYPES, rcodeToString } from './constants';
import { base64ToBytes, compareCanonicalDnsNames, displayFqdn, normalizeFqdn } from './encoding';
import type {
  AnalysisSnapshot,
  DnsPacket,
  DnsRecord,
  DohQueryLog,
  ZoneAnalysis,
} from './types';

function formatRecordLine(r: DnsRecord): string {
  const owner = r.name.padEnd(24, ' ');
  const ttl = String(r.ttl).padStart(6, ' ');
  const cls = r.rrclass === 1 ? 'IN' : `CLASS${r.rrclass}`;
  const type = r.typeName.padEnd(8, ' ');
  return `${owner} ${ttl} ${cls} ${type} ${r.rdataText}`;
}

/**
 * Formats a parsed DNS packet in classic ISC `dig` presentation format.
 */
export function formatPacketAsDig(log: DohQueryLog): string {
  const p: DnsPacket = log.packet;
  const f = p.flags;
  const activeFlags: string[] = [];
  if (f.qr) activeFlags.push('qr');
  if (f.aa) activeFlags.push('aa');
  if (f.tc) activeFlags.push('tc');
  if (f.rd) activeFlags.push('rd');
  if (f.ra) activeFlags.push('ra');
  if (f.ad) activeFlags.push('ad');
  if (f.cd) activeFlags.push('cd');

  const lines: string[] = [];
  lines.push(`; <<>> DigDeep Client-Side DoH <<>> ${log.qname} ${log.qtypeName}`);
  lines.push(`;; Endpoint: ${log.endpoint} (RFC 8484 wireformat, ${log.latencyMs} ms)`);
  lines.push(
    `;; ->>HEADER<<- opcode: QUERY, status: ${rcodeToString(f.rcode)}, id: ${p.id}`
  );
  lines.push(
    `;; flags: ${activeFlags.join(' ')}; QUERY: ${p.questions.length}, ANSWER: ${p.answers.length}, AUTHORITY: ${p.authorities.length}, ADDITIONAL: ${p.additionals.length + (p.edns ? 1 : 0)}`
  );

  if (p.edns) {
    lines.push('');
    lines.push(';; OPT PSEUDOSECTION:');
    lines.push(
      `; EDNS: version: ${p.edns.version}, flags:${p.edns.doBit ? ' do' : ''}; udp: ${p.edns.udpPayloadSize}`
    );
    if (p.edns.ecs) {
      lines.push(`; CLIENT-SUBNET: ${p.edns.ecs.presentation}`);
    }
    for (const ede of p.edns.ede) {
      lines.push(
        `; EDE: ${ede.infoCode} (${ede.name})${ede.extraText ? `: (${ede.extraText})` : ''}`
      );
    }
  }

  if (p.questions.length > 0) {
    lines.push('');
    lines.push(';; QUESTION SECTION:');
    for (const q of p.questions) {
      lines.push(`;${q.name.padEnd(23, ' ')}        IN ${q.typeName}`);
    }
  }

  if (p.answers.length > 0) {
    lines.push('');
    lines.push(';; ANSWER SECTION:');
    for (const r of p.answers) lines.push(formatRecordLine(r));
  }

  if (p.authorities.length > 0) {
    lines.push('');
    lines.push(';; AUTHORITY SECTION:');
    for (const r of p.authorities) lines.push(formatRecordLine(r));
  }

  if (p.additionals.length > 0) {
    lines.push('');
    lines.push(';; ADDITIONAL SECTION:');
    for (const r of p.additionals) lines.push(formatRecordLine(r));
  }

  lines.push('');
  lines.push(`;; MSG SIZE  rcvd: ${p.wireSize}`);
  return lines.join('\n');
}

export interface HexDumpRow {
  offsetHex: string;
  hexGroups: string;
  ascii: string;
}

export function formatWireHexDump(wireBase64: string): HexDumpRow[] {
  const bytes = base64ToBytes(wireBase64);
  const rows: HexDumpRow[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, Math.min(bytes.length, i + 16));
    const offsetHex = i.toString(16).padStart(4, '0').toUpperCase();
    const hexParts: string[] = [];
    let ascii = '';
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        const b = slice[j];
        hexParts.push(b.toString(16).padStart(2, '0').toUpperCase());
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
        ascii += ' ';
      }
    }
    const left = hexParts.slice(0, 8).join(' ');
    const right = hexParts.slice(8).join(' ');
    rows.push({
      offsetHex,
      hexGroups: `${left}  ${right}`,
      ascii,
    });
  }
  return rows;
}

export interface CliReproducerCommands {
  dig: string;
  delv: string;
  kdig: string;
  resolverIpOrHost: string;
  dohHost: string;
}

const DOH_HOST_TO_RESOLVER_IP: Record<string, string> = {
  'cloudflare-dns.com': '1.1.1.1',
  'one.one.one.one': '1.1.1.1',
  '1.1.1.1': '1.1.1.1',
  'mozilla.cloudflare-dns.com': '1.1.1.1',
  'security.cloudflare-dns.com': '1.1.1.2',
  'family.cloudflare-dns.com': '1.1.1.3',
  'dns.google': '8.8.8.8',
  '8.8.8.8': '8.8.8.8',
  'dns.quad9.net': '9.9.9.9',
  'dns9.quad9.net': '9.9.9.9',
  '9.9.9.9': '9.9.9.9',
  'dns11.quad9.net': '9.9.9.11',
  'dns10.quad9.net': '9.9.9.10',
  'dns.adguard-dns.com': '94.140.14.14',
  'unfiltered.adguard-dns.com': '94.140.14.140',
  'doh.opendns.com': '208.67.222.222',
  'dns.mullvad.net': '194.242.2.2',
  'doh.cleanbrowsing.org': '185.228.168.9',
};

/**
 * Generates ready-to-run `dig`, `delv`, and `kdig` CLI commands to reproduce a DNS query
 * or DNSSEC validation locally in a terminal.
 */
export function generateCliReproducerCommands(params: {
  qname: string;
  qtypeName: string;
  dohEndpoint?: string;
  cd?: boolean;
  ecsSubnet?: string;
  validatedAt?: number;
  capturedAt?: number;
}): CliReproducerCommands {
  const normQname = normalizeFqdn(params.qname);
  const target = normQname === '.' ? '.' : displayFqdn(normQname);
  const qtype = (params.qtypeName || 'A').trim().toUpperCase();

  let dohHost = 'cloudflare-dns.com';
  if (params.dohEndpoint) {
    try {
      const parsed = new URL(params.dohEndpoint);
      if (parsed.hostname) {
        dohHost = parsed.hostname.toLowerCase();
      }
    } catch {
      // keep default
    }
  }

  const resolverIpOrHost = DOH_HOST_TO_RESOLVER_IP[dohHost] ?? dohHost;
  const cdFlag = params.cd ? ' +cd' : '';
  const subnetFlag = params.ecsSubnet ? ` +subnet=${params.ecsSubnet}` : '';
  const hasClockOverride =
    params.validatedAt !== undefined &&
    params.capturedAt !== undefined &&
    Math.abs(params.validatedAt - params.capturedAt) > 1000;
  const delvTimeFlag = hasClockOverride
    ? ` -t ${Math.floor((params.validatedAt as number) / 1000)}`
    : '';

  return {
    dig: `dig +dnssec +multi${cdFlag}${subnetFlag} @${resolverIpOrHost} ${target} ${qtype}`,
    delv: `delv @${resolverIpOrHost} ${target} ${qtype} +rtrace${delvTimeFlag}`,
    kdig: `kdig +dnssec${cdFlag}${subnetFlag} +https @${dohHost} ${target} ${qtype}`,
    resolverIpOrHost,
    dohHost,
  };
}

const ZONEFILE_TYPE_PRIORITY: Record<string, number> = {
  SOA: 1,
  NS: 2,
  A: 3,
  AAAA: 4,
  CNAME: 5,
  MX: 6,
  TXT: 7,
  SPF: 8,
  SRV: 9,
  NAPTR: 10,
  CAA: 11,
  HTTPS: 12,
  SVCB: 13,
  TLSA: 14,
  SMIMEA: 15,
  OPENPGPKEY: 16,
  SSHFP: 17,
  PTR: 18,
  CDS: 19,
  CDNSKEY: 20,
  CSYNC: 21,
  ZONEMD: 22,
  DS: 23,
  DNSKEY: 24,
  NSEC: 25,
  NSEC3: 26,
  NSEC3PARAM: 27,
  RRSIG: 28,
};

function findDeepestMatchingZoneForOwner(owner: string, zoneNames: string[]): string {
  const norm = normalizeFqdn(owner);
  let best = '.';
  let bestLen = 0;
  for (const z of zoneNames) {
    const normZ = normalizeFqdn(z);
    if (normZ === '.') {
      if (bestLen === 0) best = '.';
      continue;
    }
    if (norm === normZ || norm.endsWith(`.${normZ}`)) {
      if (normZ.length > bestLen) {
        best = normZ;
        bestLen = normZ.length;
      }
    }
  }
  return best;
}

function formatRrsigTimestamp(epochSec: number): string {
  const d = new Date(epochSec * 1000);
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(
    d.getUTCHours()
  )}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
}

function formatMasterRecordLine(rec: DnsRecord): string {
  const owner = rec.name.padEnd(28, ' ');
  const ttl = String(rec.ttl).padStart(6, ' ');
  const cls = rec.rrclass === 1 ? 'IN' : `CLASS${rec.rrclass}`;
  const type = rec.typeName.padEnd(10, ' ');
  return `${owner} ${ttl} ${cls} ${type} ${rec.rdataText}`;
}

/**
 * Formats a single `ZoneAnalysis` as an RFC 1035 Master Zonefile snippet (`.zone`).
 */
export function formatZoneAsZonefile(
  zone: ZoneAnalysis,
  snapshot?: AnalysisSnapshot,
  options: { includeDnssecRecords?: boolean; includeHeader?: boolean } = {}
): string {
  const includeDnssec = options.includeDnssecRecords ?? true;
  const includeHeader = options.includeHeader ?? true;
  const zoneName = normalizeFqdn(zone.zoneName);
  const allZoneNames = snapshot
    ? snapshot.zones.map((z) => normalizeFqdn(z.zoneName))
    : [zoneName];
  const defaultTtl = zone.soa?.minimum ?? 3600;

  const lines: string[] = [];
  if (includeHeader) {
    lines.push('; ============================================================================');
    lines.push(`; DigDeep (https://digdeep.fyi) — RFC 1035 Master Zonefile Export`);
    lines.push(
      `; Zone: ${zoneName} (DNSSEC status: ${zone.status.toUpperCase()}, mode: ${zone.nsecMode})`
    );
    if (snapshot) {
      lines.push(
        `; Captured: ${new Date(snapshot.capturedAt).toISOString()} via ${snapshot.dohEndpoint}`
      );
    }
    lines.push('; ============================================================================');
    lines.push('');
  }

  lines.push(`$ORIGIN ${zoneName}`);
  lines.push(`$TTL ${defaultTtl}`);

  const recordMap = new Map<string, DnsRecord>();
  const addRec = (r: DnsRecord) => {
    if (
      !includeDnssec &&
      (r.type === RR_TYPES.RRSIG ||
        r.type === RR_TYPES.NSEC ||
        r.type === RR_TYPES.NSEC3 ||
        r.type === RR_TYPES.DNSKEY ||
        r.type === RR_TYPES.DS)
    ) {
      return;
    }
    const key = `${normalizeFqdn(r.name)}|${r.typeName}|${r.rdataText}`;
    if (!recordMap.has(key)) {
      recordMap.set(key, {
        ...r,
        name: normalizeFqdn(r.name),
      });
    }
  };

  // 1. Collect all records & RRSIGs from analyzed RRsets in this zone
  for (const rrset of zone.rrsets) {
    for (const r of rrset.records) {
      addRec(r);
    }
    if (includeDnssec) {
      for (const rv of rrset.rrsigs) {
        addRec({
          name: rrset.name,
          type: RR_TYPES.RRSIG,
          typeName: 'RRSIG',
          rrclass: 1,
          ttl: rv.rrsigTtl || rrset.ttl,
          section: 'answer',
          rdataBase64: '',
          canonicalRdataBase64: '',
          rdataText: `${rv.rrsig.typeCoveredName} ${rv.rrsig.algorithm} ${rv.rrsig.labels} ${rv.rrsig.originalTtl} ${formatRrsigTimestamp(rv.rrsig.expiration)} ${formatRrsigTimestamp(rv.rrsig.inception)} ${rv.rrsig.keyTag} ${rv.rrsig.signerName} ${rv.rrsig.signatureBase64}`,
          parsed: rv.rrsig,
        });
      }
    }
  }

  // 2. Ensure SOA is present if zone.soa was parsed from authority section
  const hasSoa = Array.from(recordMap.values()).some(
    (r) => r.name === zoneName && r.type === RR_TYPES.SOA
  );
  if (!hasSoa && zone.soa) {
    addRec({
      name: zoneName,
      type: RR_TYPES.SOA,
      typeName: 'SOA',
      rrclass: 1,
      ttl: zone.soa.minimum || 3600,
      section: 'authority',
      rdataBase64: '',
      canonicalRdataBase64: '',
      rdataText: `${zone.soa.mname} ${zone.soa.rname} ${zone.soa.serial} ${zone.soa.refresh} ${zone.soa.retry} ${zone.soa.expire} ${zone.soa.minimum}`,
      parsed: zone.soa,
    });
  }

  // 3. Ensure NS records are present from zone.nameservers if not already in zone.rrsets
  const hasApexNs = Array.from(recordMap.values()).some(
    (r) => r.name === zoneName && r.type === RR_TYPES.NS
  );
  if (!hasApexNs && zone.nameservers.length > 0) {
    for (const ns of zone.nameservers) {
      addRec({
        name: zoneName,
        type: RR_TYPES.NS,
        typeName: 'NS',
        rrclass: 1,
        ttl: defaultTtl,
        section: 'answer',
        rdataBase64: '',
        canonicalRdataBase64: '',
        rdataText: normalizeFqdn(ns.hostname),
        parsed: { kind: 'GENERIC', target: normalizeFqdn(ns.hostname) },
      });
    }
  }

  // 4. Also harvest any additional Answer records from snapshot.queries belonging to this zone
  // (e.g., TXT records from SPF/DMARC/DKIM/MTA-STS/BIMI probes, SRV records, etc.)
  if (snapshot) {
    for (const q of snapshot.queries) {
      if (
        q.packet.flags.rcode !== 0 ||
        q.purpose.startsWith('BGP ASN lookup') ||
        q.purpose.startsWith('DNSBL reputation lookup') ||
        q.purpose.startsWith('PSL lookup') ||
        q.purpose.startsWith('Wildcard probe')
      ) {
        continue;
      }
      for (const ans of q.packet.answers) {
        const ownerZone = findDeepestMatchingZoneForOwner(ans.name, allZoneNames);
        if (ownerZone === zoneName) {
          addRec(ans);
        }
      }
    }
  }

  const sortedRecords = Array.from(recordMap.values()).sort((a, b) => {
    // Keep zone apex SOA & NS at the very top of the zone
    const aIsApexTop = a.name === zoneName && (a.typeName === 'SOA' || a.typeName === 'NS');
    const bIsApexTop = b.name === zoneName && (b.typeName === 'SOA' || b.typeName === 'NS');
    if (aIsApexTop !== bIsApexTop) return aIsApexTop ? -1 : 1;

    const ownerCmp = compareCanonicalDnsNames(a.name, b.name);
    if (ownerCmp !== 0) return ownerCmp;

    const pa = ZONEFILE_TYPE_PRIORITY[a.typeName] ?? 20;
    const pb = ZONEFILE_TYPE_PRIORITY[b.typeName] ?? 20;
    if (pa !== pb) return pa - pb;
    return a.rdataText.localeCompare(b.rdataText);
  });

  for (const rec of sortedRecords) {
    lines.push(formatMasterRecordLine(rec));
  }

  return lines.join('\n') + '\n';
}

/**
 * Formats all discovered authoritative zones (or a filtered zone) in an `AnalysisSnapshot`
 * as a standards-compliant RFC 1035 Master Zonefile (`.zone`).
 */
export function formatSnapshotAsZonefile(
  snapshot: AnalysisSnapshot,
  options: { zoneFilter?: string; includeDnssecRecords?: boolean } = {}
): string {
  const includeDnssec = options.includeDnssecRecords ?? true;
  const headerLines: string[] = [
    '; ============================================================================',
    '; DigDeep (https://digdeep.fyi) — RFC 1035 Master Zonefile Export',
    `; Target: ${snapshot.targetName} [${snapshot.queryTypes.join(', ')}]${snapshot.mode ? ` (mode: ${snapshot.mode})` : ''}`,
    `; Captured: ${new Date(snapshot.capturedAt).toISOString()} via ${snapshot.dohEndpoint}`,
    `; Overall Validation Status: ${snapshot.overallStatus === 'policy-error' ? 'POLICY ERROR' : snapshot.overallStatus.toUpperCase()}`,
    '; ============================================================================',
    '',
  ];

  const targetZones = options.zoneFilter
    ? snapshot.zones.filter((z) => normalizeFqdn(z.zoneName) === normalizeFqdn(options.zoneFilter!))
    : // Order deepest leaf zone first when exporting a domain, or root -> leaf
      [...snapshot.zones].sort((a, b) => b.depth - a.depth);

  const sections = targetZones.map((zone) => {
    const body = formatZoneAsZonefile(zone, snapshot, {
      includeDnssecRecords: includeDnssec,
      includeHeader: false,
    });
    return `; --- Zone: ${zone.zoneName} (${zone.status.toUpperCase()} · ${zone.nsecMode}) ---\n${body}`;
  });

  return headerLines.join('\n') + sections.join('\n');
}

/**
 * Triggers a browser download of a text file (such as an RFC 1035 `.zone` master file).
 */
export function downloadTextFile(
  content: string,
  filename: string,
  mimeType = 'text/dns;charset=utf-8'
): void {
  if (typeof document === 'undefined' || typeof Blob === 'undefined') return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
