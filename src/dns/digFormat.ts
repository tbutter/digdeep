import { rcodeToString } from './constants';
import { base64ToBytes } from './encoding';
import type { DnsPacket, DnsRecord, DohQueryLog } from './types';

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
