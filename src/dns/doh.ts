import { DEFAULT_DOH_ENDPOINT, rrTypeToString } from './constants';
import { bytesToBase64, bytesToBase64Url, normalizeFqdn } from './encoding';
import type { ClientSubnetQueryOption, DohQueryLog } from './types';
import { buildDnsQuery, formatEcsQuerySubnet, parseDnsPacket } from './wire';

export interface DohClientOptions {
  endpoint?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * Session-scoped DoH client speaking RFC 8484 (`application/dns-message`) to 1.1.1.1.
 * Deduplicates identical queries within a single analysis run and logs every request/response.
 */
export class DohSession {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly inflight = new Map<string, Promise<DohQueryLog>>();
  private readonly logs: DohQueryLog[] = [];
  private counter = 0;
  public onQueryCompleted?: (count: number, lastLog: DohQueryLog) => void;

  constructor(options: DohClientOptions = {}) {
    this.endpoint = options.endpoint ?? DEFAULT_DOH_ENDPOINT;
    this.timeoutMs = options.timeoutMs ?? 9000;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  public getLogs(): DohQueryLog[] {
    return [...this.logs];
  }

  public async query(
    qname: string,
    qtype: number,
    opts: { cd?: boolean; doBit?: boolean; ecs?: ClientSubnetQueryOption; purpose: string }
  ): Promise<DohQueryLog> {
    const normName = normalizeFqdn(qname);
    const cd = opts.cd ?? true;
    const doBit = opts.doBit ?? true;
    const ecsSubnet = opts.ecs ? formatEcsQuerySubnet(opts.ecs) : undefined;
    const key = `${normName}|${qtype}|cd=${cd ? 1 : 0}|do=${doBit ? 1 : 0}${ecsSubnet ? `|ecs=${ecsSubnet}` : ''}`;

    const existing = this.inflight.get(key);
    if (existing) {
      return existing;
    }

    const promise = this.executeQuery(normName, qtype, cd, doBit, opts.purpose, opts.ecs, ecsSubnet);
    this.inflight.set(key, promise);
    return promise;
  }

  private async executeQuery(
    normName: string,
    qtype: number,
    cd: boolean,
    doBit: boolean,
    purpose: string,
    ecs?: ClientSubnetQueryOption,
    ecsSubnet?: string
  ): Promise<DohQueryLog> {
    const reqWire = buildDnsQuery(normName, qtype, {
      cd,
      doBit,
      rd: true,
      udpPayloadSize: 4096,
      ecs,
    });
    const dnsParam = bytesToBase64Url(reqWire);
    const sep = this.endpoint.includes('?') ? '&' : '?';
    const url = `${this.endpoint}${sep}dns=${dnsParam}`;

    const startedAt = Date.now();
    const perfStart = performance.now();

    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const resp = await this.fetchImpl(url, {
          method: 'GET',
          cache: 'no-store',
          headers: {
            Accept: 'application/dns-message',
          },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (!resp.ok) {
          throw new Error(`DoH HTTP ${resp.status} ${resp.statusText} from ${this.endpoint}`);
        }

        const buf = new Uint8Array(await resp.arrayBuffer());
        const latencyMs = Math.max(1, Math.round(performance.now() - perfStart));
        const packet = parseDnsPacket(buf);

        // If CD=1 (DNSSEC validation disabled on resolver) still returned SERVFAIL (rcode 2) on attempt 0,
        // retry once after a short backoff in case of a cold-cache upstream timeout.
        if (attempt === 0 && cd && packet.flags.rcode === 2) {
          await new Promise((r) => setTimeout(r, 200));
          continue;
        }

        const log: DohQueryLog = {
          id: `q-${++this.counter}-${normName}-${rrTypeToString(qtype)}`,
          qname: normName,
          qtype,
          qtypeName: rrTypeToString(qtype),
          cd,
          doBit,
          endpoint: this.endpoint,
          startedAt,
          latencyMs,
          httpStatus: resp.status,
          wireBase64: bytesToBase64(buf),
          requestWireBase64: bytesToBase64(reqWire),
          packet,
          purpose,
          ...(ecsSubnet ? { ecsSubnet } : {}),
        };

        this.logs.push(log);
        this.onQueryCompleted?.(this.logs.length, log);
        return log;
      } catch (err) {
        clearTimeout(timer);
        lastError = err;
        if (attempt === 0) {
          await new Promise((r) => setTimeout(r, 250));
        }
      }
    }

    if (lastError instanceof TypeError) {
      throw new Error(
        `Could not connect to ${this.endpoint} from the browser. Verify the URL and ensure the DoH server allows browser CORS (Access-Control-Allow-Origin) for RFC 8484 queries.`
      );
    }

    throw lastError instanceof Error
      ? lastError
      : new Error(`Failed DoH query for ${normName} ${rrTypeToString(qtype)} via ${this.endpoint}`);
  }
}
