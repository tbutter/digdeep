import { describe, expect, it } from 'vitest';
import { runMailAnalysis } from '../mailAnalyzer';
import {
  buildReportFilename,
  buildSnapshotPermalink,
  extractSnapshotCiInvariants,
  formatSnapshotMarkdownReport,
  generateSnapshotCiScript,
  generateSnapshotGitHubWorkflow,
  shellSingleQuote,
} from '../reportExport';
import type { AnalysisSnapshot } from '../types';
import { runWebAnalysis } from '../webAnalyzer';

interface NodeBuiltinBridge {
  env: Record<string, string | undefined>;
  getBuiltinModule(id: 'node:child_process'): {
    execFileSync: (
      cmd: string,
      args: string[],
      opts?: {
        encoding?: string;
        env?: Record<string, string | undefined>;
        timeout?: number;
      }
    ) => string;
  };
  getBuiltinModule(id: 'node:fs'): {
    mkdtempSync: (prefix: string) => string;
    readFileSync: (path: string, enc: string) => string;
    rmSync: (path: string, opts?: { recursive?: boolean; force?: boolean }) => void;
    writeFileSync: (path: string, content: string, opts?: { mode?: number }) => void;
  };
  getBuiltinModule(id: 'node:os'): {
    tmpdir: () => string;
  };
  getBuiltinModule(id: 'node:path'): {
    join: (...parts: string[]) => string;
  };
}

const nodeProcess = (globalThis as unknown as { process: NodeBuiltinBridge }).process;
const { execFileSync } = nodeProcess.getBuiltinModule('node:child_process');
const { mkdtempSync, readFileSync, rmSync, writeFileSync } =
  nodeProcess.getBuiltinModule('node:fs');
const { tmpdir } = nodeProcess.getBuiltinModule('node:os');
const { join } = nodeProcess.getBuiltinModule('node:path');

describe('1-Click Markdown Incident Report & CI DNSSEC / DANE Regression Check Generator (#36)', () => {
  it(
    'generates GFM incident report and executes live POSIX dig/delv CI checks for cloudflare.com (Web + CAA + DNSSEC)',
    async () => {
      const snap = await runWebAnalysis('cloudflare.com');

      // 1. Permalink & filenames
      const link = buildSnapshotPermalink(snap);
      expect(link).toBe('https://digdeep.fyi/?name=cloudflare.com&mode=web&doh=1.1.1.1');
      expect(buildReportFilename(snap, 'markdown')).toMatch(
        /^digdeep-cloudflare\.com-\d{4}-\d{2}-\d{2}\.md$/
      );
      expect(buildReportFilename(snap, 'shell')).toBe('dns-check-cloudflare.com.sh');
      expect(buildReportFilename(snap, 'workflow')).toBe('dns-check.yml');

      // 2. GitHub-Flavored Markdown report
      const md = formatSnapshotMarkdownReport(snap);
      expect(md).toContain('# ');
      expect(md).toContain('`cloudflare.com`');
      expect(md).toContain('## Audit Findings');
      expect(md).toContain('## DNSSEC Chain of Trust');
      expect(md).toContain('`cloudflare.com.`');
      expect(md).toContain('DS `#2371`');
      expect(md).toContain('## Web, HTTPS/SVCB, ECH, CAA & DANE Summary');
      expect(md).toContain('CAA Policy (RFC 8659)');
      expect(md).toContain('## CLI Reproducer Commands');
      expect(md).toContain('<details>');
      expect(md).toContain(';; ->>HEADER<<- opcode: QUERY');
      expect(md).toContain(link);

      // Wire transcript mode 'none' omits <details> blocks
      const mdNoWire = formatSnapshotMarkdownReport(snap, {
        wireTranscriptMode: 'none',
      });
      expect(mdNoWire).not.toContain('<details>');

      // 3. Extracted CI invariants
      const inv = extractSnapshotCiInvariants(snap);
      expect(inv.expectDnssecAd).toBe(true);
      expect(inv.signedZone).toBe('cloudflare.com');
      expect(inv.expectedDsKeyTags).toContain(2371);
      expect(inv.caaCheck).not.toBeNull();
      expect(inv.caaCheck?.expectedIssueCas).toContain('letsencrypt.org');

      // 4. Execute generated POSIX shell script live against 1.1.1.1!
      const script = generateSnapshotCiScript(snap);
      const tmpDir = mkdtempSync(join(tmpdir(), 'digdeep-ci-cf-'));
      try {
        const scriptPath = join(tmpDir, 'dns-check.sh');
        const stepSummaryPath = join(tmpDir, 'step-summary.md');
        writeFileSync(scriptPath, script, { mode: 0o755 });

        // Syntax check with POSIX sh -n
        execFileSync('sh', ['-n', scriptPath]);

        // Live execution against 1.1.1.1
        const stdout = execFileSync('sh', [scriptPath], {
          encoding: 'utf8',
          env: {
            ...nodeProcess.env,
            GITHUB_STEP_SUMMARY: stepSummaryPath,
          },
          timeout: 20000,
        });

        expect(stdout).toContain('[PASS] DNSSEC AD=1 (cloudflare.com');
        expect(stdout).toContain('[PASS] ISC delv Chain (cloudflare.com');
        expect(stdout).toContain('[PASS] Parent DS #2371 (cloudflare.com)');
        expect(stdout).toContain('[PASS] RRSIG Lifetime (cloudflare.com SOA)');
        expect(stdout).toContain('[PASS] CAA Issuer (cloudflare.com)');
        expect(stdout).toContain('0 failed');

        const summaryMd = readFileSync(stepSummaryPath, 'utf8');
        expect(summaryMd).toContain('### DNS Security Regression Check: `cloudflare.com`');
        expect(summaryMd).toContain('| ✅ PASS |');
        expect(summaryMd).toContain(link);

        // Verify regression failure detection when RRSIG threshold is breached
        let failedAsExpected = false;
        try {
          execFileSync('sh', [scriptPath], {
            encoding: 'utf8',
            env: {
              ...nodeProcess.env,
              SKIP_DELV: '1',
              MIN_RRSIG_HOURS: '999999',
            },
            timeout: 15000,
          });
        } catch (err) {
          failedAsExpected = true;
          const stderr = (err as { stderr?: string }).stderr ?? '';
          expect(stderr).toContain('[FAIL] RRSIG Lifetime');
        }
        expect(failedAsExpected).toBe(true);
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }

      // 5. GitHub Actions Workflow YAML
      const wf = generateSnapshotGitHubWorkflow(snap, {
        cronSchedule: '17 * * * *',
      });
      expect(wf).toContain('name: "DNS Security Check (cloudflare.com)"');
      expect(wf).toContain("- cron: '17 * * * *'");
      expect(wf).toContain('workflow_dispatch:');
      expect(wf).toContain('permissions:\n  contents: read');
      expect(wf).toContain('bind9-dnsutils');
      expect(wf).toContain('shell: sh -e {0}');
      expect(wf).toContain('check_caa_issuer');
    },
    35000
  );

  it(
    'executes live POSIX CI checks for ietf.org Mail + SMTP DANE TLSA + SPF lookup budget + DMARC',
    async () => {
      const snap = await runMailAnalysis('ietf.org');
      const md = formatSnapshotMarkdownReport(snap);
      expect(md).toContain('## Mail, SMTP DANE, SPF, DKIM & DMARC Summary');
      expect(md).toContain('SMTP DANE (`_25._tcp`)');
      expect(md).toContain('SPF (RFC 7208)');
      expect(md).toContain('DMARC (RFC 7489)');

      const inv = extractSnapshotCiInvariants(snap);
      expect(inv.expectDnssecAd).toBe(true);
      expect(inv.spfCheck).not.toBeNull();
      expect(inv.spfCheck?.maxDnsLookups).toBe(10);
      expect(inv.dmarcCheck).not.toBeNull();
      expect(inv.tlsaChecks.length).toBeGreaterThanOrEqual(1);

      const script = generateSnapshotCiScript(snap);
      const tmpDir = mkdtempSync(join(tmpdir(), 'digdeep-ci-ietf-'));
      try {
        const scriptPath = join(tmpDir, 'dns-check-ietf.sh');
        writeFileSync(scriptPath, script, { mode: 0o755 });
        execFileSync('sh', ['-n', scriptPath]);

        const stdout = execFileSync('sh', [scriptPath], {
          encoding: 'utf8',
          timeout: 25000,
        });
        expect(stdout).toContain('[PASS] DNSSEC AD=1 (ietf.org MX)');
        expect(stdout).toContain('[PASS] SPF Lookup Budget (ietf.org)');
        expect(stdout).toContain('[PASS] DMARC Policy (_dmarc.ietf.org)');
        expect(stdout).toContain('[PASS] SMTP DANE');
        expect(stdout).toContain('0 failed');
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    },
    35000
  );

  it('renders EDE/ECS consensus sections and neutralizes shell/Markdown injection payloads', () => {
    expect(shellSingleQuote(`evil'$(touch /tmp/pwn)\`id\`\n\x00`)).toBe(
      `'evil'\\''$(touch /tmp/pwn)\`id\`'`
    );

    const syntheticConsensusSnap: AnalysisSnapshot = {
      id: 'snap-consensus-ede-test',
      version: 16,
      mode: 'consensus',
      targetName: 'example.com.',
      displayDomain: 'example.com',
      queryTypes: ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS'],
      dohEndpoint: 'https://cloudflare-dns.com/dns-query',
      capturedAt: 1700000000000,
      validatedAt: 1700000000000,
      durationMs: 120,
      overallStatus: 'warning',
      overallSummary: 'Protective DNS filtering detected on 1 resolver.',
      zones: [
        {
          zoneName: 'example.com.',
          parentZone: 'com.',
          depth: 2,
          status: 'secure',
          statusReason: 'Validated chain | pipe test',
          nsecMode: 'NSEC3',
          dnskeys: [],
          dsVerifications: [],
          trustAnchorMatches: [],
          rrsets: [],
          negativeNodes: [],
          nameservers: [],
        },
      ],
      cnameEdges: [],
      findings: [
        {
          id: 'f-ede-15',
          severity: 'warning',
          code: 'CONSENSUS_PROTECTIVE_BLOCK',
          title: 'Filtered by protective resolver | pipe <script>',
          detail: 'Resolver returned EDE(15 Blocked).',
          rfc: 'RFC 8914 §4.16',
          zone: 'example.com.',
        },
      ],
      queries: [],
      trustAnchorsUsed: [],
      note: 'Incident #42 | check <tag>',
      webAnalysis: {
        targetDomain: 'example.com.',
        displayDomain: 'example.com',
        cnameChain: [],
        ipv4Addresses: ['93.184.215.14'],
        ipv6Addresses: [],
        addressDnssecStatus: 'secure',
        httpsStatus: 'not-deployed',
        httpsDnssecStatus: 'secure',
        httpsRecords: [],
        svcbRecords: [],
        supportsHttp3: false,
        supportsHttp2: false,
        echEnabled: false,
        echPublicNames: [],
        ipHintStatus: 'not-used',
        httpsSummary: 'No HTTPS record',
        caa: {
          status: 'enforced',
          effectiveOwner: 'example.com.',
          dnssecStatus: 'secure',
          hops: [],
          issueCas: [`ca.example.org'; $(whoami) #`, '`id`.ca.example.net'],
          issuewildCas: [],
          iodefUris: [],
          hasAcmeAccountBinding: false,
          hasCriticalUnknownTag: false,
          issues: [],
          summary: 'CAA enforced',
        },
        webDane: {
          qname: '_443._tcp.example.com.',
          resolvedOwner: '_443._tcp.example.com.',
          cnameChain: [],
          status: 'no-tlsa-secure',
          dnssecStatus: 'secure',
          records: [],
          rolloverReady: false,
          summary: 'No TLSA',
        },
        sshfp: {
          present: false,
          status: 'not-deployed',
          dnssecStatus: 'secure',
          records: [],
          summary: 'No SSHFP',
        },
      },
      consensusAnalysis: {
        targetDomain: 'example.com.',
        displayDomain: 'example.com',
        soaZone: 'example.com.',
        resolvers: [
          {
            endpoint: 'https://security.cloudflare-dns.com/dns-query',
            shortLabel: '1.1.1.2 Malware',
            provider: 'Cloudflare',
            role: 'protective',
            reachable: true,
            latencyMs: 18,
            rcode: 0,
            rcodeName: 'NOERROR',
            adBit: false,
            ipv4Answers: ['0.0.0.0'],
            ipv6Answers: [],
            cnameChain: [],
            dsKeyTags: [370],
            dnskeyKeyTags: [370],
            ede: [{ infoCode: 15, name: 'Blocked', extraText: 'Categorized | test' }],
            isSinkholed: true,
            classification: 'policy-blocked',
            summary: 'Blocked via EDE 15',
          },
        ],
        reachableCount: 1,
        unfilteredResolvedCount: 0,
        protectiveBlockedResolvers: ['1.1.1.2 Malware'],
        dnssecBogusResolvers: [],
        upstreamErrorResolvers: [],
        adBitConsensus: 'all-unsigned',
        rcodeConsensus: 'protective-filtered',
        answerConsensus: 'protective-sinkhole',
        soaSerialConsensus: 'synchronized',
        uniqueSoaSerials: [],
        keyTagConsensus: 'synchronized',
        edeHighlights: [
          {
            resolverLabel: '1.1.1.2 Malware',
            infoCode: 15,
            name: 'Blocked',
            category: 'policy-blocked',
            extraText: 'Categorized | test',
          },
        ],
        overallVerdict: 'protective-blocked',
        summary: 'Blocked on protective resolver.',
        ecsGeo: {
          ecsEndpoint: 'https://dns.google/dns-query',
          ecsEndpointLabel: 'Google 8.8.8.8',
          ecsSupportedByResolver: true,
          regions: [],
          steeringModel: 'geodns-ip',
          uniqueIpv4PoolCount: 4,
          uniqueIpv6PoolCount: 3,
          uniqueCnameTargets: [],
          ipv4ScopeRange: { min: 24, max: 24 },
          ipv6ScopeRange: { min: 48, max: 48 },
          optOutHonored: true,
          cacheBustingRegions: [],
          anomalyRegions: [],
          summary: '4 distinct regional IPv4 edge pools observed.',
        },
      },
    };

    const md = formatSnapshotMarkdownReport(syntheticConsensusSnap);
    expect(md).toContain('## Multi-Resolver DoH Consensus, EDE & ECS GeoDNS');
    expect(md).toContain('### RFC 8914 Extended DNS Error (EDE) Highlights');
    expect(md).toContain('`EDE(15 Blocked)`');
    expect(md).toContain('### RFC 7871 EDNS Client Subnet (ECS) Geo-Steering');
    expect(md).toContain('`geodns-ip`');
    expect(md).toContain('RFC 8914 §4.16');
    // Pipe characters inside table cells are escaped so GFM table columns stay intact
    expect(md).toContain('Categorized \\| test');

    const adversarialScript = generateSnapshotCiScript(syntheticConsensusSnap);
    const tmpDir = mkdtempSync(join(tmpdir(), 'digdeep-ci-sec-'));
    try {
      const scriptPath = join(tmpDir, 'check.sh');
      writeFileSync(scriptPath, adversarialScript, { mode: 0o755 });
      // Must parse cleanly as valid POSIX shell with adversarial strings safely single-quoted
      execFileSync('sh', ['-n', scriptPath]);
      expect(adversarialScript).toContain(
        `check_caa_issuer 'example.com' 'ca.example.org'\\''; $(whoami) #'`
      );
      expect(adversarialScript).toContain(
        `check_caa_issuer 'example.com' '\`id\`.ca.example.net'`
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
