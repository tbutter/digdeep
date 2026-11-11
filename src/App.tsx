import {
  Activity,
  AlertTriangle,
  Check,
  Clock,
  Download,
  Globe,
  Link2,
  Mail,
  Moon,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Terminal,
  WifiOff,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AuditPanel } from './components/AuditPanel';
import { ChainGraphView } from './components/ChainGraphView';
import { ConsensusView } from './components/ConsensusView';
import { DohChooser } from './components/DohChooser';
import { EmailDaneCard } from './components/EmailDaneCard';
import { HistoryPanel } from './components/HistoryPanel';
import { IpHoverBadge, seedIpAsnCacheFromSnapshot } from './components/IpHoverBadge';
import { MailAnalysisView } from './components/MailAnalysisView';
import { ResponsesPanel } from './components/ResponsesPanel';
import { ReverseDnsCard } from './components/ReverseDnsCard';
import { SettingsModal } from './components/SettingsModal';
import { StatusBadge, STATUS_META } from './components/StatusBadge';
import { WebAnalysisView } from './components/WebAnalysisView';
import { ZonesPanel } from './components/ZonesPanel';
import { reverifySnapshot, runDnsvizAnalysis, SNAPSHOT_ENGINE_VERSION } from './dns/analyzer';
import { runConsensusAnalysis } from './dns/consensusAnalyzer';
import { ANALYSIS_MODES, formatDohShortLabel, QUERYABLE_RR_TYPES } from './dns/constants';
import { parseEmailDaneInput } from './dns/emailDane';
import { parseReverseIpInput } from './dns/ipUtils';
import {
  parseDkimSelectorInput,
  queryPublicSuffix,
  runMailAnalysis,
  seedPublicSuffixCacheFromLogs,
  splitDomainByPublicSuffix,
  subscribePublicSuffixCache,
} from './dns/mailAnalyzer';
import type { AnalysisMode, AnalysisProgress, AnalysisSnapshot } from './dns/types';
import { runWebAnalysis } from './dns/webAnalyzer';
import { usePwaInstall } from './pwa/usePwaInstall';
import {
  clearUnpinnedSnapshots,
  deleteSnapshot,
  importSnapshotsFromJson,
  loadSnapshots,
  loadTheme,
  loadUserSettings,
  saveSnapshot,
  saveTheme,
  saveUserSettings,
  updateSnapshotMeta,
  type UserSettings,
} from './storage/historyStore';
import {
  buildDeepLinkSearch,
  buildShareUrl,
  parseDeepLinkParams,
  type ActiveTab,
} from './urlState';

const PRIMARY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'HTTPS', 'DNSKEY'];
const EXTRA_TYPES = QUERYABLE_RR_TYPES.filter((t) => !PRIMARY_TYPES.includes(t));

const DEFAULT_PAGE_TITLE =
  'DigDeep — Client-Side DNSSEC, MX, DANE, SPF, DKIM & DMARC Analyzer';

const EXAMPLE_TRACES: ReadonlyArray<{
  domain: string;
  mode?: AnalysisMode;
  types: string[];
  badge: string;
  description: string;
}> = [
  {
    domain: 'www.iana.org',
    types: ['A', 'AAAA'],
    badge: 'DNSSEC',
    description: 'Cross-zone signed CNAME chain',
  },
  {
    domain: 'dnssec-failed.org',
    types: ['A', 'AAAA'],
    badge: 'DNSSEC',
    description: 'Broken DS delegation & missing SEP DNSKEY (Bogus)',
  },
  {
    domain: 'ietf.org',
    mode: 'mail',
    types: ['MX', 'TXT'],
    badge: 'Mail',
    description: 'MX + SMTP DANE + SPF + DKIM + DMARC + DNSBL + SRV',
  },
  {
    domain: 'cloudflare.com',
    mode: 'web',
    types: ['A', 'AAAA', 'HTTPS', 'CAA'],
    badge: 'Web',
    description: 'HTTPS/SVCB, TLS ECHConfigList & CAA Policy',
  },
  {
    domain: 'dnssec-failed.org',
    mode: 'consensus',
    types: ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS'],
    badge: 'Consensus',
    description: 'Multi-DoH Resolver Matrix & RFC 8914 EDE',
  },
  {
    domain: 'www.wikipedia.org',
    mode: 'consensus',
    types: ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS'],
    badge: 'ECS GeoDNS',
    description: 'RFC 7871 ECS 6-continent GeoDNS & SCOPE matrix',
  },
  {
    domain: '9.9.9.9',
    types: ['PTR'],
    badge: 'rDNS',
    description: 'Signed PTR + FCrDNS + BGP ASN + DNSBL reputation',
  },
  {
    domain: 'paul@nohats.ca',
    types: ['OPENPGPKEY', 'SMIMEA'],
    badge: 'DANE ID',
    description: 'RFC 7929 OPENPGPKEY & RFC 8162 SMIMEA email identity',
  },
  {
    domain: 'cloudflare.com',
    types: ['A', 'AAAA'],
    badge: 'DNSSEC',
    description: 'ECDSA P-256 chain of trust',
  },
  {
    domain: '.',
    types: ['DNSKEY', 'SOA'],
    badge: 'DNSSEC',
    description: 'IANA Root Zone Trust Anchor & RFC 8976 ZONEMD',
  },
];

export function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => loadTheme());

  const [initialBootState] = useState(() => {
    const savedSettings = loadUserSettings();
    const savedSnapshots = loadSnapshots();
    const search = typeof window !== 'undefined' ? window.location.search : '';
    const deepLink = parseDeepLinkParams(search, savedSettings.customDohEndpoints);

    const effectiveSettings: UserSettings = {
      ...savedSettings,
      dohEndpoint: deepLink.dohEndpoint ?? savedSettings.dohEndpoint,
      showSoaAndNs: deepLink.showSoaAndNs ?? savedSettings.showSoaAndNs,
      showStandbyKeys: deepLink.showStandbyKeys ?? savedSettings.showStandbyKeys,
    };

    const initialMode: AnalysisMode =
      deepLink.mode ?? savedSnapshots[0]?.mode ?? 'dnssec';
    const initialDomain =
      deepLink.name ??
      savedSnapshots[0]?.queriedEmail ??
      savedSnapshots[0]?.displayDomain ??
      'digdeep.butter.eu';
    const initialEmailParsed = parseEmailDaneInput(initialDomain);
    const initialIpParsed = initialEmailParsed ? null : parseReverseIpInput(initialDomain);
    const initialTypes =
      deepLink.types ??
      (initialEmailParsed?.inputKind === 'email'
        ? ['OPENPGPKEY', 'SMIMEA']
        : initialIpParsed?.wasRawIpInput
          ? ['PTR']
          : savedSnapshots[0]?.queryTypes ?? ['A', 'AAAA']);
    const initialDkimSelectors =
      deepLink.dkimSelectors ?? savedSnapshots[0]?.customDkimSelectors ?? [];

    const latestSnap = savedSnapshots[0] ?? null;
    const matchesLatestSnap =
      latestSnap !== null &&
      (latestSnap.mode ?? 'dnssec') === initialMode &&
      (!deepLink.dkimSelectors ||
        (latestSnap.customDkimSelectors ?? []).join(',') === deepLink.dkimSelectors.join(',')) &&
      (!deepLink.name ||
        latestSnap.displayDomain.toLowerCase() === deepLink.name.toLowerCase().replace(/\.$/, '') ||
        (initialIpParsed &&
          latestSnap.displayDomain.toLowerCase() === initialIpParsed.displayArpa.toLowerCase()) ||
        (deepLink.name === '.' && latestSnap.displayDomain === '.'));

    const defaultTab: ActiveTab =
      initialMode === 'mail'
        ? 'mail'
        : initialMode === 'web'
          ? 'web'
          : initialMode === 'consensus'
            ? 'consensus'
            : 'graph';

    return {
      settings: effectiveSettings,
      snapshots: savedSnapshots,
      activeSnapshot: matchesLatestSnap ? latestSnap : null,
      analysisMode: initialMode,
      domainInput: initialDomain,
      selectedTypes: initialTypes,
      customDkimSelectors: initialDkimSelectors,
      hasExtraType: initialTypes.some((t) => (EXTRA_TYPES as readonly string[]).includes(t)),
      activeTab: deepLink.tab ?? defaultTab,
      focusedTarget: deepLink.focus,
      deepLink,
    };
  });

  const [settings, setSettings] = useState<UserSettings>(initialBootState.settings);
  const [snapshots, setSnapshots] = useState<AnalysisSnapshot[]>(initialBootState.snapshots);
  const [activeSnapshot, setActiveSnapshot] = useState<AnalysisSnapshot | null>(
    initialBootState.activeSnapshot
  );

  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>(initialBootState.analysisMode);
  const [domainInput, setDomainInput] = useState<string>(initialBootState.domainInput);
  const [selectedTypes, setSelectedTypes] = useState<string[]>(initialBootState.selectedTypes);
  const [customDkimSelectors, setCustomDkimSelectors] = useState<string[]>(
    initialBootState.customDkimSelectors
  );
  const [showExtraTypes, setShowExtraTypes] = useState<boolean>(initialBootState.hasExtraType);

  const [activeTab, setActiveTab] = useState<ActiveTab>(initialBootState.activeTab);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(false);
  const examplesContainerRef = useRef<HTMLDivElement | null>(null);
  const [focusedGraphTarget, setFocusedGraphTarget] = useState<string | null>(
    initialBootState.focusedTarget
  );
  const [untrustedDohPending, setUntrustedDohPending] = useState<string | null>(
    initialBootState.deepLink.isUntrustedCustomDoh ? initialBootState.deepLink.dohEndpoint : null
  );
  const [copiedLink, setCopiedLink] = useState(false);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { canInstall, isOffline, promptInstall } = usePwaInstall();

  const inputRef = useRef<HTMLInputElement | null>(null);
  const inputOverlayRef = useRef<HTMLDivElement | null>(null);
  const didBootRef = useRef(false);
  const [, setPslCacheVersion] = useState(0);

  useEffect(() => {
    return subscribePublicSuffixCache(() => {
      setPslCacheVersion((v) => v + 1);
    });
  }, []);

  // Sync dark/light class on <html>
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    saveTheme(theme);
  }, [theme]);

  // Dynamic <title> reflecting active domain & validation verdict for browser tabs, bookmarks, and history
  useEffect(() => {
    if (typeof document === 'undefined') return;
    if (activeSnapshot) {
      const verdict = STATUS_META[activeSnapshot.overallStatus].label;
      const modeLabel =
        activeSnapshot.mode === 'mail'
          ? 'Mail · DANE · SPF · DKIM · DMARC'
          : activeSnapshot.mode === 'web'
            ? 'Web · HTTPS/SVCB · ECH · CAA · DANE'
            : activeSnapshot.mode === 'consensus'
              ? 'Multi-Resolver DoH Consensus & EDE'
              : 'DNSSEC Visualizer';
      document.title = `${activeSnapshot.displayDomain} (${verdict}) — DigDeep ${modeLabel}`;
    } else {
      document.title = DEFAULT_PAGE_TITLE;
    }
  }, [activeSnapshot]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  // Press '/' anywhere outside inputs to focus domain search bar
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setExamplesOpen(false);
      }
      if (
        e.key === '/' &&
        document.activeElement?.tagName !== 'INPUT' &&
        document.activeElement?.tagName !== 'TEXTAREA' &&
        document.activeElement?.tagName !== 'SELECT'
      ) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  // Close examples overlay when clicking outside
  useEffect(() => {
    if (!examplesOpen) return;
    const onPointerDown = (e: MouseEvent) => {
      if (
        examplesContainerRef.current &&
        !examplesContainerRef.current.contains(e.target as Node)
      ) {
        setExamplesOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [examplesOpen]);

  const executeAnalysis = useCallback(
    async (
      targetDomain: string,
      typesToQuery: string[],
      options?: {
        modeOverride?: AnalysisMode;
        dkimSelectorsOverride?: string[];
        dohEndpointOverride?: string;
        preserveFocus?: boolean;
        pushHistory?: boolean;
      }
    ) => {
      const cleanDomain = targetDomain.trim() || '.';
      const parsedEmail = parseEmailDaneInput(cleanDomain);
      const parsedIp = parsedEmail ? null : parseReverseIpInput(cleanDomain);
      const modeToRun: AnalysisMode =
        parsedIp?.wasRawIpInput && !options?.modeOverride
          ? 'dnssec'
          : parsedEmail?.inputKind === 'email' &&
              !options?.modeOverride &&
              analysisMode !== 'mail'
            ? 'dnssec'
            : (options?.modeOverride ?? analysisMode);
      const rawTypes = typesToQuery.length > 0 ? typesToQuery : ['A'];
      const cleanTypes =
        parsedEmail?.inputKind === 'email' && modeToRun === 'dnssec'
          ? ['OPENPGPKEY', 'SMIMEA']
          : parsedEmail?.inputKind === 'openpgpkey-owner' &&
              rawTypes.every((t) => t.toUpperCase() === 'A' || t.toUpperCase() === 'AAAA')
            ? ['OPENPGPKEY']
            : parsedEmail?.inputKind === 'smimea-owner' &&
                rawTypes.every((t) => t.toUpperCase() === 'A' || t.toUpperCase() === 'AAAA')
              ? ['SMIMEA']
              : parsedIp?.wasRawIpInput &&
                  rawTypes.every((t) => t.toUpperCase() === 'A' || t.toUpperCase() === 'AAAA')
                ? ['PTR']
                : rawTypes;
      const dkimSelsToUse = options?.dkimSelectorsOverride ?? customDkimSelectors;
      const endpointToUse = options?.dohEndpointOverride ?? settings.dohEndpoint;

      if (parsedEmail && modeToRun === 'dnssec') {
        if (modeToRun !== analysisMode) setAnalysisMode(modeToRun);
        if (cleanTypes.some((t) => !selectedTypes.includes(t))) {
          setSelectedTypes(cleanTypes);
          setShowExtraTypes(true);
        }
        void queryPublicSuffix(parsedEmail.domain, { endpoint: endpointToUse });
      } else if (parsedIp?.wasRawIpInput) {
        if (modeToRun !== analysisMode) setAnalysisMode(modeToRun);
        if (cleanTypes.includes('PTR') && !selectedTypes.includes('PTR')) {
          setSelectedTypes(['PTR']);
          setShowExtraTypes(true);
        }
      } else if (cleanDomain !== '.') {
        void queryPublicSuffix(cleanDomain, { endpoint: endpointToUse });
      }

      if (!options?.preserveFocus) {
        setFocusedGraphTarget(null);
      }
      setUntrustedDohPending(null);
      setLoading(true);
      setError(null);
      setProgress({
        phase:
          modeToRun === 'mail'
            ? 'mail-mx'
            : modeToRun === 'web'
              ? 'web-https'
              : modeToRun === 'consensus'
                ? 'consensus-probes'
                : 'zone-cuts',
        message:
          modeToRun === 'mail'
            ? `Starting ${formatDohShortLabel(endpointToUse)} Mail, DANE, SPF, DKIM & DMARC analysis for ${cleanDomain}…`
            : modeToRun === 'web'
              ? `Starting ${formatDohShortLabel(endpointToUse)} Web, HTTPS/SVCB, ECH, CAA & DANE analysis for ${cleanDomain}…`
              : modeToRun === 'consensus'
                ? `Starting Multi-Resolver DoH Consensus & RFC 8914 EDE probe across 8 resolvers for ${cleanDomain}…`
                : `Starting ${formatDohShortLabel(endpointToUse)} DoH trace for ${cleanDomain}…`,
        completedQueries: 0,
      });

      try {
        const snap =
          modeToRun === 'mail'
            ? await runMailAnalysis(cleanDomain, {
                endpoint: endpointToUse,
                dkimSelectors: dkimSelsToUse,
                trustAnchors: settings.trustAnchors,
                onProgress: (p) => setProgress(p),
              })
            : modeToRun === 'web'
              ? await runWebAnalysis(cleanDomain, {
                  endpoint: endpointToUse,
                  trustAnchors: settings.trustAnchors,
                  onProgress: (p) => setProgress(p),
                })
              : modeToRun === 'consensus'
                ? await runConsensusAnalysis(cleanDomain, {
                    endpoint: endpointToUse,
                    trustAnchors: settings.trustAnchors,
                    onProgress: (p) => setProgress(p),
                  })
                : await runDnsvizAnalysis(cleanDomain, {
                    endpoint: endpointToUse,
                    queryTypes: cleanTypes,
                    trustAnchors: settings.trustAnchors,
                    onProgress: (p) => setProgress(p),
                  });

        const updatedList = saveSnapshot(snap);
        setSnapshots(updatedList);
        setActiveSnapshot(snap);

        let nextTab: ActiveTab = activeTab;
        if (modeToRun === 'mail') {
          if (activeTab === 'history' || (activeSnapshot?.mode ?? 'dnssec') !== 'mail') {
            nextTab = 'mail';
            setActiveTab('mail');
          }
        } else if (modeToRun === 'web') {
          if (activeTab === 'history' || (activeSnapshot?.mode ?? 'dnssec') !== 'web') {
            nextTab = 'web';
            setActiveTab('web');
          }
        } else if (modeToRun === 'consensus') {
          if (activeTab === 'history' || (activeSnapshot?.mode ?? 'dnssec') !== 'consensus') {
            nextTab = 'consensus';
            setActiveTab('consensus');
          }
        } else if (
          activeTab === 'history' ||
          activeTab === 'mail' ||
          activeTab === 'web' ||
          activeTab === 'consensus'
        ) {
          nextTab = 'graph';
          setActiveTab('graph');
        }

        if (typeof window !== 'undefined' && window.history) {
          const url = new URL(window.location.href);
          url.hash = '';
          url.search = buildDeepLinkSearch({
            name: snap.queriedEmail ?? snap.displayDomain,
            mode: snap.mode,
            types: snap.queryTypes,
            dkimSelectors: snap.customDkimSelectors,
            dohEndpoint: snap.dohEndpoint,
            tab: nextTab,
            focus: options?.preserveFocus ? focusedGraphTarget : null,
            showSoaAndNs: settings.showSoaAndNs,
            showStandbyKeys: settings.showStandbyKeys,
          });
          if (options?.pushHistory && url.toString() !== window.location.href) {
            window.history.pushState({}, '', url.toString());
          } else {
            window.history.replaceState({}, '', url.toString());
          }
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : `Failed to query ${formatDohShortLabel(endpointToUse)} DoH. Check network connectivity.`
        );
      } finally {
        setLoading(false);
        setProgress(null);
      }
    },
    [
      analysisMode,
      activeSnapshot?.mode,
      customDkimSelectors,
      settings.dohEndpoint,
      settings.trustAnchors,
      settings.showSoaAndNs,
      settings.showStandbyKeys,
      activeTab,
      focusedGraphTarget,
    ]
  );

  // Keep browser URL query string in sync as user switches tabs, selects graph elements, or toggles filters
  useEffect(() => {
    if (!activeSnapshot || loading) return;
    if (typeof window === 'undefined' || !window.history?.replaceState) return;

    const url = new URL(window.location.href);
    const nextSearch = buildDeepLinkSearch({
      name: activeSnapshot.queriedEmail ?? activeSnapshot.displayDomain,
      mode: activeSnapshot.mode,
      types: activeSnapshot.queryTypes,
      dkimSelectors: activeSnapshot.customDkimSelectors,
      dohEndpoint: activeSnapshot.dohEndpoint,
      tab: activeTab,
      focus: focusedGraphTarget,
      showSoaAndNs: settings.showSoaAndNs,
      showStandbyKeys: settings.showStandbyKeys,
    });
    if (url.search !== nextSearch) {
      url.search = nextSearch;
      window.history.replaceState({}, '', url.toString());
    }
  }, [
    activeSnapshot,
    activeTab,
    focusedGraphTarget,
    loading,
    settings.showSoaAndNs,
    settings.showStandbyKeys,
  ]);

  // Support browser Back / Forward navigation across deep-linked traces
  useEffect(() => {
    const onPopState = () => {
      const parsed = parseDeepLinkParams(window.location.search, settings.customDohEndpoints);
      const nextMode: AnalysisMode = parsed.mode ?? 'dnssec';
      const nextDkimSels = parsed.dkimSelectors ?? [];
      setAnalysisMode(nextMode);
      setCustomDkimSelectors(nextDkimSels);
      if (parsed.tab) setActiveTab(parsed.tab);
      else
        setActiveTab(
          nextMode === 'mail'
            ? 'mail'
            : nextMode === 'web'
              ? 'web'
              : nextMode === 'consensus'
                ? 'consensus'
                : 'graph'
        );

      setFocusedGraphTarget(parsed.focus);

      if (parsed.showSoaAndNs !== null || parsed.showStandbyKeys !== null || parsed.dohEndpoint) {
        setSettings((prev) => ({
          ...prev,
          dohEndpoint: parsed.dohEndpoint ?? prev.dohEndpoint,
          showSoaAndNs: parsed.showSoaAndNs ?? prev.showSoaAndNs,
          showStandbyKeys: parsed.showStandbyKeys ?? prev.showStandbyKeys,
        }));
      }

      if (!parsed.name) return;
      const targetTypes =
        parsed.types ??
        (nextMode === 'mail'
          ? ['MX', 'TXT']
          : nextMode === 'web'
            ? ['A', 'AAAA', 'HTTPS', 'SVCB', 'CAA', 'TLSA', 'SSHFP']
            : nextMode === 'consensus'
              ? ['A', 'AAAA', 'SOA', 'DNSKEY', 'DS']
              : ['A', 'AAAA']);
      const targetDoh = parsed.dohEndpoint ?? settings.dohEndpoint;
      setDomainInput(parsed.name);
      if (nextMode === 'dnssec') {
        setSelectedTypes(targetTypes);
      }

      if (parsed.isUntrustedCustomDoh && parsed.dohEndpoint) {
        setUntrustedDohPending(parsed.dohEndpoint);
        return;
      }

      const cached = snapshots.find(
        (s) =>
          (s.mode ?? 'dnssec') === nextMode &&
          (s.queriedEmail ?? s.displayDomain).toLowerCase() ===
            parsed.name!.toLowerCase().replace(/\.$/, '') &&
          (nextMode === 'mail'
            ? (s.customDkimSelectors ?? []).join(',') === nextDkimSels.join(',')
            : nextMode === 'web' || nextMode === 'consensus'
              ? true
              : s.queryTypes.join(',') === targetTypes.join(',')) &&
          s.dohEndpoint === targetDoh
      );
      if (cached) {
        setActiveSnapshot(cached);
      } else if (!isOffline) {
        void executeAnalysis(parsed.name, targetTypes, {
          modeOverride: nextMode,
          dkimSelectorsOverride: nextDkimSels,
          dohEndpointOverride: targetDoh,
          preserveFocus: Boolean(parsed.focus),
          pushHistory: false,
        });
      }
    };

    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [executeAnalysis, isOffline, settings.customDohEndpoints, settings.dohEndpoint, snapshots]);

  // Auto-upgrade any localStorage snapshots captured with an older validation engine version
  useEffect(() => {
    const stale = snapshots.filter((s) => (s.version ?? 1) < SNAPSHOT_ENGINE_VERSION);
    if (stale.length === 0) return;
    let cancelled = false;
    void (async () => {
      let latestList = snapshots;
      for (const s of stale) {
        const upgraded = await reverifySnapshot(s);
        if (cancelled) return;
        latestList = saveSnapshot(upgraded);
        setActiveSnapshot((cur) => (cur?.id === upgraded.id ? upgraded : cur));
      }
      if (!cancelled) {
        setSnapshots(latestList);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-run on initial visit if URL specifies deep-link params or if localStorage has no snapshots yet
  useEffect(() => {
    if (didBootRef.current) return;
    didBootRef.current = true;
    if (isOffline && snapshots.length > 0) return;
    if (untrustedDohPending) return;
    const { deepLink } = initialBootState;
    if (
      (!isOffline &&
        (deepLink.name !== null ||
          deepLink.mode !== null ||
          deepLink.types !== null ||
          deepLink.dkimSelectors !== null ||
          deepLink.dohEndpoint !== null ||
          snapshots.length === 0))
    ) {
      void executeAnalysis(domainInput, selectedTypes, {
        modeOverride: initialBootState.analysisMode,
        dkimSelectorsOverride: initialBootState.customDkimSelectors,
        preserveFocus: Boolean(deepLink.focus),
        pushHistory: false,
      });
    }
  }, [
    domainInput,
    executeAnalysis,
    initialBootState,
    isOffline,
    selectedTypes,
    snapshots.length,
    untrustedDohPending,
  ]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void executeAnalysis(domainInput, selectedTypes, { pushHistory: true });
  };

  const handleSwitchMode = (nextMode: AnalysisMode) => {
    if (nextMode === analysisMode) return;
    setAnalysisMode(nextMode);
    const matchingSaved = snapshots.find(
      (s) =>
        (s.mode ?? 'dnssec') === nextMode &&
        s.displayDomain.toLowerCase() === domainInput.trim().toLowerCase().replace(/\.$/, '') &&
        s.dohEndpoint === settings.dohEndpoint
    );
    if (isOffline) {
      if (matchingSaved) {
        setActiveSnapshot(matchingSaved);
        setActiveTab(
          nextMode === 'mail'
            ? 'mail'
            : nextMode === 'web'
              ? 'web'
              : nextMode === 'consensus'
                ? 'consensus'
                : 'graph'
        );
      }
      return;
    }
    if (!loading && !untrustedDohPending && domainInput.trim().length > 0) {
      void executeAnalysis(domainInput, selectedTypes, {
        modeOverride: nextMode,
        pushHistory: true,
      });
    }
  };

  const handleCopyShareLink = async () => {
    if (!activeSnapshot || typeof window === 'undefined') return;
    const shareUrl = buildShareUrl(window.location.href, {
      name: activeSnapshot.queriedEmail ?? activeSnapshot.displayDomain,
      mode: activeSnapshot.mode,
      types: activeSnapshot.queryTypes,
      dkimSelectors: activeSnapshot.customDkimSelectors,
      dohEndpoint: activeSnapshot.dohEndpoint,
      tab: activeTab,
      focus: focusedGraphTarget,
      showSoaAndNs: settings.showSoaAndNs,
      showStandbyKeys: settings.showStandbyKeys,
    });

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(shareUrl);
      } else {
        const ta = document.createElement('textarea');
        ta.value = shareUrl;
        ta.setAttribute('readonly', 'true');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopiedLink(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopiedLink(false), 2000);
    } catch {
      // Ignore clipboard permission errors
    }
  };

  const toggleQueryType = (t: string) => {
    setSelectedTypes((prev) => {
      if (prev.includes(t)) {
        return prev.length > 1 ? prev.filter((x) => x !== t) : prev;
      }
      return [...prev, t];
    });
  };

  const handleUpdateSettings = async (next: UserSettings) => {
    setSettings(next);
    saveUserSettings(next);
    if (activeSnapshot && next.trustAnchors !== settings.trustAnchors) {
      const reverified = await reverifySnapshot(activeSnapshot, {
        trustAnchors: next.trustAnchors,
      });
      setActiveSnapshot(reverified);
      setSnapshots(saveSnapshot(reverified));
    }
  };

  const handleReverifyAtTime = async (timestampMs: number) => {
    if (!activeSnapshot) return;
    const reverified = await reverifySnapshot(activeSnapshot, {
      validationTimeMs: timestampMs,
      trustAnchors: settings.trustAnchors,
    });
    setActiveSnapshot(reverified);
    setSettingsOpen(false);
  };

  const issueCount = activeSnapshot
    ? activeSnapshot.findings.filter((f) => f.severity === 'error' || f.severity === 'warning')
        .length
    : 0;

  if (activeSnapshot) {
    seedIpAsnCacheFromSnapshot(activeSnapshot);
    seedPublicSuffixCacheFromLogs(activeSnapshot.queries);
  }

  const searchSuffixParts = splitDomainByPublicSuffix(domainInput);

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* Top Header Bar — sticky on tablet/desktop; scrolls naturally on narrow mobile screens so the graph gets 100% viewport height */}
      <header className="border-b border-slate-200 dark:border-slate-800/90 bg-white/90 dark:bg-slate-950/90 backdrop-blur md:sticky md:top-0 z-30">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-500 flex items-center justify-center shadow-sm shadow-cyan-500/20">
              <Network className="w-5 h-5 text-slate-950 stroke-[2.3]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight">DigDeep</span>
                <span className="rounded-md bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 px-1.5 py-0.5 font-mono text-[10px] font-semibold">
                  {formatDohShortLabel(settings.dohEndpoint)} DoH
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:block">
                Client-Side DNSSEC, MX, DANE, SPF, DKIM &amp; DMARC Analyzer &amp; DoH Wire Inspector
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {isOffline && (
              <span
                className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-xs font-medium text-amber-700 dark:text-amber-300"
                title="Offline mode — browse, inspect, diff, and re-verify saved snapshots locally"
              >
                <WifiOff className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Offline · Local History</span>
              </span>
            )}

            {canInstall && (
              <button
                type="button"
                onClick={() => void promptInstall()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300 transition-colors cursor-pointer"
                title="Install DigDeep as a standalone Progressive Web App"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Install App</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => setActiveTab('history')}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
              title="Browse snapshots stored in browser localStorage"
            >
              <Clock className="w-3.5 h-3.5 text-cyan-500" />
              <span>History</span>
              <span className="rounded-full bg-slate-200 dark:bg-slate-800 px-1.5 py-0.2 font-mono text-[10px]">
                {snapshots.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 transition-colors cursor-pointer"
              title="Trust Anchors, Time-Travel Validation & DoH Endpoint"
            >
              <Settings className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
              <span className="hidden md:inline">Trust Anchors &amp; Clock</span>
            </button>

            <button
              type="button"
              onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
              className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-cyan-500 transition-colors cursor-pointer"
              aria-label="Toggle color theme"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Domain Query & RR Type Bar */}
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 pb-3.5 space-y-2.5">
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2">
            <div ref={examplesContainerRef} className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none z-20" />
              {searchSuffixParts && (
                <div
                  ref={inputOverlayRef}
                  aria-hidden="true"
                  data-testid="search-psl-overlay"
                  className="pointer-events-none absolute inset-0 flex items-center rounded-xl border border-transparent pl-10 pr-16 py-2.5 font-mono text-sm whitespace-pre overflow-hidden select-none z-10"
                >
                  <span className="text-slate-900 dark:text-slate-100">
                    {searchSuffixParts.leadingWhitespace}
                    {searchSuffixParts.prefix}
                  </span>
                  <span
                    data-testid="search-public-suffix"
                    title={`Public Suffix (${searchSuffixParts.publicSuffix})`}
                    className="text-cyan-600 dark:text-cyan-400"
                  >
                    {searchSuffixParts.publicSuffix}
                  </span>
                  <span className="text-slate-900 dark:text-slate-100">
                    {searchSuffixParts.trailingDotAndWhitespace}
                  </span>
                </div>
              )}
              <input
                ref={inputRef}
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onScroll={(e) => {
                  if (inputOverlayRef.current) {
                    inputOverlayRef.current.scrollLeft = e.currentTarget.scrollLeft;
                  }
                }}
                placeholder="Enter domain, email, or IPv4/IPv6 (e.g. digdeep.butter.eu, paul@nohats.ca, 1.1.1.1, .) — press / to focus"
                className={`w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 pl-10 pr-16 py-2.5 font-mono text-sm placeholder:font-sans placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 ${
                  searchSuffixParts
                    ? 'text-transparent caret-slate-900 dark:caret-slate-100 selection:bg-cyan-500/25 selection:text-transparent'
                    : 'text-slate-900 dark:text-slate-100'
                }`}
              />
              <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1 z-20">
                <kbd
                  title="Press / to focus search"
                  className="hidden sm:inline-block rounded border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 select-none"
                >
                  /
                </kbd>
                <button
                  type="button"
                  onClick={() => setExamplesOpen((v) => !v)}
                  aria-label="Example DNS traces"
                  aria-expanded={examplesOpen}
                  title="Example DNS & IP traces"
                  className={`inline-flex items-center justify-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold transition-colors cursor-pointer ${
                    examplesOpen
                      ? 'border-cyan-500 bg-cyan-500/15 text-cyan-600 dark:text-cyan-300'
                      : 'border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-cyan-300'
                  }`}
                >
                  ?
                </button>
              </div>

              {examplesOpen && (
                <div
                  role="dialog"
                  aria-label="Example DNS traces"
                  className="absolute left-0 right-0 top-full mt-1.5 z-50 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl p-3 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2 pb-1 border-b border-slate-100 dark:border-slate-800">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      Example DNS &amp; IP Traces
                    </span>
                    <span className="text-[10px] text-slate-400">Click any example to run</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {EXAMPLE_TRACES.map((ex) => {
                      const exMode: AnalysisMode = ex.mode ?? 'dnssec';
                      const href =
                        exMode === 'mail'
                          ? `?name=${encodeURIComponent(ex.domain)}&mode=mail`
                          : exMode === 'web'
                            ? `?name=${encodeURIComponent(ex.domain)}&mode=web`
                            : exMode === 'consensus'
                              ? `?name=${encodeURIComponent(ex.domain)}&mode=consensus`
                              : `?name=${encodeURIComponent(ex.domain)}&types=${ex.types.join(',')}`;
                      return (
                        <a
                          key={`${ex.domain}-${exMode}-${ex.badge}`}
                          href={href}
                          onClick={(e) => {
                            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0)
                              return;
                            e.preventDefault();
                            setExamplesOpen(false);
                            setAnalysisMode(exMode);
                            setDomainInput(ex.domain);
                            if (exMode === 'dnssec') {
                              setSelectedTypes(ex.types);
                            }
                            void executeAnalysis(ex.domain, ex.types, {
                              modeOverride: exMode,
                              pushHistory: true,
                            });
                          }}
                          className="group flex items-start justify-between gap-2 rounded-lg border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 hover:border-cyan-500/60 hover:bg-cyan-500/5 px-2.5 py-2 transition-colors"
                        >
                          <div className="min-w-0">
                            <div className="font-mono text-xs font-semibold text-cyan-700 dark:text-cyan-300 group-hover:underline truncate">
                              {ex.domain}
                            </div>
                            <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                              {ex.description}
                            </div>
                          </div>
                          <span className="shrink-0 rounded bg-slate-200/80 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-600 dark:text-slate-300">
                            {ex.badge}
                          </span>
                        </a>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            <DohChooser
              settings={settings}
              onSaveSettings={(next) => void handleUpdateSettings(next)}
            />

            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-60 px-5 py-2.5 font-semibold text-sm text-slate-950 shadow-sm shadow-cyan-500/20 transition-all cursor-pointer shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Tracing ({progress?.completedQueries ?? 0} queries)…</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>
                    {ANALYSIS_MODES.find((m) => m.id === analysisMode)?.actionLabel ??
                      'Analyze DNSSEC'}
                  </span>
                </>
              )}
            </button>
          </form>

          {/* Analysis Mode Selector + Contextual Controls */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2 text-xs">
            <div
              role="tablist"
              aria-label="DNS Analysis Mode"
              className="grid grid-cols-4 sm:inline-flex sm:flex-wrap items-center gap-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-100/90 dark:bg-slate-900/90 p-1 w-full sm:w-auto max-w-full self-start"
            >
              {ANALYSIS_MODES.map((m) => {
                const active = analysisMode === m.id;
                const ModeIcon =
                  m.id === 'mail'
                    ? Mail
                    : m.id === 'web'
                      ? Globe
                      : m.id === 'consensus'
                        ? Radio
                        : Network;
                return (
                  <button
                    key={m.id}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => handleSwitchMode(m.id)}
                    title={m.description}
                    className={`inline-flex items-center justify-center gap-1 sm:gap-1.5 rounded-lg px-2 sm:px-2.5 py-1.5 sm:py-1 text-[11px] sm:text-xs font-medium whitespace-nowrap transition-colors cursor-pointer ${
                      active
                        ? 'bg-white dark:bg-slate-800 text-cyan-700 dark:text-cyan-300 font-semibold shadow-sm border border-slate-200/80 dark:border-slate-700'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    <ModeIcon className="w-3.5 h-3.5 shrink-0" />
                    <span className="xl:hidden">{m.mobileLabel}</span>
                    <span className="hidden xl:inline">{m.label}</span>
                  </button>
                );
              })}
            </div>

            {analysisMode === 'dnssec' ? (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-[11px] font-medium text-slate-500 mr-1">RR Types:</span>
                {PRIMARY_TYPES.map((t) => {
                  const active = selectedTypes.includes(t);
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() => toggleQueryType(t)}
                      className={`px-2 py-0.5 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                        active
                          ? 'bg-cyan-500 text-slate-950 font-bold'
                          : 'bg-slate-200/70 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:bg-slate-300/70 dark:hover:bg-slate-800'
                      }`}
                    >
                      {t}
                    </button>
                  );
                })}
                {showExtraTypes &&
                  EXTRA_TYPES.map((t) => {
                    const active = selectedTypes.includes(t);
                    return (
                      <button
                        key={t}
                        type="button"
                        onClick={() => toggleQueryType(t)}
                        className={`px-2 py-0.5 rounded-md font-mono text-[11px] transition-colors cursor-pointer ${
                          active
                            ? 'bg-cyan-500 text-slate-950 font-bold'
                            : 'bg-slate-200/70 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:bg-slate-300/70 dark:hover:bg-slate-800'
                        }`}
                      >
                        {t}
                      </button>
                    );
                  })}
                <button
                  type="button"
                  onClick={() => setShowExtraTypes((v) => !v)}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] text-slate-500 hover:text-cyan-500 cursor-pointer"
                >
                  <SlidersHorizontal className="w-3 h-3" />
                  {showExtraTypes ? 'Less' : 'More'}
                </button>
              </div>
            ) : analysisMode === 'mail' ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                <span className="font-medium">Checks:</span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  MX + A/AAAA
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  _25._tcp DANE TLSA
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  SPF v=spf1
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  DKIM _domainkey
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  DMARC _dmarc
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  WebCrypto DNSSEC
                </span>
              </div>
            ) : analysisMode === 'web' ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                <span className="font-medium">Checks:</span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  HTTPS / SVCB (RFC 9460)
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  TLS ECHConfigList
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  ipv4hint / ipv6hint Drift
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  Tree-Walking CAA (RFC 8659/8657)
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  _443._tcp DANE &amp; SSHFP
                </span>
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                <span className="font-medium">Probes:</span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  8 Public DoH Resolvers
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  RFC 8914 EDE Codes
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  Protective Threat / Family Block
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  SOA Serial &amp; Key-Tag Skew
                </span>
                <span className="rounded-md bg-slate-200/70 dark:bg-slate-900 px-2 py-0.5 font-mono">
                  RFC 7871 ECS GeoDNS &amp; SCOPE
                </span>
              </div>
            )}
          </div>

          {(() => {
            const liveIp = parseReverseIpInput(domainInput);
            if (!liveIp) return null;
            return (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-semibold text-cyan-800 dark:text-cyan-200">
                    IPv{liveIp.family} Reverse DNS Detected:
                  </span>
                  <code className="font-mono font-bold text-slate-900 dark:text-slate-100">
                    <IpHoverBadge ip={liveIp.ip} />
                  </code>
                  <span className="text-slate-400">→</span>
                  <code className="font-mono text-cyan-700 dark:text-cyan-300 break-all">
                    {liveIp.displayArpa}
                  </code>
                </div>
                <span className="font-mono text-[11px] text-cyan-700 dark:text-cyan-300">
                  PTR · .arpa DNSSEC Chain · FCrDNS · BGP ASN
                </span>
              </div>
            );
          })()}
        </div>
      </header>

      {/* Live Progress / Error Banner */}
      <main className="max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-4 flex-1 space-y-4">
        {untrustedDohPending && !loading && (
          <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs text-amber-800 dark:text-amber-200">
            <span>
              Shared link specifies custom DoH endpoint{' '}
              <code className="font-mono font-semibold">{untrustedDohPending}</code>. Confirm to
              send DNS queries to this resolver.
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  void executeAnalysis(domainInput, selectedTypes, {
                    dohEndpointOverride: untrustedDohPending,
                    preserveFocus: Boolean(focusedGraphTarget),
                  })
                }
                className="rounded-lg bg-amber-500 hover:bg-amber-400 px-3 py-1 font-semibold text-slate-950 cursor-pointer"
              >
                Use &amp; Run Trace
              </button>
            </div>
          </div>
        )}

        {loading && progress && (
          <div className="rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-4 py-3 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <Activity className="w-4 h-4 text-cyan-500 animate-pulse shrink-0" />
              <span className="font-medium text-slate-800 dark:text-slate-100">
                {progress.message}
              </span>
            </div>
            <span className="font-mono text-cyan-700 dark:text-cyan-300 shrink-0">
              {progress.completedQueries} DoH wire packets
            </span>
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-xs text-rose-700 dark:text-rose-300 flex items-center justify-between">
            <span>{error}</span>
            <button
              type="button"
              onClick={() => void executeAnalysis(domainInput, selectedTypes)}
              className="underline font-semibold cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {activeSnapshot && (
          <>
            {/* Snapshot Summary Banner + Segmented View Tabs */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-3.5 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3 min-w-0">
                <StatusBadge status={activeSnapshot.overallStatus} size="md" />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    {activeSnapshot.queriedIp && (
                      <>
                        <span className="font-mono font-bold text-base text-cyan-700 dark:text-cyan-300">
                          <IpHoverBadge ip={activeSnapshot.queriedIp} />
                        </span>
                        <span className="text-slate-400">→</span>
                      </>
                    )}
                    {activeSnapshot.queriedEmail && (
                      <>
                        <span className="font-mono font-bold text-base text-cyan-700 dark:text-cyan-300 break-all">
                          {activeSnapshot.queriedEmail}
                        </span>
                        <span className="text-slate-400">→</span>
                      </>
                    )}
                    <span className="font-mono font-bold text-base text-slate-900 dark:text-slate-100 break-all">
                      {activeSnapshot.displayDomain}
                    </span>
                    {activeSnapshot.mode === 'mail' ? (
                      <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[11px] font-semibold">
                        MAIL · MX · DANE · SPF · DKIM · DMARC
                      </span>
                    ) : activeSnapshot.mode === 'web' ? (
                      <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[11px] font-semibold">
                        WEB · HTTPS/SVCB · ECH · CAA · DANE
                      </span>
                    ) : activeSnapshot.mode === 'consensus' ? (
                      <span className="rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 px-2 py-0.5 font-mono text-[11px] font-semibold">
                        MULTI-DOH · RFC 7871 ECS · RFC 8914 EDE · SKEW
                      </span>
                    ) : (
                      <span className="font-mono text-xs text-slate-500">
                        [{activeSnapshot.queryTypes.join(', ')}]
                      </span>
                    )}
                    {activeSnapshot.resolverVerdict && (
                      <span className="rounded bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                        {formatDohShortLabel(activeSnapshot.dohEndpoint)}:{' '}
                        {activeSnapshot.resolverVerdict.rcodeName} · AD=
                        {activeSnapshot.resolverVerdict.adBit ? '1' : '0'}
                      </span>
                    )}
                    {activeSnapshot.validatedAt !== activeSnapshot.capturedAt && (
                      <span className="rounded bg-amber-500/15 text-amber-600 dark:text-amber-300 px-2 py-0.5 font-mono text-[11px]">
                        Clock Override: {new Date(activeSnapshot.validatedAt).toISOString().slice(0, 16)}Z
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 truncate mt-0.5">
                    {activeSnapshot.overallSummary}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 justify-between xl:justify-end">
                <div className="text-[11px] font-mono text-slate-400 pr-2">
                  { new Date(activeSnapshot.capturedAt).toLocaleString() } ·{' '}
                  {activeSnapshot.queries.length} queries ({activeSnapshot.durationMs}ms)
                </div>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => void handleCopyShareLink()}
                    className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer ${
                      copiedLink
                        ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                        : 'border-slate-200 dark:border-slate-700 hover:border-cyan-500 text-slate-700 dark:text-slate-200'
                    }`}
                    title="Copy deep link including domain, RR types, DoH resolver, active tab, and selected graph node"
                  >
                    {copiedLink ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Link2 className="w-3.5 h-3.5 text-cyan-500" />
                        <span>Copy Link</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    disabled={loading}
                    onClick={() =>
                      void executeAnalysis(
                        activeSnapshot.queriedEmail ?? activeSnapshot.displayDomain,
                        activeSnapshot.queryTypes,
                        {
                          modeOverride: activeSnapshot.mode ?? 'dnssec',
                        }
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                    title={`Run a fresh live ${formatDohShortLabel(settings.dohEndpoint)} DoH trace and save a new snapshot`}
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    Re-probe
                  </button>
                </div>
              </div>
            </div>

            {activeSnapshot.reverseDns && (
              <ReverseDnsCard
                reverseDns={activeSnapshot.reverseDns}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
                onTraceHostname={(hostname) => {
                  setAnalysisMode('dnssec');
                  setDomainInput(hostname);
                  setSelectedTypes(['A', 'AAAA']);
                  void executeAnalysis(hostname, ['A', 'AAAA'], {
                    modeOverride: 'dnssec',
                    pushHistory: true,
                  });
                }}
              />
            )}

            {activeSnapshot.emailDane && (
              <EmailDaneCard
                emailDane={activeSnapshot.emailDane}
                currentMode={activeSnapshot.mode ?? 'dnssec'}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
                onInspectDomainMail={(emailOrDomain) => {
                  setAnalysisMode('mail');
                  setDomainInput(emailOrDomain);
                  void executeAnalysis(emailOrDomain, ['MX', 'TXT'], {
                    modeOverride: 'mail',
                    pushHistory: true,
                  });
                }}
              />
            )}

            {/* Navigation Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto border-b border-slate-200 dark:border-slate-800 pb-2">
              {(
                [
                  ...(activeSnapshot.mode === 'mail'
                    ? [
                        {
                          id: 'mail' as const,
                          label: 'Mail, DANE, SPF, DKIM & DMARC',
                          icon: Mail,
                        },
                      ]
                    : []),
                  ...(activeSnapshot.mode === 'web'
                    ? [
                        {
                          id: 'web' as const,
                          label: 'Web, HTTPS/SVCB, ECH, CAA & DANE',
                          icon: Globe,
                        },
                      ]
                    : []),
                  ...(activeSnapshot.mode === 'consensus'
                    ? [
                        {
                          id: 'consensus' as const,
                          label: 'Multi-Resolver DoH Consensus & EDE',
                          icon: Radio,
                        },
                      ]
                    : []),
                  { id: 'graph' as const, label: 'DNSSEC Chain Graph', icon: Network },
                  {
                    id: 'audit' as const,
                    label: 'Audit & RFC Checks',
                    icon: issueCount > 0 ? AlertTriangle : ShieldCheck,
                    badge: issueCount,
                  },
                  {
                    id: 'responses' as const,
                    label: 'DoH Wire Responses',
                    icon: Terminal,
                    badge: activeSnapshot.queries.length,
                  },
                  {
                    id: 'zones' as const,
                    label: 'Zones & Nameservers',
                    icon: Globe,
                    badge: activeSnapshot.zones.length,
                  },
                  {
                    id: 'history' as const,
                    label: 'Local History & Diff',
                    icon: Clock,
                    badge: snapshots.length,
                  },
                ]
              ).map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`inline-flex items-center gap-2 shrink-0 whitespace-nowrap px-3 sm:px-3.5 py-2 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                      active
                        ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-200/70 dark:hover:bg-slate-900'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                    {'badge' in tab && tab.badge !== undefined && (
                      <span
                        className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] ${
                          active
                            ? 'bg-slate-950/20 text-slate-950'
                            : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Active View Content */}
            {activeTab === 'mail' && activeSnapshot.mode === 'mail' && (
              <MailAnalysisView
                key={activeSnapshot.id}
                snapshot={activeSnapshot}
                loading={loading}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
                onOpenChainGraph={() => setActiveTab('graph')}
                onProbeDkimSelectors={(rawSelectors) => {
                  const parsedSels = parseDkimSelectorInput(
                    rawSelectors,
                    activeSnapshot.displayDomain
                  );
                  setCustomDkimSelectors(parsedSels);
                  void executeAnalysis(activeSnapshot.displayDomain, activeSnapshot.queryTypes, {
                    modeOverride: 'mail',
                    dkimSelectorsOverride: parsedSels,
                    pushHistory: true,
                  });
                }}
              />
            )}

            {activeTab === 'web' && activeSnapshot.mode === 'web' && (
              <WebAnalysisView
                key={activeSnapshot.id}
                snapshot={activeSnapshot}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
                onOpenChainGraph={() => setActiveTab('graph')}
                onTraceDomain={(domain) => {
                  setAnalysisMode('web');
                  setDomainInput(domain);
                  void executeAnalysis(domain, activeSnapshot.queryTypes, {
                    modeOverride: 'web',
                    pushHistory: true,
                  });
                }}
              />
            )}

            {activeTab === 'consensus' && activeSnapshot.mode === 'consensus' && (
              <ConsensusView
                key={activeSnapshot.id}
                snapshot={activeSnapshot}
                onOpenChainGraph={() => setActiveTab('graph')}
                onOpenWireResponses={() => setActiveTab('responses')}
              />
            )}

            {(activeTab === 'graph' ||
              (activeTab === 'mail' && activeSnapshot.mode !== 'mail') ||
              (activeTab === 'web' && activeSnapshot.mode !== 'web') ||
              (activeTab === 'consensus' && activeSnapshot.mode !== 'consensus')) && (
              <ChainGraphView
                snapshot={activeSnapshot}
                theme={theme}
                filters={{
                  showSoaAndNs: settings.showSoaAndNs,
                  showStandbyKeys: settings.showStandbyKeys,
                }}
                onChangeFilters={(f) =>
                  void handleUpdateSettings({
                    ...settings,
                    showSoaAndNs: f.showSoaAndNs,
                    showStandbyKeys: f.showStandbyKeys,
                  })
                }
                focusedTargetId={focusedGraphTarget}
                onSelectTargetId={setFocusedGraphTarget}
              />
            )}

            {activeTab === 'audit' && (
              <AuditPanel
                snapshot={activeSnapshot}
                onJumpToGraphTarget={(targetId) => {
                  setFocusedGraphTarget(targetId);
                  setActiveTab('graph');
                }}
              />
            )}

            {activeTab === 'responses' && <ResponsesPanel snapshot={activeSnapshot} />}

            {activeTab === 'zones' && <ZonesPanel snapshot={activeSnapshot} />}

            {activeTab === 'history' && (
              <HistoryPanel
                snapshots={snapshots}
                activeSnapshotId={activeSnapshot.id}
                onSelectSnapshot={(snap) => {
                  const snapMode: AnalysisMode = snap.mode ?? 'dnssec';
                  setFocusedGraphTarget(null);
                  setActiveSnapshot(snap);
                  setAnalysisMode(snapMode);
                  setDomainInput(snap.queriedEmail ?? snap.displayDomain);
                  setCustomDkimSelectors(snap.customDkimSelectors ?? []);
                  if (snapMode === 'dnssec') {
                    setSelectedTypes(snap.queryTypes);
                  }
                  setActiveTab(
                    snapMode === 'mail'
                      ? 'mail'
                      : snapMode === 'web'
                        ? 'web'
                        : snapMode === 'consensus'
                          ? 'consensus'
                          : 'graph'
                  );
                }}
                onReprobe={(dom, types, mode) => {
                  const nextMode: AnalysisMode = mode ?? 'dnssec';
                  setAnalysisMode(nextMode);
                  setDomainInput(dom);
                  if (nextMode === 'dnssec') {
                    setSelectedTypes(types);
                  }
                  void executeAnalysis(dom, types, { modeOverride: nextMode, pushHistory: true });
                }}
                onTogglePin={(id, pinned) => {
                  const next = updateSnapshotMeta(id, { pinned });
                  setSnapshots(next);
                  if (activeSnapshot.id === id) {
                    setActiveSnapshot({ ...activeSnapshot, pinned });
                  }
                }}
                onDelete={(id) => {
                  const next = deleteSnapshot(id);
                  setSnapshots(next);
                  if (activeSnapshot.id === id) {
                    setActiveSnapshot(next[0] ?? null);
                  }
                }}
                onClearUnpinned={() => {
                  const next = clearUnpinnedSnapshots();
                  setSnapshots(next);
                  if (!next.some((s) => s.id === activeSnapshot.id)) {
                    setActiveSnapshot(next[0] ?? null);
                  }
                }}
                onImportJson={(txt) => {
                  const next = importSnapshotsFromJson(txt);
                  setSnapshots(next);
                  if (next[0]) setActiveSnapshot(next[0]);
                }}
              />
            )}
          </>
        )}

        {!activeSnapshot && !loading && (
          <HistoryPanel
            snapshots={snapshots}
            onSelectSnapshot={(snap) => {
              const snapMode: AnalysisMode = snap.mode ?? 'dnssec';
              setFocusedGraphTarget(null);
              setAnalysisMode(snapMode);
              setActiveSnapshot(snap);
              setActiveTab(
                snapMode === 'mail'
                  ? 'mail'
                  : snapMode === 'web'
                    ? 'web'
                    : snapMode === 'consensus'
                      ? 'consensus'
                      : 'graph'
              );
            }}
            onReprobe={(dom, types, mode) => {
              const nextMode: AnalysisMode = mode ?? 'dnssec';
              setAnalysisMode(nextMode);
              setDomainInput(dom);
              if (nextMode === 'dnssec') {
                setSelectedTypes(types);
              }
              void executeAnalysis(dom, types, { modeOverride: nextMode, pushHistory: true });
            }}
            onTogglePin={(id, pinned) => setSnapshots(updateSnapshotMeta(id, { pinned }))}
            onDelete={(id) => setSnapshots(deleteSnapshot(id))}
            onClearUnpinned={() => setSnapshots(clearUnpinnedSnapshots())}
            onImportJson={(txt) => {
              const next = importSnapshotsFromJson(txt);
              setSnapshots(next);
              if (next[0]) setActiveSnapshot(next[0]);
            }}
          />
        )}
      </main>

      <footer className="border-t border-slate-200/80 dark:border-slate-800/80 bg-white/60 dark:bg-slate-950/60">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              <span className="font-semibold text-slate-700 dark:text-slate-300">DigDeep</span> ·
              100% client-side DNSSEC, MX, SMTP DANE, SPF, DKIM &amp; DMARC analyzer verified
              in-browser via WebCrypto &amp; RFC 8484 DoH.
            </span>
            <span className="text-slate-300 dark:text-slate-700">·</span>
            <a
              href="https://github.com/tbutter/digdeep"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="DigDeep on GitHub"
              className="inline-flex items-center gap-1 font-medium text-slate-600 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
            >
              <svg
                viewBox="0 0 16 16"
                aria-hidden="true"
                className="w-3.5 h-3.5 fill-current"
              >
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
              </svg>
              <span>GitHub</span>
            </a>
          </div>
        </div>
      </footer>

      <SettingsModal
        open={settingsOpen}
        settings={settings}
        activeSnapshot={activeSnapshot}
        onClose={() => setSettingsOpen(false)}
        onSaveSettings={(next) => void handleUpdateSettings(next)}
        onReverifyAtTime={(ts) => void handleReverifyAtTime(ts)}
      />
    </div>
  );
}
