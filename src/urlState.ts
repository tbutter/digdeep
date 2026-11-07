import {
  DEFAULT_DOH_ENDPOINT,
  DOH_SERVER_PRESETS,
  normalizeDohEndpoint,
} from './dns/constants';
import type { AnalysisMode } from './dns/types';

export type ActiveTab = 'mail' | 'web' | 'graph' | 'audit' | 'responses' | 'zones' | 'history';

const VALID_TABS: readonly ActiveTab[] = [
  'mail',
  'web',
  'graph',
  'audit',
  'responses',
  'zones',
  'history',
];
const VALID_MODES: readonly AnalysisMode[] = ['dnssec', 'mail', 'web'];

export interface DeepLinkState {
  name: string;
  mode?: AnalysisMode;
  types: string[];
  dkimSelectors?: string[];
  dohEndpoint: string;
  tab: ActiveTab;
  focus?: string | null;
  showSoaAndNs?: boolean;
  showStandbyKeys?: boolean;
}

export interface ParsedDeepLink {
  hasDeepLink: boolean;
  name: string | null;
  mode: AnalysisMode | null;
  types: string[] | null;
  dkimSelectors: string[] | null;
  dohEndpoint: string | null;
  isUntrustedCustomDoh: boolean;
  tab: ActiveTab | null;
  focus: string | null;
  showSoaAndNs: boolean | null;
  showStandbyKeys: boolean | null;
}

function isPrivateOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host === '0.0.0.0' ||
    host === '::1' ||
    host.startsWith('fe80:') ||
    host.startsWith('fc') ||
    host.startsWith('fd')
  ) {
    return true;
  }
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4Match) {
    const [, aStr, bStr] = ipv4Match;
    const a = Number(aStr);
    const b = Number(bStr);
    if (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Formats a DoH endpoint URL into a compact preset label (e.g. "1.1.1.1" or "9.9.9.9")
 * when it matches a built-in preset, or returns the full URL for custom resolvers.
 */
export function formatDohParam(endpointUrl: string): string {
  const preset = DOH_SERVER_PRESETS.find((p) => p.url === endpointUrl);
  return preset ? preset.shortLabel : endpointUrl;
}

/**
 * Resolves a `?doh=` query parameter into a canonical DoH endpoint URL.
 * Built-in presets and user-saved custom endpoints are trusted immediately;
 * unknown external HTTPS endpoints are flagged as `isUntrustedCustomDoh: true`
 * so the UI can avoid auto-querying arbitrary third-party hosts without user confirmation.
 */
export function resolveDohParam(
  rawParam: string | null,
  savedCustomEndpoints: string[] = []
): { dohEndpoint: string | null; isUntrustedCustomDoh: boolean } {
  if (!rawParam) return { dohEndpoint: null, isUntrustedCustomDoh: false };
  const trimmed = rawParam.trim();
  if (!trimmed) return { dohEndpoint: null, isUntrustedCustomDoh: false };

  const lower = trimmed.toLowerCase();
  const presetMatch = DOH_SERVER_PRESETS.find(
    (p) => p.shortLabel.toLowerCase() === lower || p.url.toLowerCase() === lower
  );
  if (presetMatch) {
    return { dohEndpoint: presetMatch.url, isUntrustedCustomDoh: false };
  }

  const normalized = normalizeDohEndpoint(trimmed);
  if (!normalized) return { dohEndpoint: null, isUntrustedCustomDoh: false };

  const normalizedMatch = DOH_SERVER_PRESETS.find((p) => p.url === normalized);
  if (normalizedMatch) {
    return { dohEndpoint: normalizedMatch.url, isUntrustedCustomDoh: false };
  }

  if (savedCustomEndpoints.includes(normalized)) {
    return { dohEndpoint: normalized, isUntrustedCustomDoh: false };
  }

  try {
    const u = new URL(normalized);
    if (u.protocol !== 'https:' || isPrivateOrLocalHost(u.hostname)) {
      return { dohEndpoint: null, isUntrustedCustomDoh: false };
    }
    return { dohEndpoint: normalized, isUntrustedCustomDoh: true };
  } catch {
    return { dohEndpoint: null, isUntrustedCustomDoh: false };
  }
}

export function parseDeepLinkParams(
  search: string,
  savedCustomEndpoints: string[] = []
): ParsedDeepLink {
  const params = new URLSearchParams(search);

  const rawName = params.get('name');
  const name = rawName !== null && rawName.trim().length > 0 ? rawName.trim() : null;

  const rawMode = params.get('mode')?.trim().toLowerCase() ?? null;
  let mode: AnalysisMode | null =
    rawMode && (VALID_MODES as readonly string[]).includes(rawMode)
      ? (rawMode as AnalysisMode)
      : null;

  const rawTypes = params.get('types');
  let types: string[] | null = null;
  if (rawTypes) {
    const parsed = Array.from(
      new Set(
        rawTypes
          .split(',')
          .map((s) => s.trim().toUpperCase())
          .filter((s) => /^[A-Z0-9]+$/.test(s))
      )
    );
    if (parsed.length > 0) {
      types = parsed;
    }
  }

  const rawDkim = params.get('dkim');
  let dkimSelectors: string[] | null = null;
  if (rawDkim) {
    const parsedSels = Array.from(
      new Set(
        rawDkim
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter((s) => s.length > 0 && s.length <= 120 && /^[a-z0-9._-]+$/.test(s))
      )
    ).slice(0, 12);
    if (parsedSels.length > 0) {
      dkimSelectors = parsedSels;
      if (mode === null) {
        mode = 'mail';
      }
    }
  }

  const { dohEndpoint, isUntrustedCustomDoh } = resolveDohParam(
    params.get('doh'),
    savedCustomEndpoints
  );

  const rawTab = params.get('tab')?.trim().toLowerCase() ?? null;
  const tab =
    rawTab && (VALID_TABS as readonly string[]).includes(rawTab)
      ? (rawTab as ActiveTab)
      : null;

  if (mode === null && tab === 'mail') {
    mode = 'mail';
  } else if (mode === null && tab === 'web') {
    mode = 'web';
  }

  const rawFocus = params.get('focus');
  const focus = rawFocus && rawFocus.trim().length > 0 ? rawFocus.trim() : null;

  const rawSoa = params.get('soa');
  const showSoaAndNs = rawSoa === '1' || rawSoa === 'true' ? true : rawSoa === '0' || rawSoa === 'false' ? false : null;

  const rawStandby = params.get('standby');
  const showStandbyKeys =
    rawStandby === '0' || rawStandby === 'false'
      ? false
      : rawStandby === '1' || rawStandby === 'true'
        ? true
        : null;

  const hasDeepLink =
    name !== null ||
    mode !== null ||
    types !== null ||
    dkimSelectors !== null ||
    dohEndpoint !== null ||
    tab !== null ||
    focus !== null ||
    showSoaAndNs !== null ||
    showStandbyKeys !== null;

  return {
    hasDeepLink,
    name,
    mode,
    types,
    dkimSelectors,
    dohEndpoint,
    isUntrustedCustomDoh,
    tab,
    focus,
    showSoaAndNs,
    showStandbyKeys,
  };
}

export function buildDeepLinkSearch(
  state: DeepLinkState,
  options?: { includeDefaultDoh?: boolean; forShare?: boolean }
): string {
  const params = new URLSearchParams();
  const cleanName = state.name.trim() || '.';
  const mode: AnalysisMode = state.mode ?? 'dnssec';
  const cleanTypes = state.types.length > 0 ? state.types : ['A'];

  params.set('name', cleanName);
  if (mode === 'mail') {
    params.set('mode', 'mail');
    const cleanSels = (state.dkimSelectors ?? [])
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0 && /^[a-z0-9._-]+$/.test(s));
    if (cleanSels.length > 0) {
      params.set('dkim', Array.from(new Set(cleanSels)).join(','));
    }
  } else if (mode === 'web') {
    params.set('mode', 'web');
  } else {
    params.set('types', cleanTypes.join(','));
  }

  if (options?.includeDefaultDoh || state.dohEndpoint !== DEFAULT_DOH_ENDPOINT) {
    params.set('doh', formatDohParam(state.dohEndpoint));
  }

  const defaultTab: ActiveTab = mode === 'mail' ? 'mail' : mode === 'web' ? 'web' : 'graph';
  // History is stored in browser localStorage, so shared links open on the primary tab instead
  const effectiveTab: ActiveTab =
    options?.forShare && state.tab === 'history' ? defaultTab : state.tab;

  if (effectiveTab !== defaultTab) {
    params.set('tab', effectiveTab);
  }

  if (effectiveTab === 'graph') {
    if (state.focus && state.focus.trim().length > 0) {
      params.set('focus', state.focus.trim());
    }
    if (state.showSoaAndNs) {
      params.set('soa', '1');
    }
    if (state.showStandbyKeys === false) {
      params.set('standby', '0');
    }
  }

  const str = params.toString();
  // Keep comma-separated RR types human-readable in URLs (RFC 3986 sub-delims)
  return str ? `?${str.replace(/%2C/gi, ',')}` : '';
}

export function buildShareUrl(baseHref: string, state: DeepLinkState): string {
  const url = new URL(baseHref);
  url.hash = '';
  url.search = buildDeepLinkSearch(state, { includeDefaultDoh: true, forShare: true });
  return url.toString();
}
