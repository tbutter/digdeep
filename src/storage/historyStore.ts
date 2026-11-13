import {
  DEFAULT_DOH_ENDPOINT,
  IANA_ROOT_TRUST_ANCHORS,
  type TrustAnchor,
} from '../dns/constants';
import type { AnalysisSnapshot, SpfDomainNode, ValidationStatus } from '../dns/types';

const HISTORY_STORAGE_KEY = 'digdeep:history:v1';
const SETTINGS_STORAGE_KEY = 'digdeep:settings:v1';
const THEME_STORAGE_KEY = 'digdeep:theme:v1';
const MAX_DEFAULT_SNAPSHOTS = 60;
const ESTIMATED_LOCALSTORAGE_QUOTA = 5 * 1024 * 1024; // 5 MiB typical browser quota

export interface UserSettings {
  dohEndpoint: string;
  customDohEndpoints: string[];
  trustAnchors: TrustAnchor[];
  showSoaAndNs: boolean;
  showStandbyKeys: boolean;
  layoutDirection: 'TB' | 'LR';
}

export const DEFAULT_USER_SETTINGS: UserSettings = {
  dohEndpoint: DEFAULT_DOH_ENDPOINT,
  customDohEndpoints: [],
  trustAnchors: IANA_ROOT_TRUST_ANCHORS,
  showSoaAndNs: false,
  showStandbyKeys: true,
  layoutDirection: 'TB',
};

export function loadTheme(): 'dark' | 'light' {
  try {
    const val = localStorage.getItem(THEME_STORAGE_KEY);
    if (val === 'light' || val === 'dark') return val;
  } catch {
    // ignore storage errors
  }
  return 'dark';
}

export function saveTheme(theme: 'dark' | 'light'): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // ignore
  }
}

export function loadUserSettings(): UserSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return DEFAULT_USER_SETTINGS;
    const parsed = JSON.parse(raw) as Partial<UserSettings>;
    // Ensure built-in IANA anchors stay up to date while preserving enabled flags and custom anchors
    const savedAnchors = Array.isArray(parsed.trustAnchors) ? parsed.trustAnchors : [];
    const mergedAnchors: TrustAnchor[] = IANA_ROOT_TRUST_ANCHORS.map((builtin) => {
      const match = savedAnchors.find((a) => a.id === builtin.id);
      return match ? { ...builtin, enabled: match.enabled } : builtin;
    });
    for (const custom of savedAnchors) {
      if (!custom.builtin && !mergedAnchors.some((m) => m.id === custom.id)) {
        mergedAnchors.push(custom);
      }
    }
    return {
      dohEndpoint: parsed.dohEndpoint || DEFAULT_DOH_ENDPOINT,
      customDohEndpoints: Array.isArray(parsed.customDohEndpoints)
        ? parsed.customDohEndpoints.filter((u): u is string => typeof u === 'string')
        : [],
      trustAnchors: mergedAnchors,
      showSoaAndNs: Boolean(parsed.showSoaAndNs),
      showStandbyKeys: parsed.showStandbyKeys ?? true,
      layoutDirection: parsed.layoutDirection === 'LR' ? 'LR' : 'TB',
    };
  } catch {
    return DEFAULT_USER_SETTINGS;
  }
}

export function saveUserSettings(settings: UserSettings): void {
  try {
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore
  }
}

function spfNodeHasBogus(node: SpfDomainNode | undefined): boolean {
  if (!node) return false;
  if (node.dnssecStatus === 'bogus') return true;
  return node.terms.some((t) => spfNodeHasBogus(t.childNode));
}

export function normalizeLegacySnapshotStatus(snap: AnalysisSnapshot): AnalysisSnapshot {
  if (snap.overallStatus !== 'bogus') {
    return snap;
  }
  const mode = snap.mode ?? 'dnssec';
  if (mode !== 'mail' && mode !== 'web' && !snap.emailDane) {
    return snap;
  }

  const anyZoneBogus = snap.zones.some(
    (z) =>
      z.status === 'bogus' ||
      z.rrsets.some((r) => r.status === 'bogus') ||
      z.negativeNodes.some((n) => n.status === 'bogus') ||
      z.dnskeys.some((k) => k.status === 'bogus') ||
      z.dsVerifications.some((d) => d.status === 'bogus') ||
      z.zonemd?.dnssecStatus === 'bogus'
  );
  if (anyZoneBogus || snap.consensusAnalysis?.overallVerdict === 'dnssec-bogus') {
    return snap;
  }

  const m = snap.mailAnalysis;
  const anyMailDnssecBogus = Boolean(
    m &&
      (m.mxDnssecStatus === 'bogus' ||
        m.mxHosts.some(
          (h) =>
            h.ipv4Status === 'bogus' ||
            h.ipv6Status === 'bogus' ||
            h.dane.dnssecStatus === 'bogus' ||
            h.addresses.some((a) => a.ptrDnssecStatus === 'bogus')
        ) ||
        spfNodeHasBogus(m.spf.rootNode) ||
        m.dmarc.dnssecStatus === 'bogus' ||
        m.dkim.selectors.some((s) => s.dnssecStatus === 'bogus') ||
        m.mtaSts.dnssecStatus === 'bogus' ||
        m.tlsRpt.dnssecStatus === 'bogus' ||
        m.bimi.dnssecStatus === 'bogus' ||
        (m.srvDiscovery?.services.some((svc) => svc.dnssecStatus === 'bogus') ?? false))
  );
  if (anyMailDnssecBogus) return snap;

  const w = snap.webAnalysis;
  const anyWebDnssecBogus = Boolean(
    w &&
      (w.addressDnssecStatus === 'bogus' ||
        w.httpsDnssecStatus === 'bogus' ||
        w.caa.dnssecStatus === 'bogus' ||
        w.caa.hops.some((h) => h.dnssecStatus === 'bogus') ||
        w.webDane.dnssecStatus === 'bogus' ||
        w.sshfp.dnssecStatus === 'bogus')
  );
  if (anyWebDnssecBogus) return snap;

  const ed = snap.emailDane;
  const anyEmailDnssecBogus = Boolean(
    ed && (ed.openpgpkey?.dnssecStatus === 'bogus' || ed.smimea?.dnssecStatus === 'bogus')
  );
  if (anyEmailDnssecBogus) return snap;

  if (snap.zones.length === 0 && !m && !w && !ed) {
    return snap;
  }

  return {
    ...snap,
    overallStatus: 'policy-error',
  };
}

export function loadSnapshots(): AnalysisSnapshot[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];
    return (list as AnalysisSnapshot[])
      .map(normalizeLegacySnapshotStatus)
      .sort((a, b) => b.capturedAt - a.capturedAt);
  } catch {
    return [];
  }
}

function writeSnapshotsWithEviction(snapshots: AnalysisSnapshot[]): AnalysisSnapshot[] {
  let working = [...snapshots].sort((a, b) => b.capturedAt - a.capturedAt);

  // Enforce soft cap on unpinned snapshots first
  if (working.length > MAX_DEFAULT_SNAPSHOTS) {
    const pinned = working.filter((s) => s.pinned);
    const unpinned = working.filter((s) => !s.pinned);
    const allowedUnpinned = Math.max(5, MAX_DEFAULT_SNAPSHOTS - pinned.length);
    working = [...pinned, ...unpinned.slice(0, allowedUnpinned)].sort(
      (a, b) => b.capturedAt - a.capturedAt
    );
  }

  // Handle QuotaExceededError gracefully by trimming oldest unpinned entries
  for (let attempt = 0; attempt < 15; attempt++) {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(working));
      return working;
    } catch {
      const oldestUnpinnedIdx = working.map((s) => Boolean(s.pinned)).lastIndexOf(false);
      if (oldestUnpinnedIdx !== -1 && working.length > 1) {
        working.splice(oldestUnpinnedIdx, 1);
      } else if (working.length > 1) {
        working.pop();
      } else {
        break;
      }
    }
  }
  return working;
}

export function saveSnapshot(snapshot: AnalysisSnapshot): AnalysisSnapshot[] {
  const current = loadSnapshots().filter((s) => s.id !== snapshot.id);
  return writeSnapshotsWithEviction([snapshot, ...current]);
}

export function updateSnapshotMeta(
  id: string,
  patch: Pick<Partial<AnalysisSnapshot>, 'pinned' | 'note'>
): AnalysisSnapshot[] {
  const current = loadSnapshots().map((s) => (s.id === id ? { ...s, ...patch } : s));
  return writeSnapshotsWithEviction(current);
}

export function deleteSnapshot(id: string): AnalysisSnapshot[] {
  const current = loadSnapshots().filter((s) => s.id !== id);
  return writeSnapshotsWithEviction(current);
}

export function clearUnpinnedSnapshots(): AnalysisSnapshot[] {
  const pinnedOnly = loadSnapshots().filter((s) => s.pinned);
  return writeSnapshotsWithEviction(pinnedOnly);
}

export function saveSnapshotsBatch(batch: AnalysisSnapshot[]): AnalysisSnapshot[] {
  if (batch.length === 0) return loadSnapshots();
  const batchIds = new Set(batch.map((s) => s.id));
  const current = loadSnapshots().filter((s) => !batchIds.has(s.id));
  return writeSnapshotsWithEviction([...batch, ...current]);
}

export function importSnapshotsFromJson(jsonText: string): AnalysisSnapshot[] {
  const parsed = JSON.parse(jsonText);
  const incoming: AnalysisSnapshot[] = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Array.isArray(parsed.snapshots)
      ? parsed.snapshots
      : [parsed];
  const valid = incoming.filter(
    (s) =>
      s &&
      typeof s === 'object' &&
      typeof s.targetName === 'string' &&
      Array.isArray(s.zones) &&
      Array.isArray(s.queries)
  );
  if (valid.length === 0) {
    throw new Error('No valid DigDeep snapshot objects found in JSON file');
  }
  const existing = loadSnapshots();
  const byId = new Map<string, AnalysisSnapshot>();
  for (const s of existing) byId.set(s.id, s);
  for (const s of valid) byId.set(s.id, normalizeLegacySnapshotStatus(s));
  return writeSnapshotsWithEviction(Array.from(byId.values()));
}

export function getStorageStats(): {
  snapshotCount: number;
  usedBytes: number;
  quotaBytes: number;
  percentUsed: number;
} {
  try {
    let chars = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k) continue;
      const v = localStorage.getItem(k) ?? '';
      chars += k.length + v.length;
    }
    const usedBytes = chars * 2; // UTF-16 code units in DOMString storage
    const snapshots = loadSnapshots();
    return {
      snapshotCount: snapshots.length,
      usedBytes,
      quotaBytes: ESTIMATED_LOCALSTORAGE_QUOTA,
      percentUsed: Math.min(100, Math.round((usedBytes / ESTIMATED_LOCALSTORAGE_QUOTA) * 1000) / 10),
    };
  } catch {
    return { snapshotCount: 0, usedBytes: 0, quotaBytes: ESTIMATED_LOCALSTORAGE_QUOTA, percentUsed: 0 };
  }
}

export interface SnapshotDiff {
  older: AnalysisSnapshot;
  newer: AnalysisSnapshot;
  statusChanged: boolean;
  zoneChanges: {
    zoneName: string;
    change: 'added' | 'removed' | 'modified' | 'unchanged';
    oldStatus?: ValidationStatus;
    newStatus?: ValidationStatus;
    oldSerial?: number;
    newSerial?: number;
    addedKeys: number[];
    removedKeys: number[];
    addedDs: number[];
    removedDs: number[];
  }[];
  recordChanges: {
    name: string;
    typeName: string;
    addedRecords: string[];
    removedRecords: string[];
    oldSignerTags: number[];
    newSignerTags: number[];
  }[];
  findingChanges: {
    added: string[];
    resolved: string[];
  };
}

/**
 * Compares two historic snapshots client-side to highlight key rollovers, SOA serial bumps,
 * delegation changes, record edits, and DNSSEC status regressions/fixes.
 */
export function diffSnapshots(a: AnalysisSnapshot, b: AnalysisSnapshot): SnapshotDiff {
  const [older, newer] = a.capturedAt <= b.capturedAt ? [a, b] : [b, a];

  const allZoneNames = Array.from(
    new Set([...older.zones.map((z) => z.zoneName), ...newer.zones.map((z) => z.zoneName)])
  );

  const zoneChanges: SnapshotDiff['zoneChanges'] = allZoneNames.map((zn) => {
    const oz = older.zones.find((z) => z.zoneName === zn);
    const nz = newer.zones.find((z) => z.zoneName === zn);
    if (!oz && nz) {
      return {
        zoneName: zn,
        change: 'added',
        newStatus: nz.status,
        newSerial: nz.soa?.serial,
        addedKeys: nz.dnskeys.filter((k) => k.role !== 'missing').map((k) => k.keyTag),
        removedKeys: [],
        addedDs: nz.dsVerifications.map((d) => d.ds.keyTag),
        removedDs: [],
      };
    }
    if (oz && !nz) {
      return {
        zoneName: zn,
        change: 'removed',
        oldStatus: oz.status,
        oldSerial: oz.soa?.serial,
        addedKeys: [],
        removedKeys: oz.dnskeys.filter((k) => k.role !== 'missing').map((k) => k.keyTag),
        addedDs: [],
        removedDs: oz.dsVerifications.map((d) => d.ds.keyTag),
      };
    }
    const oldKeys = new Set(oz!.dnskeys.filter((k) => k.role !== 'missing').map((k) => k.keyTag));
    const newKeys = new Set(nz!.dnskeys.filter((k) => k.role !== 'missing').map((k) => k.keyTag));
    const addedKeys = Array.from(newKeys).filter((k) => !oldKeys.has(k));
    const removedKeys = Array.from(oldKeys).filter((k) => !newKeys.has(k));

    const oldDs = new Set(oz!.dsVerifications.map((d) => d.ds.keyTag));
    const newDs = new Set(nz!.dsVerifications.map((d) => d.ds.keyTag));
    const addedDs = Array.from(newDs).filter((d) => !oldDs.has(d));
    const removedDs = Array.from(oldDs).filter((d) => !newDs.has(d));

    const modified =
      oz!.status !== nz!.status ||
      oz!.soa?.serial !== nz!.soa?.serial ||
      addedKeys.length > 0 ||
      removedKeys.length > 0 ||
      addedDs.length > 0 ||
      removedDs.length > 0;

    return {
      zoneName: zn,
      change: modified ? 'modified' : 'unchanged',
      oldStatus: oz!.status,
      newStatus: nz!.status,
      oldSerial: oz!.soa?.serial,
      newSerial: nz!.soa?.serial,
      addedKeys,
      removedKeys,
      addedDs,
      removedDs,
    };
  });

  // Compare non-NSEC RRsets
  const collectRrMap = (snap: AnalysisSnapshot) => {
    const m = new Map<string, { name: string; typeName: string; values: Set<string>; signers: number[] }>();
    for (const z of snap.zones) {
      for (const rr of z.rrsets) {
        if (rr.typeName === 'NSEC' || rr.typeName === 'NSEC3' || rr.typeName === 'DNSKEY' || rr.typeName === 'DS') {
          continue;
        }
        const key = `${rr.name}|${rr.typeName}`;
        m.set(key, {
          name: rr.name,
          typeName: rr.typeName,
          values: new Set(rr.records.map((r) => r.rdataText)),
          signers: Array.from(new Set(rr.rrsigs.map((s) => s.signerKeyTag))),
        });
      }
    }
    return m;
  };

  const oldRrs = collectRrMap(older);
  const newRrs = collectRrMap(newer);
  const allRrKeys = Array.from(new Set([...oldRrs.keys(), ...newRrs.keys()]));
  const recordChanges: SnapshotDiff['recordChanges'] = [];

  for (const k of allRrKeys) {
    const o = oldRrs.get(k);
    const n = newRrs.get(k);
    const name = n?.name ?? o!.name;
    const typeName = n?.typeName ?? o!.typeName;
    const oVals = o?.values ?? new Set<string>();
    const nVals = n?.values ?? new Set<string>();
    const addedRecords = Array.from(nVals).filter((v) => !oVals.has(v));
    const removedRecords = Array.from(oVals).filter((v) => !nVals.has(v));
    const oldSignerTags = o?.signers ?? [];
    const newSignerTags = n?.signers ?? [];
    const signersChanged = oldSignerTags.join(',') !== newSignerTags.join(',');

    if (addedRecords.length > 0 || removedRecords.length > 0 || signersChanged) {
      recordChanges.push({
        name,
        typeName,
        addedRecords,
        removedRecords,
        oldSignerTags,
        newSignerTags,
      });
    }
  }

  const oldTitles = new Set(older.findings.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`));
  const newTitles = new Set(newer.findings.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`));

  return {
    older,
    newer,
    statusChanged: older.overallStatus !== newer.overallStatus,
    zoneChanges,
    recordChanges,
    findingChanges: {
      added: Array.from(newTitles).filter((t) => !oldTitles.has(t)),
      resolved: Array.from(oldTitles).filter((t) => !newTitles.has(t)),
    },
  };
}
