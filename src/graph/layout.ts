import { RR_TYPES, formatAlgorithm, formatDigestType } from '../dns/constants';
import { displayFqdn } from '../dns/encoding';
import type {
  AnalysisSnapshot,
  AnalyzedDnskey,
  AnalyzedRrset,
  CnameEdge,
  DsVerification,
  NegativeNode,
  NegativeProofVerification,
  RrsigVerification,
  ValidationStatus,
  ZoneAnalysis,
} from '../dns/types';

export interface GraphFilterOptions {
  showSoaAndNs: boolean;
  showStandbyKeys: boolean;
}

export type GraphNodeKind =
  | 'dnskey'
  | 'rrset'
  | 'ds-group'
  | 'unsigned-delegation'
  | 'negative';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  zone: string;
  x: number;
  y: number;
  width: number;
  height: number;
  title: string;
  subtitle: string;
  meta: string;
  badge: string;
  status: ValidationStatus;
  dashed?: boolean;
  doubleRing?: boolean;
  dnskey?: AnalyzedDnskey;
  rrset?: AnalyzedRrset;
  dsVerifications?: DsVerification[];
  childZone?: string;
  negativeNode?: NegativeNode;
  delegationProof?: NegativeProofVerification;
}

export type GraphEdgeKind = 'rrsig' | 'rrsig-self' | 'ds' | 'insecure-delegation' | 'cname' | 'nsec-proof';

export interface GraphEdge {
  id: string;
  kind: GraphEdgeKind;
  fromId: string;
  toId: string;
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  label: string;
  status: ValidationStatus;
  dashed?: boolean;
  rrsigVerification?: RrsigVerification;
  dsVerification?: DsVerification;
  cnameEdge?: CnameEdge;
  proof?: NegativeProofVerification;
}

export interface GraphZoneBox {
  id: string;
  zone: ZoneAnalysis;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface ComputedGraph {
  width: number;
  height: number;
  zones: GraphZoneBox[];
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const NODE_W = 204;
const KEY_H = 62;
const RR_H = 60;
const NODE_GAP_X = 20;
const TIER_GAP_Y = 46;
const ZONE_PAD_X = 26;
const ZONE_HEADER_H = 46;
const ZONE_PAD_BOTTOM = 24;
const ZONE_GAP_X = 48;
const ZONE_GAP_Y = 76;
const CANVAS_PAD = 48;

interface InternalZoneLayout {
  zone: ZoneAnalysis;
  localWidth: number;
  localHeight: number;
  localNodes: GraphNode[]; // coordinates relative to zone top-left (0, 0)
  subtreeWidth: number;
  children: InternalZoneLayout[];
  absX: number;
  absY: number;
}

function summarizeRrsetPreview(rr: AnalyzedRrset): string {
  if (rr.records.length === 0) return '0 records';
  const first = rr.records[0].rdataText;
  const short = first.length > 26 ? `${first.slice(0, 24)}…` : first;
  return rr.records.length > 1 ? `${short} (+${rr.records.length - 1})` : short;
}

export function buildChainGraph(
  snapshot: AnalysisSnapshot,
  filters: GraphFilterOptions
): ComputedGraph {
  const zonesByName = new Map<string, ZoneAnalysis>();
  for (const z of snapshot.zones) zonesByName.set(z.zoneName, z);

  const childrenMap = new Map<string, ZoneAnalysis[]>();
  const roots: ZoneAnalysis[] = [];

  for (const z of snapshot.zones) {
    if (!z.parentZone || !zonesByName.has(z.parentZone)) {
      roots.push(z);
    } else {
      const list = childrenMap.get(z.parentZone) ?? [];
      list.push(z);
      childrenMap.set(z.parentZone, list);
    }
  }

  // Step 1: Build internal row layout for each zone container
  const buildInternalZone = (zone: ZoneAnalysis): InternalZoneLayout => {
    const childZones = childrenMap.get(zone.zoneName) ?? [];
    const childLayouts = childZones.map(buildInternalZone);

    // Filter keys
    const visibleKeys = zone.dnskeys.filter((k) => {
      if (k.role === 'standby' && !filters.showStandbyKeys) return false;
      return true;
    });

    const entryKeys = visibleKeys.filter(
      (k) =>
        k.role === 'trust-anchor' ||
        k.role === 'ksk' ||
        k.role === 'csk' ||
        k.role === 'missing' ||
        k.role === 'revoked' ||
        (k.role === 'standby' && k.isSep)
    );
    const zskKeys = visibleKeys.filter((k) => !entryKeys.includes(k));

    // Determine visible RRsets inside this zone (excluding DNSKEY which is represented by key nodes, and DS which goes in bottom delegation row)
    const childZoneNames = new Set(childZones.map((c) => c.zoneName));

    // NSEC/NSEC3 RRsets referenced by negative nodes or child insecure delegations
    const referencedProofRrsetIds = new Set<string>();
    for (const neg of zone.negativeNodes) {
      for (const cid of neg.coveringRrsetIds) referencedProofRrsetIds.add(cid);
    }

    const bodyRrsets = zone.rrsets.filter((rr) => {
      if (rr.type === RR_TYPES.DNSKEY && rr.name === zone.zoneName) return false;
      if (rr.type === RR_TYPES.DS && childZoneNames.has(rr.name)) return false;
      if (rr.type === RR_TYPES.NSEC || rr.type === RR_TYPES.NSEC3) {
        return referencedProofRrsetIds.has(rr.id) || rr.isQueryTarget;
      }
      if ((rr.type === RR_TYPES.SOA || rr.type === RR_TYPES.NS) && !rr.isQueryTarget) {
        return filters.showSoaAndNs;
      }
      return true;
    });

    const proofRrsets = bodyRrsets.filter(
      (r) => r.type === RR_TYPES.NSEC || r.type === RR_TYPES.NSEC3
    );
    const dataRrsets = bodyRrsets.filter(
      (r) => r.type !== RR_TYPES.NSEC && r.type !== RR_TYPES.NSEC3
    );

    // Delegation items at bottom of parent zone (one per child zone!)
    const delegationItems: Array<
      | { kind: 'ds'; child: ZoneAnalysis; rrset?: AnalyzedRrset }
      | { kind: 'unsigned'; child: ZoneAnalysis }
    > = childZones.map((cz) => {
      if (cz.dsVerifications.length > 0) {
        const dsRrset = zone.rrsets.find(
          (r) => r.type === RR_TYPES.DS && r.name === cz.zoneName
        );
        return { kind: 'ds', child: cz, rrset: dsRrset };
      }
      return { kind: 'unsigned', child: cz };
    });

    // Assemble rows of GraphNodes (initially x=0, we center each row once maxRowWidth is known)
    const rows: { height: number; nodes: GraphNode[] }[] = [];

    const makeDnskeyNode = (k: AnalyzedDnskey): GraphNode => {
      const roleLabels: Record<AnalyzedDnskey['role'], string> = {
        'trust-anchor': 'TRUST ANCHOR',
        ksk: 'KSK · SEP',
        csk: 'CSK · SEP',
        zsk: 'ZSK',
        standby: 'STANDBY',
        revoked: 'REVOKED',
        missing: 'MISSING KEY',
      };
      const algShort = formatAlgorithm(k.algorithm);
      return {
        id: k.id,
        kind: 'dnskey',
        zone: zone.zoneName,
        x: 0,
        y: 0,
        width: NODE_W,
        height: KEY_H,
        title: `DNSKEY #${k.keyTag}`,
        subtitle: algShort,
        meta: k.keySizeInfo,
        badge: roleLabels[k.role],
        status: k.status,
        dashed: k.role === 'standby' || k.role === 'missing',
        doubleRing: k.role === 'trust-anchor' || k.role === 'ksk' || k.role === 'csk',
        dnskey: k,
      };
    };

    if (entryKeys.length > 0) {
      rows.push({ height: KEY_H, nodes: entryKeys.map(makeDnskeyNode) });
    }
    if (zskKeys.length > 0) {
      rows.push({ height: KEY_H, nodes: zskKeys.map(makeDnskeyNode) });
    }

    if (dataRrsets.length > 0) {
      rows.push({
        height: RR_H,
        nodes: dataRrsets.map((rr) => ({
          id: rr.id,
          kind: 'rrset',
          zone: zone.zoneName,
          x: 0,
          y: 0,
          width: NODE_W,
          height: RR_H,
          title: `${displayFqdn(rr.name)}`,
          subtitle: summarizeRrsetPreview(rr),
          meta: `TTL ${rr.ttl}s · ${rr.records.length} RR${rr.records.length === 1 ? '' : 's'}`,
          badge: rr.typeName,
          status: rr.status,
          rrset: rr,
        })),
      });
    }

    if (proofRrsets.length > 0) {
      rows.push({
        height: RR_H,
        nodes: proofRrsets.map((rr) => {
          const shortOwner =
            rr.type === RR_TYPES.NSEC3
              ? `${rr.name.split('.')[0].slice(0, 12)}…`
              : displayFqdn(rr.name);
          return {
            id: rr.id,
            kind: 'rrset',
            zone: zone.zoneName,
            x: 0,
            y: 0,
            width: NODE_W,
            height: RR_H,
            title: shortOwner,
            subtitle: summarizeRrsetPreview(rr),
            meta: `Denial Proof · TTL ${rr.ttl}s`,
            badge: rr.typeName,
            status: rr.status,
            dashed: true,
            rrset: rr,
          };
        }),
      });
    }

    if (zone.negativeNodes.length > 0) {
      rows.push({
        height: RR_H,
        nodes: zone.negativeNodes.map((neg) => ({
          id: neg.id,
          kind: 'negative',
          zone: zone.zoneName,
          x: 0,
          y: 0,
          width: NODE_W,
          height: RR_H,
          title: displayFqdn(neg.qname),
          subtitle: `${neg.kind} (${neg.qtypeName})`,
          meta: neg.proof.protocol !== 'NONE' ? `${neg.proof.protocol} verified` : 'Unsigned negative',
          badge: neg.kind,
          status: neg.status,
          dashed: true,
          negativeNode: neg,
        })),
      });
    }

    if (delegationItems.length > 0) {
      rows.push({
        height: RR_H,
        nodes: delegationItems.map((item) => {
          if (item.kind === 'ds') {
            const dsv = item.child.dsVerifications;
            const tags = dsv.map((d) => `#${d.ds.keyTag}`).join(', ');
            const digests = Array.from(
              new Set(dsv.map((d) => formatDigestType(d.ds.digestType)))
            ).join(', ');
            const dsStatus: ValidationStatus = item.rrset
              ? item.rrset.status === 'bogus'
                ? 'bogus'
                : dsv.some((d) => d.status === 'secure')
                  ? 'secure'
                  : dsv.some((d) => d.status === 'warning')
                    ? 'warning'
                    : 'bogus'
              : 'bogus';
            return {
              id: item.rrset?.id ?? `ds-group-${zone.zoneName}-${item.child.zoneName}`,
              kind: 'ds-group',
              zone: zone.zoneName,
              x: 0,
              y: 0,
              width: NODE_W,
              height: RR_H,
              title: `DS → ${displayFqdn(item.child.zoneName)}`,
              subtitle: `Key ${tags}`,
              meta: digests,
              badge: 'DS',
              status: dsStatus,
              rrset: item.rrset,
              dsVerifications: dsv,
              childZone: item.child.zoneName,
            };
          }
          const proof = item.child.insecureDelegationProof;
          return {
            id: `unsigned-del-${zone.zoneName}-${item.child.zoneName}`,
            kind: 'unsigned-delegation',
            zone: zone.zoneName,
            x: 0,
            y: 0,
            width: NODE_W,
            height: RR_H,
            title: `No DS → ${displayFqdn(item.child.zoneName)}`,
            subtitle: proof
              ? `${proof.protocol}${proof.optOutUsed ? ' Opt-Out' : ''} Proof`
              : 'Unsigned Delegation',
            meta: item.child.status === 'bogus' ? 'Missing DS proof' : 'Insecure Delegation',
            badge: proof?.protocol && proof.protocol !== 'NONE' ? proof.protocol : 'NO DS',
            status: item.child.status === 'bogus' ? 'bogus' : 'insecure',
            dashed: true,
            childZone: item.child.zoneName,
            delegationProof: proof,
          };
        }),
      });
    }

    // Fallback placeholder if an unsigned leaf zone has zero visible nodes inside
    if (rows.length === 0) {
      rows.push({
        height: RR_H,
        nodes: [
          {
            id: `empty-${zone.zoneName}`,
            kind: 'unsigned-delegation',
            zone: zone.zoneName,
            x: 0,
            y: 0,
            width: NODE_W,
            height: RR_H,
            title: displayFqdn(zone.zoneName),
            subtitle: 'No DNSSEC keys in zone',
            meta: zone.nsecMode,
            badge: 'ZONE',
            status: zone.status,
            dashed: true,
          },
        ],
      });
    }

    const maxCols = Math.max(1, ...rows.map((r) => r.nodes.length));
    const contentWidth = maxCols * NODE_W + (maxCols - 1) * NODE_GAP_X;
    const localWidth = Math.max(300, contentWidth + ZONE_PAD_X * 2);

    let cursorY = ZONE_HEADER_H + 18;
    const localNodes: GraphNode[] = [];
    for (let rIdx = 0; rIdx < rows.length; rIdx++) {
      const row = rows[rIdx];
      const rowW = row.nodes.length * NODE_W + (row.nodes.length - 1) * NODE_GAP_X;
      let startX = (localWidth - rowW) / 2;
      for (const n of row.nodes) {
        n.x = startX;
        n.y = cursorY;
        localNodes.push(n);
        startX += NODE_W + NODE_GAP_X;
      }
      cursorY += row.height + (rIdx < rows.length - 1 ? TIER_GAP_Y : 0);
    }

    const localHeight = cursorY + ZONE_PAD_BOTTOM;
    const childrenSpan =
      childLayouts.length === 0
        ? 0
        : childLayouts.reduce((acc, c) => acc + c.subtreeWidth, 0) +
          (childLayouts.length - 1) * ZONE_GAP_X;
    const subtreeWidth = Math.max(localWidth, childrenSpan);

    return {
      zone,
      localWidth,
      localHeight,
      localNodes,
      subtreeWidth,
      children: childLayouts,
      absX: 0,
      absY: 0,
    };
  };

  const rootLayouts = roots.map(buildInternalZone);

  // Step 2: Assign absolute (x, y) coordinates top-down
  const flatZoneLayouts: InternalZoneLayout[] = [];

  const placeSubtree = (layout: InternalZoneLayout, leftX: number, topY: number) => {
    layout.absX = leftX + (layout.subtreeWidth - layout.localWidth) / 2;
    layout.absY = topY;
    flatZoneLayouts.push(layout);

    if (layout.children.length > 0) {
      const totalChildSpan =
        layout.children.reduce((acc, c) => acc + c.subtreeWidth, 0) +
        (layout.children.length - 1) * ZONE_GAP_X;
      let childCursorX = leftX + (layout.subtreeWidth - totalChildSpan) / 2;
      const childTopY = topY + layout.localHeight + ZONE_GAP_Y;

      // Also align parent delegation nodes horizontally toward their corresponding child subtree if multiple children exist
      for (const child of layout.children) {
        placeSubtree(child, childCursorX, childTopY);
        childCursorX += child.subtreeWidth + ZONE_GAP_X;
      }
    }
  };

  let rootCursorX = CANVAS_PAD;
  for (const rl of rootLayouts) {
    placeSubtree(rl, rootCursorX, CANVAS_PAD);
    rootCursorX += rl.subtreeWidth + ZONE_GAP_X;
  }

  // Materialize absolute GraphZoneBoxes and GraphNodes
  const graphZones: GraphZoneBox[] = [];
  const graphNodes: GraphNode[] = [];
  const nodeById = new Map<string, GraphNode>();

  for (const zl of flatZoneLayouts) {
    graphZones.push({
      id: `zone-${zl.zone.zoneName}`,
      zone: zl.zone,
      x: zl.absX,
      y: zl.absY,
      width: zl.localWidth,
      height: zl.localHeight,
    });
    for (const ln of zl.localNodes) {
      const absNode: GraphNode = {
        ...ln,
        x: zl.absX + ln.x,
        y: zl.absY + ln.y,
      };
      graphNodes.push(absNode);
      nodeById.set(absNode.id, absNode);
    }
  }

  // Step 3: Build Directed Edges (DS delegations, RRSIGs, NSEC proofs, CNAMEs)
  const edges: GraphEdge[] = [];

  for (const zl of flatZoneLayouts) {
    const z = zl.zone;
    const keyNodeByTag = new Map<number, GraphNode>();
    for (const k of z.dnskeys) {
      const kn = nodeById.get(k.id);
      if (kn) keyNodeByTag.set(k.keyTag, kn);
    }

    // 3a. DNSKEY RRset RRSIG edges (KSK -> ZSKs or KSK self-signature arc)
    const dnskeyRrset = z.rrsets.find((r) => r.type === RR_TYPES.DNSKEY && r.name === z.zoneName);
    if (dnskeyRrset) {
      const zskNodes = z.dnskeys
        .filter((k) => k.role === 'zsk')
        .map((k) => nodeById.get(k.id))
        .filter((n): n is GraphNode => Boolean(n));

      for (const rv of dnskeyRrset.rrsigs) {
        const signerNode =
          keyNodeByTag.get(rv.signerKeyTag) ??
          nodeById.get(`dnskey-${z.zoneName}-${rv.signerKeyTag}-missing`);
        if (!signerNode) continue;

        if (zskNodes.length > 0) {
          for (const targetZsk of zskNodes) {
            edges.push({
              id: `edge-dnskey-${rv.id}-${targetZsk.id}`,
              kind: 'rrsig',
              fromId: signerNode.id,
              toId: targetZsk.id,
              fromX: signerNode.x + signerNode.width / 2,
              fromY: signerNode.y + signerNode.height,
              toX: targetZsk.x + targetZsk.width / 2,
              toY: targetZsk.y,
              label: `RRSIG #${rv.signerKeyTag}`,
              status: rv.status,
              dashed: rv.status === 'bogus',
              rrsigVerification: rv,
            });
          }
        } else {
          // Self-signing CSK / KSK loop
          edges.push({
            id: `edge-self-${rv.id}`,
            kind: 'rrsig-self',
            fromId: signerNode.id,
            toId: signerNode.id,
            fromX: signerNode.x + signerNode.width,
            fromY: signerNode.y + signerNode.height * 0.35,
            toX: signerNode.x + signerNode.width,
            toY: signerNode.y + signerNode.height * 0.72,
            label: `Self RRSIG`,
            status: rv.status,
            dashed: rv.status === 'bogus',
            rrsigVerification: rv,
          });
        }
      }
    }

    // 3b. RRSIG edges from DNSKEY -> visible RRset / DS-group nodes in this zone
    for (const rr of z.rrsets) {
      if (rr.type === RR_TYPES.DNSKEY && rr.name === z.zoneName) continue;
      const targetNode = nodeById.get(rr.id);
      if (!targetNode) continue;

      for (const rv of rr.rrsigs) {
        const signerNode =
          keyNodeByTag.get(rv.signerKeyTag) ??
          nodeById.get(`dnskey-${z.zoneName}-${rv.signerKeyTag}-missing`);
        if (!signerNode) continue;

        edges.push({
          id: `edge-rrsig-${rv.id}-${targetNode.id}`,
          kind: 'rrsig',
          fromId: signerNode.id,
          toId: targetNode.id,
          fromX: signerNode.x + signerNode.width / 2,
          fromY: signerNode.y + signerNode.height,
          toX: targetNode.x + targetNode.width / 2,
          toY: targetNode.y,
          label: `RRSIG #${rv.signerKeyTag}`,
          status: rv.status,
          dashed: rv.status === 'bogus',
          rrsigVerification: rv,
        });
      }
    }

    // 3c. Parent DS / Unsigned Delegation -> THIS zone's DNSKEYs or Zone Box
    if (z.parentZone) {
      if (z.dsVerifications.length > 0) {
        const parentDsNode =
          (z.parentDsRrsetId ? nodeById.get(z.parentDsRrsetId) : undefined) ??
          nodeById.get(`ds-group-${z.parentZone}-${z.zoneName}`);

        if (parentDsNode) {
          for (const dsv of z.dsVerifications) {
            const childKeyNode =
              keyNodeByTag.get(dsv.ds.keyTag) ??
              nodeById.get(`dnskey-${z.zoneName}-${dsv.ds.keyTag}-missing`);
            if (childKeyNode) {
              edges.push({
                id: `edge-ds-${dsv.id}`,
                kind: 'ds',
                fromId: parentDsNode.id,
                toId: childKeyNode.id,
                fromX: parentDsNode.x + parentDsNode.width / 2,
                fromY: parentDsNode.y + parentDsNode.height,
                toX: childKeyNode.x + childKeyNode.width / 2,
                toY: childKeyNode.y,
                label: `DS #${dsv.ds.keyTag} (${dsv.ds.digestType === 2 ? 'SHA-256' : dsv.ds.digestType === 4 ? 'SHA-384' : `Type ${dsv.ds.digestType}`})`,
                status: dsv.status,
                dashed: !dsv.digestValid,
                dsVerification: dsv,
              });
            }
          }
        }
      } else {
        const unsignedNode = nodeById.get(`unsigned-del-${z.parentZone}-${z.zoneName}`);
        const firstChildNode = graphNodes.find((n) => n.zone === z.zoneName);
        if (unsignedNode && firstChildNode) {
          edges.push({
            id: `edge-unsigned-${z.parentZone}-${z.zoneName}`,
            kind: 'insecure-delegation',
            fromId: unsignedNode.id,
            toId: firstChildNode.id,
            fromX: unsignedNode.x + unsignedNode.width / 2,
            fromY: unsignedNode.y + unsignedNode.height,
            toX: zl.absX + zl.localWidth / 2,
            toY: zl.absY,
            label: z.insecureDelegationProof?.optOutUsed ? 'NSEC3 Opt-Out' : 'Unsigned',
            status: z.status === 'bogus' ? 'bogus' : 'insecure',
            dashed: true,
            proof: z.insecureDelegationProof,
          });
        }
      }
    }

    // 3d. NSEC / NSEC3 -> NegativeNode proof edges
    for (const neg of z.negativeNodes) {
      const negGraphNode = nodeById.get(neg.id);
      if (!negGraphNode) continue;
      for (const covId of neg.coveringRrsetIds) {
        const covNode = nodeById.get(covId);
        if (!covNode) continue;
        edges.push({
          id: `edge-proof-${covId}-${neg.id}`,
          kind: 'nsec-proof',
          fromId: covNode.id,
          toId: negGraphNode.id,
          fromX: covNode.x + covNode.width / 2,
          fromY: covNode.y + covNode.height,
          toX: negGraphNode.x + negGraphNode.width / 2,
          toY: negGraphNode.y,
          label: `Proves ${neg.kind}`,
          status: neg.status,
          dashed: true,
          proof: neg.proof,
        });
      }
    }
  }

  // 3e. CNAME alias edges (within same zone OR across sibling zone branches!)
  for (const ce of snapshot.cnameEdges) {
    const fromNode = nodeById.get(ce.fromRrsetId);
    const toNode =
      (ce.toRrsetId ? nodeById.get(ce.toRrsetId) : undefined) ??
      (ce.toNegativeNodeId ? nodeById.get(ce.toNegativeNodeId) : undefined);
    if (!fromNode || !toNode) continue;

    const sameZone = fromNode.zone === toNode.zone;
    const goingRight = toNode.x >= fromNode.x;
    const fromX = sameZone
      ? fromNode.x + fromNode.width / 2
      : goingRight
        ? fromNode.x + fromNode.width
        : fromNode.x;
    const fromY = sameZone ? fromNode.y + fromNode.height : fromNode.y + fromNode.height / 2;
    const toX = sameZone
      ? toNode.x + toNode.width / 2
      : goingRight
        ? toNode.x
        : toNode.x + toNode.width;
    const toY = sameZone ? toNode.y : toNode.y + toNode.height / 2;

    edges.push({
      id: ce.id,
      kind: 'cname',
      fromId: fromNode.id,
      toId: toNode.id,
      fromX,
      fromY,
      toX,
      toY,
      label: `CNAME → ${displayFqdn(ce.toName)}`,
      status: fromNode.status === 'bogus' ? 'bogus' : 'secure',
      dashed: false,
      cnameEdge: ce,
    });
  }

  let maxRight = 800;
  let maxBottom = 600;
  for (const zb of graphZones) {
    maxRight = Math.max(maxRight, zb.x + zb.width + CANVAS_PAD);
    maxBottom = Math.max(maxBottom, zb.y + zb.height + CANVAS_PAD);
  }

  return {
    width: maxRight,
    height: maxBottom,
    zones: graphZones,
    nodes: graphNodes,
    edges,
  };
}
