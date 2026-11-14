import {
  Download,
  Eye,
  FileImage,
  HelpCircle,
  Maximize2,
  RotateCcw,
  Share2,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { createPortal } from 'react-dom';
import { formatDohShortLabel } from '../dns/constants';
import type { AnalysisSnapshot, ValidationStatus } from '../dns/types';
import {
  buildChainGraph,
  computeDefaultCanvasHeight,
  computeDefaultGraphTransform,
  computeFitAllGraphTransform,
  MAX_GRAPH_ZOOM,
  MIN_GRAPH_ZOOM,
  type GraphEdge,
  type GraphFilterOptions,
  type GraphNode,
} from '../graph/layout';
import {
  type FocusedWireQueryRequest,
  type FocusedWireSubMode,
  findGraphSelectionWireQuery,
} from '../dns/wireQueryFilter';
import { GraphInspector, type GraphSelection } from './GraphInspector';
import {
  IpAsnHoverCardContent,
  seedIpAsnCacheFromSnapshot,
  useIpAsnInfos,
} from './IpHoverBadge';
import { STATUS_META } from './StatusBadge';
import { WireSideDrawer } from './WireSideDrawer';

function getEdgeColor(edge: GraphEdge): string {
  if (edge.kind === 'cname') return edge.status === 'bogus' ? '#f43f5e' : '#8b5cf6';
  return STATUS_META[edge.status].svgStroke;
}

function getMarkerId(edge: GraphEdge): string {
  if (edge.kind === 'cname' && edge.status !== 'bogus') return 'arrow-cname';
  return `arrow-${edge.status}`;
}

function buildEdgePath(edge: GraphEdge): { d: string; labelX: number; labelY: number } {
  if (edge.kind === 'rrsig-self') {
    const x = edge.fromX;
    const y1 = edge.fromY;
    const y2 = edge.toY;
    const loopOut = 34;
    return {
      d: `M ${x} ${y1} C ${x + loopOut} ${y1 - 12}, ${x + loopOut} ${y2 + 12}, ${x} ${y2}`,
      labelX: x + loopOut + 4,
      labelY: (y1 + y2) / 2,
    };
  }

  if (edge.kind === 'cname' && Math.abs(edge.fromX - edge.toX) > 120) {
    // Horizontal/cross-branch CNAME arc
    const dx = (edge.toX - edge.fromX) * 0.45;
    const midX = (edge.fromX + edge.toX) / 2;
    const midY = (edge.fromY + edge.toY) / 2 - 14;
    return {
      d: `M ${edge.fromX} ${edge.fromY} C ${edge.fromX + dx} ${edge.fromY - 18}, ${edge.toX - dx} ${edge.toY - 18}, ${edge.toX} ${edge.toY}`,
      labelX: midX,
      labelY: midY,
    };
  }

  const dy = Math.max(24, Math.abs(edge.toY - edge.fromY) * 0.48);
  const midX = (edge.fromX + edge.toX) / 2;
  const midY = (edge.fromY + edge.toY) / 2;
  return {
    d: `M ${edge.fromX} ${edge.fromY} C ${edge.fromX} ${edge.fromY + dy}, ${edge.toX} ${edge.toY - dy}, ${edge.toX} ${edge.toY}`,
    labelX: midX,
    labelY: midY,
  };
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Clones the live SVG graph, resets pan/zoom to 1:1, prepends a solid theme background,
 * and appends a non-overlapping DigDeep attribution footer bar for standalone SVG/PNG sharing.
 */
export function prepareExportSvgElement(
  svgEl: SVGSVGElement,
  snapshot: AnalysisSnapshot,
  graph: { width: number; height: number },
  theme: 'dark' | 'light'
): { clone: SVGSVGElement; exportWidth: number; exportHeight: number } {
  const doc = svgEl.ownerDocument;
  const isDark = theme === 'dark';

  const dohLabel = formatDohShortLabel(snapshot.dohEndpoint);
  const statusMeta = STATUS_META[snapshot.overallStatus];
  const utcStr = `${new Date(snapshot.capturedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC`;
  const domainLabel = snapshot.displayDomain === '.' ? '. (root)' : snapshot.displayDomain;
  const metaRightText = `${domainLabel} [${snapshot.queryTypes.join(',')}] · ${statusMeta.label} · ${dohLabel} DoH · ${utcStr}`;

  const footerHeight = 42;
  const minWidthForFooter = Math.ceil(metaRightText.length * 6.9 + 248);
  const exportWidth = Math.max(graph.width, minWidthForFooter, 640);
  const exportHeight = graph.height + footerHeight;
  const offsetX = Math.round((exportWidth - graph.width) / 2);

  const clone = svgEl.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('width', String(exportWidth));
  clone.setAttribute('height', String(exportHeight));
  clone.setAttribute('viewBox', `0 0 ${exportWidth} ${exportHeight}`);

  const rootGroup = clone.querySelector('[data-pan-zoom-root="true"]');
  if (rootGroup) {
    rootGroup.setAttribute('transform', `translate(${offsetX}, 0) scale(1)`);
  }

  // Prepend solid background rect for standalone SVG/PNG export
  const bgRect = doc.createElementNS(SVG_NS, 'rect');
  bgRect.setAttribute('x', '0');
  bgRect.setAttribute('y', '0');
  bgRect.setAttribute('width', String(exportWidth));
  bgRect.setAttribute('height', String(exportHeight));
  bgRect.setAttribute('fill', isDark ? '#090d16' : '#f8fafc');
  clone.insertBefore(bgRect, clone.firstChild);

  // Append dedicated attribution footer bar below the graph canvas
  const footerGroup = doc.createElementNS(SVG_NS, 'g');
  footerGroup.setAttribute('data-export-attribution', 'true');

  const footerBg = doc.createElementNS(SVG_NS, 'rect');
  footerBg.setAttribute('x', '0');
  footerBg.setAttribute('y', String(graph.height));
  footerBg.setAttribute('width', String(exportWidth));
  footerBg.setAttribute('height', String(footerHeight));
  footerBg.setAttribute('fill', isDark ? '#060a12' : '#f1f5f9');
  footerGroup.appendChild(footerBg);

  const divider = doc.createElementNS(SVG_NS, 'line');
  divider.setAttribute('x1', '0');
  divider.setAttribute('y1', String(graph.height + 0.5));
  divider.setAttribute('x2', String(exportWidth));
  divider.setAttribute('y2', String(graph.height + 0.5));
  divider.setAttribute('stroke', isDark ? '#1e293b' : '#cbd5e1');
  divider.setAttribute('stroke-width', '1');
  footerGroup.appendChild(divider);

  // Mini DigDeep brand badge on the left
  const badgeY = graph.height + 11;
  const badgeRect = doc.createElementNS(SVG_NS, 'rect');
  badgeRect.setAttribute('x', '16');
  badgeRect.setAttribute('y', String(badgeY));
  badgeRect.setAttribute('width', '20');
  badgeRect.setAttribute('height', '20');
  badgeRect.setAttribute('rx', '5');
  badgeRect.setAttribute('fill', '#22d3ee');
  footerGroup.appendChild(badgeRect);

  const glyphGroup = doc.createElementNS(SVG_NS, 'g');
  glyphGroup.setAttribute('transform', `translate(20, ${badgeY + 4}) scale(0.5)`);
  glyphGroup.setAttribute('fill', 'none');
  glyphGroup.setAttribute('stroke', '#020617');
  glyphGroup.setAttribute('stroke-width', '2.5');
  glyphGroup.setAttribute('stroke-linecap', 'round');
  glyphGroup.setAttribute('stroke-linejoin', 'round');
  for (const [rx, ry] of [
    [9, 2],
    [2, 16],
    [16, 16],
  ]) {
    const box = doc.createElementNS(SVG_NS, 'rect');
    box.setAttribute('x', String(rx));
    box.setAttribute('y', String(ry));
    box.setAttribute('width', '6');
    box.setAttribute('height', '6');
    box.setAttribute('rx', '1');
    glyphGroup.appendChild(box);
  }
  const p1 = doc.createElementNS(SVG_NS, 'path');
  p1.setAttribute('d', 'M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3');
  glyphGroup.appendChild(p1);
  const p2 = doc.createElementNS(SVG_NS, 'path');
  p2.setAttribute('d', 'M12 12V8');
  glyphGroup.appendChild(p2);
  footerGroup.appendChild(glyphGroup);

  const brandText = doc.createElementNS(SVG_NS, 'text');
  brandText.setAttribute('x', '44');
  brandText.setAttribute('y', String(graph.height + 25));
  brandText.setAttribute('font-family', 'Inter, system-ui, -apple-system, sans-serif');
  brandText.setAttribute('font-size', '12');

  const brandName = doc.createElementNS(SVG_NS, 'tspan');
  brandName.setAttribute('font-weight', '700');
  brandName.setAttribute('fill', isDark ? '#f8fafc' : '#0f172a');
  brandName.textContent = 'DigDeep';
  brandText.appendChild(brandName);

  const brandUrl = doc.createElementNS(SVG_NS, 'tspan');
  brandUrl.setAttribute('font-weight', '600');
  brandUrl.setAttribute('fill', isDark ? '#22d3ee' : '#0891b2');
  brandUrl.textContent = ' · digdeep.fyi';
  brandText.appendChild(brandUrl);
  footerGroup.appendChild(brandText);

  // Right-aligned domain, status dot, DoH resolver, and UTC timestamp
  const metaText = doc.createElementNS(SVG_NS, 'text');
  metaText.setAttribute('x', String(exportWidth - 16));
  metaText.setAttribute('y', String(graph.height + 25));
  metaText.setAttribute('text-anchor', 'end');
  metaText.setAttribute('font-family', 'JetBrains Mono, ui-monospace, monospace');
  metaText.setAttribute('font-size', '11');
  metaText.setAttribute('font-weight', '500');
  metaText.setAttribute('fill', isDark ? '#94a3b8' : '#475569');

  const prefixSpan = doc.createElementNS(SVG_NS, 'tspan');
  prefixSpan.textContent = `${domainLabel} [${snapshot.queryTypes.join(',')}] · `;
  metaText.appendChild(prefixSpan);

  const statusDotSpan = doc.createElementNS(SVG_NS, 'tspan');
  statusDotSpan.setAttribute('fill', statusMeta.svgStroke);
  statusDotSpan.setAttribute('font-weight', '700');
  statusDotSpan.textContent = `● ${statusMeta.label}`;
  metaText.appendChild(statusDotSpan);

  const suffixSpan = doc.createElementNS(SVG_NS, 'tspan');
  suffixSpan.textContent = ` · ${dohLabel} DoH · ${utcStr}`;
  metaText.appendChild(suffixSpan);

  footerGroup.appendChild(metaText);
  clone.appendChild(footerGroup);

  return { clone, exportWidth, exportHeight };
}

export function ChainGraphView({
  snapshot,
  theme,
  filters,
  onChangeFilters,
  focusedTargetId,
  onSelectTargetId,
  onInspectWireQuery,
  dockedWireQuery = null,
  onSelectDockedWireQuery,
  onOpenFullWireTab,
  onCloseDockedWireDrawer,
}: {
  snapshot: AnalysisSnapshot;
  theme: 'dark' | 'light';
  filters: GraphFilterOptions;
  onChangeFilters: (next: GraphFilterOptions) => void;
  focusedTargetId?: string | null;
  onSelectTargetId?: (targetId: string | null) => void;
  onInspectWireQuery?: (queryId: string, mode?: 'dig' | 'hex-resp' | 'hex-req') => void;
  dockedWireQuery?: FocusedWireQueryRequest | null;
  onSelectDockedWireQuery?: (queryId: string, mode?: FocusedWireSubMode) => void;
  onOpenFullWireTab?: (queryId: string, mode: FocusedWireSubMode) => void;
  onCloseDockedWireDrawer?: () => void;
}) {
  seedIpAsnCacheFromSnapshot(snapshot);
  const graph = useMemo(() => buildChainGraph(snapshot, filters), [snapshot, filters]);
  const rootWrapperRef = useRef<HTMLDivElement | null>(null);
  const graphPaneRef = useRef<HTMLDivElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const getEstimatedWidth = () =>
    typeof window !== 'undefined' && typeof window.innerWidth === 'number' && window.innerWidth > 0
      ? Math.min(1552, Math.max(320, window.innerWidth - 48))
      : 1200;

  const [wrapperWidth, setWrapperWidth] = useState<number>(getEstimatedWidth);
  const canvasHeight = useMemo(
    () => computeDefaultCanvasHeight(graph, wrapperWidth),
    [graph, wrapperWidth]
  );

  const [transform, setTransform] = useState(() => {
    const w = getEstimatedWidth();
    const h = computeDefaultCanvasHeight(graph, w);
    return computeDefaultGraphTransform(graph, w, h);
  });
  const [dragging, setDragging] = useState(false);
  const dragStartRef = useRef({ clientX: 0, clientY: 0, startX: 0, startY: 0, moved: false });
  const pinchStateRef = useRef<{ dist: number; midX: number; midY: number } | null>(null);

  const [selection, setSelection] = useState<GraphSelection | null>(null);
  const [rightRailTab, setRightRailTab] = useState<'crypto' | 'wire'>(() =>
    dockedWireQuery ? 'wire' : 'crypto'
  );
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [showLegend, setShowLegend] = useState(false);
  const hasUserZoomedRef = useRef(false);

  useEffect(() => {
    if (dockedWireQuery) {
      setRightRailTab('wire');
    } else {
      setRightRailTab('crypto');
    }
  }, [dockedWireQuery?.seq, dockedWireQuery?.queryId, dockedWireQuery?.mode, Boolean(dockedWireQuery)]);

  const selectAndNotify = useCallback(
    (next: GraphSelection | null) => {
      setSelection(next);
      if (!next) {
        onSelectTargetId?.(null);
        return;
      }
      if (next.kind === 'node') {
        onSelectTargetId?.(next.node.id);
      } else if (next.kind === 'edge') {
        onSelectTargetId?.(next.edge.id);
      } else if (next.kind === 'zone') {
        onSelectTargetId?.(next.zone.zoneName);
      }
      if (dockedWireQuery && onSelectDockedWireQuery) {
        const matchedWire = findGraphSelectionWireQuery(next, snapshot.queries);
        if (matchedWire) {
          onSelectDockedWireQuery(matchedWire.id, dockedWireQuery.mode);
        }
      }
    },
    [onSelectTargetId, dockedWireQuery, onSelectDockedWireQuery, snapshot.queries]
  );

  const resetToDefaultZoom = useCallback(() => {
    const paneEl = containerRef.current ?? rootWrapperRef.current;
    const measuredW = paneEl ? paneEl.getBoundingClientRect().width : 0;
    const w = measuredW > 0 ? measuredW : wrapperWidth;
    const h = computeDefaultCanvasHeight(graph, w);
    hasUserZoomedRef.current = false;
    if (measuredW > 0 && !selection) {
      setWrapperWidth(measuredW);
    }
    setTransform(computeDefaultGraphTransform(graph, w, h));
  }, [graph, wrapperWidth, selection]);

  const fitEntireChain = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const visibleViewportHeight =
      typeof window !== 'undefined' &&
      typeof window.innerHeight === 'number' &&
      window.innerHeight > 0
        ? Math.min(rect.height, Math.max(360, window.innerHeight - 190))
        : rect.height;
    hasUserZoomedRef.current = true;
    setTransform(computeFitAllGraphTransform(graph, rect.width, visibleViewportHeight));
  }, [graph]);

  const zoomAroundPoint = useCallback((factor: number, focalX: number, focalY: number) => {
    setTransform((prev) => {
      const nextScale = Math.max(MIN_GRAPH_ZOOM, Math.min(MAX_GRAPH_ZOOM, prev.scale * factor));
      const ratio = nextScale / prev.scale;
      return {
        scale: nextScale,
        x: focalX - (focalX - prev.x) * ratio,
        y: focalY - (focalY - prev.y) * ratio,
      };
    });
  }, []);

  const zoomAroundCenter = useCallback(
    (factor: number) => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const hasWinHeight =
        typeof window !== 'undefined' &&
        typeof window.innerHeight === 'number' &&
        window.innerHeight > 0;
      const visibleTop = hasWinHeight ? Math.max(0, -rect.top) : 0;
      const visibleBottom = hasWinHeight
        ? Math.min(rect.height, window.innerHeight - rect.top)
        : rect.height;
      const focalY =
        visibleBottom > visibleTop ? (visibleTop + visibleBottom) / 2 : rect.height / 2;
      hasUserZoomedRef.current = true;
      zoomAroundPoint(factor, rect.width / 2, focalY);
    },
    [zoomAroundPoint]
  );

  // Reset to default 90%-width zoom + full-graph canvas height whenever snapshot or filters change
  useEffect(() => {
    hasUserZoomedRef.current = false;
    setSelection(null);
    const applyFit = () => {
      const rootEl = rootWrapperRef.current;
      const w =
        rootEl && rootEl.getBoundingClientRect().width > 0
          ? rootEl.getBoundingClientRect().width
          : getEstimatedWidth();
      setWrapperWidth(w);
      const h = computeDefaultCanvasHeight(graph, w);
      setTransform(computeDefaultGraphTransform(graph, w, h));
    };
    if (typeof requestAnimationFrame !== 'function') {
      applyFit();
      return;
    }
    const id = requestAnimationFrame(applyFit);
    return () => {
      if (typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(id);
      }
    };
  }, [snapshot.id, graph]);

  // Keep wrapperWidth (and default zoom if user hasn't manually zoomed/panned) synced to container width
  useEffect(() => {
    const rootEl = rootWrapperRef.current;
    if (!rootEl || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      const nextW = entry ? entry.contentRect.width : rootEl.getBoundingClientRect().width;
      if (nextW <= 0) return;
      setWrapperWidth((prev) => (Math.abs(prev - nextW) >= 1 ? nextW : prev));
      if (!hasUserZoomedRef.current) {
        const nextH = computeDefaultCanvasHeight(graph, nextW);
        setTransform(computeDefaultGraphTransform(graph, nextW, nextH));
      }
    });
    observer.observe(rootEl);
    return () => observer.disconnect();
  }, [graph]);

  // Focus node/edge/zone when user clicks a finding in Audit panel or opens a ?focus= deep link
  useEffect(() => {
    if (!focusedTargetId) return;
    const matchedNode = graph.nodes.find((n) => n.id === focusedTargetId);
    if (matchedNode) {
      setSelection({ kind: 'node', node: matchedNode });
      const el = containerRef.current;
      if (el) {
        const rect = el.getBoundingClientRect();
        const nodeCenterY = transform.y + (matchedNode.y + matchedNode.height / 2) * transform.scale;
        if (
          typeof window !== 'undefined' &&
          typeof window.scrollTo === 'function' &&
          typeof window.scrollY === 'number' &&
          typeof window.innerHeight === 'number'
        ) {
          const pageTargetY = Math.max(
            0,
            window.scrollY + rect.top + nodeCenterY - window.innerHeight / 2
          );
          window.scrollTo({ top: pageTargetY, behavior: 'smooth' });
        }
      }
      return;
    }
    const matchedEdge = graph.edges.find((e) => e.id === focusedTargetId);
    if (matchedEdge) {
      setSelection({ kind: 'edge', edge: matchedEdge });
      return;
    }
    const matchedZone = graph.zones.find(
      (z) => z.id === focusedTargetId || z.zone.zoneName === focusedTargetId
    );
    if (matchedZone) {
      setSelection({ kind: 'zone', zone: matchedZone.zone });
    }
  }, [focusedTargetId, graph.nodes, graph.edges, graph.zones]);

  // Plain scroll scrolls the full page; trackpad/touchscreen pinch or Shift+Scroll zooms the graph!
  useEffect(() => {
    const paneEl = graphPaneRef.current;
    const rootEl = rootWrapperRef.current;
    const canvasEl = containerRef.current;
    if (!paneEl || !rootEl || !canvasEl) return;

    let lastWheelZoomTime = 0;

    const onWheel = (e: WheelEvent) => {
      const isPinchOrCtrl = e.ctrlKey || e.metaKey;
      const isShiftZoom = e.shiftKey;

      // Let normal vertical/horizontal scroll pass straight through to scroll the full page
      if (!isPinchOrCtrl && !isShiftZoom) {
        return;
      }

      e.preventDefault();
      e.stopPropagation();
      lastWheelZoomTime = performance.now();

      const rect = canvasEl.getBoundingClientRect();
      const cursorX = e.clientX - rect.left;
      const cursorY = e.clientY - rect.top;

      // Many OS/browsers remap Shift + vertical mouse wheel into deltaX (with deltaY === 0)
      const primaryDelta =
        isShiftZoom && Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
      if (primaryDelta === 0) return;

      const rawDelta =
        e.deltaMode === 1
          ? primaryDelta * 28
          : e.deltaMode === 2
            ? primaryDelta * 300
            : primaryDelta;
      const clampedDelta = Math.max(-140, Math.min(140, rawDelta));
      const sensitivity = isPinchOrCtrl ? 0.0085 : 0.0025;
      const factor = Math.exp(-clampedDelta * sensitivity);

      hasUserZoomedRef.current = true;
      zoomAroundPoint(factor, cursorX, cursorY);
    };

    // Guard against accidental trackpad pinch (ctrlKey wheel) over inspector drawer zooming full browser page
    const onRootWheelGuard = (e: WheelEvent) => {
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
      }
    };

    // Safari macOS/iOS proprietary GestureEvent trackpad/pinch support
    let prevGestureScale = 1;
    const onGestureStart = (e: Event) => {
      e.preventDefault();
      prevGestureScale = (e as unknown as { scale?: number }).scale ?? 1;
    };
    const onGestureChange = (e: Event) => {
      e.preventDefault();
      if (performance.now() - lastWheelZoomTime < 80) return;
      const ge = e as unknown as { scale?: number; clientX?: number; clientY?: number };
      const curScale = ge.scale ?? 1;
      if (prevGestureScale > 0 && curScale > 0) {
        const factor = curScale / prevGestureScale;
        prevGestureScale = curScale;
        const rect = canvasEl.getBoundingClientRect();
        const cx = (ge.clientX ?? rect.left + rect.width / 2) - rect.left;
        const cy = (ge.clientY ?? rect.top + rect.height / 2) - rect.top;
        hasUserZoomedRef.current = true;
        zoomAroundPoint(factor, cx, cy);
      }
    };
    const onGestureEnd = (e: Event) => {
      e.preventDefault();
    };

    // Touchscreen: 1 finger scrolls the page natively (`touch-action: pan-y`), 2 fingers pinch-zoom + pan
    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length >= 2) {
        e.preventDefault();
        dragStartRef.current.moved = true;
        const t0 = e.touches[0];
        const t1 = e.touches[1];
        const dist = Math.max(1, Math.hypot(t1.clientX - t0.clientX, t1.clientY - t0.clientY));
        const midX = (t0.clientX + t1.clientX) / 2;
        const midY = (t0.clientY + t1.clientY) / 2;
        pinchStateRef.current = { dist, midX, midY };
      }
    };

    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length >= 2) {
        e.preventDefault();
        const rect = canvasEl.getBoundingClientRect();
        const t0 = e.touches[0];
        const t1 = e.touches[1];
        const newDist = Math.max(1, Math.hypot(t1.clientX - t0.clientX, t1.clientY - t0.clientY));
        const newMidX = (t0.clientX + t1.clientX) / 2;
        const newMidY = (t0.clientY + t1.clientY) / 2;

        const prev = pinchStateRef.current;
        pinchStateRef.current = { dist: newDist, midX: newMidX, midY: newMidY };
        if (!prev) return;

        const factor = newDist / prev.dist;
        const panDx = newMidX - prev.midX;
        const panDy = newMidY - prev.midY;
        const focalX = newMidX - rect.left;
        const focalY = newMidY - rect.top;

        hasUserZoomedRef.current = true;
        setTransform((cur) => {
          const nextScale = Math.max(MIN_GRAPH_ZOOM, Math.min(MAX_GRAPH_ZOOM, cur.scale * factor));
          const ratio = nextScale / cur.scale;
          const pannedX = cur.x + panDx;
          const pannedY = cur.y + panDy;
          return {
            scale: nextScale,
            x: focalX - (focalX - pannedX) * ratio,
            y: focalY - (focalY - pannedY) * ratio,
          };
        });
      }
    };

    const onTouchEnd = (e: TouchEvent) => {
      if (e.touches.length < 2) {
        pinchStateRef.current = null;
      }
      if (e.touches.length === 0 && dragStartRef.current.moved) {
        setTimeout(() => {
          dragStartRef.current.moved = false;
        }, 50);
      }
    };

    paneEl.addEventListener('wheel', onWheel, { passive: false });
    rootEl.addEventListener('wheel', onRootWheelGuard, { passive: false });
    paneEl.addEventListener('gesturestart', onGestureStart, { passive: false });
    paneEl.addEventListener('gesturechange', onGestureChange, { passive: false });
    paneEl.addEventListener('gestureend', onGestureEnd, { passive: false });
    canvasEl.addEventListener('touchstart', onTouchStart, { passive: false });
    canvasEl.addEventListener('touchmove', onTouchMove, { passive: false });
    canvasEl.addEventListener('touchend', onTouchEnd);
    canvasEl.addEventListener('touchcancel', onTouchEnd);

    return () => {
      paneEl.removeEventListener('wheel', onWheel);
      rootEl.removeEventListener('wheel', onRootWheelGuard);
      paneEl.removeEventListener('gesturestart', onGestureStart);
      paneEl.removeEventListener('gesturechange', onGestureChange);
      paneEl.removeEventListener('gestureend', onGestureEnd);
      canvasEl.removeEventListener('touchstart', onTouchStart);
      canvasEl.removeEventListener('touchmove', onTouchMove);
      canvasEl.removeEventListener('touchend', onTouchEnd);
      canvasEl.removeEventListener('touchcancel', onTouchEnd);
    };
  }, [zoomAroundPoint]);

  const handlePointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    // Touch scrolling (1 finger) & pinch-zoom (2 fingers) are handled via `touch-action: pan-y` + TouchEvents
    if (e.pointerType === 'touch') return;
    if (e.pointerType === 'mouse' && e.button !== 0) return;

    setDragging(true);
    dragStartRef.current = {
      clientX: e.clientX,
      clientY: e.clientY,
      startX: transform.x,
      startY: transform.y,
      moved: false,
    };
  };

  const handlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.pointerType === 'touch' || !dragging) return;

    const dx = e.clientX - dragStartRef.current.clientX;
    const dy = e.clientY - dragStartRef.current.clientY;
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) {
      dragStartRef.current.moved = true;
      hasUserZoomedRef.current = true;
    }
    setTransform((prev) => ({
      ...prev,
      x: dragStartRef.current.startX + dx,
      y: dragStartRef.current.startY + dy,
    }));
  };

  const handlePointerEnd = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.pointerType === 'touch') return;
    setDragging(false);
  };

  // Connected lineage highlight set when hovering or selecting a node/edge
  const activeFocusId =
    hoveredId ??
    (selection?.kind === 'node'
      ? selection.node.id
      : selection?.kind === 'edge'
        ? selection.edge.id
        : null);

  const highlightedIds = useMemo(() => {
    if (!activeFocusId) return null;
    const set = new Set<string>([activeFocusId]);
    for (const e of graph.edges) {
      if (e.id === activeFocusId || e.fromId === activeFocusId || e.toId === activeFocusId) {
        set.add(e.id);
        set.add(e.fromId);
        set.add(e.toId);
      }
    }
    return set;
  }, [activeFocusId, graph.edges]);

  const canNativeShare =
    typeof navigator !== 'undefined' && typeof navigator.share === 'function';

  const renderDiagramPngBlob = (): Promise<{ blob: Blob; filename: string } | null> => {
    const svgEl = svgRef.current;
    if (!svgEl) return Promise.resolve(null);

    const { clone, exportWidth, exportHeight } = prepareExportSvgElement(
      svgEl,
      snapshot,
      graph,
      theme
    );

    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(clone);
    const safeName = snapshot.displayDomain.replace(/[^a-z0-9.-]/gi, '_') || 'root';
    const filename = `digdeep-${safeName}.png`;

    return new Promise((resolve) => {
      const img = new Image();
      const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(svgBlob);
      img.onload = () => {
        const scale = 2;
        const canvas = document.createElement('canvas');
        canvas.width = exportWidth * scale;
        canvas.height = exportHeight * scale;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.scale(scale, scale);
          ctx.drawImage(img, 0, 0);
          canvas.toBlob((pngBlob) => {
            URL.revokeObjectURL(url);
            resolve(pngBlob ? { blob: pngBlob, filename } : null);
          }, 'image/png');
        } else {
          URL.revokeObjectURL(url);
          resolve(null);
        }
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        resolve(null);
      };
      img.src = url;
    });
  };

  const exportDiagram = (format: 'svg' | 'png') => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    if (format === 'svg') {
      const { clone } = prepareExportSvgElement(svgEl, snapshot, graph, theme);
      const serializer = new XMLSerializer();
      const svgString = serializer.serializeToString(clone);
      const safeName = snapshot.displayDomain.replace(/[^a-z0-9.-]/gi, '_') || 'root';
      const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `digdeep-${safeName}.svg`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    void renderDiagramPngBlob().then((rendered) => {
      if (!rendered) return;
      const pngUrl = URL.createObjectURL(rendered.blob);
      const a = document.createElement('a');
      a.href = pngUrl;
      a.download = rendered.filename;
      a.click();
      URL.revokeObjectURL(pngUrl);
    });
  };

  const shareDiagramPng = async () => {
    if (!canNativeShare) return;
    const rendered = await renderDiagramPngBlob();
    if (!rendered) return;

    try {
      const file = new File([rendered.blob], rendered.filename, { type: 'image/png' });
      const title = `DigDeep Chain Graph — ${snapshot.displayDomain}`;
      if (typeof navigator.canShare === 'function' && navigator.canShare({ files: [file] })) {
        await navigator.share({
          files: [file],
          title,
          text: snapshot.overallSummary,
        });
      } else {
        await navigator.share({
          title,
          text: snapshot.overallSummary,
          url: typeof window !== 'undefined' ? window.location.href : undefined,
        });
      }
    } catch {
      // User dismissed share sheet or share canceled
    }
  };

  const isDark = theme === 'dark';

  const hoveredIpNode = useMemo(() => {
    if (!hoveredId || dragging) return null;
    return (
      graph.nodes.find(
        (n) =>
          n.id === hoveredId &&
          n.rrset &&
          (n.rrset.typeName === 'A' || n.rrset.typeName === 'AAAA') &&
          n.rrset.records.length > 0
      ) ?? null
    );
  }, [hoveredId, dragging, graph.nodes]);

  const hoveredNodeIps = useMemo(
    () => (hoveredIpNode?.rrset ? hoveredIpNode.rrset.records.map((r) => r.rdataText) : []),
    [hoveredIpNode]
  );

  const hoveredIpEntries = useIpAsnInfos(hoveredNodeIps, Boolean(hoveredIpNode) && !dragging);

  const hoveredIpOverlayPos = useMemo(() => {
    if (!hoveredIpNode || typeof window === 'undefined' || !containerRef.current) return null;
    const rect = containerRef.current.getBoundingClientRect();
    const centerScreenX =
      rect.left + transform.x + (hoveredIpNode.x + hoveredIpNode.width / 2) * transform.scale;
    const topScreenY = rect.top + transform.y + hoveredIpNode.y * transform.scale;
    const bottomScreenY =
      rect.top + transform.y + (hoveredIpNode.y + hoveredIpNode.height) * transform.scale;
    const cardHalfWidth = 160;
    const clampedLeft = Math.max(
      12 + cardHalfWidth,
      Math.min(window.innerWidth - 12 - cardHalfWidth, centerScreenX)
    );
    const placement: 'top' | 'bottom' = topScreenY > 190 ? 'top' : 'bottom';
    return {
      left: clampedLeft,
      top: placement === 'top' ? topScreenY - 10 : bottomScreenY + 10,
      placement,
    };
  }, [hoveredIpNode, transform]);

  return (
    <div
      ref={rootWrapperRef}
      className="flex flex-col lg:flex-row lg:items-start gap-3 relative"
    >
      {/* Main Interactive Graph Card — note: use `lg:flex-1` (NOT `flex-1` in mobile `flex-col`, which sets `flex-basis: 0%` vertically and collapses height!) */}
      <div
        ref={graphPaneRef}
        className="w-full lg:w-auto lg:flex-1 lg:min-w-0 flex flex-col rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#090d16] overflow-hidden"
      >
        {/* Dedicated Non-Overlapping Graph Controls Header Bar */}
        <div className="px-2.5 sm:px-3 py-2 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-1.5 cursor-pointer select-none text-slate-700 dark:text-slate-300 pr-2 border-r border-slate-200 dark:border-slate-800">
              <input
                type="checkbox"
                checked={filters.showStandbyKeys}
                onChange={(e) =>
                  onChangeFilters({ ...filters, showStandbyKeys: e.target.checked })
                }
                className="rounded accent-cyan-500"
              />
              <span>Standby Keys</span>
            </label>
            <label className="inline-flex items-center gap-1.5 cursor-pointer select-none text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={filters.showSoaAndNs}
                onChange={(e) => onChangeFilters({ ...filters, showSoaAndNs: e.target.checked })}
                className="rounded accent-cyan-500"
              />
              <Eye className="w-3.5 h-3.5 text-slate-400" />
              <span>SOA &amp; NS RRsets</span>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-1 sm:gap-1.5 text-xs">
            <button
              type="button"
              onClick={() => zoomAroundCenter(1.22)}
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <span className="font-mono text-[11px] text-slate-500 w-11 text-center">
              {Math.round(transform.scale * 100)}%
            </span>
            <button
              type="button"
              onClick={() => zoomAroundCenter(1 / 1.22)}
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={resetToDefaultZoom}
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Reset default zoom (widest box = 90% width)"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={fitEntireChain}
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Fit entire chain in viewport"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 mx-0.5" />
            <button
              type="button"
              onClick={() => exportDiagram('svg')}
              className="inline-flex items-center gap-1 px-1.5 sm:px-2 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium cursor-pointer"
              title="Export vector SVG diagram"
            >
              <Download className="w-3.5 h-3.5" />
              <span>SVG</span>
            </button>
            <button
              type="button"
              onClick={() => exportDiagram('png')}
              className="inline-flex items-center gap-1 px-1.5 sm:px-2 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium cursor-pointer"
              title="Export high-DPI PNG image"
            >
              <FileImage className="w-3.5 h-3.5" />
              <span>PNG</span>
            </button>
            {canNativeShare && (
              <button
                type="button"
                data-testid="share-png-diagram-btn"
                onClick={() => void shareDiagramPng()}
                className="inline-flex items-center gap-1 px-1.5 sm:px-2 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium cursor-pointer"
                title="Share high-DPI PNG chain diagram via native OS share sheet"
              >
                <Share2 className="w-3.5 h-3.5 text-cyan-500" />
                <span>Share</span>
              </button>
            )}
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 mx-0.5" />
            <button
              type="button"
              onClick={() => setShowLegend((v) => !v)}
              className={`inline-flex items-center gap-1 px-1.5 sm:px-2 py-1 rounded font-medium cursor-pointer ${
                showLegend
                  ? 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-300'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>Legend</span>
            </button>
          </div>
        </div>

        {/* Pan/Zoom SVG Surface with explicit un-collapsible pixel height */}
        <div
          ref={containerRef}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerEnd}
          onPointerCancel={handlePointerEnd}
          onPointerLeave={(e) => {
            if (e.pointerType === 'mouse') handlePointerEnd(e);
          }}
          style={{
            height: `${canvasHeight}px`,
            minHeight: `${canvasHeight}px`,
            touchAction: 'pan-y',
          }}
          className={`w-full shrink-0 relative overflow-hidden graph-canvas-bg select-none touch-pan-y ${
            dragging ? 'cursor-grabbing' : 'cursor-grab'
          }`}
        >
          {/* Interactive Legend Overlay */}
          {showLegend && (
            <div className="absolute top-3 right-3 z-20 max-w-[calc(100%-1.5rem)] w-72 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur p-3.5 shadow-xl text-xs space-y-2.5">
              <div className="font-semibold text-slate-900 dark:text-slate-100">
                DNSViz Chain-of-Trust Legend
              </div>
              <div className="space-y-1.5">
                {(
                  [
                    ['secure', 'Verified cryptographic chain from Trust Anchor'],
                    ['warning', 'Valid signature with RFC 8624 / expiry warning'],
                    ['insecure', 'Provably unsigned delegation (NSEC / NSEC3)'],
                    ['bogus', 'Cryptographic failure, expired sig, or missing SEP'],
                  ] as [ValidationStatus, string][]
                ).map(([st, desc]) => (
                  <div key={st} className="flex items-start gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-full mt-1 shrink-0"
                      style={{ backgroundColor: STATUS_META[st].svgStroke }}
                    />
                    <div>
                      <span className="font-mono font-semibold text-[11px]">
                        {STATUS_META[st].label}:
                      </span>{' '}
                      <span className="text-slate-600 dark:text-slate-400">{desc}</span>
                    </div>
                  </div>
                ))}
                <div className="flex items-start gap-2 pt-1 border-t border-slate-200 dark:border-slate-800">
                  <span className="w-2.5 h-2.5 rounded-full mt-1 shrink-0 bg-violet-500" />
                  <div>
                    <span className="font-mono font-semibold text-[11px]">CNAME ALIAS:</span>{' '}
                    <span className="text-slate-600 dark:text-slate-400">
                      Canonical name redirection (intra- or cross-zone)
                    </span>
                  </div>
                </div>
                <div className="text-[11px] text-slate-500 pt-1">
                  Double-ring capsules denote SEP / KSK / Trust Anchor keys. Click any zone, node, or
                  edge to inspect raw crypto &amp; records.
                </div>
              </div>
            </div>
          )}

          <svg
            ref={svgRef}
            width="100%"
            height={canvasHeight}
            xmlns="http://www.w3.org/2000/svg"
            style={{ display: 'block', fontFamily: 'Inter, system-ui, sans-serif' }}
          >
            <defs>
              {(['secure', 'warning', 'insecure', 'bogus', 'indeterminate'] as ValidationStatus[]).map(
                (st) => (
                  <marker
                    key={st}
                    id={`arrow-${st}`}
                    viewBox="0 0 10 10"
                    refX="8.5"
                    refY="5"
                    markerWidth="6.5"
                    markerHeight="6.5"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={STATUS_META[st].svgStroke} />
                  </marker>
                )
              )}
              <marker
                id="arrow-cname"
                viewBox="0 0 10 10"
                refX="8.5"
                refY="5"
                markerWidth="6.5"
                markerHeight="6.5"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#8b5cf6" />
              </marker>
            </defs>

            <g
              data-pan-zoom-root="true"
              transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}
            >
              {/* LAYER 1: Zone Containers */}
              {graph.zones.map((zb) => {
                const stMeta = STATUS_META[zb.zone.status];
                const isSelectedZone =
                  selection?.kind === 'zone' && selection.zone.zoneName === zb.zone.zoneName;
                return (
                  <g
                    key={zb.id}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (!dragStartRef.current.moved) {
                        selectAndNotify({ kind: 'zone', zone: zb.zone });
                      }
                    }}
                    style={{ cursor: 'pointer' }}
                  >
                    <rect
                      x={zb.x}
                      y={zb.y}
                      width={zb.width}
                      height={zb.height}
                      rx={16}
                      fill={isDark ? 'rgba(15, 23, 42, 0.82)' : 'rgba(255, 255, 255, 0.92)'}
                      stroke={isSelectedZone ? '#06b6d4' : stMeta.svgStroke}
                      strokeWidth={isSelectedZone ? 2.4 : 1.5}
                      strokeOpacity={isSelectedZone ? 1 : 0.65}
                    />
                    {/* Zone Header Bar */}
                    <path
                      d={`M ${zb.x + 16} ${zb.y} H ${zb.x + zb.width - 16} A 16 16 0 0 1 ${zb.x + zb.width} ${zb.y + 16} V ${zb.y + 42} H ${zb.x} V ${zb.y + 16} A 16 16 0 0 1 ${zb.x + 16} ${zb.y} Z`}
                      fill={isDark ? 'rgba(30, 41, 59, 0.7)' : 'rgba(241, 245, 249, 0.95)'}
                    />
                    <line
                      x1={zb.x}
                      y1={zb.y + 42}
                      x2={zb.x + zb.width}
                      y2={zb.y + 42}
                      stroke={isDark ? '#1e293b' : '#e2e8f0'}
                      strokeWidth={1}
                    />
                    <text
                      x={zb.x + 16}
                      y={zb.y + 26}
                      fill={isDark ? '#f8fafc' : '#0f172a'}
                      fontSize={13}
                      fontWeight={700}
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {zb.zone.zoneName === '.' ? '. (root)' : zb.zone.zoneName}
                    </text>

                    {/* Zone Status Pill */}
                    <rect
                      x={zb.x + zb.width - 96}
                      y={zb.y + 11}
                      width={82}
                      height={20}
                      rx={10}
                      fill={stMeta.svgBadgeBg}
                    />
                    <text
                      x={zb.x + zb.width - 55}
                      y={zb.y + 24.5}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize={9.5}
                      fontWeight={700}
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {stMeta.label}
                    </text>
                  </g>
                );
              })}

              {/* LAYER 2: Directed Edges (DS, RRSIG, NSEC Proof, CNAME) */}
              {graph.edges.map((edge) => {
                const { d, labelX, labelY } = buildEdgePath(edge);
                const stroke = getEdgeColor(edge);
                const dimmed = highlightedIds !== null && !highlightedIds.has(edge.id);
                const isSelected = selection?.kind === 'edge' && selection.edge.id === edge.id;
                const showInlineTag =
                  edge.kind === 'ds' ||
                  edge.kind === 'cname' ||
                  edge.kind === 'insecure-delegation' ||
                  isSelected ||
                  hoveredId === edge.id;

                return (
                  <g
                    key={edge.id}
                    opacity={dimmed ? 0.2 : 1}
                    onMouseEnter={() => setHoveredId(edge.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (!dragStartRef.current.moved) {
                        selectAndNotify({ kind: 'edge', edge });
                      }
                    }}
                    style={{ cursor: 'pointer', transition: 'opacity 140ms ease' }}
                  >
                    {/* Wide invisible click target */}
                    <path d={d} fill="none" stroke="transparent" strokeWidth={14} />
                    <path
                      d={d}
                      fill="none"
                      stroke={stroke}
                      strokeWidth={
                        isSelected
                          ? 3.2
                          : edge.kind === 'ds' || edge.kind === 'cname'
                            ? 2.4
                            : 1.75
                      }
                      strokeDasharray={edge.dashed ? '5 4' : undefined}
                      markerEnd={`url(#${getMarkerId(edge)})`}
                    />
                    {showInlineTag && (
                      <g transform={`translate(${labelX}, ${labelY})`}>
                        <rect
                          x={-Math.max(44, edge.label.length * 3.3)}
                          y={-9}
                          width={Math.max(88, edge.label.length * 6.6)}
                          height={18}
                          rx={9}
                          fill={isDark ? '#0f172a' : '#ffffff'}
                          stroke={stroke}
                          strokeWidth={1.1}
                        />
                        <text
                          x={0}
                          y={3.5}
                          textAnchor="middle"
                          fill={isDark ? '#e2e8f0' : '#1e293b'}
                          fontSize={9.5}
                          fontWeight={600}
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {edge.label}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}

              {/* LAYER 3: Graph Nodes (DNSKEY capsules, RRset cards, DS bridges, Negative proofs) */}
              {graph.nodes.map((node: GraphNode) => {
                const stMeta = STATUS_META[node.status];
                const isDnskey = node.kind === 'dnskey';
                const rx = isDnskey ? node.height / 2 : 11;
                const isSelected = selection?.kind === 'node' && selection.node.id === node.id;
                const dimmed = highlightedIds !== null && !highlightedIds.has(node.id);

                return (
                  <g
                    key={node.id}
                    opacity={dimmed ? 0.3 : 1}
                    onMouseEnter={() => setHoveredId(node.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    onClick={(e) => {
                      e.stopPropagation();
                      if (!dragStartRef.current.moved) {
                        selectAndNotify({ kind: 'node', node });
                      }
                    }}
                    style={{ cursor: 'pointer', transition: 'opacity 140ms ease' }}
                  >
                    <rect
                      x={node.x}
                      y={node.y}
                      width={node.width}
                      height={node.height}
                      rx={rx}
                      fill={isDark ? stMeta.svgFillDark : stMeta.svgFillLight}
                      stroke={isSelected ? '#06b6d4' : stMeta.svgStroke}
                      strokeWidth={isSelected ? 2.6 : 1.75}
                      strokeDasharray={node.dashed ? '5 3' : undefined}
                    />

                    {/* Double inner ring for Trust Anchor / KSK / SEP capsules (DNSViz signature look) */}
                    {node.doubleRing && (
                      <rect
                        x={node.x + 4}
                        y={node.y + 4}
                        width={node.width - 8}
                        height={node.height - 8}
                        rx={Math.max(6, rx - 4)}
                        fill="none"
                        stroke={stMeta.svgStroke}
                        strokeOpacity={0.55}
                        strokeWidth={1}
                      />
                    )}

                    {/* Top-right Role / RR Type Badge */}
                    <rect
                      x={node.x + node.width - Math.max(40, node.badge.length * 6.2 + 12) - 10}
                      y={node.y + 8}
                      width={Math.max(40, node.badge.length * 6.2 + 12)}
                      height={16}
                      rx={8}
                      fill={stMeta.svgBadgeBg}
                    />
                    <text
                      x={
                        node.x +
                        node.width -
                        Math.max(40, node.badge.length * 6.2 + 12) / 2 -
                        10
                      }
                      y={node.y + 19}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize={8.5}
                      fontWeight={700}
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.badge}
                    </text>

                    {/* Title */}
                    <text
                      x={node.x + (isDnskey ? 18 : 12)}
                      y={node.y + 21}
                      fill={isDark ? '#f8fafc' : '#0f172a'}
                      fontSize={11.5}
                      fontWeight={700}
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.title.length > 17 ? `${node.title.slice(0, 16)}…` : node.title}
                    </text>

                    {/* Subtitle */}
                    <text
                      x={node.x + (isDnskey ? 18 : 12)}
                      y={node.y + 38}
                      fill={isDark ? '#cbd5e1' : '#334155'}
                      fontSize={10.5}
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {node.subtitle.length > 26
                        ? `${node.subtitle.slice(0, 25)}…`
                        : node.subtitle}
                    </text>

                    {/* Meta footer */}
                    <text
                      x={node.x + (isDnskey ? 18 : 12)}
                      y={node.y + 52}
                      fill={isDark ? '#94a3b8' : '#64748b'}
                      fontSize={9.5}
                      fontFamily="Inter, system-ui, sans-serif"
                    >
                      {node.meta}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Dedicated Non-Overlapping Hint Footer */}
        <div className="px-3 py-1.5 border-t border-slate-200/80 dark:border-slate-800/80 bg-white/85 dark:bg-slate-950/85 text-[11px] text-slate-500 dark:text-slate-400">
          Pinch or Shift + Scroll to zoom · Drag to pan · Tap or click any zone, DNSKEY, RRset, or RRSIG edge to inspect
        </div>
      </div>

      {/* Right-Hand Cryptographic & Wire Inspector Unified Rail */}
      {dockedWireQuery && (rightRailTab === 'wire' || !selection) ? (
        <WireSideDrawer
          snapshot={snapshot}
          focusedQuery={dockedWireQuery}
          onSelectQuery={(qid, mode) => onSelectDockedWireQuery?.(qid, mode)}
          onOpenFullWireTab={(qid, mode) => onOpenFullWireTab?.(qid, mode)}
          onClose={() => onCloseDockedWireDrawer?.()}
          graphRailContext={
            selection
              ? {
                  selectionLabel:
                    selection.kind === 'zone'
                      ? selection.zone.zoneName === '.'
                        ? '. (root)'
                        : selection.zone.zoneName
                      : selection.kind === 'node'
                        ? selection.node.title
                        : selection.edge.label,
                  onSwitchToGraphCrypto: () => setRightRailTab('crypto'),
                }
              : null
          }
        />
      ) : (
        <GraphInspector
          selection={selection}
          dohEndpoint={snapshot.dohEndpoint}
          capturedAt={snapshot.capturedAt}
          validatedAt={snapshot.validatedAt}
          queries={snapshot.queries}
          onInspectWireQuery={onInspectWireQuery}
          dockedWireRail={
            dockedWireQuery
              ? {
                  wireSize: snapshot.queries.find((q) => q.id === dockedWireQuery.queryId)?.packet
                    .wireSize,
                  onSwitchToWire: () => setRightRailTab('wire'),
                }
              : null
          }
          onClose={() => {
            selectAndNotify(null);
            if (dockedWireQuery) {
              onCloseDockedWireDrawer?.();
            }
          }}
        />
      )}

      {/* Floating BGP ASN & Network Hover Card for SVG A / AAAA Nodes */}
      {hoveredIpNode &&
        hoveredIpOverlayPos &&
        hoveredIpEntries.length > 0 &&
        typeof document !== 'undefined' &&
        document.body &&
        createPortal(
          <div
            style={{
              position: 'fixed',
              left: `${hoveredIpOverlayPos.left}px`,
              top: `${hoveredIpOverlayPos.top}px`,
              transform:
                hoveredIpOverlayPos.placement === 'top'
                  ? 'translate(-50%, -100%)'
                  : 'translate(-50%, 0)',
              zIndex: 9999,
              pointerEvents: 'none',
            }}
          >
            <IpAsnHoverCardContent
              entries={hoveredIpEntries}
              titleLabel={`${hoveredIpNode.title} · ${hoveredIpNode.badge} RRset`}
              showActions={false}
            />
          </div>,
          document.body
        )}
    </div>
  );
}
