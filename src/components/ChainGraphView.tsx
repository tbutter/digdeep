import {
  Download,
  Eye,
  FileImage,
  HelpCircle,
  Maximize2,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type WheelEvent as ReactWheelEvent,
} from 'react';
import type { AnalysisSnapshot, ValidationStatus } from '../dns/types';
import {
  buildChainGraph,
  type GraphEdge,
  type GraphFilterOptions,
  type GraphNode,
} from '../graph/layout';
import { GraphInspector, type GraphSelection } from './GraphInspector';
import { STATUS_META } from './StatusBadge';

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

export function ChainGraphView({
  snapshot,
  theme,
  filters,
  onChangeFilters,
  focusedTargetId,
}: {
  snapshot: AnalysisSnapshot;
  theme: 'dark' | 'light';
  filters: GraphFilterOptions;
  onChangeFilters: (next: GraphFilterOptions) => void;
  focusedTargetId?: string | null;
}) {
  const graph = useMemo(() => buildChainGraph(snapshot, filters), [snapshot, filters]);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const [transform, setTransform] = useState({ x: 40, y: 24, scale: 1 });
  const [dragging, setDragging] = useState(false);
  const dragStartRef = useRef({ clientX: 0, clientY: 0, startX: 0, startY: 0, moved: false });

  const [selection, setSelection] = useState<GraphSelection | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [showLegend, setShowLegend] = useState(false);

  const fitToViewport = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;

    const scaleX = (rect.width - 48) / graph.width;
    const scaleY = (rect.height - 48) / graph.height;
    const scale = Math.max(0.32, Math.min(1.08, Math.min(scaleX, scaleY)));
    const x = Math.round((rect.width - graph.width * scale) / 2);
    const y = Math.max(16, Math.round((rect.height - graph.height * scale) / 2));
    setTransform({ x, y, scale });
  }, [graph.width, graph.height]);

  useEffect(() => {
    setSelection(null);
    const id = requestAnimationFrame(fitToViewport);
    return () => cancelAnimationFrame(id);
  }, [snapshot.id, fitToViewport]);

  // Focus node/zone when user clicks a finding in Audit panel
  useEffect(() => {
    if (!focusedTargetId) return;
    const matchedNode = graph.nodes.find((n) => n.id === focusedTargetId);
    if (matchedNode) {
      setSelection({ kind: 'node', node: matchedNode });
      const el = containerRef.current;
      if (el) {
        const rect = el.getBoundingClientRect();
        const scale = Math.max(transform.scale, 0.85);
        setTransform({
          scale,
          x: rect.width / 2 - (matchedNode.x + matchedNode.width / 2) * scale,
          y: rect.height / 2 - (matchedNode.y + matchedNode.height / 2) * scale,
        });
      }
      return;
    }
    const matchedZone = graph.zones.find(
      (z) => z.id === focusedTargetId || z.zone.zoneName === focusedTargetId
    );
    if (matchedZone) {
      setSelection({ kind: 'zone', zone: matchedZone.zone });
    }
  }, [focusedTargetId, graph.nodes, graph.zones]);

  const handleWheel = (e: ReactWheelEvent<HTMLDivElement>) => {
    e.preventDefault();
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const cursorX = e.clientX - rect.left;
    const cursorY = e.clientY - rect.top;

    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    setTransform((prev) => {
      const nextScale = Math.max(0.22, Math.min(2.4, prev.scale * factor));
      const ratio = nextScale / prev.scale;
      return {
        scale: nextScale,
        x: cursorX - (cursorX - prev.x) * ratio,
        y: cursorY - (cursorY - prev.y) * ratio,
      };
    });
  };

  const handleMouseDown = (e: ReactMouseEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    setDragging(true);
    dragStartRef.current = {
      clientX: e.clientX,
      clientY: e.clientY,
      startX: transform.x,
      startY: transform.y,
      moved: false,
    };
  };

  const handleMouseMove = (e: ReactMouseEvent<HTMLDivElement>) => {
    if (!dragging) return;
    const dx = e.clientX - dragStartRef.current.clientX;
    const dy = e.clientY - dragStartRef.current.clientY;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      dragStartRef.current.moved = true;
    }
    setTransform((prev) => ({
      ...prev,
      x: dragStartRef.current.startX + dx,
      y: dragStartRef.current.startY + dy,
    }));
  };

  const handleMouseUp = () => {
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

  const exportDiagram = (format: 'svg' | 'png') => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const clone = svgEl.cloneNode(true) as SVGSVGElement;
    clone.setAttribute('width', String(graph.width));
    clone.setAttribute('height', String(graph.height));
    clone.setAttribute('viewBox', `0 0 ${graph.width} ${graph.height}`);

    const rootGroup = clone.querySelector('[data-pan-zoom-root="true"]');
    if (rootGroup) {
      rootGroup.setAttribute('transform', 'translate(0, 0) scale(1)');
    }

    // Prepend solid background rect for standalone SVG/PNG export
    const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bgRect.setAttribute('x', '0');
    bgRect.setAttribute('y', '0');
    bgRect.setAttribute('width', String(graph.width));
    bgRect.setAttribute('height', String(graph.height));
    bgRect.setAttribute('fill', theme === 'dark' ? '#090d16' : '#f8fafc');
    clone.insertBefore(bgRect, clone.firstChild);

    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(clone);
    const safeName = snapshot.displayDomain.replace(/[^a-z0-9.-]/gi, '_') || 'root';

    if (format === 'svg') {
      const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `digdeep-${safeName}.svg`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    const img = new Image();
    const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    img.onload = () => {
      const scale = 2;
      const canvas = document.createElement('canvas');
      canvas.width = graph.width * scale;
      canvas.height = graph.height * scale;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.scale(scale, scale);
        ctx.drawImage(img, 0, 0);
        canvas.toBlob((pngBlob) => {
          if (pngBlob) {
            const pngUrl = URL.createObjectURL(pngBlob);
            const a = document.createElement('a');
            a.href = pngUrl;
            a.download = `digdeep-${safeName}.png`;
            a.click();
            URL.revokeObjectURL(pngUrl);
          }
        }, 'image/png');
      }
      URL.revokeObjectURL(url);
    };
    img.src = url;
  };

  const isDark = theme === 'dark';

  return (
    <div className="flex flex-col lg:flex-row h-[calc(100vh-215px)] min-h-[540px] rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#090d16] overflow-hidden relative">
      {/* Main Interactive Canvas */}
      <div className="flex-1 relative flex flex-col min-h-[380px] overflow-hidden">
        {/* Floating Graph Controls Toolbar */}
        <div className="absolute top-3 left-3 right-3 z-10 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-slate-200/90 dark:border-slate-800/90 bg-white/90 dark:bg-slate-900/90 backdrop-blur px-2.5 py-1.5 shadow-sm pointer-events-auto text-xs">
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
            <label className="inline-flex items-center gap-1.5 cursor-pointer select-none text-slate-700 dark:text-slate-300 pl-1">
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

          <div className="flex items-center gap-1.5 rounded-lg border border-slate-200/90 dark:border-slate-800/90 bg-white/90 dark:bg-slate-900/90 backdrop-blur px-2 py-1 shadow-sm pointer-events-auto text-xs">
            <button
              type="button"
              onClick={() =>
                setTransform((p) => ({ ...p, scale: Math.min(2.4, p.scale * 1.2) }))
              }
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
              onClick={() =>
                setTransform((p) => ({ ...p, scale: Math.max(0.22, p.scale / 1.2) }))
              }
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={fitToViewport}
              className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
              title="Fit chain to viewport"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 mx-0.5" />
            <button
              type="button"
              onClick={() => exportDiagram('svg')}
              className="inline-flex items-center gap-1 px-2 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium cursor-pointer"
              title="Export vector SVG diagram"
            >
              <Download className="w-3.5 h-3.5" />
              SVG
            </button>
            <button
              type="button"
              onClick={() => exportDiagram('png')}
              className="inline-flex items-center gap-1 px-2 py-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium cursor-pointer"
              title="Export high-DPI PNG image"
            >
              <FileImage className="w-3.5 h-3.5" />
              PNG
            </button>
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-800 mx-0.5" />
            <button
              type="button"
              onClick={() => setShowLegend((v) => !v)}
              className={`inline-flex items-center gap-1 px-2 py-1 rounded font-medium cursor-pointer ${
                showLegend
                  ? 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-300'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
              }`}
            >
              <HelpCircle className="w-3.5 h-3.5" />
              Legend
            </button>
          </div>
        </div>

        {/* Interactive Legend Overlay */}
        {showLegend && (
          <div className="absolute top-14 right-3 z-20 w-72 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur p-3.5 shadow-xl text-xs space-y-2.5">
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

        {/* Bottom-left Hint */}
        <div className="absolute bottom-2.5 left-3 z-10 pointer-events-none text-[11px] text-slate-400 dark:text-slate-500 bg-white/75 dark:bg-slate-950/75 px-2.5 py-1 rounded-md backdrop-blur-sm">
          Scroll to zoom · Drag to pan · Click any zone, DNSKEY, RRset, or RRSIG edge to inspect
        </div>

        {/* Pan/Zoom SVG Surface */}
        <div
          ref={containerRef}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          className={`flex-1 w-full h-full graph-canvas-bg select-none ${
            dragging ? 'cursor-grabbing' : 'cursor-grab'
          }`}
        >
          <svg
            ref={svgRef}
            width="100%"
            height="100%"
            xmlns="http://www.w3.org/2000/svg"
            style={{ fontFamily: 'Inter, system-ui, sans-serif' }}
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
                        setSelection({ kind: 'zone', zone: zb.zone });
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
                        setSelection({ kind: 'edge', edge });
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
                        setSelection({ kind: 'node', node });
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
      </div>

      {/* Right-Hand Cryptographic & Wire Inspector Drawer */}
      <GraphInspector selection={selection} onClose={() => setSelection(null)} />
    </div>
  );
}
