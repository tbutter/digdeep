import {
  AlertTriangle,
  ArrowRight,
  Binary,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Layers,
  Link2,
  X,
} from 'lucide-react';
import { type PointerEvent, useEffect, useMemo, useState } from 'react';
import type {
  DissectedWirePacket,
  WireCompressionJump,
  WireSectionSpan,
  WireSpanCategory,
  WireSubfieldSpan,
} from '../dns/wireDissector';

export type HexBytesPerRow = 8 | 16;

const NARROW_HEX_MEDIA_QUERY = '(max-width: 639px)';
let persistedManualBytesPerRow: HexBytesPerRow | null = null;

export function resetWireGridWidthPreference(): void {
  persistedManualBytesPerRow = null;
}

function detectNarrowHexViewport(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return Boolean(window.matchMedia(NARROW_HEX_MEDIA_QUERY)?.matches);
}

interface WireSelection {
  sectionId: string;
  fieldId?: string;
  byteOffset?: number;
  jumpId?: string;
}

interface ByteCellMeta {
  section?: WireSectionSpan;
  field?: WireSubfieldSpan;
  pointerJump?: WireCompressionJump;
}

const CATEGORY_STYLES: Record<
  WireSpanCategory,
  {
    badge: string;
    idleByte: string;
    sectionTint: string;
    activeByte: string;
    borderAccent: string;
    label: string;
  }
> = {
  header: {
    label: 'Header',
    badge: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    idleByte: 'text-cyan-300 hover:bg-cyan-500/20',
    sectionTint: 'bg-cyan-500/10 text-cyan-200',
    activeByte: 'bg-cyan-500/35 text-white ring-1 ring-cyan-400 font-bold',
    borderAccent: 'border-l-cyan-400',
  },
  question: {
    label: 'Question',
    badge: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
    idleByte: 'text-sky-300 hover:bg-sky-500/20',
    sectionTint: 'bg-sky-500/10 text-sky-200',
    activeByte: 'bg-sky-500/35 text-white ring-1 ring-sky-400 font-bold',
    borderAccent: 'border-l-sky-400',
  },
  answer: {
    label: 'Answer',
    badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    idleByte: 'text-emerald-300 hover:bg-emerald-500/20',
    sectionTint: 'bg-emerald-500/10 text-emerald-200',
    activeByte: 'bg-emerald-500/35 text-white ring-1 ring-emerald-400 font-bold',
    borderAccent: 'border-l-emerald-400',
  },
  authority: {
    label: 'Authority',
    badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    idleByte: 'text-amber-300 hover:bg-amber-500/20',
    sectionTint: 'bg-amber-500/10 text-amber-200',
    activeByte: 'bg-amber-500/35 text-white ring-1 ring-amber-400 font-bold',
    borderAccent: 'border-l-amber-400',
  },
  additional: {
    label: 'Additional',
    badge: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
    idleByte: 'text-indigo-300 hover:bg-indigo-500/20',
    sectionTint: 'bg-indigo-500/10 text-indigo-200',
    activeByte: 'bg-indigo-500/35 text-white ring-1 ring-indigo-400 font-bold',
    borderAccent: 'border-l-indigo-400',
  },
  edns: {
    label: 'EDNS0 OPT',
    badge: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    idleByte: 'text-purple-300 hover:bg-purple-500/20',
    sectionTint: 'bg-purple-500/10 text-purple-200',
    activeByte: 'bg-purple-500/35 text-white ring-1 ring-purple-400 font-bold',
    borderAccent: 'border-l-purple-400',
  },
};

function fmtHexOffset(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(4, '0')}`;
}

interface InspectorDisplayState {
  key: string;
  section: WireSectionSpan;
  field?: WireSubfieldSpan;
  jump?: WireCompressionJump;
}

function InspectorDescriptionBody({
  section,
  field,
  jump,
  byteOffset,
  byteValue,
  showPinnedControl,
  isSizer,
  onClearPin,
}: {
  section: WireSectionSpan;
  field?: WireSubfieldSpan;
  jump?: WireCompressionJump;
  byteOffset?: number;
  byteValue?: number;
  showPinnedControl: boolean;
  isSizer?: boolean;
  onClearPin?: () => void;
}) {
  const startOff = field?.startOffset ?? section.startOffset;
  const endOff = field?.endOffset ?? section.endOffset;
  const spanLen = endOff - startOff;

  return (
    <div className="space-y-1.5 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 text-xs min-w-0">
          <span
            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
              CATEGORY_STYLES[section.category].badge
            }`}
          >
            {section.title}
          </span>
          {field && (
            <>
              <span className="text-slate-500">/</span>
              <span className="font-semibold text-white">{field.label}</span>
            </>
          )}
          <span className="font-mono text-[11px] text-cyan-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
            {fmtHexOffset(startOff)}..{fmtHexOffset(Math.max(startOff, endOff - 1))} ({spanLen}B)
          </span>
          {byteOffset !== undefined && (
            <span className="font-mono text-[10px] text-slate-400">
              Byte @{fmtHexOffset(byteOffset)} = 0x
              {(byteValue ?? 0).toString(16).toUpperCase().padStart(2, '0')}
            </span>
          )}
        </div>

        {showPinnedControl &&
          (isSizer ? (
            <span className="inline-flex items-center gap-1 rounded bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.5 text-[10px] font-medium text-cyan-200">
              <X className="w-3 h-3" />
              Pinned (clear)
            </span>
          ) : (
            <button
              type="button"
              onClick={onClearPin}
              className="inline-flex items-center gap-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 px-2 py-0.5 text-[10px] font-medium text-cyan-200 cursor-pointer"
            >
              <X className="w-3 h-3" />
              Pinned (clear)
            </button>
          ))}
      </div>

      <div className="font-mono text-[11px] text-slate-300 break-words">
        {field ? field.valueSummary : section.subtitle}
      </div>

      {jump && (
        <div className="rounded border border-fuchsia-500/30 bg-fuchsia-950/25 px-2.5 py-1.5 font-mono text-[11px] text-fuchsia-200 flex flex-wrap items-center gap-1.5">
          <span className="font-semibold text-fuchsia-300">Pointer Trace:</span>
          {jump.hops.map((hop, idx) => (
            <span key={hop.pointerOffset} className="inline-flex items-center gap-1">
              {idx > 0 && <span className="text-slate-500">→</span>}
              <span className="rounded bg-fuchsia-500/25 px-1 text-fuchsia-200">
                {fmtHexOffset(hop.pointerOffset)} ({hop.pointerHex})
              </span>
              <ArrowRight className="w-3 h-3 text-amber-400" />
              <span className="rounded bg-amber-500/25 px-1 text-amber-200">
                {fmtHexOffset(hop.targetOffset)} &quot;{hop.resolvedSuffix}&quot;
              </span>
            </span>
          ))}
          <span className="text-slate-400">·</span>
          <span className="text-emerald-300 break-all">
            FQDN: {jump.fullName} ({jump.inlineBytes}B inline vs {jump.uncompressedBytes}B
            uncompressed, saves {jump.savedBytes}B)
          </span>
        </div>
      )}
    </div>
  );
}

export function WirePacketDissectorView({
  dissected,
  packetLabel = 'DNS Wire Packet',
  defaultBytesPerRow,
}: {
  dissected: DissectedWirePacket;
  packetLabel?: string;
  defaultBytesPerRow?: HexBytesPerRow;
}) {
  const [pinned, setPinned] = useState<WireSelection | null>(null);
  const [hovered, setHovered] = useState<WireSelection | null>(null);
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [copiedB64Url, setCopiedB64Url] = useState(false);
  const [manualBytesPerRow, setManualBytesPerRow] = useState<HexBytesPerRow | null>(
    () => defaultBytesPerRow ?? persistedManualBytesPerRow
  );
  const [isNarrowViewport, setIsNarrowViewport] = useState<boolean>(detectNarrowHexViewport);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const mql = window.matchMedia(NARROW_HEX_MEDIA_QUERY);
    if (!mql) return;
    setIsNarrowViewport(Boolean(mql.matches));
    const onChange = (ev: MediaQueryListEvent) => setIsNarrowViewport(ev.matches);
    if (typeof mql.addEventListener === 'function') {
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    }
    if (typeof mql.addListener === 'function') {
      mql.addListener(onChange);
      return () => mql.removeListener(onChange);
    }
  }, []);

  const bytesPerRow: HexBytesPerRow =
    manualBytesPerRow ?? defaultBytesPerRow ?? (isNarrowViewport ? 8 : 16);
  const midColIdx = bytesPerRow === 8 ? 3 : 7;

  const chooseBytesPerRow = (next: HexBytesPerRow) => {
    persistedManualBytesPerRow = next;
    setManualBytesPerRow(next);
  };

  const handleHoverEnter = (e: PointerEvent<HTMLElement>, sel: WireSelection) => {
    if (e.pointerType !== 'touch') {
      setHovered(sel);
    }
  };

  const handleHoverLeave = (e: PointerEvent<HTMLElement>) => {
    if (e.pointerType !== 'touch') {
      setHovered(null);
    }
  };

  const byteLookup = useMemo<ByteCellMeta[]>(() => {
    const table: ByteCellMeta[] = Array.from({ length: dissected.wireSize }, () => ({}));
    for (const section of dissected.spans) {
      const sStart = Math.max(0, section.startOffset);
      const sEnd = Math.min(dissected.wireSize, section.endOffset);
      for (let i = sStart; i < sEnd; i++) {
        table[i].section = section;
      }
      for (const field of section.fields) {
        const fStart = Math.max(0, field.startOffset);
        const fEnd = Math.min(dissected.wireSize, field.endOffset);
        for (let i = fStart; i < fEnd; i++) {
          table[i].field = field;
        }
      }
    }
    for (const jump of dissected.compressionJumps) {
      for (let i = jump.pointerOffset; i < Math.min(dissected.wireSize, jump.pointerOffset + 2); i++) {
        table[i].pointerJump = jump;
      }
    }
    return table;
  }, [dissected]);

  const validPinned = useMemo(() => {
    if (!pinned) return null;
    return dissected.spans.some((s) => s.id === pinned.sectionId) ? pinned : null;
  }, [pinned, dissected.spans]);

  const activeSelection = hovered ?? validPinned;

  const activeContext = useMemo(() => {
    if (!activeSelection) return null;
    const section = dissected.spans.find((s) => s.id === activeSelection.sectionId);
    if (!section) return null;
    const field = activeSelection.fieldId
      ? section.fields.find((f) => f.id === activeSelection.fieldId)
      : undefined;

    let jump: WireCompressionJump | undefined;
    if (activeSelection.jumpId) {
      jump = dissected.compressionJumps.find((j) => j.id === activeSelection.jumpId);
    } else if (field?.isCompressionPointer) {
      jump = dissected.compressionJumps.find((j) => j.pointerOffset === field.startOffset);
    } else if (activeSelection.byteOffset !== undefined) {
      jump = byteLookup[activeSelection.byteOffset]?.pointerJump;
    }

    const pointerByteSet = new Set<number>();
    const targetByteSet = new Set<number>();
    const prefixByteSet = new Set<number>();
    if (jump) {
      for (let i = jump.nameStartOffset; i < jump.pointerOffset; i++) {
        prefixByteSet.add(i);
      }
      for (const hop of jump.hops) {
        pointerByteSet.add(hop.pointerOffset);
        pointerByteSet.add(hop.pointerOffset + 1);
        for (let k = 0; k < hop.targetSpanLength; k++) {
          const tIdx = hop.targetOffset + k;
          if (tIdx >= 0 && tIdx < dissected.wireSize && !pointerByteSet.has(tIdx)) {
            targetByteSet.add(tIdx);
          }
        }
      }
    }

    return {
      section,
      field,
      jump,
      pointerByteSet,
      targetByteSet,
      prefixByteSet,
    };
  }, [activeSelection, dissected, byteLookup]);

  const hexRows = useMemo(() => {
    const rows: Array<{ rowOffset: number; bytes: number[] }> = [];
    for (let offset = 0; offset < dissected.wireSize; offset += bytesPerRow) {
      const slice: number[] = [];
      for (let j = 0; j < bytesPerRow && offset + j < dissected.wireSize; j++) {
        slice.push(dissected.bytes[offset + j]);
      }
      rows.push({ rowOffset: offset, bytes: slice });
    }
    return rows;
  }, [dissected, bytesPerRow]);

  const togglePin = (sel: WireSelection) => {
    setPinned((prev) => {
      if (
        prev &&
        prev.sectionId === sel.sectionId &&
        prev.fieldId === sel.fieldId &&
        prev.jumpId === sel.jumpId &&
        prev.byteOffset === sel.byteOffset
      ) {
        return null;
      }
      return sel;
    });
  };

  const selectJump = (jump: WireCompressionJump, pin: boolean, pointerType?: string) => {
    if (!pin && pointerType === 'touch') return;
    const meta = byteLookup[jump.pointerOffset];
    const sel: WireSelection = {
      sectionId: meta?.section?.id ?? dissected.spans[0]?.id ?? 'section-header',
      fieldId: meta?.field?.id,
      byteOffset: jump.pointerOffset,
      jumpId: jump.id,
    };
    if (pin) {
      togglePin(sel);
    } else {
      setHovered(sel);
    }
  };

  const presentCategories = useMemo(() => {
    const seen = new Set<WireSpanCategory>();
    for (const s of dissected.spans) seen.add(s.category);
    return Array.from(seen);
  }, [dissected.spans]);

  // Precompute deduplicated reachable description states so CSS Grid locks the inspector banner
  // height to the tallest description in this packet (preventing hex-grid vertical layout jumps on hover).
  const inspectorSizerCandidates = useMemo<InspectorDisplayState[]>(() => {
    const seenKeys = new Set<string>();
    const all: Array<InspectorDisplayState & { score: number; headerScore: number; summaryScore: number; jumpScore: number }> = [];

    const addCandidate = (
      section: WireSectionSpan,
      field?: WireSubfieldSpan,
      jump?: WireCompressionJump
    ) => {
      const summary = field ? field.valueSummary : section.subtitle;
      const startOff = field?.startOffset ?? section.startOffset;
      const endOff = field?.endOffset ?? section.endOffset;
      const spanDigits = String(endOff - startOff).length;
      const dedupKey = `${section.title}|${field?.label ?? ''}|${spanDigits}|${summary}|${jump?.id ?? ''}`;
      if (seenKeys.has(dedupKey)) return;
      seenKeys.add(dedupKey);

      const headerScore = section.title.length + (field ? field.label.length + 3 : 0) + spanDigits;
      const summaryScore = summary.length;
      const jumpScore = jump
        ? 60 +
          jump.fullName.length +
          jump.hops.reduce((acc, h) => acc + h.resolvedSuffix.length + 18, 0)
        : 0;

      all.push({
        key: dedupKey,
        section,
        field,
        jump,
        score: headerScore + summaryScore + jumpScore,
        headerScore,
        summaryScore,
        jumpScore,
      });
    };

    for (const section of dissected.spans) {
      addCandidate(section, undefined, undefined);
      for (const field of section.fields) {
        const directJump = field.isCompressionPointer
          ? dissected.compressionJumps.find((j) => j.pointerOffset === field.startOffset)
          : dissected.compressionJumps.find(
              (j) => j.pointerOffset >= field.startOffset && j.pointerOffset < field.endOffset
            );
        if (directJump) {
          addCandidate(section, field, directJump);
        } else {
          addCandidate(section, field, undefined);
        }
      }
    }

    for (const jump of dissected.compressionJumps) {
      const meta = byteLookup[jump.pointerOffset];
      if (meta?.section) {
        addCandidate(meta.section, meta.field, jump);
      }
    }

    if (all.length <= 40) {
      return all;
    }

    const picked = new Map<string, InspectorDisplayState>();
    const pickTop = (
      sorted: typeof all,
      limit: number
    ) => {
      for (let i = 0; i < Math.min(limit, sorted.length); i++) {
        picked.set(sorted[i].key, sorted[i]);
      }
    };
    pickTop([...all].sort((a, b) => b.score - a.score), 16);
    pickTop([...all].sort((a, b) => b.summaryScore - a.summaryScore), 10);
    pickTop([...all].sort((a, b) => b.headerScore - a.headerScore), 8);
    pickTop([...all].filter((x) => x.jumpScore > 0).sort((a, b) => b.jumpScore - a.jumpScore), 10);
    return Array.from(picked.values());
  }, [dissected, byteLookup]);

  const { compressionStats } = dissected;

  return (
    <div className="space-y-3 text-slate-200" data-testid="wire-packet-dissector">
      {/* 1. Top Wire Telemetry & Compression Savings Bar */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/90 p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-100">
              <Binary className="w-3.5 h-3.5 text-cyan-400" />
              {packetLabel}
            </span>
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300 border border-slate-700">
              {dissected.wireSize} bytes (0x0000..{fmtHexOffset(Math.max(0, dissected.wireSize - 1))})
            </span>
            {compressionStats.pointerCount > 0 ? (
              <span
                className="inline-flex items-center gap-1.5 rounded bg-fuchsia-500/15 px-2 py-0.5 font-mono text-[11px] text-fuchsia-300 border border-fuchsia-500/30"
                title="RFC 1035 §4.1.4 Domain Name Message Compression Savings"
              >
                <Link2 className="w-3 h-3" />
                {compressionStats.pointerCount} 0xC0xx pointer{compressionStats.pointerCount === 1 ? '' : 's'} ·
                saved {compressionStats.totalSavedBytes}B (-{compressionStats.savingsPercent}% vs{' '}
                {compressionStats.uncompressedEquivalentSize}B uncompressed)
              </span>
            ) : (
              <span className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-slate-400 border border-slate-800">
                0 compression pointers (uncompressed)
              </span>
            )}
          </div>

          <button
            type="button"
            onClick={() => {
              navigator.clipboard?.writeText(dissected.base64Url);
              setCopiedB64Url(true);
              setTimeout(() => setCopiedB64Url(false), 1500);
            }}
            className="inline-flex items-center gap-1 rounded border border-slate-700 hover:border-cyan-500 bg-slate-950 px-2 py-1 font-mono text-[11px] text-slate-300 hover:text-white cursor-pointer"
            title="Copy RFC 8484 Base64url (?dns=...) wire payload"
          >
            {copiedB64Url ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span>Copied ?dns=</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy ?dns= Base64url</span>
              </>
            )}
          </button>
        </div>

        {/* Section Color Legend */}
        <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
          <span className="text-slate-500 uppercase tracking-wider font-semibold mr-1">
            Wire Map:
          </span>
          {presentCategories.map((cat) => (
            <span
              key={cat}
              className={`rounded border px-1.5 py-0.5 font-mono ${CATEGORY_STYLES[cat].badge}`}
            >
              {CATEGORY_STYLES[cat].label}
            </span>
          ))}
          {compressionStats.pointerCount > 0 && (
            <span className="rounded border border-fuchsia-500/40 bg-fuchsia-500/15 px-1.5 py-0.5 font-mono text-fuchsia-300">
              0xC0xx Pointer
            </span>
          )}
          {compressionStats.pointerCount > 0 && (
            <span className="rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-amber-300">
              Pointer Target Label
            </span>
          )}
        </div>

        {dissected.parseWarning && (
          <div className="flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <span>
              <strong>Partial / Truncated Wire Dissection:</strong> {dissected.parseWarning}
            </span>
          </div>
        )}
      </div>

      {/* 2. 16-Bit Header Flags & RCODE Register (Bytes 0x0002..0x0003) */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/90 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div className="text-[11px] font-semibold text-slate-300 flex items-center gap-2">
            <span>16-Bit Header Flags Register</span>
            <span className="font-mono text-cyan-300">
              Offset 0x0002..0x0003 = {dissected.flagWordHex}
            </span>
          </div>
          <span className="font-mono text-[10px] text-slate-400 tracking-widest">
            0b{dissected.flagWordBinary.slice(0, 8)}_{dissected.flagWordBinary.slice(8)}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-1.5">
          {dissected.headerBits.map((bit) => (
            <button
              key={bit.name}
              type="button"
              onPointerEnter={(e) =>
                handleHoverEnter(e, {
                  sectionId: 'section-header',
                  fieldId: 'hdr-flags',
                  byteOffset: 2,
                })
              }
              onPointerLeave={handleHoverLeave}
              onClick={() =>
                togglePin({
                  sectionId: 'section-header',
                  fieldId: 'hdr-flags',
                  byteOffset: 2,
                })
              }
              title={`${bit.name} (${bit.bitsLabel}, mask ${bit.maskHex}): ${bit.summary}`}
              className={`rounded border px-2 py-1.5 text-left transition-colors cursor-pointer ${
                bit.active
                  ? bit.name === 'Z' || (bit.name === 'RCODE' && bit.numericValue !== 0)
                    ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
                    : 'border-cyan-500/50 bg-cyan-500/15 text-cyan-100'
                  : 'border-slate-800 bg-slate-950/70 text-slate-400 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-1">
                <span className="font-mono text-[10px] font-bold">{bit.name}</span>
                <span className="font-mono text-[10px] opacity-80">{bit.binaryValue}</span>
              </div>
              <div className="text-[9px] truncate mt-0.5 opacity-85">{bit.summary}</div>
            </button>
          ))}
        </div>
      </div>

      {/* 3. RFC 1035 §4.1.4 Compression Pointer (0xC0xx) Jump Tracer Strip */}
      {dissected.compressionJumps.length > 0 && (
        <div className="rounded-lg border border-fuchsia-500/25 bg-fuchsia-950/15 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="text-[11px] font-semibold text-fuchsia-200 flex items-center gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-fuchsia-400" />
              <span>RFC 1035 §4.1.4 Compression Pointer Jumps ({dissected.compressionJumps.length})</span>
            </div>
            <span className="text-[10px] text-fuchsia-300/80">
              Tap or hover a pointer to trace source → target label bytes
            </span>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {dissected.compressionJumps.map((jump) => {
              const isSelected = activeContext?.jump?.id === jump.id;
              const firstHop = jump.hops[0];
              return (
                <button
                  key={jump.id}
                  type="button"
                  onPointerEnter={(e) => selectJump(jump, false, e.pointerType)}
                  onPointerLeave={handleHoverLeave}
                  onClick={() => selectJump(jump, true)}
                  className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-[11px] transition-colors cursor-pointer ${
                    isSelected
                      ? 'border-fuchsia-400 bg-fuchsia-500/30 text-white ring-1 ring-fuchsia-400'
                      : 'border-fuchsia-500/30 bg-slate-950/80 text-fuchsia-200 hover:bg-fuchsia-500/20'
                  }`}
                >
                  <span className="text-fuchsia-300 font-semibold">
                    {fmtHexOffset(jump.pointerOffset)}
                  </span>
                  <span className="text-slate-400">[{firstHop.pointerHex}]</span>
                  <ArrowRight className="w-3 h-3 text-amber-400 shrink-0" />
                  <span className="text-amber-300 font-semibold">
                    {fmtHexOffset(jump.targetOffset)}
                  </span>
                  <span className="text-slate-300 truncate max-w-[170px]">{jump.fullName}</span>
                  <span className="text-emerald-400 text-[10px]">(-{jump.savedBytes}B)</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* 4. Sticky Active Byte / Subfield & Pointer Jump Inspector Banner (CSS-Grid locked to tallest description in packet) */}
      <div
        className="sticky top-0 z-20 rounded-lg border border-slate-700/90 bg-slate-900/95 backdrop-blur-sm px-3 py-2.5 min-h-[58px] shadow-md shadow-slate-950/80 grid grid-cols-1 items-start"
        data-testid="wire-inspector-banner"
      >
        {/* Invisible sizer stack: reserves exact height of the longest description in this packet */}
        <div
          aria-hidden="true"
          data-wire-sizer="idle"
          className="col-start-1 row-start-1 self-center invisible pointer-events-none select-none min-w-0 text-[11px] flex items-center gap-2"
        >
          <Layers className="w-3.5 h-3.5 shrink-0" />
          <span>
            Tap or hover any hex byte, ASCII character, compression pointer, or decoded RFC field
            below to highlight its exact wire span. Tap or click to pin selection.
          </span>
        </div>
        {inspectorSizerCandidates.map((cand) => (
          <div
            key={cand.key}
            aria-hidden="true"
            data-wire-sizer="candidate"
            className="col-start-1 row-start-1 invisible pointer-events-none select-none min-w-0"
          >
            <InspectorDescriptionBody
              section={cand.section}
              field={cand.field}
              jump={cand.jump}
              byteOffset={cand.field?.startOffset ?? cand.section.startOffset}
              byteValue={0xff}
              showPinnedControl={true}
              isSizer={true}
            />
          </div>
        ))}

        {/* Visible active or idle description */}
        <div
          className={`col-start-1 row-start-1 min-w-0 ${activeContext ? '' : 'self-center'}`}
        >
          {activeContext ? (
            <InspectorDescriptionBody
              section={activeContext.section}
              field={activeContext.field}
              jump={activeContext.jump}
              byteOffset={activeSelection?.byteOffset}
              byteValue={
                activeSelection?.byteOffset !== undefined
                  ? dissected.bytes[activeSelection.byteOffset]
                  : undefined
              }
              showPinnedControl={Boolean(validPinned)}
              onClearPin={() => {
                setPinned(null);
                setHovered(null);
              }}
            />
          ) : (
            <div className="text-[11px] text-slate-400 flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>
                Tap or hover any hex byte, ASCII character, compression pointer, or decoded RFC
                field below to highlight its exact wire span. Tap or click to pin selection.
              </span>
            </div>
          )}
        </div>
      </div>

      {/* 5. Synchronized Offset-Mapped Hex & ASCII Grid (Responsive 8B Mobile / 16B Desktop) */}
      <div
        className="rounded-lg border border-slate-800 bg-slate-950 p-2 sm:p-3"
        data-testid="wire-hex-grid"
        data-bytes-per-row={bytesPerRow}
      >
        <div className="flex items-center justify-between gap-2 mb-2 text-[10px] font-mono text-slate-500 select-none">
          <span>
            {dissected.wireSize} OCTETS · {bytesPerRow}B/ROW
          </span>
          <div
            className="inline-flex items-center rounded border border-slate-800 bg-slate-900 p-0.5 text-[10px] font-mono"
            role="group"
            aria-label="Hex bytes per row"
          >
            <button
              type="button"
              data-testid="wire-grid-width-8"
              aria-pressed={bytesPerRow === 8}
              onClick={() => chooseBytesPerRow(8)}
              className={`px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
                bytesPerRow === 8
                  ? 'bg-cyan-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Compact 8 bytes per row (fits narrow mobile screens without horizontal scrolling)"
            >
              8B
            </button>
            <button
              type="button"
              data-testid="wire-grid-width-16"
              aria-pressed={bytesPerRow === 16}
              onClick={() => chooseBytesPerRow(16)}
              className={`px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
                bytesPerRow === 16
                  ? 'bg-cyan-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Full 16 bytes per row"
            >
              16B
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <div
            className="flex items-center whitespace-nowrap mb-1 pb-1 border-b border-slate-900 text-[10px] font-mono text-slate-500 select-none"
            data-testid="wire-grid-ruler"
          >
            <span className="w-10 sm:w-14 shrink-0">OFFSET</span>
            <div className="flex items-center">
              {Array.from({ length: bytesPerRow }).map((_, colIdx) => {
                const spacer =
                  colIdx === bytesPerRow - 1
                    ? ''
                    : colIdx === midColIdx
                      ? bytesPerRow === 8
                        ? 'mr-1.5'
                        : 'mr-2'
                      : 'mr-0.5';
                return (
                  <span
                    key={colIdx}
                    className={`inline-block w-[18px] sm:w-5 text-center ${spacer}`}
                  >
                    {colIdx.toString(16).toUpperCase().padStart(2, '0')}
                  </span>
                );
              })}
            </div>
            <div className="ml-1.5 sm:ml-3 pl-1.5 sm:pl-2 border-l border-slate-800/70">
              <span>ASCII</span>
            </div>
          </div>

          <div className="space-y-0.5 font-mono text-[11px] leading-5">
            {hexRows.map((row) => (
              <div
                key={row.rowOffset}
                data-row-offset={row.rowOffset.toString(16).toUpperCase().padStart(4, '0')}
                className="flex items-center whitespace-nowrap"
              >
                <span className="w-10 sm:w-14 shrink-0 text-slate-500 select-none">
                  {row.rowOffset.toString(16).toUpperCase().padStart(4, '0')}
                </span>

                {/* 8 or 16 Hex Octets */}
                <div className="flex items-center">
                  {Array.from({ length: bytesPerRow }).map((_, colIdx) => {
                    const byteOffset = row.rowOffset + colIdx;
                    const spacer =
                      colIdx === bytesPerRow - 1
                        ? ''
                        : colIdx === midColIdx
                          ? bytesPerRow === 8
                            ? 'mr-1.5'
                            : 'mr-2'
                          : 'mr-0.5';
                    if (colIdx >= row.bytes.length) {
                      return (
                        <span
                          key={colIdx}
                          className={`inline-block w-[18px] sm:w-5 text-center select-none ${spacer}`}
                        >
                          {'  '}
                        </span>
                      );
                    }

                    const byteVal = row.bytes[colIdx];
                    const meta = byteLookup[byteOffset];
                    const cat = meta?.section?.category;
                    const style = cat ? CATEGORY_STYLES[cat] : undefined;

                    const isPointerJumpSource = activeContext?.pointerByteSet.has(byteOffset);
                    const isPointerJumpTarget = activeContext?.targetByteSet.has(byteOffset);
                    const isPointerPrefix = activeContext?.prefixByteSet.has(byteOffset);

                    const isFieldActive =
                      activeContext?.field &&
                      byteOffset >= activeContext.field.startOffset &&
                      byteOffset < activeContext.field.endOffset;
                    const isSectionOnlyActive =
                      activeContext &&
                      !activeContext.field &&
                      byteOffset >= activeContext.section.startOffset &&
                      byteOffset < activeContext.section.endOffset;
                    const isSameSection =
                      activeContext &&
                      byteOffset >= activeContext.section.startOffset &&
                      byteOffset < activeContext.section.endOffset;

                    let cellClass = style ? style.idleByte : 'text-slate-400 hover:bg-slate-800';
                    if (meta?.pointerJump) {
                      cellClass =
                        'text-fuchsia-300 underline decoration-fuchsia-400/80 decoration-dotted underline-offset-2 font-semibold hover:bg-fuchsia-500/25';
                    }
                    if (isSameSection && style) {
                      cellClass = style.sectionTint;
                    }
                    if ((isFieldActive || isSectionOnlyActive) && style) {
                      cellClass = style.activeByte;
                    }
                    if (isPointerPrefix) {
                      cellClass = 'bg-fuchsia-500/20 text-fuchsia-100 ring-1 ring-fuchsia-500/40';
                    }
                    if (isPointerJumpTarget) {
                      cellClass = 'bg-amber-400/30 text-amber-100 ring-1 ring-amber-400 font-bold';
                    }
                    if (isPointerJumpSource) {
                      cellClass = 'bg-fuchsia-500/45 text-white ring-1 ring-fuchsia-400 font-bold';
                    }

                    const sel: WireSelection = {
                      sectionId: meta?.section?.id ?? dissected.spans[0]?.id ?? 'section-header',
                      fieldId: meta?.field?.id,
                      byteOffset,
                      jumpId: meta?.pointerJump?.id,
                    };

                    return (
                      <button
                        key={colIdx}
                        type="button"
                        onPointerEnter={(e) => handleHoverEnter(e, sel)}
                        onPointerLeave={handleHoverLeave}
                        onClick={() => togglePin(sel)}
                        className={`inline-block w-[18px] sm:w-5 rounded-[3px] text-center transition-colors cursor-pointer ${spacer} ${cellClass}`}
                        title={`${fmtHexOffset(byteOffset)}: ${meta?.section?.title ?? 'Trailing Byte'}${meta?.field ? ` — ${meta.field.label}` : ''}`}
                      >
                        {byteVal.toString(16).toUpperCase().padStart(2, '0')}
                      </button>
                    );
                  })}
                </div>

                {/* 8-Byte or 16-Byte ASCII Column */}
                <div className="ml-1.5 sm:ml-3 pl-1.5 sm:pl-2 border-l border-slate-800 flex items-center text-slate-400">
                  <span className="text-slate-600 select-none">|</span>
                  {row.bytes.map((byteVal, colIdx) => {
                    const byteOffset = row.rowOffset + colIdx;
                    const meta = byteLookup[byteOffset];
                    const ch =
                      byteVal >= 0x20 && byteVal <= 0x7e ? String.fromCharCode(byteVal) : '.';

                    const isPointerJumpSource = activeContext?.pointerByteSet.has(byteOffset);
                    const isPointerJumpTarget = activeContext?.targetByteSet.has(byteOffset);
                    const isFieldActive =
                      activeContext?.field &&
                      byteOffset >= activeContext.field.startOffset &&
                      byteOffset < activeContext.field.endOffset;
                    const isSectionOnlyActive =
                      activeContext &&
                      !activeContext.field &&
                      byteOffset >= activeContext.section.startOffset &&
                      byteOffset < activeContext.section.endOffset;

                    let asciiClass = 'text-slate-400 hover:text-white';
                    if (isFieldActive || isSectionOnlyActive) {
                      asciiClass = 'bg-cyan-500/30 text-white font-bold';
                    }
                    if (isPointerJumpTarget) {
                      asciiClass = 'bg-amber-400/30 text-amber-100 font-bold';
                    }
                    if (isPointerJumpSource) {
                      asciiClass = 'bg-fuchsia-500/45 text-fuchsia-100 font-bold';
                    }

                    const sel: WireSelection = {
                      sectionId: meta?.section?.id ?? dissected.spans[0]?.id ?? 'section-header',
                      fieldId: meta?.field?.id,
                      byteOffset,
                      jumpId: meta?.pointerJump?.id,
                    };

                    return (
                      <button
                        key={colIdx}
                        type="button"
                        onPointerEnter={(e) => handleHoverEnter(e, sel)}
                        onPointerLeave={handleHoverLeave}
                        onClick={() => togglePin(sel)}
                        className={`inline-block w-[7px] sm:w-[8px] text-center rounded-[2px] cursor-pointer ${asciiClass}`}
                      >
                        {ch}
                      </button>
                    );
                  })}
                  <span className="text-slate-600 select-none">|</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 6. Structural RFC 1035 / RFC 6891 Section & Subfield Tree */}
      <div className="space-y-2">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-0.5">
          Decoded Packet Structure ({dissected.spans.length} Section{dissected.spans.length === 1 ? '' : 's'})
        </div>

        {dissected.spans.map((section) => {
          const style = CATEGORY_STYLES[section.category];
          const isCollapsed = Boolean(collapsedSections[section.id]);
          const isSectionActive = activeContext?.section.id === section.id;

          return (
            <div
              key={section.id}
              className={`rounded-lg border bg-slate-900/80 overflow-hidden border-l-4 ${style.borderAccent} ${
                isSectionActive ? 'border-slate-600' : 'border-slate-800'
              }`}
            >
              <div
                className="flex items-center justify-between gap-2 px-3 py-2 bg-slate-900/95 hover:bg-slate-800/70 transition-colors cursor-pointer"
                onPointerEnter={(e) => handleHoverEnter(e, { sectionId: section.id })}
                onPointerLeave={handleHoverLeave}
                onClick={() =>
                  setCollapsedSections((prev) => ({ ...prev, [section.id]: !prev[section.id] }))
                }
              >
                <div className="flex items-center gap-2 min-w-0">
                  {isCollapsed ? (
                    <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  )}
                  <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] shrink-0 ${style.badge}`}>
                    {style.label}
                  </span>
                  <span className="font-mono text-xs font-semibold text-slate-100 truncate">
                    {section.title}
                  </span>
                </div>
                <span className="font-mono text-[11px] text-slate-400 shrink-0">
                  {section.subtitle}
                </span>
              </div>

              {!isCollapsed && (
                <div className="divide-y divide-slate-800/70 border-t border-slate-800">
                  {section.fields.map((field) => {
                    const isFieldSelected = activeContext?.field?.id === field.id;
                    const linkedJump = field.isCompressionPointer
                      ? dissected.compressionJumps.find((j) => j.pointerOffset === field.startOffset)
                      : undefined;

                    const sel: WireSelection = {
                      sectionId: section.id,
                      fieldId: field.id,
                      byteOffset: field.startOffset,
                      jumpId: linkedJump?.id,
                    };

                    return (
                      <button
                        key={field.id}
                        type="button"
                        onPointerEnter={(e) => handleHoverEnter(e, sel)}
                        onPointerLeave={handleHoverLeave}
                        onClick={() => togglePin(sel)}
                        className={`w-full text-left px-3 py-1.5 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono transition-colors cursor-pointer ${
                          isFieldSelected
                            ? field.isCompressionPointer
                              ? 'bg-fuchsia-500/20 text-white'
                              : 'bg-cyan-500/15 text-white'
                            : 'hover:bg-slate-800/60 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-slate-500 w-24 shrink-0">
                            {fmtHexOffset(field.startOffset)}..
                            {fmtHexOffset(Math.max(field.startOffset, field.endOffset - 1))}
                          </span>
                          <span
                            className={`font-semibold ${
                              field.isCompressionPointer ? 'text-fuchsia-300' : 'text-slate-200'
                            }`}
                          >
                            {field.label}
                          </span>
                        </div>
                        <div className="text-right text-slate-300 truncate max-w-full sm:max-w-[60%]">
                          {field.valueSummary}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
