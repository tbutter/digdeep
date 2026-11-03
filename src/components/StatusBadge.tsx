import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ShieldOff,
} from 'lucide-react';
import type { ValidationStatus } from '../dns/types';

export const STATUS_META: Record<
  ValidationStatus,
  {
    label: string;
    shortLabel: string;
    badgeClass: string;
    dotClass: string;
    borderClass: string;
    svgStroke: string;
    svgFillDark: string;
    svgFillLight: string;
    svgBadgeBg: string;
    svgBadgeText: string;
  }
> = {
  secure: {
    label: 'SECURE',
    shortLabel: 'Secure',
    badgeClass:
      'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30',
    dotClass: 'bg-emerald-500',
    borderClass: 'border-emerald-500/40',
    svgStroke: '#10b981',
    svgFillDark: '#06281e',
    svgFillLight: '#ecfdf5',
    svgBadgeBg: '#059669',
    svgBadgeText: '#ffffff',
  },
  warning: {
    label: 'VALID · WARN',
    shortLabel: 'Warning',
    badgeClass:
      'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30',
    dotClass: 'bg-amber-500',
    borderClass: 'border-amber-500/40',
    svgStroke: '#f59e0b',
    svgFillDark: '#2b1d07',
    svgFillLight: '#fffbeb',
    svgBadgeBg: '#d97706',
    svgBadgeText: '#ffffff',
  },
  insecure: {
    label: 'INSECURE',
    shortLabel: 'Insecure',
    badgeClass:
      'bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30',
    dotClass: 'bg-slate-400',
    borderClass: 'border-slate-500/40',
    svgStroke: '#64748b',
    svgFillDark: '#161f30',
    svgFillLight: '#f1f5f9',
    svgBadgeBg: '#475569',
    svgBadgeText: '#ffffff',
  },
  bogus: {
    label: 'BOGUS',
    shortLabel: 'Bogus',
    badgeClass:
      'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/35',
    dotClass: 'bg-rose-500',
    borderClass: 'border-rose-500/50',
    svgStroke: '#f43f5e',
    svgFillDark: '#310b16',
    svgFillLight: '#fff1f2',
    svgBadgeBg: '#e11d48',
    svgBadgeText: '#ffffff',
  },
  indeterminate: {
    label: 'INDETERMINATE',
    shortLabel: 'Indeterminate',
    badgeClass:
      'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30',
    dotClass: 'bg-purple-400',
    borderClass: 'border-purple-500/40',
    svgStroke: '#a855f7',
    svgFillDark: '#231236',
    svgFillLight: '#faf5ff',
    svgBadgeBg: '#7e22ce',
    svgBadgeText: '#ffffff',
  },
};

export function StatusIcon({
  status,
  className = 'w-4 h-4',
}: {
  status: ValidationStatus;
  className?: string;
}) {
  switch (status) {
    case 'secure':
      return <CheckCircle2 className={`${className} text-emerald-500`} />;
    case 'warning':
      return <AlertTriangle className={`${className} text-amber-500`} />;
    case 'insecure':
      return <ShieldOff className={`${className} text-slate-400`} />;
    case 'bogus':
      return <ShieldAlert className={`${className} text-rose-500`} />;
    case 'indeterminate':
      return <HelpCircle className={`${className} text-purple-400`} />;
  }
}

export function StatusBadge({
  status,
  size = 'sm',
}: {
  status: ValidationStatus;
  size?: 'xs' | 'sm' | 'md';
}) {
  const meta = STATUS_META[status];
  const sizeCls =
    size === 'xs'
      ? 'text-[10px] px-1.5 py-0.5 gap-1'
      : size === 'sm'
        ? 'text-xs px-2.5 py-0.5 gap-1.5'
        : 'text-xs px-3 py-1 gap-1.5 font-semibold';

  return (
    <span
      className={`inline-flex items-center rounded-full font-mono font-medium tracking-tight ${sizeCls} ${meta.badgeClass}`}
    >
      <StatusIcon status={status} className={size === 'xs' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
      {meta.label}
    </span>
  );
}
