import type { Severity } from '@/types'

/** Sort weight: CRITICAL first → INFO last. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

/** Tailwind classes for a severity pill / strip cell. */
export const SEVERITY_BADGE: Record<Severity, string> = {
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-300',
  MEDIUM: 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300',
  LOW: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300',
  INFO: 'bg-slate-100 text-slate-600 dark:bg-slate-500/15 dark:text-slate-300',
}

/** Solid accent color per severity — used for stacked-bar segments and chip dots. */
export const SEVERITY_DOT: Record<Severity, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-amber-400',
  LOW: 'bg-sky-500',
  INFO: 'bg-slate-400',
}

/** Severities in display order (CRITICAL → INFO). */
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
