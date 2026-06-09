import type { Scan, ScanStatus } from '@/types'

const BADGE: Record<ScanStatus, string> = {
  PENDING: 'bg-slate-100 text-slate-600 dark:bg-slate-500/15 dark:text-slate-300',
  RUNNING: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300',
  COMPLETE: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300',
  FAILED: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300',
  CANCELLED: 'bg-slate-100 text-slate-500 dark:bg-slate-500/15 dark:text-slate-400',
}

const CANCELING = 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300'

/** True while a running scan has been asked to cancel but hasn't wound down yet. */
export function isCanceling(scan: Scan): boolean {
  return scan.status === 'RUNNING' && scan.cancelRequested
}

export function isTerminalStatus(status: ScanStatus): boolean {
  return status === 'COMPLETE' || status === 'FAILED' || status === 'CANCELLED'
}

export function statusLabel(scan: Scan): string {
  return isCanceling(scan) ? 'Canceling' : scan.status
}

export function statusBadgeClass(scan: Scan): string {
  return isCanceling(scan) ? CANCELING : BADGE[scan.status]
}
