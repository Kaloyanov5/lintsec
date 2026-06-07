import { Link } from 'react-router-dom'
import { cn } from '@/lib/cn'
import type { Scan, ScanStatus } from '@/types'

const STATUS_BADGE: Record<ScanStatus, string> = {
  PENDING: 'bg-slate-100 text-slate-600 dark:bg-slate-500/15 dark:text-slate-300',
  RUNNING: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300',
  COMPLETE: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300',
  FAILED: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300',
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

/** One scan row linking to its results page. Shared by the History and Dashboard pages. */
export function ScanListItem({ scan }: { scan: Scan }) {
  return (
    <Link
      to={`/scans/${scan.id}`}
      className="flex items-center gap-4 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3 transition-colors hover:bg-[color:var(--color-surface-muted)]"
    >
      <span className={cn('shrink-0 rounded-full px-2.5 py-1 text-xs font-medium', STATUS_BADGE[scan.status])}>
        {scan.status}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-sm text-[color:var(--color-foreground)]">
          {scan.targetUrl}
        </span>
        <span className="block text-xs text-[color:var(--color-muted)]">
          {scan.pagesCrawled} pages · {formatDate(scan.createdAt)}
          {scan.authenticated && ' · Authenticated'}
        </span>
      </span>
    </Link>
  )
}
