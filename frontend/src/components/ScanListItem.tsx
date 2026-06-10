import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { RotateCw, Trash2, X } from 'lucide-react'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import { isCanceling, isTerminalStatus } from '@/lib/scanStatus'
import { StatusBadge } from '@/components/StatusBadge'
import type { Scan } from '@/types'

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

/**
 * One scan row linking to its results page. Shared by the History and Dashboard pages.
 * When `onChanged` is provided, lifecycle actions (cancel/re-run/delete) are shown and
 * call `onChanged` after a successful mutation so the parent can refresh.
 */
export function ScanListItem({ scan, onChanged }: { scan: Scan; onChanged?: () => void }) {
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)

  const canceling = isCanceling(scan)
  const terminal = isTerminalStatus(scan.status)

  async function onCancel() {
    setBusy(true)
    try {
      await scanService.cancelScan(scan.id)
      toast.success('Cancellation requested.')
      onChanged?.()
    } catch (err) {
      toast.error(parseProblem(err).message)
    } finally {
      setBusy(false)
    }
  }

  async function onDelete() {
    if (!window.confirm('Delete this scan and all its findings? This cannot be undone.')) return
    setBusy(true)
    try {
      await scanService.deleteScan(scan.id)
      toast.success('Scan deleted.')
      onChanged?.()
    } catch (err) {
      toast.error(parseProblem(err).message)
    } finally {
      setBusy(false)
    }
  }

  function onRerun() {
    navigate('/scans/new', { state: { from: scan } })
  }

  return (
    <div className="flex items-center gap-4 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3 shadow-[var(--shadow-card)] transition-all duration-200 hover:-translate-y-0.5 hover:border-[color:var(--color-border-strong)] hover:shadow-[var(--shadow-card-hover)]">
      <Link to={`/scans/${scan.id}`} className="flex min-w-0 flex-1 items-center gap-4">
        <StatusBadge scan={scan} />
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

      {onChanged && (
        <div className="flex shrink-0 items-center gap-1">
          {scan.status === 'RUNNING' && (
            <button
              type="button"
              onClick={onCancel}
              disabled={busy || canceling}
              title={canceling ? 'Canceling…' : 'Cancel scan'}
              className="rounded-md p-1.5 text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)] disabled:opacity-50"
            >
              <X size={16} aria-hidden="true" />
              <span className="sr-only">Cancel scan</span>
            </button>
          )}
          {terminal && (
            <button
              type="button"
              onClick={onRerun}
              disabled={busy}
              title="Re-run scan"
              className="rounded-md p-1.5 text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)] disabled:opacity-50"
            >
              <RotateCw size={16} aria-hidden="true" />
              <span className="sr-only">Re-run scan</span>
            </button>
          )}
          {terminal && (
            <button
              type="button"
              onClick={onDelete}
              disabled={busy}
              title="Delete scan"
              className="rounded-md p-1.5 text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-danger)] disabled:opacity-50"
            >
              <Trash2 size={16} aria-hidden="true" />
              <span className="sr-only">Delete scan</span>
            </button>
          )}
        </div>
      )}
    </div>
  )
}
