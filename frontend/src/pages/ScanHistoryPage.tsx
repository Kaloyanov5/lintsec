import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
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

export default function ScanHistoryPage() {
  const navigate = useNavigate()
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    scanService
      .listScans()
      .then((page) => {
        if (active) setScans(page.content)
      })
      .catch((err) => {
        if (active) setError(parseProblem(err).message)
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  return (
    <main className="mx-auto max-w-5xl px-6 py-12">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-medium">Scans</h1>
        <Button
          size="sm"
          onClick={() => navigate('/scans/new')}
          leftIcon={<Plus size={15} aria-hidden="true" />}
        >
          New scan
        </Button>
      </div>

      {loading ? (
        <div className="flex justify-center py-24">
          <Spinner />
        </div>
      ) : error ? (
        <p className="mt-6 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4 text-sm text-[color:var(--color-danger)]">
          {error}
        </p>
      ) : scans.length === 0 ? (
        <div className="mt-6 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-10 text-center">
          <p className="text-sm text-[color:var(--color-muted)]">No scans yet.</p>
          <Button className="mt-4" onClick={() => navigate('/scans/new')}>
            Start your first scan
          </Button>
        </div>
      ) : (
        <div className="mt-6 space-y-2">
          {scans.map((scan) => (
            <Link
              key={scan.id}
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
          ))}
        </div>
      )}
    </main>
  )
}
