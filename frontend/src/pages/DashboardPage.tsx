import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Radar, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ScanListItem } from '@/components/ScanListItem'
import { cn } from '@/lib/cn'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import { useAuth } from '@/contexts/AuthContext'
import { SEVERITIES, SEVERITY_BADGE } from '@/lib/severity'
import type { Scan, ScanStats } from '@/types'

export default function DashboardPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [recent, setRecent] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    Promise.all([scanService.getStats(), scanService.listScans(0, 5)])
      .then(([statsResult, page]) => {
        if (!active) return
        setStats(statsResult)
        setRecent(page.content)
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

  const name = user?.displayName ?? user?.email ?? 'there'

  if (loading) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-12">
        <div className="flex justify-center py-24">
          <Spinner />
        </div>
      </main>
    )
  }

  if (error || !stats) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-12">
        <p className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4 text-sm text-[color:var(--color-danger)]">
          {error ?? 'Could not load your dashboard.'}
        </p>
      </main>
    )
  }

  // Onboarding hero — a brand-new user with no scans.
  if (stats.totalScans === 0) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-12">
        <h1 className="text-2xl font-medium">Welcome to LintSec, {name}</h1>
        <div className="mt-6 flex flex-col items-center rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-6 py-16 text-center">
          <ShieldCheck size={40} className="text-[color:var(--color-muted)]" aria-hidden="true" />
          <h2 className="mt-4 text-lg font-medium">No scans yet</h2>
          <p className="mt-1 max-w-sm text-sm text-[color:var(--color-muted)]">
            Point LintSec at a site you own to find security issues.
          </p>
          <Button
            className="mt-6"
            onClick={() => navigate('/scans/new')}
            leftIcon={<Plus size={15} aria-hidden="true" />}
          >
            Run your first scan
          </Button>
        </div>
      </main>
    )
  }

  const tiles = [
    { label: 'Scans', value: stats.totalScans },
    { label: 'Completed', value: stats.completedScans },
    { label: 'Findings', value: stats.totalFindings },
  ]

  return (
    <main className="mx-auto max-w-5xl px-6 py-12">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-medium">Welcome back, {name}</h1>
          <p className="mt-1 text-sm text-[color:var(--color-muted)]">Your security overview</p>
        </div>
        <Button
          onClick={() => navigate('/scans/new')}
          leftIcon={<Plus size={15} aria-hidden="true" />}
        >
          New scan
        </Button>
      </div>

      <div className="mt-6 grid grid-cols-3 gap-3">
        {tiles.map((tile) => (
          <div
            key={tile.label}
            className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-5 text-center"
          >
            <div className="text-2xl font-semibold text-[color:var(--color-foreground)]">{tile.value}</div>
            <div className="mt-1 text-xs uppercase tracking-wide text-[color:var(--color-muted)]">
              {tile.label}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3 grid grid-cols-5 gap-2">
        {SEVERITIES.map((severity) => (
          <div
            key={severity}
            className={cn('rounded-lg px-2 py-3 text-center', SEVERITY_BADGE[severity])}
          >
            <div className="text-lg font-semibold">{stats.findingsBySeverity[severity]}</div>
            <div className="text-[10px] font-medium uppercase tracking-wide">{severity}</div>
          </div>
        ))}
      </div>

      <div className="mt-8 flex items-center justify-between gap-4">
        <h2 className="text-sm font-medium uppercase tracking-wide text-[color:var(--color-muted)]">
          Recent scans
        </h2>
        <button
          type="button"
          onClick={() => navigate('/scans/history')}
          className="cursor-pointer text-sm font-medium text-[color:var(--color-muted)] transition-colors hover:text-[color:var(--color-foreground)]"
        >
          View all →
        </button>
      </div>

      {recent.length === 0 ? (
        <div className="mt-3 flex flex-col items-center rounded-xl border border-dashed border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-6 py-10 text-center">
          <Radar size={28} className="text-[color:var(--color-muted)]" aria-hidden="true" />
          <p className="mt-2 text-sm font-medium">Nothing here yet</p>
          <p className="mt-1 text-sm text-[color:var(--color-muted)]">Your scans will show up here.</p>
          <Button
            className="mt-4"
            size="sm"
            onClick={() => navigate('/scans/new')}
            leftIcon={<Plus size={15} aria-hidden="true" />}
          >
            New scan
          </Button>
        </div>
      ) : (
        <div className="mt-3 space-y-2">
          {recent.map((scan) => (
            <ScanListItem key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </main>
  )
}
