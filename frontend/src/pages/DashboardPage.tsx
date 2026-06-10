import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bug, CheckCircle2, Plus, Radar, ShieldCheck } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/ui/PageHeader'
import { Skeleton } from '@/components/ui/Skeleton'
import { ScanListItem } from '@/components/ScanListItem'
import { useCountUp } from '@/hooks/useCountUp'
import { cn } from '@/lib/cn'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import { useAuth } from '@/contexts/AuthContext'
import { SEVERITIES, SEVERITY_BADGE, SEVERITY_DOT } from '@/lib/severity'
import type { Scan, ScanStats, Severity } from '@/types'

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
        <div className="flex items-center justify-between gap-4">
          <Skeleton className="h-8 w-64 rounded-lg" />
          <Skeleton className="h-10 w-28 rounded-lg" />
        </div>
        <div className="mt-6 grid grid-cols-3 gap-3">
          <Skeleton className="h-[5.25rem] rounded-xl" />
          <Skeleton className="h-[5.25rem] rounded-xl" />
          <Skeleton className="h-[5.25rem] rounded-xl" />
        </div>
        <Skeleton className="mt-4 h-2.5 rounded-full" />
        <div className="mt-8 space-y-2">
          <Skeleton className="h-[4.25rem] rounded-xl" />
          <Skeleton className="h-[4.25rem] rounded-xl" />
          <Skeleton className="h-[4.25rem] rounded-xl" />
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
      <main className="mx-auto max-w-5xl px-6 py-12 motion-safe:animate-fade-in-up">
        <PageHeader title={`Welcome to LintSec, ${name}`} />
        <div className="mt-6">
          <EmptyState
            icon={ShieldCheck}
            title="No scans yet"
            action={
              <Button
                onClick={() => navigate('/scans/new')}
                leftIcon={<Plus size={15} aria-hidden="true" />}
              >
                Run your first scan
              </Button>
            }
          >
            Point LintSec at a site you own to find security issues.
          </EmptyState>
        </div>
      </main>
    )
  }

  const tiles: { label: string; value: number; icon: LucideIcon }[] = [
    { label: 'Scans', value: stats.totalScans, icon: Radar },
    { label: 'Completed', value: stats.completedScans, icon: CheckCircle2 },
    { label: 'Findings', value: stats.totalFindings, icon: Bug },
  ]

  return (
    <main className="mx-auto max-w-5xl px-6 py-12 motion-safe:animate-fade-in-up">
      <PageHeader
        title={`Welcome back, ${name}`}
        subtitle="Your security overview"
        actions={
          <Button
            onClick={() => navigate('/scans/new')}
            leftIcon={<Plus size={15} aria-hidden="true" />}
          >
            New scan
          </Button>
        }
      />

      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
        {tiles.map((tile) => (
          <StatTile key={tile.label} label={tile.label} value={tile.value} icon={tile.icon} />
        ))}
      </div>

      <div className="mt-4">
        <SeverityBar counts={stats.findingsBySeverity} />
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
        <div className="mt-3">
          <EmptyState
            icon={Radar}
            title="Nothing here yet"
            action={
              <Button
                size="sm"
                onClick={() => navigate('/scans/new')}
                leftIcon={<Plus size={15} aria-hidden="true" />}
              >
                New scan
              </Button>
            }
          >
            Your scans will show up here.
          </EmptyState>
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

function StatTile({ label, value, icon: Icon }: { label: string; value: number; icon: LucideIcon }) {
  const display = useCountUp(value)
  return (
    <div className="flex items-center gap-4 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-5 shadow-[var(--shadow-card)] transition-shadow hover:shadow-[var(--shadow-card-hover)]">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[color:var(--color-primary-soft)]">
        <Icon size={18} className="text-[color:var(--color-primary)]" aria-hidden="true" />
      </div>
      <div>
        <div className="text-2xl font-semibold tabular-nums text-[color:var(--color-foreground)]">
          {display}
        </div>
        <div className="mt-0.5 text-xs uppercase tracking-wide text-[color:var(--color-muted)]">
          {label}
        </div>
      </div>
    </div>
  )
}

/** Proportional stacked severity bar with a count legend. All-zero renders a muted empty bar. */
function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((sum, severity) => sum + counts[severity], 0)
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-[color:var(--color-surface-muted)]">
        {total > 0 &&
          SEVERITIES.filter((severity) => counts[severity] > 0).map((severity) => (
            <div
              key={severity}
              className={SEVERITY_DOT[severity]}
              style={{ width: `${(counts[severity] / total) * 100}%` }}
              title={`${counts[severity]} ${severity}`}
            />
          ))}
      </div>
      <div className="mt-2.5 flex flex-wrap gap-2">
        {SEVERITIES.map((severity) => (
          <span
            key={severity}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
              counts[severity] > 0
                ? SEVERITY_BADGE[severity]
                : 'bg-[color:var(--color-surface-muted)] text-[color:var(--color-muted)]',
            )}
          >
            <span
              aria-hidden="true"
              className={cn(
                'h-1.5 w-1.5 rounded-full',
                counts[severity] > 0 ? SEVERITY_DOT[severity] : 'bg-current opacity-40',
              )}
            />
            {counts[severity]} {severity}
          </span>
        ))}
      </div>
    </div>
  )
}
