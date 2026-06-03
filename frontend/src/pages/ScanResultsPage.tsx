import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Check,
  ChevronDown,
  Download,
  FileJson,
  FileText,
  RefreshCw,
  Sparkles,
} from 'lucide-react'
import { scanService } from '@/services/scanService'
import { useScanEvents } from '@/hooks/useScanEvents'
import { parseProblem } from '@/lib/problem'
import { cn } from '@/lib/cn'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import type { FindingGroup, Severity, VulnerabilityType } from '@/types'
import type { Scan, ScanStatus, ScanEvent } from '@/types'

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

const SEVERITY_BADGE: Record<Severity, string> = {
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-300',
  MEDIUM: 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300',
  LOW: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300',
  INFO: 'bg-slate-100 text-slate-600 dark:bg-slate-500/15 dark:text-slate-300',
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const VULN_LABEL: Record<VulnerabilityType, string> = {
  XSS: 'Cross-Site Scripting',
  SQL_INJECTION: 'SQL Injection',
  CORS: 'CORS Misconfiguration',
  SECURITY_HEADERS: 'Security Headers',
  SENSITIVE_DATA: 'Sensitive Data',
  OPEN_REDIRECT: 'Open Redirect',
  COOKIE_SECURITY: 'Cookie Security',
  CSRF: 'CSRF',
  DIRECTORY_LISTING: 'Directory Listing',
  INSECURE_HTTP_METHOD: 'Insecure HTTP Method',
}

const STATUS_BADGE: Record<ScanStatus, string> = {
  PENDING: 'bg-slate-100 text-slate-600 dark:bg-slate-500/15 dark:text-slate-300',
  RUNNING: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300',
  COMPLETE: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300',
  FAILED: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300',
}

function vulnLabel(type: VulnerabilityType): string {
  return VULN_LABEL[type] ?? type
}

/** A stable key for a group, since groups have no id of their own. */
function groupKey(g: FindingGroup): string {
  return `${g.vulnerabilityType}|${g.severity}|${g.title}`
}

function countBySeverity(groups: FindingGroup[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const g of groups) counts[g.severity] += 1
  return counts
}

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>()
  // Remount per id so loading/error state re-initializes cleanly when navigating between scans.
  return id ? <ScanResults key={id} id={id} /> : null
}

function ScanResults({ id }: { id: string }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [groups, setGroups] = useState<FindingGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  useEffect(() => {
    let active = true
    Promise.all([scanService.getScan(id), scanService.getGroupedFindings(id)])
      .then(([scanData, groupData]) => {
        if (!active) return
        setScan(scanData)
        setGroups(groupData)
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
  }, [id])

  const reload = useCallback(async () => {
    const [scanData, groupData] = await Promise.all([
      scanService.getScan(id),
      scanService.getGroupedFindings(id),
    ])
    setScan(scanData)
    setGroups(groupData)
  }, [id])

  async function handleRefresh() {
    setRefreshing(true)
    try {
      await reload()
    } catch (err) {
      setError(parseProblem(err).message)
    } finally {
      setRefreshing(false)
    }
  }

  // Live progress: subscribe to the scan event stream only while the scan can still change.
  // `live` starts false (scan is null pre-fetch), so an already-finished scan never opens a
  // stream — the backend stream has no replay to catch up on. On a terminal event the hook
  // calls back to refetch the now-complete scan + findings.
  const live = scan?.status === 'PENDING' || scan?.status === 'RUNNING'
  const liveEvent = useScanEvents(id, live, () => {
    reload().catch((err) => setError(parseProblem(err).message))
  })

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  if (loading) {
    return (
      <main className="mx-auto flex max-w-5xl items-center justify-center px-6 py-24">
        <Spinner />
      </main>
    )
  }

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-12">
        <BackLink />
        <p className="mt-6 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4 text-sm text-[color:var(--color-danger)]">
          {error}
        </p>
      </main>
    )
  }

  const sorted = [...groups].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    return sev !== 0 ? sev : a.title.localeCompare(b.title)
  })
  const counts = countBySeverity(groups)
  const totalOccurrences = groups.reduce((sum, g) => sum + g.count, 0)
  const aiReady = groups.filter((g) => g.aiExplanation).length

  return (
    <main className="mx-auto max-w-5xl px-6 py-12">
      <BackLink />

      <div className="mt-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-medium">Scan results</h1>
          {scan && (
            <p className="mt-1 truncate font-mono text-sm text-[color:var(--color-muted)]">
              {scan.targetUrl}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ExportLink id={id} format="pdf" icon={<FileText size={15} aria-hidden="true" />}>
            PDF
          </ExportLink>
          <ExportLink id={id} format="json" icon={<FileJson size={15} aria-hidden="true" />}>
            JSON
          </ExportLink>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            loading={refreshing}
            leftIcon={<RefreshCw size={15} aria-hidden="true" />}
          >
            Refresh
          </Button>
        </div>
      </div>

      {scan && (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className={cn('rounded-full px-2.5 py-1 font-medium', STATUS_BADGE[scan.status])}>
            {scan.status}
          </span>
          {scan.authenticated && (
            <span className="rounded-full border border-[color:var(--color-border)] px-2.5 py-1 font-medium text-[color:var(--color-muted)]">
              Authenticated
            </span>
          )}
          <span className="text-[color:var(--color-muted)]">{scan.pagesCrawled} pages crawled</span>
          <span className="text-[color:var(--color-muted)]">·</span>
          <span className="text-[color:var(--color-muted)]">
            {groups.length} issues · {totalOccurrences} occurrences
          </span>
          <span className="text-[color:var(--color-muted)]">·</span>
          <span className="text-[color:var(--color-muted)]">
            AI explanations {aiReady}/{groups.length}
          </span>
        </div>
      )}

      {scan?.status === 'FAILED' && scan.errorMessage && (
        <p className="mt-3 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-3 text-sm text-[color:var(--color-danger)]">
          {scan.errorMessage}
        </p>
      )}

      {/* Severity summary (distinct issues per severity) */}
      <div className="mt-5 flex flex-wrap gap-2">
        {SEVERITIES.map((sev) => (
          <span
            key={sev}
            className={cn(
              'rounded-lg px-3 py-1.5 text-xs font-medium',
              counts[sev] > 0 ? SEVERITY_BADGE[sev] : 'bg-[color:var(--color-surface-muted)] text-[color:var(--color-muted)]',
            )}
          >
            {counts[sev]} {sev}
          </span>
        ))}
      </div>

      {/* Findings */}
      <div className="mt-6 space-y-3">
        {live ? (
          <LivePanel event={liveEvent} />
        ) : sorted.length === 0 ? (
          <p className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 text-center text-sm text-[color:var(--color-muted)]">
            No findings for this scan.
          </p>
        ) : (
          sorted.map((group) => {
            const key = groupKey(group)
            return (
              <GroupCard
                key={key}
                group={group}
                open={expanded.has(key)}
                onToggle={() => toggle(key)}
              />
            )
          })
        )}
      </div>
    </main>
  )
}

function BackLink() {
  return (
    <Link
      to="/scans/history"
      className="inline-flex items-center gap-1.5 text-sm text-[color:var(--color-muted)] transition-colors hover:text-[color:var(--color-foreground)]"
    >
      <ArrowLeft size={15} aria-hidden="true" />
      All scans
    </Link>
  )
}

/** Export downloads are plain links (GET + cookie); styled to match the secondary Button. */
function ExportLink({
  id,
  format,
  icon,
  children,
}: {
  id: string
  format: 'pdf' | 'json'
  icon: ReactNode
  children: ReactNode
}) {
  return (
    <a
      href={scanService.exportUrl(id, format)}
      className={cn(
        'inline-flex h-9 items-center justify-center gap-1.5 rounded-lg border px-3 text-sm font-medium transition-colors',
        'border-[color:var(--color-border)] bg-[color:var(--color-surface)] text-[color:var(--color-foreground)]',
        'hover:bg-[color:var(--color-surface-muted)]',
      )}
      title={`Download ${format.toUpperCase()} report`}
    >
      <Download size={14} aria-hidden="true" />
      {icon}
      {children}
    </a>
  )
}

/** Indeterminate live progress shown while a scan is RUNNING, driven by SSE milestones. */
function LivePanel({ event }: { event: ScanEvent | null }) {
  const crawlDone = event != null && event.type !== 'STARTED'
  return (
    <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5">
      <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--color-foreground)]">
        <Spinner size="sm" />
        Scanning in progress
      </div>
      <ul className="mt-4 space-y-2 text-sm">
        <li className="flex items-center gap-2 text-[color:var(--color-muted)]">
          {crawlDone ? (
            <>
              <Check size={15} className="text-emerald-500" aria-hidden="true" />
              Crawled {event.pagesCrawled} pages
            </>
          ) : (
            <>
              <Spinner size="sm" />
              Crawling…
            </>
          )}
        </li>
        {crawlDone && (
          <li className="flex items-center gap-2 text-[color:var(--color-muted)]">
            <Spinner size="sm" />
            Running security modules…
          </li>
        )}
      </ul>
    </div>
  )
}

function GroupCard({
  group,
  open,
  onToggle,
}: {
  group: FindingGroup
  open: boolean
  onToggle: () => void
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-[color:var(--color-surface-muted)]"
      >
        <span className={cn('shrink-0 rounded-full px-2.5 py-1 text-xs font-semibold', SEVERITY_BADGE[group.severity])}>
          {group.severity}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-[color:var(--color-foreground)]">
            {group.title}
          </span>
          <span className="block text-xs text-[color:var(--color-muted)]">
            {vulnLabel(group.vulnerabilityType)}
          </span>
        </span>
        {group.count > 1 && (
          <span className="shrink-0 rounded-full bg-[color:var(--color-surface-muted)] px-2 py-0.5 text-xs font-medium text-[color:var(--color-muted)]">
            ×{group.count}
          </span>
        )}
        {group.aiExplanation && (
          <Sparkles size={15} className="shrink-0 text-cyan-500" aria-label="AI explanation available" />
        )}
        <ChevronDown
          size={16}
          aria-hidden="true"
          className={cn('shrink-0 text-[color:var(--color-muted)] transition-transform', open && 'rotate-180')}
        />
      </button>

      {open && (
        <div className="space-y-4 border-t border-[color:var(--color-border)] px-4 py-4 text-sm">
          {/* AI explanation, featured */}
          <div className="rounded-lg border border-cyan-200 bg-cyan-50 p-3 dark:border-cyan-500/20 dark:bg-cyan-500/10">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300">
              <Sparkles size={14} aria-hidden="true" />
              AI explanation
            </div>
            {group.aiExplanation ? (
              <p className="mt-1.5 leading-relaxed text-[color:var(--color-foreground)]">
                {group.aiExplanation}
              </p>
            ) : (
              <p className="mt-1.5 text-[color:var(--color-muted)]">
                Pending — explanations are generated automatically after the scan completes. Try
                Refresh in a moment.
              </p>
            )}
          </div>

          {group.description && <Section title="Description">{group.description}</Section>}
          {group.remediation && <Section title="Remediation">{group.remediation}</Section>}

          {/* Affected locations */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-muted)]">
              Affected locations ({group.count})
            </h3>
            <ul className="mt-1.5 space-y-1">
              {group.instances.map((inst) => (
                <li key={inst.id} className="break-words font-mono text-xs text-[color:var(--color-foreground)]">
                  {inst.url ?? '(no url)'}
                  {inst.parameter && (
                    <span className="text-[color:var(--color-muted)]"> · param: {inst.parameter}</span>
                  )}
                  {inst.note && <span className="text-[color:var(--color-muted)]"> — {inst.note}</span>}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-muted)]">
        {title}
      </h3>
      <p className="mt-1.5 leading-relaxed text-[color:var(--color-foreground)]">{children}</p>
    </div>
  )
}
