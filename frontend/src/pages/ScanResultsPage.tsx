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
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { scanService } from '@/services/scanService'
import { useScanEvents } from '@/hooks/useScanEvents'
import { parseProblem } from '@/lib/problem'
import { SEVERITIES, SEVERITY_BADGE, SEVERITY_DOT, SEVERITY_ORDER, SEVERITY_RAIL } from '@/lib/severity'
import { cn } from '@/lib/cn'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/ui/PageHeader'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusBadge } from '@/components/StatusBadge'
import type { FindingGroup, Severity, VulnerabilityType } from '@/types'
import type { Scan, ScanEvent } from '@/types'

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
  PATH_TRAVERSAL: 'Path Traversal',
  COMMAND_INJECTION: 'Command Injection',
  MIXED_CONTENT: 'Mixed Content',
  MISSING_SRI: 'Missing Subresource Integrity',
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
  const [finalizing, setFinalizing] = useState(false)
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
  // calls back so we can refetch the now-complete scan + findings.
  const live = scan?.status === 'PENDING' || scan?.status === 'RUNNING'
  const liveEvent = useScanEvents(id, live, (event) => {
    // Hold a brief "Scan complete — loading findings" beat so results don't snap in abruptly.
    // The panel stays up until BOTH the refetch and the beat finish (failures skip the beat).
    const beatMs = event.type === 'SCAN_COMPLETE' ? 700 : 0
    setFinalizing(true)
    Promise.all([
      reload().catch((err) => setError(parseProblem(err).message)),
      new Promise((resolve) => setTimeout(resolve, beatMs)),
    ]).then(() => setFinalizing(false))
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
      <main className="mx-auto max-w-5xl px-6 py-12">
        <BackLink />
        <div className="mt-4 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <Skeleton className="h-8 w-44 rounded-lg" />
            <Skeleton className="mt-2 h-4 w-72 rounded" />
          </div>
          <Skeleton className="h-9 w-60 rounded-lg" />
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <Skeleton className="h-7 w-24 rounded-lg" />
          <Skeleton className="h-7 w-20 rounded-lg" />
          <Skeleton className="h-7 w-24 rounded-lg" />
          <Skeleton className="h-7 w-16 rounded-lg" />
          <Skeleton className="h-7 w-16 rounded-lg" />
        </div>
        <div className="mt-6 space-y-3">
          <Skeleton className="h-14 rounded-xl" />
          <Skeleton className="h-14 rounded-xl" />
          <Skeleton className="h-14 rounded-xl" />
        </div>
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
    <main className="mx-auto max-w-5xl px-6 py-12 motion-safe:animate-fade-in-up">
      <BackLink />

      <div className="mt-4">
        <PageHeader
          title="Scan results"
          subtitle={
            scan ? (
              <span className="block max-w-xl truncate font-mono">{scan.targetUrl}</span>
            ) : undefined
          }
          actions={
            <>
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
            </>
          }
        />
      </div>

      {scan && (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <StatusBadge scan={scan} />
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
              'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium',
              counts[sev] > 0 ? SEVERITY_BADGE[sev] : 'bg-[color:var(--color-surface-muted)] text-[color:var(--color-muted)]',
            )}
          >
            <span
              aria-hidden="true"
              className={cn(
                'h-1.5 w-1.5 rounded-full',
                counts[sev] > 0 ? SEVERITY_DOT[sev] : 'bg-current opacity-40',
              )}
            />
            {counts[sev]} {sev}
          </span>
        ))}
      </div>

      {/* Findings */}
      <div className="mt-6 space-y-3">
        {live || finalizing ? (
          <LivePanel event={liveEvent} />
        ) : sorted.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No findings">
            This scan completed without detecting any issues.
          </EmptyState>
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

/** Step shown with a check when done, a spinner while in progress. */
function LiveStep({ done, label }: { done: boolean; label: string }) {
  return (
    <li className="flex items-center gap-2 text-[color:var(--color-muted)]">
      {done ? (
        <Check size={15} className="text-emerald-500" aria-hidden="true" />
      ) : (
        <Spinner size="sm" />
      )}
      {label}
    </li>
  )
}

/**
 * Indeterminate live progress shown while a scan is RUNNING or finalizing, driven by SSE
 * milestones. On SCAN_COMPLETE it briefly reads "Scan complete · Loading findings…" before the
 * page swaps in the results, so the transition isn't an abrupt jump.
 */
function LivePanel({ event }: { event: ScanEvent | null }) {
  const failed = event?.type === 'FAILED'
  const crawlDone = event != null && (event.type === 'CRAWL_COMPLETE' || event.type === 'SCAN_COMPLETE')
  const scanDone = event?.type === 'SCAN_COMPLETE'
  const heading = scanDone ? 'Scan complete' : failed ? 'Scan failed' : 'Scanning in progress'

  return (
    <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        {scanDone ? (
          <Check size={16} className="text-emerald-500" aria-hidden="true" />
        ) : failed ? null : (
          <Spinner size="sm" />
        )}
        <span className={cn(failed ? 'text-[color:var(--color-danger)]' : 'text-[color:var(--color-foreground)]')}>
          {heading}
        </span>
      </div>
      {!failed && !scanDone && (
        <div className="relative mt-4 h-1 overflow-hidden rounded-full bg-[color:var(--color-surface-muted)]">
          <div className="absolute inset-y-0 w-1/3 rounded-full bg-[color:var(--color-primary)] motion-safe:animate-progress-sweep" />
        </div>
      )}
      {!failed && (
        <ul className="mt-4 space-y-2 text-sm">
          <LiveStep done={crawlDone} label={crawlDone ? `Crawled ${event.pagesCrawled} pages` : 'Crawling…'} />
          {crawlDone && (
            <LiveStep done={scanDone} label={scanDone ? 'Security checks complete' : 'Running security modules…'} />
          )}
          {scanDone && <LiveStep done={false} label="Loading findings…" />}
        </ul>
      )}
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
    <div
      className={cn(
        'overflow-hidden rounded-xl border border-l-4 border-[color:var(--color-border)] bg-[color:var(--color-surface)] shadow-[var(--shadow-card)]',
        SEVERITY_RAIL[group.severity],
      )}
    >
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
        <div className="space-y-4 border-t border-[color:var(--color-border)] px-4 py-4 text-sm motion-safe:animate-fade-in-up">
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
