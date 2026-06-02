import { useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  ChevronDown,
  RefreshCw,
  Sparkles,
} from 'lucide-react'
import { scanService } from '@/services/scanService'
import { parseProblem } from '@/lib/problem'
import { cn } from '@/lib/cn'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import type { Finding, Severity, VulnerabilityType } from '@/types'
import type { Scan, ScanStatus } from '@/types'

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

/** evidenceJson is a raw JSON string from the backend; render it readably, falling back to raw text. */
function parseEvidence(evidenceJson: string | null): Record<string, unknown> | null {
  if (!evidenceJson) return null
  try {
    const parsed: unknown = JSON.parse(evidenceJson)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const f of findings) counts[f.severity] += 1
  return counts
}

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>()
  // Remount per id so loading/error state re-initializes cleanly when navigating between scans.
  return id ? <ScanResults key={id} id={id} /> : null
}

function ScanResults({ id }: { id: string }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  useEffect(() => {
    let active = true
    Promise.all([scanService.getScan(id), scanService.getFindings(id)])
      .then(([scanData, findingsData]) => {
        if (!active) return
        setScan(scanData)
        setFindings(findingsData)
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

  async function handleRefresh() {
    setRefreshing(true)
    try {
      const [scanData, findingsData] = await Promise.all([
        scanService.getScan(id),
        scanService.getFindings(id),
      ])
      setScan(scanData)
      setFindings(findingsData)
    } catch (err) {
      setError(parseProblem(err).message)
    } finally {
      setRefreshing(false)
    }
  }

  function toggle(findingId: number) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(findingId)) next.delete(findingId)
      else next.add(findingId)
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

  const sorted = [...findings].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    return sev !== 0 ? sev : a.createdAt.localeCompare(b.createdAt)
  })
  const counts = countBySeverity(findings)
  const aiReady = findings.filter((f) => f.aiExplanation).length

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

      {scan && (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className={cn('rounded-full px-2.5 py-1 font-medium', STATUS_BADGE[scan.status])}>
            {scan.status}
          </span>
          <span className="text-[color:var(--color-muted)]">{scan.pagesCrawled} pages crawled</span>
          <span className="text-[color:var(--color-muted)]">·</span>
          <span className="text-[color:var(--color-muted)]">
            AI explanations {aiReady}/{findings.length}
          </span>
        </div>
      )}

      {/* Severity summary */}
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

      {scan?.status === 'RUNNING' && (
        <p className="mt-4 text-sm text-[color:var(--color-muted)]">
          This scan is still running — refresh to see new findings as they arrive.
        </p>
      )}

      {/* Findings */}
      <div className="mt-6 space-y-3">
        {sorted.length === 0 ? (
          <p className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 text-center text-sm text-[color:var(--color-muted)]">
            No findings for this scan.
          </p>
        ) : (
          sorted.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              open={expanded.has(finding.id)}
              onToggle={() => toggle(finding.id)}
            />
          ))
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

function FindingCard({
  finding,
  open,
  onToggle,
}: {
  finding: Finding
  open: boolean
  onToggle: () => void
}) {
  const evidence = parseEvidence(finding.evidenceJson)

  return (
    <div className="overflow-hidden rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-[color:var(--color-surface-muted)]"
      >
        <span className={cn('shrink-0 rounded-full px-2.5 py-1 text-xs font-semibold', SEVERITY_BADGE[finding.severity])}>
          {finding.severity}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-[color:var(--color-foreground)]">
            {finding.title}
          </span>
          <span className="block text-xs text-[color:var(--color-muted)]">
            {vulnLabel(finding.vulnerabilityType)}
          </span>
        </span>
        {finding.aiExplanation && (
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
            {finding.aiExplanation ? (
              <p className="mt-1.5 leading-relaxed text-[color:var(--color-foreground)]">
                {finding.aiExplanation}
              </p>
            ) : (
              <p className="mt-1.5 text-[color:var(--color-muted)]">
                Pending — explanations are generated automatically after the scan completes. Try
                Refresh in a moment.
              </p>
            )}
          </div>

          {finding.description && (
            <Section title="Description">{finding.description}</Section>
          )}
          {finding.remediation && (
            <Section title="Remediation">{finding.remediation}</Section>
          )}

          {evidence && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-muted)]">
                Evidence
              </h3>
              <dl className="mt-1.5 space-y-1">
                {Object.entries(evidence)
                  .filter(([, value]) => value != null && value !== '')
                  .map(([key, value]) => (
                    <div key={key} className="flex gap-2">
                      <dt className="shrink-0 font-mono text-xs text-[color:var(--color-muted)]">{key}</dt>
                      <dd className="min-w-0 break-words font-mono text-xs text-[color:var(--color-foreground)]">
                        {String(value)}
                      </dd>
                    </div>
                  ))}
              </dl>
            </div>
          )}

          {finding.payloadRef && (
            <div className="text-xs text-[color:var(--color-muted)]">
              Payload reference:{' '}
              <code className="rounded bg-[color:var(--color-surface-muted)] px-1.5 py-0.5 font-mono text-[color:var(--color-foreground)]">
                {finding.payloadRef}
              </code>
            </div>
          )}
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
