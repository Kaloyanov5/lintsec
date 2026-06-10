import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Radar } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/ui/PageHeader'
import { Skeleton } from '@/components/ui/Skeleton'
import { ScanListItem } from '@/components/ScanListItem'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import type { Scan } from '@/types'

export default function ScanHistoryPage() {
  const navigate = useNavigate()
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    return scanService
      .listScans()
      .then((page) => setScans(page.content))
      .catch((err) => setError(parseProblem(err).message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <main className="mx-auto max-w-5xl px-6 py-12 motion-safe:animate-fade-in-up">
      <PageHeader
        title="Scans"
        actions={
          <Button
            size="sm"
            onClick={() => navigate('/scans/new')}
            leftIcon={<Plus size={15} aria-hidden="true" />}
          >
            New scan
          </Button>
        }
      />

      {loading ? (
        <div className="mt-6 space-y-2">
          <Skeleton className="h-[4.25rem] rounded-xl" />
          <Skeleton className="h-[4.25rem] rounded-xl" />
          <Skeleton className="h-[4.25rem] rounded-xl" />
          <Skeleton className="h-[4.25rem] rounded-xl" />
        </div>
      ) : error ? (
        <p className="mt-6 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4 text-sm text-[color:var(--color-danger)]">
          {error}
        </p>
      ) : scans.length === 0 ? (
        <div className="mt-6">
          <EmptyState
            icon={Radar}
            title="No scans yet"
            action={<Button onClick={() => navigate('/scans/new')}>Start your first scan</Button>}
          >
            Run your first scan to see results here.
          </EmptyState>
        </div>
      ) : (
        <div className="mt-6 space-y-2">
          {scans.map((scan) => (
            <ScanListItem key={scan.id} scan={scan} onChanged={load} />
          ))}
        </div>
      )}
    </main>
  )
}
