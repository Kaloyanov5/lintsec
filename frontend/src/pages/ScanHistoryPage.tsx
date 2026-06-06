import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ScanListItem } from '@/components/ScanListItem'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import type { Scan } from '@/types'

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
            <ScanListItem key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </main>
  )
}
