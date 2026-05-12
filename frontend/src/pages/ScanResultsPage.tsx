import { useParams } from 'react-router-dom'

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>()
  return (
    <main className="mx-auto max-w-5xl px-6 py-12">
      <h1 className="text-2xl font-medium">Scan #{id}</h1>
      <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Placeholder.</p>
    </main>
  )
}
