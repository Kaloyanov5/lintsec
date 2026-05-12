import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <main className="mx-auto max-w-md px-6 py-12">
      <h1 className="text-2xl font-medium">Not found</h1>
      <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
        That route doesn't exist.
      </p>
      <Link to="/" className="mt-4 inline-block text-sm underline">
        Back to home
      </Link>
    </main>
  )
}
