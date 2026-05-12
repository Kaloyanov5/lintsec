import { Link } from 'react-router-dom'

export default function LandingPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-medium">LintSec</h1>
      <p className="mt-3 text-slate-500 dark:text-slate-400">
        Web application security scanner. (Landing — placeholder.)
      </p>
      <nav className="mt-6 flex gap-4 text-sm">
        <Link to="/login" className="underline">Login</Link>
        <Link to="/register" className="underline">Register</Link>
        <Link to="/dashboard" className="underline">Dashboard</Link>
      </nav>
    </main>
  )
}
