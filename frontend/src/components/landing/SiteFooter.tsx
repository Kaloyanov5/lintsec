import { Link } from 'react-router-dom'
import { Logo } from '@/components/ui/Logo'

export function SiteFooter() {
  return (
    <footer className="border-t border-[color:var(--color-border)] px-6 py-12">
      <div className="mx-auto flex max-w-5xl flex-col items-center gap-6 text-center sm:flex-row sm:justify-between sm:text-left">
        <div className="flex flex-col items-center gap-2 sm:items-start">
          <Logo className="h-8" />
          <p className="text-sm text-[color:var(--color-muted)]">
            Web application security scanning, made actionable.
          </p>
        </div>
        <nav className="flex items-center gap-5 text-sm text-[color:var(--color-muted)]">
          <a href="#features" className="transition-colors hover:text-[color:var(--color-foreground)]">
            Features
          </a>
          <a href="#how-it-works" className="transition-colors hover:text-[color:var(--color-foreground)]">
            How it works
          </a>
          <Link to="/login" className="transition-colors hover:text-[color:var(--color-foreground)]">
            Log in
          </Link>
        </nav>
      </div>
      <p className="mx-auto mt-8 max-w-5xl text-center text-xs text-[color:var(--color-muted)] sm:text-left">
        © {new Date().getFullYear()} LintSec. Scan only applications you own or are authorized to test.
      </p>
    </footer>
  )
}
