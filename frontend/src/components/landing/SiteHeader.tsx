import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Menu, X } from 'lucide-react'
import { Logo } from '@/components/ui/Logo'
import { Button } from '@/components/ui/Button'
import { ThemeToggle } from '@/components/ThemeToggle'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/cn'

const navLinks = [
  { label: 'Features', href: '#features' },
  { label: 'How it works', href: '#how-it-works' },
  { label: 'FAQ', href: '#faq' },
]

export function SiteHeader() {
  const { status } = useAuth()
  const authenticated = status === 'authenticated'
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <header className="sticky top-0 z-40 px-4 pt-4">
      <div className="relative mx-auto max-w-5xl">
        <div className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]/80 shadow-sm backdrop-blur">
          <div className="flex items-center justify-between gap-4 px-4 py-2.5">
            <Link to="/" aria-label="LintSec home" className="flex items-center">
              <span className="sm:hidden">
                <Logo variant="mark" className="h-9" />
              </span>
              <span className="hidden sm:block">
                <Logo className="h-9" />
              </span>
            </Link>

            <nav className="hidden items-center gap-1 md:flex">
              {navLinks.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  className="rounded-lg px-3 py-1.5 text-sm font-medium text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)]"
                >
                  {link.label}
                </a>
              ))}
            </nav>

            <div className="flex items-center gap-2">
              <ThemeToggle />
              {status === 'loading' ? (
                <div className="h-9 w-24 animate-pulse rounded-lg bg-[color:var(--color-surface-muted)]" />
              ) : authenticated ? (
                <Link to="/dashboard">
                  <Button size="sm">Dashboard</Button>
                </Link>
              ) : (
                <>
                  <Link to="/login" className="hidden sm:block">
                    <Button size="sm" variant="ghost">
                      Log in
                    </Button>
                  </Link>
                  <Link to="/register" className="hidden sm:block">
                    <Button size="sm">Get started</Button>
                  </Link>
                </>
              )}
              <button
                type="button"
                onClick={() => setMenuOpen((open) => !open)}
                aria-label={menuOpen ? 'Close menu' : 'Open menu'}
                aria-expanded={menuOpen}
                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)] md:hidden"
              >
                {menuOpen ? <X size={16} /> : <Menu size={16} />}
              </button>
            </div>
          </div>
        </div>

        <div
          className={cn(
            'absolute inset-x-0 top-full mt-2 origin-top rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]/95 p-2 shadow-lg backdrop-blur transition-all duration-200 ease-out md:hidden',
            menuOpen
              ? 'pointer-events-auto translate-y-0 opacity-100'
              : 'pointer-events-none -translate-y-2 opacity-0',
          )}
        >
          <nav className="flex flex-col gap-1">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={() => setMenuOpen(false)}
                className="rounded-lg px-3 py-2 text-sm font-medium text-[color:var(--color-muted)] transition-colors hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)]"
              >
                {link.label}
              </a>
            ))}
          </nav>
          {status === 'unauthenticated' ? (
            <div className="mt-2 flex flex-col gap-2 border-t border-[color:var(--color-border)] pt-2">
              <Link to="/login" onClick={() => setMenuOpen(false)}>
                <Button size="sm" variant="secondary" className="w-full">
                  Log in
                </Button>
              </Link>
              <Link to="/register" onClick={() => setMenuOpen(false)}>
                <Button size="sm" className="w-full">
                  Get started
                </Button>
              </Link>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  )
}
