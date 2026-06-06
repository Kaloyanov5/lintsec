import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { ChevronDown, LogOut, Menu, X } from 'lucide-react'
import { Logo } from '@/components/ui/Logo'
import { ThemeToggle } from '@/components/ThemeToggle'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/cn'

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/scans/new', label: 'New scan' },
  { to: '/scans/history', label: 'History' },
]

function navLinkClass({ isActive }: { isActive: boolean }): string {
  return cn(
    'rounded-lg px-3 py-1.5 text-sm font-medium transition-colors',
    isActive
      ? 'bg-[color:var(--color-surface-muted)] text-[color:var(--color-foreground)]'
      : 'text-[color:var(--color-muted)] hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)]',
  )
}

export function AppHeader() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const userRef = useRef<HTMLDivElement>(null)

  // Close the user dropdown on outside-click or Escape. Listeners only — no setState in the
  // effect body (keeps the React Compiler lint happy).
  useEffect(() => {
    if (!userOpen) return
    function onDocClick(e: MouseEvent) {
      if (userRef.current && !userRef.current.contains(e.target as Node)) setUserOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setUserOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [userOpen])

  const accountLabel = user?.displayName ?? user?.email ?? 'Account'

  async function handleLogout() {
    setUserOpen(false)
    await signOut()
    navigate('/')
  }

  return (
    <header className="sticky top-0 z-40 px-4 pt-4">
      <div className="relative mx-auto max-w-5xl">
        <div className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]/80 shadow-sm backdrop-blur">
          <div className="flex items-center justify-between gap-4 px-4 py-2.5">
            <Link to="/dashboard" aria-label="LintSec dashboard" className="flex items-center">
              <span className="sm:hidden">
                <Logo variant="mark" className="h-9" />
              </span>
              <span className="hidden sm:block">
                <Logo className="h-9" />
              </span>
            </Link>

            <nav className="hidden items-center gap-1 md:flex">
              {NAV_LINKS.map((link) => (
                <NavLink key={link.to} to={link.to} className={navLinkClass}>
                  {link.label}
                </NavLink>
              ))}
            </nav>

            <div className="flex items-center gap-2">
              <ThemeToggle />

              <div className="relative hidden md:block" ref={userRef}>
                <button
                  type="button"
                  onClick={() => setUserOpen((open) => !open)}
                  aria-haspopup="menu"
                  aria-expanded={userOpen}
                  className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-3 py-1.5 text-sm font-medium text-[color:var(--color-foreground)] transition-colors hover:bg-[color:var(--color-surface-muted)]"
                >
                  <span className="max-w-[16ch] truncate">{accountLabel}</span>
                  <ChevronDown size={14} aria-hidden="true" />
                </button>
                <div
                  role="menu"
                  className={cn(
                    'absolute right-0 top-full mt-2 w-56 origin-top-right rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]/95 p-1.5 shadow-lg backdrop-blur transition-all duration-150 ease-out',
                    userOpen
                      ? 'pointer-events-auto translate-y-0 opacity-100'
                      : 'pointer-events-none -translate-y-1 opacity-0',
                  )}
                >
                  {user?.displayName && (
                    <div className="border-b border-[color:var(--color-border)] px-3 py-2">
                      <p className="truncate text-xs text-[color:var(--color-muted)]">{user.email}</p>
                    </div>
                  )}
                  <button
                    type="button"
                    role="menuitem"
                    onClick={handleLogout}
                    className="mt-1 flex w-full cursor-pointer items-center gap-2 rounded-lg px-3 py-2 text-left text-sm font-medium text-[color:var(--color-foreground)] transition-colors hover:bg-[color:var(--color-surface-muted)]"
                  >
                    <LogOut size={15} aria-hidden="true" />
                    Log out
                  </button>
                </div>
              </div>

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
            'absolute inset-x-4 top-full mt-2 origin-top rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]/95 p-2 shadow-lg backdrop-blur transition-all duration-200 ease-out md:hidden',
            menuOpen
              ? 'pointer-events-auto translate-y-0 opacity-100'
              : 'pointer-events-none -translate-y-2 opacity-0',
          )}
        >
          <nav className="flex flex-col gap-1">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                onClick={() => setMenuOpen(false)}
                className={navLinkClass}
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <div className="mt-2 flex flex-col gap-1 border-t border-[color:var(--color-border)] pt-2">
            <p className="px-3 py-1 text-xs text-[color:var(--color-muted)]">{accountLabel}</p>
            <button
              type="button"
              onClick={() => {
                setMenuOpen(false)
                void handleLogout()
              }}
              className="flex w-full cursor-pointer items-center gap-2 rounded-lg px-3 py-2 text-left text-sm font-medium text-[color:var(--color-foreground)] transition-colors hover:bg-[color:var(--color-surface-muted)]"
            >
              <LogOut size={15} aria-hidden="true" />
              Log out
            </button>
          </div>
        </div>
      </div>
    </header>
  )
}
