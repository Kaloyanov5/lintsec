import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Logo } from './Logo'

type AuthLayoutProps = {
  title: string
  description?: ReactNode
  children: ReactNode
  footer?: ReactNode
}

export function AuthLayout({ title, description, children, footer }: AuthLayoutProps) {
  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <Link to="/" aria-label="LintSec home">
            <Logo />
          </Link>
        </div>
        <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 shadow-sm sm:p-8">
          <div className="mb-6">
            <h1 className="text-xl font-semibold text-[color:var(--color-foreground)]">
              {title}
            </h1>
            {description ? (
              <p className="mt-1 text-sm text-[color:var(--color-muted)]">{description}</p>
            ) : null}
          </div>
          {children}
        </div>
        {footer ? (
          <div className="mt-6 text-center text-sm text-[color:var(--color-muted)]">
            {footer}
          </div>
        ) : null}
      </div>
    </main>
  )
}
