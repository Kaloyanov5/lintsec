import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

type EmptyStateProps = {
  icon: LucideIcon
  title: string
  children?: ReactNode
  action?: ReactNode
}

/** Centered empty-state card: icon in a soft tinted ring, title, sub-line, optional action. */
export function EmptyState({ icon: Icon, title, children, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-6 py-14 text-center shadow-[var(--shadow-card)]">
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-[color:var(--color-primary-soft)] ring-8 ring-[color:var(--color-primary-soft)]">
        <Icon size={26} className="text-[color:var(--color-primary)]" aria-hidden="true" />
      </div>
      <h2 className="mt-5 text-lg font-medium text-[color:var(--color-foreground)]">{title}</h2>
      {children ? (
        <p className="mt-1 max-w-sm text-sm text-[color:var(--color-muted)]">{children}</p>
      ) : null}
      {action ? <div className="mt-6">{action}</div> : null}
    </div>
  )
}
