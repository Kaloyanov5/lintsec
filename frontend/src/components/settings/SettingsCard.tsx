import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

type SettingsCardProps = {
  title: string
  description?: string
  icon?: LucideIcon
  children: ReactNode
}

export function SettingsCard({ title, description, icon: Icon, children }: SettingsCardProps) {
  return (
    <section className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 shadow-[var(--shadow-card)]">
      <div className="flex items-start gap-3">
        {Icon ? (
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[color:var(--color-primary-soft)]">
            <Icon size={17} className="text-[color:var(--color-primary)]" aria-hidden="true" />
          </div>
        ) : null}
        <div className="min-w-0">
          <h2 className="text-lg font-medium text-[color:var(--color-foreground)]">{title}</h2>
          {description ? (
            <p className="mt-1 text-sm text-[color:var(--color-muted)]">{description}</p>
          ) : null}
        </div>
      </div>
      <div className="mt-5">{children}</div>
    </section>
  )
}
