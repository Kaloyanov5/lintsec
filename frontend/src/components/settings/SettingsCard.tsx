import type { ReactNode } from 'react'

type SettingsCardProps = {
  title: string
  description?: string
  children: ReactNode
}

export function SettingsCard({ title, description, children }: SettingsCardProps) {
  return (
    <section className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
      <h2 className="text-lg font-medium text-[color:var(--color-foreground)]">{title}</h2>
      {description ? (
        <p className="mt-1 text-sm text-[color:var(--color-muted)]">{description}</p>
      ) : null}
      <div className="mt-5">{children}</div>
    </section>
  )
}
