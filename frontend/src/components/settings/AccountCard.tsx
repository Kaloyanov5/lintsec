import { SettingsCard } from '@/components/settings/SettingsCard'
import { useAuth } from '@/contexts/AuthContext'

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

export function AccountCard() {
  const { user } = useAuth()
  if (!user) return null

  const rows: { label: string; value: string }[] = [
    { label: 'Display name', value: user.displayName ?? '—' },
    { label: 'Email', value: user.email },
    { label: 'Provider', value: user.provider === 'GOOGLE' ? 'Google' : 'Email & password' },
    { label: 'Email verified', value: user.emailVerified ? 'Yes' : 'No' },
    { label: 'Member since', value: formatDate(user.createdAt) },
  ]

  return (
    <SettingsCard title="Account">
      <dl className="divide-y divide-[color:var(--color-border)]">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-4 py-2.5 text-sm">
            <dt className="text-[color:var(--color-muted)]">{row.label}</dt>
            <dd className="font-medium text-[color:var(--color-foreground)]">{row.value}</dd>
          </div>
        ))}
      </dl>
    </SettingsCard>
  )
}
