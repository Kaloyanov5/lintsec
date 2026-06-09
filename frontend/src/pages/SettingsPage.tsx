import { AccountCard } from '@/components/settings/AccountCard'
import { PasswordCard } from '@/components/settings/PasswordCard'
import { TwoFactorCard } from '@/components/settings/TwoFactorCard'
import { useAuth } from '@/contexts/AuthContext'

export default function SettingsPage() {
  const { user } = useAuth()
  const isLocal = user?.provider === 'LOCAL'

  return (
    <main className="mx-auto max-w-3xl px-6 py-12">
      <h1 className="text-2xl font-medium">Settings</h1>
      <p className="mt-1 text-sm text-[color:var(--color-muted)]">
        Manage your account and security.
      </p>

      <div className="mt-8 flex flex-col gap-4">
        <AccountCard />
        {isLocal ? (
          <>
            <PasswordCard />
            <TwoFactorCard />
          </>
        ) : (
          <section className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
            <h2 className="text-lg font-medium text-[color:var(--color-foreground)]">Security</h2>
            <p className="mt-1 text-sm text-[color:var(--color-muted)]">
              Password and two-factor authentication are managed by your Google account.
            </p>
          </section>
        )}
      </div>
    </main>
  )
}
