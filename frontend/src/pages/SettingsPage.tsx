import { ShieldCheck } from 'lucide-react'
import { PageHeader } from '@/components/ui/PageHeader'
import { AccountCard } from '@/components/settings/AccountCard'
import { PasswordCard } from '@/components/settings/PasswordCard'
import { SettingsCard } from '@/components/settings/SettingsCard'
import { TwoFactorCard } from '@/components/settings/TwoFactorCard'
import { useAuth } from '@/contexts/AuthContext'

export default function SettingsPage() {
  const { user } = useAuth()
  const isLocal = user?.provider === 'LOCAL'

  return (
    <main className="mx-auto max-w-3xl px-6 py-12 motion-safe:animate-fade-in-up">
      <PageHeader title="Settings" subtitle="Manage your account and security." />

      <div className="mt-8 flex flex-col gap-4">
        <AccountCard />
        {isLocal ? (
          <>
            <PasswordCard />
            <TwoFactorCard />
          </>
        ) : (
          <SettingsCard title="Security" icon={ShieldCheck}>
            <p className="text-sm text-[color:var(--color-muted)]">
              Password and two-factor authentication are managed by your Google account.
            </p>
          </SettingsCard>
        )}
      </div>
    </main>
  )
}
