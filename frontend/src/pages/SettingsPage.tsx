import { AccountCard } from '@/components/settings/AccountCard'

export default function SettingsPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-12">
      <h1 className="text-2xl font-medium">Settings</h1>
      <p className="mt-1 text-sm text-[color:var(--color-muted)]">
        Manage your account and security.
      </p>

      <div className="mt-8 flex flex-col gap-4">
        <AccountCard />
      </div>
    </main>
  )
}
