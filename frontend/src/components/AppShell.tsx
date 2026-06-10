import { Outlet } from 'react-router-dom'
import { AppHeader } from '@/components/AppHeader'

/** Chrome for authenticated pages: shared header plus a quiet top glow behind the content. */
export function AppShell() {
  return (
    <>
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-x-0 top-0 -z-10 flex justify-center overflow-hidden"
      >
        <div
          className="h-[28rem] w-[44rem] max-w-full -translate-y-1/2 rounded-full opacity-20 blur-3xl"
          style={{
            background:
              'radial-gradient(circle, color-mix(in srgb, var(--color-primary) 45%, transparent), transparent 70%)',
          }}
        />
      </div>
      <AppHeader />
      <Outlet />
    </>
  )
}
