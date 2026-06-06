import { Outlet } from 'react-router-dom'
import { AppHeader } from '@/components/AppHeader'

/** Chrome for authenticated pages: the shared header above the routed page content. */
export function AuthLayout() {
  return (
    <>
      <AppHeader />
      <Outlet />
    </>
  )
}
