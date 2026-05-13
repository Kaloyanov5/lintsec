import { Toaster } from 'sonner'
import { useTheme } from '@/contexts/ThemeContext'

export function ThemedToaster() {
  const { resolvedTheme } = useTheme()
  return <Toaster theme={resolvedTheme} position="top-right" richColors closeButton />
}
