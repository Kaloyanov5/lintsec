import { Monitor, Moon, Sun } from 'lucide-react'
import { useTheme, type Theme } from '@/contexts/ThemeContext'
import { cn } from '@/lib/cn'

const order: Theme[] = ['light', 'dark', 'system']

const icons: Record<Theme, typeof Sun> = {
  light: Sun,
  dark: Moon,
  system: Monitor,
}

const labels: Record<Theme, string> = {
  light: 'Light theme',
  dark: 'Dark theme',
  system: 'System theme',
}

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, setTheme } = useTheme()
  const Icon = icons[theme]

  const cycle = () => {
    const next = order[(order.indexOf(theme) + 1) % order.length]
    setTheme(next)
  }

  return (
    <button
      type="button"
      onClick={cycle}
      aria-label={`${labels[theme]} (click to change)`}
      title={labels[theme]}
      className={cn(
        'inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg',
        'border border-[color:var(--color-border)] bg-[color:var(--color-surface)]',
        'text-[color:var(--color-muted)] transition-colors',
        'hover:bg-[color:var(--color-surface-muted)] hover:text-[color:var(--color-foreground)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-primary)]',
        className,
      )}
    >
      <Icon size={16} aria-hidden="true" />
    </button>
  )
}
