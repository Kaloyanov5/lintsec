import { cn } from '@/lib/cn'

type SpinnerProps = {
  className?: string
  size?: 'sm' | 'md'
}

export function Spinner({ className, size = 'md' }: SpinnerProps) {
  const sizeClass = size === 'sm' ? 'h-4 w-4' : 'h-5 w-5'
  return (
    <svg
      className={cn('animate-spin', sizeClass, className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v3a5 5 0 0 0-5 5H4z"
      />
    </svg>
  )
}
