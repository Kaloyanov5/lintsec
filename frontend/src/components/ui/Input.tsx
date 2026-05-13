import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  invalid?: boolean
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { invalid = false, className, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={cn(
        'h-10 w-full rounded-lg border bg-[color:var(--color-surface)] px-3 text-sm',
        'text-[color:var(--color-foreground)] placeholder:text-[color:var(--color-muted)]',
        'transition-[color,background-color,border-color,box-shadow] duration-150',
        'focus:outline-none focus:ring-2',
        'disabled:cursor-not-allowed disabled:opacity-60',
        invalid
          ? 'border-[color:var(--color-danger)] focus:ring-[color:var(--color-danger)]'
          : 'border-[color:var(--color-border)] focus:ring-[color:var(--color-primary)] focus:border-[color:var(--color-primary)]',
        className,
      )}
      {...rest}
    />
  )
})
