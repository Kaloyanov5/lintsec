import { useId, type ReactElement, cloneElement } from 'react'
import { cn } from '@/lib/cn'

type FormFieldProps = {
  label: string
  hint?: string
  error?: string
  children: ReactElement<{ id?: string; invalid?: boolean; 'aria-describedby'?: string }>
  className?: string
}

export function FormField({ label, hint, error, children, className }: FormFieldProps) {
  const id = useId()
  const descId = error ? `${id}-error` : hint ? `${id}-hint` : undefined

  const control = cloneElement(children, {
    id,
    invalid: Boolean(error),
    'aria-describedby': descId,
  })

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <label
        htmlFor={id}
        className="text-sm font-medium text-[color:var(--color-foreground)]"
      >
        {label}
      </label>
      {control}
      {error ? (
        <p id={descId} className="text-xs text-[color:var(--color-danger)]">
          {error}
        </p>
      ) : hint ? (
        <p id={descId} className="text-xs text-[color:var(--color-muted)]">
          {hint}
        </p>
      ) : null}
    </div>
  )
}
