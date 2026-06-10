import { cn } from '@/lib/cn'
import { statusBadgeClass, statusLabel } from '@/lib/scanStatus'
import type { Scan } from '@/types'

/** Scan status pill with a leading dot; the dot pulses while the scan is PENDING/RUNNING. */
export function StatusBadge({ scan, className }: { scan: Scan; className?: string }) {
  const active = scan.status === 'PENDING' || scan.status === 'RUNNING'
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
        statusBadgeClass(scan),
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn('h-1.5 w-1.5 rounded-full bg-current', active && 'motion-safe:animate-pulse')}
      />
      {statusLabel(scan)}
    </span>
  )
}
