import { cn } from '@/lib/cn'

/** Shimmering placeholder block; set size/shape via className (e.g. "h-24 rounded-xl"). */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cn('skeleton motion-safe:animate-shimmer', className)} />
}
