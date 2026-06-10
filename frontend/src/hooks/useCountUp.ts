import { useEffect, useState } from 'react'

/** Animates 0 → target over durationMs (ease-out cubic). Snaps to target under reduced motion. */
export function useCountUp(target: number, durationMs = 400): number {
  const [value, setValue] = useState(0)

  useEffect(() => {
    let frame: number
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      frame = requestAnimationFrame(() => setValue(target))
    } else {
      const start = performance.now()
      const tick = (now: number) => {
        const t = Math.min((now - start) / durationMs, 1)
        const eased = 1 - Math.pow(1 - t, 3)
        setValue(Math.round(eased * target))
        if (t < 1) frame = requestAnimationFrame(tick)
      }
      frame = requestAnimationFrame(tick)
    }
    return () => cancelAnimationFrame(frame)
  }, [target, durationMs])

  return value
}
