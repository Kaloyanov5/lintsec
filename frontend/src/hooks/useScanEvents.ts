import { useEffect, useRef, useState } from 'react'
import { scanService } from '@/services/scanService'
import type { ScanEvent, ScanEventType } from '@/types'

function isTerminal(type: ScanEventType): boolean {
  return type === 'SCAN_COMPLETE' || type === 'FAILED'
}

/**
 * Subscribes to the live scan event stream while `enabled` is true and returns the most
 * recently received event (null until the first arrives). `onTerminal` fires once when a
 * terminal event (SCAN_COMPLETE/FAILED) arrives — the caller uses it to refetch findings.
 *
 * Owns the EventSource lifecycle: opens on enable, listens for the named `scan` event, and
 * closes on a terminal event and on unmount/disable. We close explicitly on terminal events
 * because the server completes the emitter, and EventSource would otherwise auto-reconnect to
 * a now-empty stream for the full server timeout.
 *
 * State updates happen inside the stream's event callback (an external-system subscription),
 * not in an effect body, so there is no cascading-render churn. `onTerminal` is held in a ref
 * so the latest closure is always called without re-subscribing the stream.
 */
export function useScanEvents(
  id: string,
  enabled: boolean,
  onTerminal?: () => void,
): ScanEvent | null {
  const [event, setEvent] = useState<ScanEvent | null>(null)

  // Keep the latest callback in a ref so the stream subscription can call the current closure
  // without being torn down and re-opened whenever the caller passes a new function instance.
  const onTerminalRef = useRef(onTerminal)
  useEffect(() => {
    onTerminalRef.current = onTerminal
  })

  useEffect(() => {
    if (!enabled) return

    const source = new EventSource(scanService.eventsUrl(id), { withCredentials: true })

    source.addEventListener('scan', (e) => {
      const data = JSON.parse((e as MessageEvent).data) as ScanEvent
      setEvent(data)
      if (isTerminal(data.type)) {
        source.close()
        onTerminalRef.current?.()
      }
    })
    // EventSource auto-retries transient drops on its own; nothing to do here. The manual
    // Refresh button on the page is the fallback for hard failures.

    return () => source.close()
  }, [id, enabled])

  return event
}
