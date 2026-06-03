export type ScanEventType = 'STARTED' | 'CRAWL_COMPLETE' | 'SCAN_COMPLETE' | 'FAILED'

/** Mirrors the backend `ScanEvent` record, sent as the named SSE event `scan`. */
export type ScanEvent = {
  scanId: number
  type: ScanEventType
  pagesCrawled: number
  findingsCount: number
  message: string | null
}
