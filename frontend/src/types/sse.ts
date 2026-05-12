import type { FindingSummary } from './finding'
import type { ScanDetail, ScanPageDto } from './scan'

export type ScanPhase = 'CRAWLING' | 'SCANNING'

export type ProgressEventData = {
  phase: ScanPhase
  percent: number
  pagesCrawled: number
  totalPages: number
  currentScanner?: string
}

export type AiReadyEventData = {
  findingId: number
}

export type ErrorEventData = {
  message: string
}

export type ScanEvent =
  | { type: 'progress'; data: ProgressEventData }
  | { type: 'page-crawled'; data: ScanPageDto }
  | { type: 'finding'; data: FindingSummary }
  | { type: 'ai-ready'; data: AiReadyEventData }
  | { type: 'complete'; data: ScanDetail }
  | { type: 'error'; data: ErrorEventData }
