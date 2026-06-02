import type { Severity } from './finding'

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED'

/**
 * Mirrors the backend `ScanResponse` returned by `GET /api/scans/{id}` and `GET /api/scans`.
 * Live shape; ScanDetail/ScanSummary below are the richer CONTRACT.md target.
 */
export type Scan = {
  id: number
  targetUrl: string
  status: ScanStatus
  maxDepth: number
  maxPages: number
  requestDelayMs: number
  pagesCrawled: number
  errorMessage: string | null
  startedAt: string | null
  completedAt: string | null
  createdAt: string
}

export type FindingsBySeverity = Record<Severity, number>

export type CreateScanRequest = {
  targetUrl: string
  ownershipConfirmed: boolean
}

export type ScanSummary = {
  id: number
  targetUrl: string
  status: ScanStatus
  createdAt: string
  completedAt: string | null
  pagesCrawled: number
  findingsBySeverity: FindingsBySeverity
}

export type ScanDetail = {
  id: number
  targetUrl: string
  status: ScanStatus
  errorMessage: string | null
  ownershipConfirmed: boolean
  pagesCrawled: number
  maxDepth: number
  maxPages: number
  requestDelayMs: number
  startedAt: string | null
  completedAt: string | null
  createdAt: string
  findingsBySeverity: FindingsBySeverity
  durationMs: number | null
}

export type ScanPageDto = {
  id: number
  url: string
  statusCode: number | null
  depth: number
  title: string | null
  crawledAt: string
}
