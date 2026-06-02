import type { ScanPageDto } from './scan'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type VulnerabilityType =
  | 'XSS'
  | 'SQL_INJECTION'
  | 'CORS'
  | 'SECURITY_HEADERS'
  | 'SENSITIVE_DATA'
  | 'OPEN_REDIRECT'
  | 'COOKIE_SECURITY'
  | 'CSRF'
  | 'DIRECTORY_LISTING'
  | 'INSECURE_HTTP_METHOD'

export type AiStatus = 'PENDING' | 'READY' | 'FAILED'

/**
 * Mirrors the backend `FindingResponse` returned by `GET /api/scans/{id}/findings`.
 * This is the *live* shape; the FindingSummary/FindingDetail types below describe the
 * richer CONTRACT.md target the backend has not yet caught up to.
 */
export type Finding = {
  id: number
  vulnerabilityType: VulnerabilityType
  severity: Severity
  title: string
  description: string | null
  remediation: string | null
  evidenceJson: string | null
  payloadRef: string | null
  aiExplanation: string | null
  createdAt: string
}

/** One occurrence within a {@link FindingGroup} — mirrors backend `FindingInstanceResponse`. */
export type FindingInstance = {
  id: number
  url: string | null
  parameter: string | null
  note: string | null
  payloadRef: string | null
  createdAt: string
}

/**
 * A set of duplicate findings collapsed by (type, severity, title) — mirrors backend
 * `FindingGroupResponse` from `GET /api/scans/{id}/findings/grouped`. Descriptive fields are
 * shared; the per-occurrence detail lives in `instances`.
 */
export type FindingGroup = {
  vulnerabilityType: VulnerabilityType
  severity: Severity
  title: string
  description: string | null
  remediation: string | null
  aiExplanation: string | null
  count: number
  instances: FindingInstance[]
}

export type FindingSummary = {
  id: number
  vulnerabilityType: VulnerabilityType
  severity: Severity
  title: string
  pageUrl: string | null
  createdAt: string
  aiStatus: AiStatus
}

export type FindingDetail = {
  id: number
  vulnerabilityType: VulnerabilityType
  severity: Severity
  title: string
  description: string | null
  evidence: Record<string, unknown> | null
  payloadRef: string | null
  page: ScanPageDto | null
  aiStatus: AiStatus
  aiExplanation: string | null
  createdAt: string
}
