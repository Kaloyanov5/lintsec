import type { ScanPageDto } from './scan'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type VulnerabilityType =
  | 'XSS'
  | 'SQL_INJECTION'
  | 'CORS'
  | 'SECURITY_HEADERS'
  | 'SENSITIVE_DATA'

export type AiStatus = 'PENDING' | 'READY' | 'FAILED'

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
