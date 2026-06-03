import { api } from '@/lib/api'
import type { CreateScanRequest, Finding, FindingGroup, Page, Scan } from '@/types'

const apiBase = import.meta.env.VITE_API_BASE_URL ?? '/api'

export const scanService = {
  createScan(body: CreateScanRequest) {
    return api.post<Scan>('/scans', body).then((r) => r.data)
  },

  listScans(page = 0, size = 20) {
    return api.get<Page<Scan>>('/scans', { params: { page, size } }).then((r) => r.data)
  },

  getScan(id: number | string) {
    return api.get<Scan>(`/scans/${id}`).then((r) => r.data)
  },

  getFindings(id: number | string) {
    return api.get<Finding[]>(`/scans/${id}/findings`).then((r) => r.data)
  },

  getGroupedFindings(id: number | string) {
    return api.get<FindingGroup[]>(`/scans/${id}/findings/grouped`).then((r) => r.data)
  },

  /** Direct download URL for an export; GET + same-origin cookie, no CSRF needed. */
  exportUrl(id: number | string, format: 'pdf' | 'json') {
    return `${apiBase}/scans/${id}/export.${format}`
  },

  /** Live event stream URL; consumed by EventSource (GET + same-origin cookie, no CSRF). */
  eventsUrl(id: number | string) {
    return `${apiBase}/scans/${id}/events`
  },
}
