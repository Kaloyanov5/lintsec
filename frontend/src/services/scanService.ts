import { api } from '@/lib/api'
import type { CreateScanRequest, Finding, Page, Scan } from '@/types'

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
}
