import { api } from '@/lib/api'
import type { Finding, Scan } from '@/types'

export const scanService = {
  getScan(id: number | string) {
    return api.get<Scan>(`/scans/${id}`).then((r) => r.data)
  },

  getFindings(id: number | string) {
    return api.get<Finding[]>(`/scans/${id}/findings`).then((r) => r.data)
  },
}
