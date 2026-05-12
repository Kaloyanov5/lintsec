import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL ?? '/api'

function readCookie(name: string): string | undefined {
  const cookies = document.cookie ? document.cookie.split('; ') : []
  for (const c of cookies) {
    const eq = c.indexOf('=')
    if (eq === -1) continue
    if (c.slice(0, eq) === name) {
      return decodeURIComponent(c.slice(eq + 1))
    }
  }
  return undefined
}

const STATE_CHANGING = new Set(['post', 'put', 'patch', 'delete'])

export const api: AxiosInstance = axios.create({
  baseURL,
  withCredentials: true,
  headers: { Accept: 'application/json' },
})

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const method = (config.method ?? 'get').toLowerCase()
  if (STATE_CHANGING.has(method)) {
    const token = readCookie('XSRF-TOKEN')
    if (token) {
      config.headers.set('X-XSRF-TOKEN', token)
    }
  }
  return config
})
