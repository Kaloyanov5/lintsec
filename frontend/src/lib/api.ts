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

async function mintCsrfToken(): Promise<string | undefined> {
  try {
    await axios.get(`${baseURL}/me`, { withCredentials: true })
  } catch {
    // Even a 401 sets the XSRF-TOKEN cookie; only network errors leave us empty-handed.
  }
  return readCookie('XSRF-TOKEN')
}

api.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  const method = (config.method ?? 'get').toLowerCase()
  if (STATE_CHANGING.has(method)) {
    let token = readCookie('XSRF-TOKEN')
    if (!token) {
      token = await mintCsrfToken()
    }
    if (token) {
      config.headers.set('X-XSRF-TOKEN', token)
    }
  }
  return config
})
