import axios from 'axios'
import type { ProblemDetail } from '@/types'

export type ParsedProblem = {
  status: number | null
  message: string
  fieldErrors: Record<string, string>
  retryAfterSeconds?: number
}

const FALLBACK_MESSAGE = 'Something went wrong. Please try again.'

export function parseProblem(err: unknown): ParsedProblem {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status ?? null
    const data = err.response?.data as ProblemDetail | undefined

    if (data && typeof data === 'object') {
      const fieldErrors: Record<string, string> = {}
      if (Array.isArray(data.errors)) {
        for (const fieldError of data.errors) {
          if (fieldError?.field && fieldError?.message) {
            fieldErrors[fieldError.field] = fieldError.message
          }
        }
      }
      return {
        status,
        message: data.detail || data.title || FALLBACK_MESSAGE,
        fieldErrors,
        retryAfterSeconds: data.retryAfterSeconds,
      }
    }

    return {
      status,
      message: err.message || FALLBACK_MESSAGE,
      fieldErrors: {},
    }
  }

  return { status: null, message: FALLBACK_MESSAGE, fieldErrors: {} }
}
