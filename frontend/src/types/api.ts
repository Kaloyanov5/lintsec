export type Page<T> = {
  content: T[]
  totalElements: number
  totalPages: number
  number: number
  size: number
  first: boolean
  last: boolean
}

export type ProblemDetailFieldError = {
  field: string
  message: string
}

export type ProblemDetail = {
  type: string
  title: string
  status: number
  detail?: string
  instance?: string
  errors?: ProblemDetailFieldError[]
  retryAfterSeconds?: number
}
