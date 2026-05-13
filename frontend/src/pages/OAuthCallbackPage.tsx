import { useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { Spinner } from '@/components/ui/Spinner'
import { useAuth } from '@/contexts/AuthContext'
import { describeOAuthError } from '@/lib/oauthErrors'

type OAuthMessage =
  | { type: 'lintsec-oauth-success' }
  | { type: 'lintsec-oauth-error'; error: string; message?: string }

function buildMessage(searchParams: URLSearchParams): OAuthMessage {
  const error = searchParams.get('error')
  if (error) {
    const message = searchParams.get('message') ?? undefined
    return { type: 'lintsec-oauth-error', error, message }
  }
  return { type: 'lintsec-oauth-success' }
}

export default function OAuthCallbackPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { refresh } = useAuth()

  useEffect(() => {
    const message = buildMessage(searchParams)
    const opener = window.opener as Window | null

    if (opener && !opener.closed) {
      try {
        opener.postMessage(message, window.location.origin)
      } catch {
        // Posting may fail in rare edge cases; the fallback below covers the no-opener case.
      }
      window.close()
      return
    }

    if (message.type === 'lintsec-oauth-error') {
      toast.error(describeOAuthError(message.error, message.message))
      navigate('/login', { replace: true })
      return
    }

    refresh()
      .catch(() => undefined)
      .finally(() => navigate('/dashboard', { replace: true }))
  }, [navigate, refresh, searchParams])

  return (
    <main className="flex min-h-screen items-center justify-center">
      <div className="flex items-center gap-3 text-sm text-[color:var(--color-muted)]">
        <Spinner size="sm" />
        <span>Finishing sign-in…</span>
      </div>
    </main>
  )
}
