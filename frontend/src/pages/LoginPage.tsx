import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { AuthLayout } from '@/components/ui/AuthLayout'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { useAuth } from '@/contexts/AuthContext'
import { describeOAuthError } from '@/lib/oauthErrors'
import { parseProblem } from '@/lib/problem'
import { authService } from '@/services/authService'

const loginSchema = z.object({
  email: z.string().email('Enter a valid email'),
  password: z.string().min(1, 'Password is required'),
})

const codeSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code'),
})

type LoginValues = z.infer<typeof loginSchema>
type CodeValues = z.infer<typeof codeSchema>

type LocationState = { from?: { pathname?: string } } | null

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { setUser, refresh } = useAuth()

  const from = (location.state as LocationState)?.from?.pathname ?? '/dashboard'

  const [challengeId, setChallengeId] = useState<string | null>(null)

  const loginForm = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  })

  const codeForm = useForm<CodeValues>({
    resolver: zodResolver(codeSchema),
    defaultValues: { code: '' },
  })

  const onLoginSubmit = loginForm.handleSubmit(async (values) => {
    try {
      const result = await authService.login(values)
      if (result.twoFactorRequired) {
        setChallengeId(result.challengeId)
        toast.success('We sent a 6-digit code to your email.')
        return
      }
      setUser(result.user)
      navigate(from, { replace: true })
    } catch (err) {
      const problem = parseProblem(err)
      for (const [field, message] of Object.entries(problem.fieldErrors)) {
        if (field === 'email' || field === 'password') {
          loginForm.setError(field, { message })
        }
      }
      if (problem.status === 429 && problem.retryAfterSeconds) {
        toast.error(
          `Too many attempts. Try again in ${problem.retryAfterSeconds} seconds.`,
        )
      } else {
        toast.error(problem.message)
      }
    }
  })

  const onCodeSubmit = codeForm.handleSubmit(async (values) => {
    if (!challengeId) return
    try {
      await authService.twoFactorVerify({ challengeId, code: values.code })
      await refresh()
      navigate(from, { replace: true })
    } catch (err) {
      const problem = parseProblem(err)
      if (problem.fieldErrors.code) {
        codeForm.setError('code', { message: problem.fieldErrors.code })
      } else {
        toast.error(problem.message)
      }
    }
  })

  const onGoogle = () => {
    const width = 500
    const height = 620
    const left = window.screenX + (window.outerWidth - width) / 2
    const top = window.screenY + (window.outerHeight - height) / 2
    const popup = window.open(
      authService.googleOAuthUrl,
      'lintsec-google-oauth',
      `width=${width},height=${height},left=${left},top=${top}`,
    )

    if (!popup) {
      toast.error('Allow popups to sign in with Google.')
      return
    }

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return
      const data = event.data as
        | { type: 'lintsec-oauth-success' }
        | { type: 'lintsec-oauth-error'; error: string; message?: string }
        | undefined
      if (!data || (data.type !== 'lintsec-oauth-success' && data.type !== 'lintsec-oauth-error')) return
      window.removeEventListener('message', onMessage)
      if (data.type === 'lintsec-oauth-error') {
        toast.error(describeOAuthError(data.error, data.message))
        return
      }
      void refresh().then(() => navigate(from, { replace: true }))
    }

    window.addEventListener('message', onMessage)
  }

  if (challengeId) {
    return (
      <AuthLayout
        title="Two-factor verification"
        description="Enter the 6-digit code we sent to your email."
      >
        <form onSubmit={onCodeSubmit} className="flex flex-col gap-4" noValidate>
          <FormField label="Verification code" error={codeForm.formState.errors.code?.message}>
            <Input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              autoFocus
              {...codeForm.register('code')}
            />
          </FormField>
          <Button type="submit" loading={codeForm.formState.isSubmitting}>
            Verify
          </Button>
          <button
            type="button"
            onClick={() => {
              setChallengeId(null)
              codeForm.reset()
            }}
            className="cursor-pointer text-xs text-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
          >
            Use a different account
          </button>
        </form>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Welcome back"
      description="Sign in to run and review your security scans."
      footer={
        <>
          Don't have an account?{' '}
          <Link to="/register" className="font-medium text-[color:var(--color-primary)] hover:underline">
            Create one
          </Link>
        </>
      }
    >
      <form onSubmit={onLoginSubmit} className="flex flex-col gap-4" noValidate>
        <FormField label="Email" error={loginForm.formState.errors.email?.message}>
          <Input
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            autoFocus
            {...loginForm.register('email')}
          />
        </FormField>
        <FormField label="Password" error={loginForm.formState.errors.password?.message}>
          <Input
            type="password"
            autoComplete="current-password"
            placeholder="••••••••"
            {...loginForm.register('password')}
          />
        </FormField>
        <Button type="submit" loading={loginForm.formState.isSubmitting}>
          Sign in
        </Button>
      </form>

      <div className="my-6 flex items-center gap-3">
        <span className="h-px flex-1 bg-[color:var(--color-border)]" />
        <span className="text-xs uppercase tracking-wide text-[color:var(--color-muted)]">or</span>
        <span className="h-px flex-1 bg-[color:var(--color-border)]" />
      </div>

      <Button
        type="button"
        variant="secondary"
        onClick={onGoogle}
        leftIcon={<GoogleIcon />}
        className="w-full"
      >
        Continue with Google
      </Button>
    </AuthLayout>
  )
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
      <path
        d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.71-1.58 2.68-3.9 2.68-6.62z"
        fill="#4285F4"
      />
      <path
        d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.92v2.33A9 9 0 0 0 9 18z"
        fill="#34A853"
      />
      <path
        d="M3.97 10.71A5.41 5.41 0 0 1 3.68 9c0-.59.1-1.17.29-1.71V4.96H.92A9 9 0 0 0 0 9c0 1.45.35 2.83.92 4.04l3.05-2.33z"
        fill="#FBBC05"
      />
      <path
        d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58A9 9 0 0 0 9 0 9 9 0 0 0 .92 4.96l3.05 2.33C4.68 5.16 6.66 3.58 9 3.58z"
        fill="#EA4335"
      />
    </svg>
  )
}
