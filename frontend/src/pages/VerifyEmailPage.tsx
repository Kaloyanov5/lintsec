import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { AuthLayout } from '@/components/ui/AuthLayout'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { useAuth } from '@/contexts/AuthContext'
import { parseProblem } from '@/lib/problem'
import { authService } from '@/services/authService'

const schema = z.object({
  email: z.string().email('Enter a valid email'),
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code'),
})

type Values = z.infer<typeof schema>

const RESEND_COOLDOWN_SECONDS = 60

export default function VerifyEmailPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { refresh } = useAuth()

  const initialEmail = searchParams.get('email') ?? ''

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { email: initialEmail, code: '' },
  })

  const [cooldown, setCooldown] = useState(0)

  useEffect(() => {
    if (cooldown <= 0) return
    const timer = setInterval(() => setCooldown((s) => Math.max(0, s - 1)), 1000)
    return () => clearInterval(timer)
  }, [cooldown])

  const onSubmit = form.handleSubmit(async (values) => {
    try {
      await authService.verifyEmail(values)
      await refresh()
      toast.success('Email verified. Welcome to LintSec.')
      navigate('/dashboard', { replace: true })
    } catch (err) {
      const problem = parseProblem(err)
      for (const [field, message] of Object.entries(problem.fieldErrors)) {
        if (field === 'email' || field === 'code') {
          form.setError(field, { message })
        }
      }
      if (Object.keys(problem.fieldErrors).length === 0) {
        toast.error(problem.message)
      }
    }
  })

  const onResend = async () => {
    const email = form.getValues('email').trim()
    if (!email) {
      form.setError('email', { message: 'Enter your email first' })
      return
    }
    try {
      await authService.resendVerification({ email })
      toast.success('A new code is on its way.')
      setCooldown(RESEND_COOLDOWN_SECONDS)
    } catch (err) {
      const problem = parseProblem(err)
      if (problem.status === 429 && problem.retryAfterSeconds) {
        setCooldown(problem.retryAfterSeconds)
        toast.error(`Hold on — try again in ${problem.retryAfterSeconds} seconds.`)
      } else {
        toast.error(problem.message)
      }
    }
  }

  return (
    <AuthLayout
      title="Verify your email"
      description="We sent a 6-digit code to your inbox. Enter it below to activate your account."
      footer={
        <>
          Wrong email?{' '}
          <Link to="/register" className="font-medium text-[color:var(--color-primary)] hover:underline">
            Register again
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <FormField label="Email" error={form.formState.errors.email?.message}>
          <Input
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            {...form.register('email')}
          />
        </FormField>
        <FormField label="Verification code" error={form.formState.errors.code?.message}>
          <Input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            autoFocus
            {...form.register('code')}
          />
        </FormField>
        <Button type="submit" loading={form.formState.isSubmitting}>
          Verify email
        </Button>
        <button
          type="button"
          onClick={onResend}
          disabled={cooldown > 0}
          className="cursor-pointer text-xs text-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
        </button>
      </form>
    </AuthLayout>
  )
}
