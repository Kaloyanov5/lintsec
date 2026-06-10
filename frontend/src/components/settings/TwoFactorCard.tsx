import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { SettingsCard } from '@/components/settings/SettingsCard'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/cn'
import { parseProblem } from '@/lib/problem'
import { authService } from '@/services/authService'

const codeSchema = z.object({ code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code') })
const passwordSchema = z.object({ password: z.string().min(1, 'Password is required') })

type CodeValues = z.infer<typeof codeSchema>
type PasswordValues = z.infer<typeof passwordSchema>

export function TwoFactorCard() {
  const { user, refresh } = useAuth()
  const [enableStage, setEnableStage] = useState<'idle' | 'codeSent'>('idle')
  const [disabling, setDisabling] = useState(false)

  const codeForm = useForm<CodeValues>({
    resolver: zodResolver(codeSchema),
    defaultValues: { code: '' },
  })
  const passwordForm = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { password: '' },
  })

  const enabled = user?.twoFactorEnabled ?? false

  async function startEnable() {
    try {
      await authService.twoFactorEnable()
      setEnableStage('codeSent')
      toast.success('We sent a 6-digit code to your email.')
    } catch (err) {
      toast.error(parseProblem(err).message)
    }
  }

  const onConfirm = codeForm.handleSubmit(async (values) => {
    try {
      await authService.twoFactorConfirm({ code: values.code })
      await refresh()
      setEnableStage('idle')
      codeForm.reset()
      toast.success('Two-factor authentication is on.')
    } catch (err) {
      const problem = parseProblem(err)
      if (problem.fieldErrors.code) {
        codeForm.setError('code', { message: problem.fieldErrors.code })
      } else {
        toast.error(problem.message)
      }
    }
  })

  const onDisable = passwordForm.handleSubmit(async (values) => {
    try {
      await authService.twoFactorDisable({ password: values.password })
      await refresh()
      setDisabling(false)
      passwordForm.reset()
      toast.success('Two-factor authentication is off.')
    } catch (err) {
      const problem = parseProblem(err)
      if (problem.status === 401) {
        passwordForm.setError('password', { message: 'Incorrect password' })
      } else {
        toast.error(problem.message)
      }
    }
  })

  return (
    <SettingsCard
      title="Two-factor authentication"
      icon={ShieldCheck}
      description="Require a one-time email code when you sign in."
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="inline-flex items-center gap-2 text-sm font-medium">
          <span
            className={cn(
              'h-2 w-2 rounded-full',
              enabled ? 'bg-[color:var(--color-success)]' : 'bg-[color:var(--color-muted)]',
            )}
            aria-hidden="true"
          />
          {enabled ? 'Enabled' : 'Disabled'}
        </span>

        {enabled && !disabling && (
          <Button type="button" variant="secondary" onClick={() => setDisabling(true)}>
            Disable
          </Button>
        )}
        {!enabled && enableStage === 'idle' && (
          <Button type="button" onClick={startEnable}>
            Enable
          </Button>
        )}
      </div>

      {!enabled && enableStage === 'codeSent' && (
        <form onSubmit={onConfirm} className="mt-5 flex flex-col gap-4" noValidate>
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
          <div className="flex items-center gap-3">
            <Button type="submit" loading={codeForm.formState.isSubmitting}>
              Confirm
            </Button>
            <button
              type="button"
              onClick={startEnable}
              className="cursor-pointer text-xs text-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
            >
              Resend code
            </button>
            <button
              type="button"
              onClick={() => {
                setEnableStage('idle')
                codeForm.reset()
              }}
              className="cursor-pointer text-xs text-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {enabled && disabling && (
        <form onSubmit={onDisable} className="mt-5 flex flex-col gap-4" noValidate>
          <FormField
            label="Current password"
            error={passwordForm.formState.errors.password?.message}
          >
            <Input
              type="password"
              autoComplete="current-password"
              autoFocus
              {...passwordForm.register('password')}
            />
          </FormField>
          <div className="flex items-center gap-3">
            <Button type="submit" loading={passwordForm.formState.isSubmitting}>
              Confirm disable
            </Button>
            <button
              type="button"
              onClick={() => {
                setDisabling(false)
                passwordForm.reset()
              }}
              className="cursor-pointer text-xs text-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </SettingsCard>
  )
}
