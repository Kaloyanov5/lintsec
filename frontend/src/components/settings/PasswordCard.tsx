import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { SettingsCard } from '@/components/settings/SettingsCard'
import { parseProblem } from '@/lib/problem'
import { authService } from '@/services/authService'

const schema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z
      .string()
      .min(10, 'At least 10 characters')
      .regex(/[A-Za-z]/, 'Must contain a letter')
      .regex(/\d/, 'Must contain a digit'),
    confirmPassword: z.string(),
  })
  .refine((v) => v.newPassword === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'Passwords do not match',
  })

type Values = z.infer<typeof schema>

export function PasswordCard() {
  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { currentPassword: '', newPassword: '', confirmPassword: '' },
  })

  const onSubmit = form.handleSubmit(async (values) => {
    try {
      await authService.changePassword({
        currentPassword: values.currentPassword,
        newPassword: values.newPassword,
      })
      toast.success('Password updated.')
      form.reset()
    } catch (err) {
      const problem = parseProblem(err)
      if (problem.status === 401) {
        form.setError('currentPassword', { message: 'Incorrect password' })
      } else if (problem.fieldErrors.newPassword) {
        form.setError('newPassword', { message: problem.fieldErrors.newPassword })
      } else {
        toast.error(problem.message)
      }
    }
  })

  return (
    <SettingsCard title="Password" description="Change the password you use to sign in.">
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <FormField label="Current password" error={form.formState.errors.currentPassword?.message}>
          <Input
            type="password"
            autoComplete="current-password"
            {...form.register('currentPassword')}
          />
        </FormField>
        <FormField
          label="New password"
          hint="At least 10 characters with a letter and a digit."
          error={form.formState.errors.newPassword?.message}
        >
          <Input type="password" autoComplete="new-password" {...form.register('newPassword')} />
        </FormField>
        <FormField
          label="Confirm new password"
          error={form.formState.errors.confirmPassword?.message}
        >
          <Input type="password" autoComplete="new-password" {...form.register('confirmPassword')} />
        </FormField>
        <div>
          <Button type="submit" loading={form.formState.isSubmitting}>
            Update password
          </Button>
        </div>
      </form>
    </SettingsCard>
  )
}
