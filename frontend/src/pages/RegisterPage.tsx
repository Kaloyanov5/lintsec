import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { AuthLayout } from '@/components/ui/AuthLayout'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { parseProblem } from '@/lib/problem'
import { authService } from '@/services/authService'

const registerSchema = z.object({
  displayName: z
    .string()
    .trim()
    .min(1, 'Display name is required')
    .max(100, 'Display name must be 100 characters or fewer'),
  email: z.string().email('Enter a valid email'),
  password: z
    .string()
    .min(10, 'At least 10 characters')
    .regex(/[A-Za-z]/, 'Must contain a letter')
    .regex(/\d/, 'Must contain a digit'),
})

type RegisterValues = z.infer<typeof registerSchema>

export default function RegisterPage() {
  const navigate = useNavigate()
  const form = useForm<RegisterValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: { displayName: '', email: '', password: '' },
  })

  const onSubmit = form.handleSubmit(async (values) => {
    try {
      await authService.register(values)
      toast.success('Account created. Check your email for a verification code.')
      navigate(`/verify-email?email=${encodeURIComponent(values.email)}`, { replace: true })
    } catch (err) {
      const problem = parseProblem(err)
      for (const [field, message] of Object.entries(problem.fieldErrors)) {
        if (field === 'email' || field === 'password' || field === 'displayName') {
          form.setError(field, { message })
        }
      }
      if (Object.keys(problem.fieldErrors).length === 0) {
        toast.error(problem.message)
      }
    }
  })

  return (
    <AuthLayout
      title="Create your account"
      description="Start scanning your sites for common security issues."
      footer={
        <>
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-[color:var(--color-primary)] hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <FormField label="Display name" error={form.formState.errors.displayName?.message}>
          <Input
            type="text"
            autoComplete="name"
            placeholder="Jane Doe"
            autoFocus
            {...form.register('displayName')}
          />
        </FormField>
        <FormField label="Email" error={form.formState.errors.email?.message}>
          <Input
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            {...form.register('email')}
          />
        </FormField>
        <FormField
          label="Password"
          hint="At least 10 characters with a letter and a digit."
          error={form.formState.errors.password?.message}
        >
          <Input
            type="password"
            autoComplete="new-password"
            placeholder="••••••••••"
            {...form.register('password')}
          />
        </FormField>
        <Button type="submit" loading={form.formState.isSubmitting}>
          Create account
        </Button>
      </form>
    </AuthLayout>
  )
}
