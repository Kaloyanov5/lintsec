import { forwardRef, type InputHTMLAttributes, type ReactNode } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { ArrowLeft, Gauge, Globe, KeyRound } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { PageHeader } from '@/components/ui/PageHeader'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'
import type { Scan } from '@/types'

const authSchema = z
  .object({
    loginUrl: z.string().optional(),
    usernameField: z.string().optional(),
    passwordField: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    successCheck: z.string().optional(),
    sessionCookie: z.string().optional(),
  })
  .optional()

const schema = z.object({
  targetUrl: z
    .string()
    .regex(/^https?:\/\/\S+$/, 'Enter a valid http(s) URL'),
  maxDepth: z.number().int().min(0, 'Min 0').max(3, 'Max 3'),
  maxPages: z.number().int().min(1, 'Min 1').max(50, 'Max 50'),
  requestDelayMs: z.number().int().min(0, 'Min 0').max(5000, 'Max 5000'),
  ownershipConfirmed: z
    .boolean()
    .refine((v) => v, { message: 'You must confirm you are authorized to scan this target' }),
  ignoreRobots: z.boolean(),
  authEnabled: z.boolean(),
  auth: authSchema,
})

type ScanFormValues = z.infer<typeof schema>

export default function NewScanPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: Scan } | null)?.from ?? null

  const defaultValues: ScanFormValues = {
    targetUrl: from?.targetUrl ?? '',
    maxDepth: from?.maxDepth ?? 2,
    maxPages: from?.maxPages ?? 50,
    requestDelayMs: from?.requestDelayMs ?? 300,
    ownershipConfirmed: false,
    ignoreRobots: false,
    authEnabled: from?.authenticated ?? false,
    auth: {
      loginUrl: '',
      usernameField: 'username',
      passwordField: 'password',
      username: '',
      password: '',
      successCheck: '',
      sessionCookie: '',
    },
  }

  const form = useForm<ScanFormValues>({
    resolver: zodResolver(schema),
    defaultValues,
  })

  const onSubmit = form.handleSubmit(async (values) => {
    try {
      const { authEnabled, auth, ...rest } = values
      const body = authEnabled && auth ? { ...rest, auth } : rest
      const scan = await scanService.createScan(body)
      toast.success('Scan started.')
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      const problem = parseProblem(err)
      for (const [field, message] of Object.entries(problem.fieldErrors)) {
        if (field in values) {
          form.setError(field as keyof ScanFormValues, { message })
        }
      }
      toast.error(problem.message)
    }
  })

  const errors = form.formState.errors

  return (
    <main className="mx-auto max-w-2xl px-6 py-12 motion-safe:animate-fade-in-up">
      <Link
        to="/scans/history"
        className="inline-flex items-center gap-1.5 text-sm text-[color:var(--color-muted)] transition-colors hover:text-[color:var(--color-foreground)]"
      >
        <ArrowLeft size={15} aria-hidden="true" />
        All scans
      </Link>

      <div className="mt-4">
        <PageHeader
          title="New scan"
          subtitle="Only scan targets you own or are explicitly authorized to test."
        />
      </div>

      {from && (
        <p className="mt-3 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-3 text-xs text-[color:var(--color-muted)]">
          Re-running a previous scan. Review the settings and re-confirm authorization
          {from.authenticated ? '. Re-enter your login credentials to scan behind login.' : '.'}
        </p>
      )}

      <form
        onSubmit={onSubmit}
        className="mt-8 flex flex-col gap-6 rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 shadow-[var(--shadow-card)]"
        noValidate
      >
        <section className="flex flex-col gap-4">
          <SectionTitle icon={Globe}>Target</SectionTitle>
          <FormField label="Target URL" error={errors.targetUrl?.message}>
            <Input
              type="url"
              placeholder="https://example.com"
              autoFocus
              {...form.register('targetUrl')}
            />
          </FormField>
          <Checkbox
            label="I own this target or am authorized to scan it"
            error={errors.ownershipConfirmed?.message}
            {...form.register('ownershipConfirmed')}
          />
        </section>

        <section className="flex flex-col gap-4 border-t border-[color:var(--color-border)] pt-5">
          <SectionTitle icon={Gauge}>Crawl limits</SectionTitle>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <FormField label="Max depth" hint="0–3" error={errors.maxDepth?.message}>
              <Input type="number" min={0} max={3} {...form.register('maxDepth', { valueAsNumber: true })} />
            </FormField>
            <FormField label="Max pages" hint="1–50" error={errors.maxPages?.message}>
              <Input type="number" min={1} max={50} {...form.register('maxPages', { valueAsNumber: true })} />
            </FormField>
            <FormField label="Delay (ms)" hint="0–5000" error={errors.requestDelayMs?.message}>
              <Input type="number" min={0} max={5000} {...form.register('requestDelayMs', { valueAsNumber: true })} />
            </FormField>
          </div>
          <Checkbox
            label="Ignore robots.txt (only for sandboxes that disallow crawling)"
            {...form.register('ignoreRobots')}
          />
        </section>

        <section className="flex flex-col gap-4 border-t border-[color:var(--color-border)] pt-5">
          <SectionTitle icon={KeyRound}>Authentication</SectionTitle>
          <Checkbox
            label="Authenticated scan (log in before crawling)"
            {...form.register('authEnabled')}
          />
          {form.watch('authEnabled') && (
            <div className="flex flex-col gap-4 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface-muted)]/50 p-4">
              <FormField label="Login page URL" hint="The page with the login form">
                <Input type="url" placeholder="http://localhost:8081/login.php" {...form.register('auth.loginUrl')} />
              </FormField>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <FormField label="Username field name" hint="HTML input name">
                  <Input placeholder="username" {...form.register('auth.usernameField')} />
                </FormField>
                <FormField label="Password field name" hint="HTML input name">
                  <Input placeholder="password" {...form.register('auth.passwordField')} />
                </FormField>
                <FormField label="Username">
                  <Input {...form.register('auth.username')} />
                </FormField>
                <FormField label="Password">
                  <Input type="password" {...form.register('auth.password')} />
                </FormField>
              </div>
              <FormField label="Success check (optional)" hint="Text expected on a logged-in page, e.g. Logout">
                <Input placeholder="Logout" {...form.register('auth.successCheck')} />
              </FormField>
              <FormField label="Or paste a session cookie (optional)" hint="Skips form login, e.g. PHPSESSID=abc123">
                <Input placeholder="PHPSESSID=..." {...form.register('auth.sessionCookie')} />
              </FormField>
            </div>
          )}
        </section>

        <Button type="submit" loading={form.formState.isSubmitting} className="self-start">
          Start scan
        </Button>
      </form>
    </main>
  )
}

function SectionTitle({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-muted)]">
      <Icon size={14} className="text-[color:var(--color-primary)]" aria-hidden="true" />
      {children}
    </div>
  )
}

const Checkbox = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement> & { label: string; error?: string }
>(function Checkbox({ label, error, ...rest }, ref) {
  return (
    <div className="flex flex-col gap-1">
      <label className="flex cursor-pointer items-start gap-2.5 text-sm text-[color:var(--color-foreground)]">
        <input
          ref={ref}
          type="checkbox"
          className="mt-0.5 h-4 w-4 accent-[color:var(--color-primary)]"
          {...rest}
        />
        <span>{label}</span>
      </label>
      {error && <p className="text-xs text-[color:var(--color-danger)]">{error}</p>}
    </div>
  )
})
