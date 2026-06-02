import { forwardRef, type InputHTMLAttributes } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FormField } from '@/components/ui/FormField'
import { Input } from '@/components/ui/Input'
import { parseProblem } from '@/lib/problem'
import { scanService } from '@/services/scanService'

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
})

type ScanFormValues = z.infer<typeof schema>

export default function NewScanPage() {
  const navigate = useNavigate()

  const form = useForm<ScanFormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      targetUrl: '',
      maxDepth: 2,
      maxPages: 50,
      requestDelayMs: 300,
      ownershipConfirmed: false,
      ignoreRobots: false,
    },
  })

  const onSubmit = form.handleSubmit(async (values) => {
    try {
      const scan = await scanService.createScan(values)
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
    <main className="mx-auto max-w-2xl px-6 py-12">
      <Link
        to="/scans/history"
        className="inline-flex items-center gap-1.5 text-sm text-[color:var(--color-muted)] transition-colors hover:text-[color:var(--color-foreground)]"
      >
        <ArrowLeft size={15} aria-hidden="true" />
        All scans
      </Link>

      <h1 className="mt-4 text-2xl font-medium">New scan</h1>
      <p className="mt-1 text-sm text-[color:var(--color-muted)]">
        Only scan targets you own or are explicitly authorized to test.
      </p>

      <form onSubmit={onSubmit} className="mt-8 flex flex-col gap-5" noValidate>
        <FormField label="Target URL" error={errors.targetUrl?.message}>
          <Input
            type="url"
            placeholder="https://example.com"
            autoFocus
            {...form.register('targetUrl')}
          />
        </FormField>

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
          label="I own this target or am authorized to scan it"
          error={errors.ownershipConfirmed?.message}
          {...form.register('ownershipConfirmed')}
        />
        <Checkbox
          label="Ignore robots.txt (only for sandboxes that disallow crawling)"
          {...form.register('ignoreRobots')}
        />

        <Button type="submit" loading={form.formState.isSubmitting} className="self-start">
          Start scan
        </Button>
      </form>
    </main>
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
