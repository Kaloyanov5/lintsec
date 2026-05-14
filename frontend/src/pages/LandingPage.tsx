import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  ChevronDown,
  FileText,
  History,
  ListChecks,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'
import { SiteHeader } from '@/components/landing/SiteHeader'
import { SiteFooter } from '@/components/landing/SiteFooter'
import { Reveal } from '@/components/Reveal'
import { Button } from '@/components/ui/Button'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/cn'

const primaryCta = { authed: '/dashboard', guest: '/register' } as const

export default function LandingPage() {
  const { status } = useAuth()
  const ctaHref = status === 'authenticated' ? primaryCta.authed : primaryCta.guest

  return (
    <div className="relative min-h-screen">
      <BackgroundGlow />
      <SiteHeader />
      <main>
        <Hero ctaHref={ctaHref} />
        <Features />
        <HowItWorks />
        <Faq />
        <FinalCta ctaHref={ctaHref} />
      </main>
      <SiteFooter />
    </div>
  )
}

function BackgroundGlow() {
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
      <div
        className="absolute -top-40 left-1/2 h-[36rem] w-[36rem] -translate-x-1/2 rounded-full opacity-40 blur-3xl"
        style={{
          background:
            'radial-gradient(circle, color-mix(in srgb, var(--color-primary) 55%, transparent), transparent 70%)',
        }}
      />
      <div
        className="absolute right-[-10rem] top-[28rem] h-[24rem] w-[24rem] rounded-full opacity-25 blur-3xl"
        style={{
          background:
            'radial-gradient(circle, color-mix(in srgb, var(--color-primary) 50%, transparent), transparent 70%)',
        }}
      />
    </div>
  )
}

function Eyebrow({ children }: { children: string }) {
  return (
    <span className="text-xs font-semibold uppercase tracking-[0.18em] text-[color:var(--color-primary)]">
      {children}
    </span>
  )
}

function Hero({ ctaHref }: { ctaHref: string }) {
  return (
    <section className="relative mx-auto grid min-h-[calc(100svh-4.5rem)] max-w-5xl content-center items-center gap-12 px-6 pb-16 pt-8 lg:grid-cols-2 lg:gap-10">
      <Reveal>
        <span className="inline-flex items-center gap-2 rounded-full border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-3 py-1 text-xs font-medium text-[color:var(--color-muted)]">
          <ShieldCheck size={14} className="text-[color:var(--color-primary)]" />
          Web application security scanner
        </span>
        <h1 className="mt-5 text-4xl font-semibold leading-tight tracking-tight text-[color:var(--color-foreground)] sm:text-5xl">
          Find the cracks in your web app{' '}
          <span className="text-[color:var(--color-primary)]">before attackers do.</span>
        </h1>
        <p className="mt-5 max-w-xl text-base text-[color:var(--color-muted)] sm:text-lg">
          LintSec scans your running application, ranks every finding by severity, and hands
          you an audit-ready report — in minutes, straight from your browser.
        </p>
        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Link to={ctaHref}>
            <Button size="md" rightIcon={<ArrowRight size={16} />} className="w-full sm:w-auto">
              Start a free scan
            </Button>
          </Link>
          <a href="#how-it-works">
            <Button size="md" variant="secondary" className="w-full sm:w-auto">
              See how it works
            </Button>
          </a>
        </div>
        <p className="mt-4 text-xs text-[color:var(--color-muted)]">
          No agents to install. Just point it at a URL you own.
        </p>
      </Reveal>

      <Reveal delay={150}>
        <ScanPreview />
      </Reveal>

      <a
        href="#features"
        aria-label="Scroll to features"
        className="absolute bottom-5 left-1/2 hidden -translate-x-1/2 flex-col items-center gap-1 text-[color:var(--color-muted)] transition-colors hover:text-[color:var(--color-foreground)] lg:flex"
      >
        <span className="text-xs font-medium uppercase tracking-wide">More</span>
        <ChevronDown size={18} className="motion-safe:animate-bounce" />
      </a>
    </section>
  )
}

const severityRows = [
  { label: 'Critical', count: 2, color: '#DC2626' },
  { label: 'High', count: 5, color: '#EA580C' },
  { label: 'Medium', count: 8, color: '#D97706' },
  { label: 'Low', count: 3, color: '#0EA5E9' },
]

const sampleFindings = [
  { title: 'Reflected XSS in search parameter', color: '#DC2626' },
  { title: 'Missing Content-Security-Policy header', color: '#EA580C' },
  { title: 'Cookie set without Secure flag', color: '#D97706' },
]

function ScanPreview() {
  return (
    <div className="relative motion-safe:animate-float">
      <div className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5 shadow-xl">
        <div className="flex items-center justify-between gap-3 border-b border-[color:var(--color-border)] pb-3">
          <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--color-foreground)]">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[color:var(--color-primary)] opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[color:var(--color-primary)]" />
            </span>
            Scanning app.example.com
          </div>
          <span className="text-xs text-[color:var(--color-muted)]">68%</span>
        </div>

        <div className="mt-4 grid grid-cols-4 gap-2">
          {severityRows.map((row) => (
            <div
              key={row.label}
              className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface-muted)] px-2 py-2 text-center"
            >
              <div className="text-lg font-semibold" style={{ color: row.color }}>
                {row.count}
              </div>
              <div className="text-[10px] uppercase tracking-wide text-[color:var(--color-muted)]">
                {row.label}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 space-y-2">
          {sampleFindings.map((finding) => (
            <div
              key={finding.title}
              className="flex items-center gap-3 rounded-lg border border-[color:var(--color-border)] px-3 py-2.5"
            >
              <span
                className="h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: finding.color }}
              />
              <span className="truncate text-sm text-[color:var(--color-foreground)]">
                {finding.title}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="absolute -bottom-5 -left-5 hidden rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3 shadow-lg sm:block">
        <div className="text-xs text-[color:var(--color-muted)]">Scan completed in</div>
        <div className="text-sm font-semibold text-[color:var(--color-foreground)]">2m 41s</div>
      </div>
    </div>
  )
}

type Feature = {
  icon: typeof Activity
  title: string
  body: string
  large?: boolean
}

const features: Feature[] = [
  {
    icon: Activity,
    title: 'Live scan progress',
    body: 'Findings stream in as the scanner works — no spinner staring, no guessing how far along you are.',
    large: true,
  },
  {
    icon: ListChecks,
    title: 'Severity-ranked findings',
    body: 'Every issue is scored Critical to Low with clear, actionable remediation guidance so you know what to fix first.',
    large: true,
  },
  {
    icon: FileText,
    title: 'Audit-ready reports',
    body: 'Export any completed scan as a clean PDF you can hand to stakeholders.',
  },
  {
    icon: History,
    title: 'Full scan history',
    body: 'Every scan is saved, so you can track progress and prove issues were resolved.',
  },
  {
    icon: ShieldCheck,
    title: 'OWASP-aligned checks',
    body: 'Coverage built around the vulnerability classes that actually matter.',
  },
  {
    icon: RefreshCw,
    title: 'One-click rescan',
    body: 'Shipped a fix? Re-run the same target and confirm it in seconds.',
  },
]

function Features() {
  return (
    <section id="features" className="mx-auto max-w-5xl px-6 py-20 lg:py-28">
      <Reveal className="text-center">
        <Eyebrow>Why LintSec</Eyebrow>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight text-[color:var(--color-foreground)] sm:text-4xl">
          Security findings, made actionable
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-[color:var(--color-muted)]">
          Most scanners hand you a wall of raw output. LintSec is built so the next step is
          always obvious.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {features.map((feature, index) => (
          <Reveal
            key={feature.title}
            delay={index * 80}
            className={cn('h-full', feature.large && 'sm:col-span-2')}
          >
            <FeatureCard feature={feature} />
          </Reveal>
        ))}
      </div>
    </section>
  )
}

function FeatureCard({ feature }: { feature: Feature }) {
  const Icon = feature.icon
  return (
    <div className="flex h-full flex-col rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 transition-colors hover:border-[color:var(--color-border-strong)]">
      <span className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-[color:var(--color-primary)]/10 text-[color:var(--color-primary)]">
        <Icon size={20} />
      </span>
      <h3 className="mt-4 text-base font-semibold text-[color:var(--color-foreground)]">
        {feature.title}
      </h3>
      <p className="mt-2 text-sm text-[color:var(--color-muted)]">{feature.body}</p>
    </div>
  )
}

const steps = [
  {
    title: 'Create your account',
    body: 'Sign up free in under a minute — email and password, or continue with Google.',
  },
  {
    title: 'Submit a URL you own',
    body: 'Confirm you are authorized to test the target, then point LintSec at your app.',
  },
  {
    title: 'Watch the scan run live',
    body: 'Findings surface in real time over a streaming connection as the scanner works.',
  },
  {
    title: 'Review and export',
    body: 'Triage findings by severity, then download a shareable PDF report.',
  },
]

function HowItWorks() {
  return (
    <section
      id="how-it-works"
      className="border-y border-[color:var(--color-border)] bg-[color:var(--color-surface)]/40 px-6 py-20 lg:py-28"
    >
      <div className="mx-auto max-w-3xl">
        <Reveal className="text-center">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-[color:var(--color-foreground)] sm:text-4xl">
            From sign-up to report in four steps
          </h2>
        </Reveal>

        <ol className="mt-12 space-y-4">
          {steps.map((step, index) => (
            <li key={step.title}>
              <Reveal
                delay={index * 90}
                className="flex gap-4 rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5"
              >
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[color:var(--color-primary)] text-sm font-semibold text-[color:var(--color-primary-foreground)]">
                  {index + 1}
                </span>
                <div>
                  <h3 className="text-base font-semibold text-[color:var(--color-foreground)]">
                    {step.title}
                  </h3>
                  <p className="mt-1 text-sm text-[color:var(--color-muted)]">{step.body}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}

const faqs = [
  {
    q: 'Is LintSec safe to run against my site?',
    a: 'LintSec performs non-destructive checks, but you should only scan applications you own or are explicitly authorized to test.',
  },
  {
    q: 'Do I need to install anything?',
    a: 'No. LintSec runs entirely from your browser against a URL — no agents, no extensions, no infrastructure.',
  },
  {
    q: 'How long does a scan take?',
    a: 'Most scans finish in a few minutes. Progress streams live, so you are never left guessing.',
  },
  {
    q: 'Can I share the results?',
    a: 'Yes. Every completed scan can be exported as a PDF report you can hand to your team or stakeholders.',
  },
]

function Faq() {
  return (
    <section id="faq" className="mx-auto max-w-3xl px-6 py-20 lg:py-28">
      <Reveal className="text-center">
        <Eyebrow>FAQ</Eyebrow>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight text-[color:var(--color-foreground)] sm:text-4xl">
          Questions, answered
        </h2>
      </Reveal>

      <div className="mt-10 space-y-3">
        {faqs.map((faq, index) => (
          <Reveal key={faq.q} delay={index * 70}>
            <FaqItem question={faq.q} answer={faq.a} />
          </Reveal>
        ))}
      </div>
    </section>
  )
}

function FaqItem({ question, answer }: { question: string; answer: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-2xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center justify-between gap-4 p-5 text-left text-base font-medium text-[color:var(--color-foreground)]"
      >
        {question}
        <span
          className={cn(
            'shrink-0 text-lg leading-none text-[color:var(--color-muted)] transition-transform duration-300 ease-out',
            open && 'rotate-45',
          )}
        >
          +
        </span>
      </button>
      <div
        className={cn(
          'grid transition-[grid-template-rows,opacity] duration-300 ease-out motion-reduce:transition-none',
          open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        <div className="overflow-hidden">
          <p className="px-5 pb-5 text-sm text-[color:var(--color-muted)]">{answer}</p>
        </div>
      </div>
    </div>
  )
}

function FinalCta({ ctaHref }: { ctaHref: string }) {
  return (
    <section className="px-6 pb-24">
      <Reveal className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-8 py-14 text-center shadow-sm">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{
            background:
              'radial-gradient(circle at 50% 0%, color-mix(in srgb, var(--color-primary) 22%, transparent), transparent 60%)',
          }}
        />
        <div className="relative">
          <h2 className="text-3xl font-semibold tracking-tight text-[color:var(--color-foreground)] sm:text-4xl">
            Ready to see what's exposed?
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-[color:var(--color-muted)]">
            Run your first scan today and get a prioritized list of what to fix.
          </p>
          <div className="mt-8 flex justify-center">
            <Link to={ctaHref}>
              <Button size="md" rightIcon={<ArrowRight size={16} />}>
                Start your first scan
              </Button>
            </Link>
          </div>
        </div>
      </Reveal>
    </section>
  )
}
