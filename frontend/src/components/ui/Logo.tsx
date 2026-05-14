import { cn } from '@/lib/cn'
import logoLight from '@/assets/logo-light.svg'
import logoDark from '@/assets/logo-dark.svg'
import logoMark from '@/assets/logo-mark.svg'

type LogoProps = {
  className?: string
  variant?: 'wordmark' | 'mark'
  alt?: string
}

export function Logo({ className, variant = 'wordmark', alt = 'LintSec' }: LogoProps) {
  const sizing = className ?? 'h-14'
  if (variant === 'mark') {
    return <img src={logoMark} alt={alt} className={cn('w-auto', sizing)} />
  }
  return (
    <>
      <img
        src={logoLight}
        alt={alt}
        className={cn('block w-auto dark:hidden', sizing)}
      />
      <img
        src={logoDark}
        alt=""
        aria-hidden="true"
        className={cn('hidden w-auto dark:block', sizing)}
      />
    </>
  )
}
