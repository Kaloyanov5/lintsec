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
  if (variant === 'mark') {
    return <img src={logoMark} alt={alt} className={cn('h-14 w-auto', className)} />
  }
  return (
    <>
      <img
        src={logoLight}
        alt={alt}
        className={cn('block h-14 w-auto dark:hidden', className)}
      />
      <img
        src={logoDark}
        alt=""
        aria-hidden="true"
        className={cn('hidden h-14 w-auto dark:block', className)}
      />
    </>
  )
}
