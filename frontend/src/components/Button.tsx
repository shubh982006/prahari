import type { Icon } from '@phosphor-icons/react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

interface Props {
  to?: string
  href?: string
  onClick?: () => void
  variant?: 'primary' | 'secondary'
  icon?: Icon
  children: ReactNode
}

/** Signal Blue is reserved for the one filled primary action per view. */
export function Button({ to, href, onClick, variant = 'primary', icon: I, children }: Props) {
  const cls = `btn btn--${variant}`
  const body = (
    <>
      {I && <I size={16} weight={variant === 'primary' ? 'bold' : 'regular'} aria-hidden />}
      <span>{children}</span>
    </>
  )
  if (to) return <Link className={cls} to={to}>{body}</Link>
  if (href)
    return (
      <a className={cls} href={href} target="_blank" rel="noreferrer">
        {body}
      </a>
    )
  return (
    <button type="button" className={cls} onClick={onClick}>
      {body}
    </button>
  )
}
