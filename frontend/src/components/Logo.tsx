import { Link } from 'react-router-dom'

/** A single violet signal lamp inside a steel ring. */
export function LogoMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
      <circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" strokeOpacity="0.35" strokeWidth="1.5" />
      <circle cx="12" cy="12" r="4.5" fill="#7140fd" />
      <circle cx="12" cy="12" r="7.5" fill="none" stroke="#7140fd" strokeOpacity="0.45" strokeWidth="1" />
    </svg>
  )
}

export function Logo({ to = '/' }: { to?: string }) {
  return (
    <Link to={to} className="logo" aria-label="Prahari home">
      <LogoMark />
      <span>Prahari</span>
    </Link>
  )
}
