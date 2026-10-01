import { ArrowClockwise } from '@phosphor-icons/react'

/** Placeholder bars while a panel loads; content arrives in the same footprint. */
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} style={{ width: `${92 - ((i * 17) % 38)}%` }} />
      ))}
    </div>
  )
}

export function PanelError({ title, error, retry, inline }: { title: string; error: Error; retry: () => void; inline?: boolean }){
  return (
    <div className={inline ? 'panel-error panel-error--inline' : 'panel panel-error'} role="alert">
      <strong>{title}</strong>
      <span>{error.message}</span>
      <button type="button" onClick={retry}>
        <ArrowClockwise size={14} aria-hidden /> Try again
      </button>
    </div>
  )
}

