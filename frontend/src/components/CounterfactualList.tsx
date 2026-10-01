import { ArrowCounterClockwise, Target, Warning } from '@phosphor-icons/react'
import type { Priority } from '../lib/score'
import { severityOf } from '../lib/score'
import { SeverityChip } from './SeverityChip'

/** One counterfactual as the engine computed it (GET /incidents/{id}/counterfactuals). */
export interface CfRow {
  id: string
  kind: 'factor' | 'asset' | 'alert' | 'boundary'
  label: string
  risk?: number
  priority?: Priority
  delta?: number
  closesCase?: boolean
  /** boundary rows: false when no value in 0..1 reaches the band edge */
  reachable?: boolean
}

interface Props {
  rows: CfRow[]
  applied: string | null
  onApply: (id: string | null) => void
  onPreview?: (id: string | null) => void
}

/** "What would make this not a P1": each row is the engine's recomputation of the score. */
export function CounterfactualList({ rows, applied, onApply, onPreview }: Props) {
  if (rows.length === 0) {
    return <p className="cf__empty">No counterfactual changes the priority of this incident.</p>
  }
  return (
    <ul className="cf" aria-label="Counterfactuals">
      {rows.map((cf) => {
        if (cf.kind === 'boundary' || cf.risk === undefined || !cf.priority) {
          const unreachable = cf.reachable === false
          return (
            <li key={cf.id} className={`cf__row cf__row--boundary ${unreachable ? 'is-unreachable' : ''}`}>
              <Target size={16} aria-hidden className="cf__icon" />
              <span className="cf__label">{cf.label}</span>
              <span className="cf__boundary-tag">{unreachable ? 'Unreachable' : 'Boundary'}</span>
            </li>
          )
        }
        const delta = cf.delta ?? 0
        const on = applied === cf.id
        return (
          <li key={cf.id}>
            <button
              type="button"
              className={`cf__row ${on ? 'is-on' : ''}`}
              aria-pressed={on}
              onClick={() => onApply(on ? null : cf.id)}
              onMouseEnter={() => onPreview?.(cf.id)}
              onMouseLeave={() => onPreview?.(null)}
              onFocus={() => onPreview?.(cf.id)}
              onBlur={() => onPreview?.(null)}
            >
              <span className="cf__kind">{cf.kind}</span>
              <span className="cf__label">
                {cf.label}
                {cf.closesCase && (
                  <span className="cf__closes">
                    <Warning size={12} weight="fill" aria-hidden /> closes the compliance case
                  </span>
                )}
              </span>
              <span className={`cf__delta tnum ${delta < 0 ? 'is-down' : ''}`}>
                {delta === 0 ? '±0.00' : `${delta > 0 ? '+' : '−'}${Math.abs(delta).toFixed(2)}`}
              </span>
              <span className="cf__result tnum">{cf.risk.toFixed(2)}</span>
              <SeverityChip severity={severityOf(cf.priority)} priority={cf.priority} compact />
            </button>
          </li>
        )
      })}
      {applied && (
        <li>
          <button type="button" className="cf__reset" onClick={() => onApply(null)}>
            <ArrowCounterClockwise size={14} aria-hidden /> Clear what-if
          </button>
        </li>
      )}
    </ul>
  )
}
