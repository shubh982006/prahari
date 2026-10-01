import { STAGES } from '../data/seed'
import type { Severity } from '../lib/score'

export function StageBar({ reached, severity }: { reached: number; severity: Severity }) {
  return (
    <span
      className="stage-bar"
      role="img"
      aria-label={`Reached stage ${reached} of 7: ${STAGES[reached - 1]}`}
      title={`Stage ${reached}/7 · ${STAGES[reached - 1]}`}
      style={{ ['--seg' as string]: `var(--sev-${severity})` }}
    >
      {STAGES.map((s, i) => (
        <span key={s} className={i < reached ? 'is-on' : undefined} />
      ))}
    </span>
  )
}
