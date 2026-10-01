import { Info, Warning, WarningCircle, WarningDiamond, WarningOctagon, type Icon } from '@phosphor-icons/react'
import type { Priority, Severity } from '../lib/score'

const GLYPH: Record<Severity, Icon> = {
  critical: WarningOctagon,
  high: Warning,
  medium: WarningDiamond,
  low: WarningCircle,
  info: Info,
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

interface Props {
  severity: Severity
  priority?: Priority
  /** Compact keeps glyph + priority and moves the severity word to the tooltip. */
  compact?: boolean
}

/** Glyph + label + color, always all three. */
export function SeverityChip({ severity, priority, compact }: Props) {
  const Glyph = GLYPH[severity]
  const word = SEVERITY_LABEL[severity]
  return (
    <span
      className={`sev-chip sev-${severity}`}
      title={priority ? `${priority} · ${word}` : word}
      aria-label={priority ? `Priority ${priority.slice(1)}, ${word}` : `Severity ${word}`}
      role="img"
    >
      <Glyph size={12} weight="fill" aria-hidden />
      {priority && <span className="sev-chip__p">{priority}</span>}
      {(!compact || !priority) && <span>{word}</span>}
    </span>
  )
}
