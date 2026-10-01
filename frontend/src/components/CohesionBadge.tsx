import { LinkBreak, LinkSimple, SealCheck } from '@phosphor-icons/react'
import type { Cohesion } from '../data/seed'

const META = {
  solid: { Icon: SealCheck, word: 'Solid', hint: 'held together by rare entities' },
  moderate: { Icon: LinkSimple, word: 'Moderate', hint: 'one bridge holds a large side' },
  fragile: { Icon: LinkBreak, word: 'Fragile', hint: 'may be 2 incidents' },
} as const

interface Props {
  cohesion: Cohesion
  onClick?: () => void
  expanded?: boolean
  compact?: boolean
}

export function CohesionBadge({ cohesion, onClick, expanded, compact }: Props) {
  const { Icon, word, hint } = META[cohesion]
  const body = (
    <>
      <Icon size={14} weight={cohesion === 'fragile' ? 'bold' : 'regular'} aria-hidden />
      <span>{word}</span>
      {!compact && <span className="cohesion__hint">{hint}</span>}
    </>
  )
  if (onClick) {
    return (
      <button type="button" className={`cohesion cohesion--${cohesion}`} onClick={onClick} aria-expanded={expanded}>
        {body}
      </button>
    )
  }
  return (
    <span className={`cohesion cohesion--${cohesion}`} title={`Cohesion: ${word}, ${hint}`}>
      {body}
    </span>
  )
}
