import { clockState, formatDuration } from '../lib/clock'
import { RingGauge } from './RingGauge'

interface Props {
  label: string
  authority?: string
  /** epoch ms the trigger fired; stored once, never recomputed */
  detectedAt: number
  /** epoch ms the obligation falls due */
  deadline: number
  now: number
  size?: number
}

/** One regulatory countdown. Green above 50% remaining, amber 20–50%, red below 20% with a pulse. */
export function ComplianceClock({ label, authority, detectedAt, deadline, now, size = 176 }: Props) {
  const s = clockState(detectedAt, deadline, now)
  const due = new Date(deadline + 5.5 * 3_600_000).toISOString().slice(11, 16)
  const hours = Math.round((deadline - detectedAt) / 3_600_000)
  return (
    <figure className={`clock clock--${s.severity}`}>
      <RingGauge
        value={s.overdue ? 100 : Math.max(0, s.frac * 100)}
        severity={s.severity}
        size={size}
        label={`${label}: ${s.overdue ? 'overdue by' : 'remaining'} ${formatDuration(s.remaining)}`}
        pulse={s.frac < 0.2}
      >
        <span className="clock__time tnum">
          {s.overdue && '+'}
          {formatDuration(s.remaining)}
        </span>
        <span className="clock__state">{s.overdue ? 'overdue' : 'remaining'}</span>
      </RingGauge>
      <figcaption>
        <strong>{label}</strong>
        <span className="tnum">
          {hours} h · due {due} IST
        </span>
        {authority && <span className="clock__authority">{authority}</span>}
      </figcaption>
    </figure>
  )
}
