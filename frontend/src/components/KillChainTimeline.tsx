import { Pause, Play } from '@phosphor-icons/react'
import {
  animate,
  motion,
  useMotionValue,
  useReducedMotion,
  useTransform,
  type MotionValue,
} from 'framer-motion'
import { useMemo, useState } from 'react'
import { formatClock, STAGES, type Alert } from '../data/seed'
import { useMeasure } from '../lib/useMeasure'

interface Props {
  alerts: Alert[]
  highlight?: string | null
  onHover?: (id: string | null) => void
  onSelect?: (id: string) => void
  /** Scroll-scrubbed drawing (0..1). When absent the chart draws on its own play control. */
  progress?: MotionValue<number>
  showPlay?: boolean
  label: string
  /** Formats an alert's `t` for axis ticks and tooltips. Defaults to the synthetic window clock. */
  clock?: (t: number) => string
}

const LANE = 30
const TOP = 10
const AXIS = 30

export function KillChainTimeline({ alerts, highlight, onHover, onSelect, progress, showPlay = true, label, clock = formatClock }: Props) {
  const [ref, width] = useMeasure<HTMLDivElement>(640)
  const reduce = useReducedMotion()
  const own = useMotionValue(1)
  const draw = progress ?? own
  const [playing, setPlaying] = useState(false)
  const [hover, setHover] = useState<string | null>(null)

  const labelCol = width >= 540 ? 184 : 26
  const height = TOP + LANE * 7 + AXIS
  const t0 = Math.min(...alerts.map((a) => a.t))
  const t1 = Math.max(...alerts.map((a) => a.t))
  const span = Math.max(1, t1 - t0)
  const pad = span * 0.05
  const x = (t: number) => labelCol + 10 + ((t - t0 + pad) / (span + pad * 2)) * (width - labelCol - 20)
  const y = (stage: number) => TOP + LANE * (stage - 1) + LANE / 2

  const chain = useMemo(() => alerts.filter((a) => a.onChain).sort((a, b) => a.t - b.t), [alerts])
  const d = chain.map((a, i) => `${i ? 'L' : 'M'}${x(a.t).toFixed(1)} ${y(a.stage).toFixed(1)}`).join(' ')

  const ticks = Array.from({ length: 4 }, (_, i) => t0 - pad + ((span + pad * 2) * (i + 0.5)) / 4)

  const play = () => {
    if (playing) return
    setPlaying(true)
    own.set(0)
    animate(own, 1, { duration: reduce ? 0 : 2.6, ease: 'linear', onComplete: () => setPlaying(false) })
  }

  const active = highlight ?? hover
  const hovered = alerts.find((a) => a.id === hover)

  return (
    <div className="kc" ref={ref}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
        {STAGES.map((s, i) => (
          <g key={s}>
            <line x1={labelCol} x2={width} y1={y(i + 1)} y2={y(i + 1)} className="kc__lane" />
            <text x={0} y={y(i + 1) + 4} className="kc__stage">
              {labelCol > 40 ? s : i + 1}
            </text>
          </g>
        ))}
        {ticks.map((t) => (
          <text key={t} x={x(t)} y={height - 8} className="kc__tick tnum" textAnchor="middle">
            {clock(t).slice(0, 5)}
          </text>
        ))}
        <motion.path d={d} className="kc__chain" style={{ pathLength: draw }} />
        {alerts.map((a) => (
          <Dot
            key={a.id}
            alert={a}
            clock={clock}
            cx={x(a.t)}
            cy={y(a.stage)}
            threshold={(x(a.t) - labelCol) / (width - labelCol)}
            draw={draw}
            active={active === a.id}
            onEnter={() => {
              setHover(a.id)
              onHover?.(a.id)
            }}
            onLeave={() => {
              setHover(null)
              onHover?.(null)
            }}
            onSelect={() => onSelect?.(a.id)}
          />
        ))}
      </svg>
      {hovered && (
        <div
          className="kc__tip"
          style={{ left: Math.min(Math.max(x(hovered.t), 120), width - 120), top: y(hovered.stage) - 12 }}
          role="status"
        >
          <span className="tnum kc__tip-id">
            {hovered.id} · {clock(hovered.t)}
          </span>
          <span>{hovered.title}</span>
          <span className="kc__tip-meta tnum">
            {hovered.technique ? `${hovered.technique} · ` : ''}
            {STAGES[hovered.stage - 1]}
            {!hovered.onChain && ' · off the forward chain'}
          </span>
        </div>
      )}
      {showPlay && !progress && (
        <button type="button" className="kc__play" onClick={play} aria-label="Replay the attack chain">
          {playing ? <Pause size={14} weight="fill" /> : <Play size={14} weight="fill" />}
          <span>{playing ? 'Playing' : 'Replay chain'}</span>
        </button>
      )}
    </div>
  )
}

interface DotProps {
  alert: Alert
  clock: (t: number) => string
  cx: number
  cy: number
  threshold: number
  draw: MotionValue<number>
  active: boolean
  onEnter: () => void
  onLeave: () => void
  onSelect: () => void
}

function Dot({ alert, clock, cx, cy, threshold, draw, active, onEnter, onLeave, onSelect }: DotProps) {
  const base = alert.onChain ? 1 : 0.45
  const opacity = useTransform(draw, [Math.max(0, threshold - 0.06), Math.max(0.001, threshold)], [0.12, base])
  return (
    <motion.g
      style={{ opacity }}
      className="kc__dot"
      tabIndex={0}
      role="button"
      aria-label={`${alert.id}, ${alert.title}, ${clock(alert.t)}`}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
      onFocus={onEnter}
      onBlur={onLeave}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect()
        }
      }}
    >
      <circle cx={cx} cy={cy} r={14} fill="transparent" />
      {active && <circle cx={cx} cy={cy} r={9.5} className="kc__halo" />}
      <circle cx={cx} cy={cy} r={active ? 6 : 4.5} style={{ fill: `var(--sev-${alert.severity})` }} className="kc__mark" />
    </motion.g>
  )
}
