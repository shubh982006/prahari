import { animate, useReducedMotion } from 'framer-motion'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { EASE_OUT } from '../lib/motion'
import type { Severity } from '../lib/score'

interface Props {
  /** 0..100 */
  value: number
  severity: Severity
  size?: number
  variant?: 'arc' | 'full'
  label: string
  children?: ReactNode
  pulse?: boolean
  className?: string
}

const TICKS = 60

/** Sixty 2×8 ticks around an arc. Ticks under the value take the severity color. */
export function RingGauge({ value, severity, size = 200, variant = 'arc', label, children, pulse, className }: Props) {
  const reduce = useReducedMotion()
  const [animated, setAnimated] = useState(0)
  const from = useRef(0)
  const shown = reduce ? value : animated

  useEffect(() => {
    if (reduce) {
      from.current = value
      return
    }
    const controls = animate(from.current, value, {
      duration: 0.7,
      ease: EASE_OUT,
      onUpdate: (v) => {
        from.current = v
        setAnimated(v)
      },
    })
    return () => controls.stop()
  }, [value, reduce])

  const sweep = variant === 'arc' ? 240 : 360
  const start = variant === 'arc' ? -120 : 0
  const c = size / 2
  const r = c - 6
  const lit = Math.round((Math.max(0, Math.min(100, shown)) / 100) * (TICKS - 1))
  const steps = variant === 'arc' ? TICKS - 1 : TICKS

  return (
    <div
      className={`ring ${pulse ? 'ring--pulse' : ''} ${className ?? ''}`}
      style={{ width: size, height: variant === 'arc' ? size * 0.86 : size }}
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(value * 100) / 100}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
        {Array.from({ length: TICKS }, (_, i) => {
          const angle = start + (sweep * i) / steps
          const on = i <= lit && value > 0
          const head = i === lit && value > 0
          return (
            <rect
              key={i}
              x={c - 1}
              y={c - r}
              width={2}
              height={head ? 12 : 8}
              rx={1}
              transform={`rotate(${angle} ${c} ${c})`}
              style={{
                fill: on ? `var(--sev-${severity})` : 'var(--line-strong)',
                opacity: head ? 1 : on ? 0.82 : 1,
              }}
            />
          )
        })}
      </svg>
      <div className="ring__center">{children ?? <span className="tnum">{shown.toFixed(value % 1 ? 2 : 0)}</span>}</div>
    </div>
  )
}
