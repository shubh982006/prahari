import { motion, useReducedMotion, useScroll, useTransform, type MotionValue } from 'framer-motion'
import { useRef } from 'react'
import { FEATURED } from '../data/seed'

const W = 1200
const H = 440
const MID = H / 2

// Deterministic field: the same picture on every load, like the engine.
function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function buildField() {
  const rnd = mulberry32(42)
  let ticks = ''
  for (let i = 0; i < 1500; i++) {
    const x = 8 + rnd() * (W - 16)
    const y = 14 + Math.floor(rnd() * 36) * 11.6
    ticks += `M${x.toFixed(1)} ${y.toFixed(1)}v7`
  }
  let groups = ''
  for (let i = 0; i < 212; i++) {
    const x = 20 + rnd() * (W - 40)
    const y = MID + (rnd() - 0.5) * 150
    groups += `M${x.toFixed(1)} ${y.toFixed(1)}m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0`
  }
  const t0 = FEATURED.alerts[0].t
  const t1 = FEATURED.alerts[FEATURED.alerts.length - 1].t
  const chain = FEATURED.alerts
    .filter((a) => a.onChain)
    .map((a) => ({
      id: a.id,
      severity: a.severity,
      x: 90 + ((a.t - t0) / (t1 - t0)) * (W - 180),
      y: MID + 90 - (a.stage - 1) * 30,
    }))
  const thread = chain.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join('')
  return { ticks, groups, chain, thread }
}

const field = buildField()

const STEPS = [
  { n: '3,000', unit: 'alerts in one night', body: 'Five detectors, forty hosts, one SOC analyst. Read in timestamp order at 30 seconds each, that is 25 hours of reading.' },
  { n: '212', unit: 'incidents after correlation', body: 'Alerts link when they share a rare entity inside a two-hour window. Common entities are stop-listed so a busy DNS server cannot glue the night together.' },
  { n: '1', unit: 'P1 at the top of the queue', body: 'Scenario A, a password spray that ends in a 2.3 GB exfiltration from fin-db-01, ranks first or second on every one of ten seeds.' },
]

export function Collapse() {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLElement>(null)
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] })
  const p = useTransform(scrollYProgress, (v) => (reduce ? 1 : v))

  const ticksOpacity = useTransform(p, [0, 0.3, 0.5], [0.9, 0.5, 0.06])
  const ticksScale = useTransform(p, [0.12, 0.5], [1, 0.3])
  const groupsOpacity = useTransform(p, [0.25, 0.42, 0.66, 0.8], [0, 0.9, 0.9, 0.12])
  const thread = useTransform(p, [0.66, 0.94], [0, 1])

  return (
    <section ref={ref} id="collapse" className={`collapse on-dark ${reduce ? 'is-static' : ''}`} aria-labelledby="collapse-title">
      <div className="collapse__sticky">
        <div className="wrap collapse__inner">
          <h2 id="collapse-title" className="sr-only">
            From three thousand alerts to one incident
          </h2>
          <div className="collapse__steps">
            {STEPS.map((step, i) => (
              <Step key={step.n} progress={p} index={i} reduce={!!reduce} {...step} />
            ))}
          </div>
          <svg className="collapse__field" viewBox={`0 0 ${W} ${H}`} aria-hidden preserveAspectRatio="xMidYMid meet">
            <motion.path
              d={field.ticks}
              className="collapse__ticks"
              style={{ opacity: ticksOpacity, scaleY: ticksScale, transformOrigin: `${W / 2}px ${MID}px` }}
            />
            <motion.path d={field.groups} className="collapse__groups" style={{ opacity: groupsOpacity }} />
            <motion.path d={field.thread} className="collapse__thread" style={{ pathLength: thread }} />
            {field.chain.map((c, i) => (
              <ChainDot key={c.id} progress={thread} at={i / (field.chain.length - 1)} {...c} />
            ))}
          </svg>
        </div>
      </div>
    </section>
  )
}

function Step({ progress, index, reduce, n, unit, body }: { progress: MotionValue<number>; index: number; reduce: boolean } & (typeof STEPS)[number]) {
  const a = index / 3
  const b = (index + 1) / 3
  const opacity = useTransform(
    progress,
    index === 0 ? [0, b - 0.06, b] : index === 2 ? [a - 0.02, a + 0.06, 1] : [a - 0.02, a + 0.06, b - 0.06, b],
    index === 0 ? [1, 1, 0] : index === 2 ? [0, 1, 1] : [0, 1, 1, 0],
  )
  const y = useTransform(progress, [a - 0.02, a + 0.08], [index === 0 ? 0 : 24, 0])
  return (
    <motion.div className="collapse__step" style={reduce ? undefined : { opacity, y }}>
      <p className="collapse__n tnum">{n}</p>
      <p className="collapse__unit">{unit}</p>
      <p className="collapse__body">{body}</p>
    </motion.div>
  )
}

function ChainDot({ progress, at, x, y, severity }: { progress: MotionValue<number>; at: number; x: number; y: number; severity: string }) {
  const start = at * 0.95
  const opacity = useTransform(progress, [start, start + 0.05], [0, 1])
  const scale = useTransform(progress, [start, start + 0.05], [0.4, 1])
  return (
    <motion.circle
      cx={x}
      cy={y}
      r={6}
      style={{ opacity, scale, fill: `var(--sev-${severity})`, transformOrigin: `${x}px ${y}px` }}
      className="collapse__dot"
    />
  )
}
