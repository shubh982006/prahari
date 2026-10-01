import { motion, useReducedMotion, useScroll, useTransform, type MotionValue } from 'framer-motion'
import { useRef, type ComponentType, type SVGProps } from 'react'
import { INK } from './palette'
import { AlertCoin, Crystal, Magnifier, Padlock, ReportDoc, Sparkle, Stopwatch } from './Stickers'

const W = 1200
const H = 480

function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const wave = (x: number) => H * 0.62 - (x / W) * 100 + Math.sin((x / W) * Math.PI * 2.2 + 0.4) * 58

// Glitter trail: three tone buckets, each one path of tiny circles.
function buildTrail() {
  const rnd = mulberry32(7)
  const gauss = () => (rnd() + rnd() + rnd() - 1.5) / 1.5
  const buckets = ['', '', '']
  for (let i = 0; i < 1100; i++) {
    const x = rnd() * W
    const spread = 34 + 26 * Math.sin((x / W) * Math.PI)
    const y = wave(x) + gauss() * spread
    const r = 0.7 + rnd() * rnd() * 2.6
    const b = rnd() < 0.08 ? 2 : rnd() < 0.55 ? 0 : 1
    buckets[b] += `M${(x - r).toFixed(1)} ${y.toFixed(1)}a${r.toFixed(2)} ${r.toFixed(2)} 0 1 0 ${(2 * r).toFixed(2)} 0a${r.toFixed(2)} ${r.toFixed(2)} 0 1 0 ${(-2 * r).toFixed(2)} 0`
  }
  return buckets
}
const TRAIL = buildTrail()

type Art = ComponentType<SVGProps<SVGSVGElement>>
interface Item {
  Art: Art
  x: number
  size: number
  dy: number
  rot: number
  depth: number
  bob: number
  hideSm?: boolean
}

const coin = (tone: 'critical' | 'high' | 'low' | 'lock'): Art => (p) => <AlertCoin tone={tone} {...p} />
const crystal = (tone: 'teal' | 'violet'): Art => (p) => <Crystal tone={tone} {...p} />

const ITEMS: Item[] = [
  { Art: coin('high'), x: 70, size: 78, dy: -40, rot: -16, depth: 70, bob: 5.2 },
  { Art: crystal('teal'), x: 190, size: 30, dy: 60, rot: 14, depth: 150, bob: 4.1, hideSm: true },
  { Art: Padlock, x: 300, size: 92, dy: -58, rot: -8, depth: 40, bob: 6.3 },
  { Art: coin('low'), x: 420, size: 46, dy: 64, rot: 22, depth: 130, bob: 4.6, hideSm: true },
  { Art: Magnifier, x: 540, size: 104, dy: -20, rot: 8, depth: 80, bob: 5.8 },
  { Art: coin('critical'), x: 665, size: 66, dy: 70, rot: -22, depth: 120, bob: 4.9 },
  { Art: Stopwatch, x: 790, size: 94, dy: -44, rot: -10, depth: 55, bob: 6.8 },
  { Art: crystal('violet'), x: 900, size: 34, dy: 48, rot: -18, depth: 160, bob: 3.9, hideSm: true },
  { Art: coin('lock'), x: 985, size: 60, dy: -30, rot: 16, depth: 100, bob: 5.5, hideSm: true },
  { Art: ReportDoc, x: 1110, size: 96, dy: 18, rot: 9, depth: 60, bob: 6.1 },
]

const SPARKS = [
  { x: 150, dy: -70, s: 18 },
  { x: 480, dy: -90, s: 14 },
  { x: 720, dy: -100, s: 20 },
  { x: 1040, dy: 80, s: 16 },
  { x: 260, dy: 90, s: 12 },
]

/**
 * The night's alert stream: a glitter trail of alerts with the things Prahari
 * turns them into (a locked case, a clock, evidence under a lens, a report)
 * drifting along it at different depths.
 */
export function Stream() {
  const ref = useRef<HTMLDivElement>(null)
  const reduce = useReducedMotion() ?? false
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'end start'] })
  const p = useTransform(scrollYProgress, (v) => (reduce ? 0.5 : v))
  const trailX = useTransform(p, [0, 1], [-50, 50])

  return (
    <div className="stream" ref={ref} aria-hidden>
      <motion.svg className="stream__trail" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid slice" style={{ x: trailX }}>
        <path d={TRAIL[0]} fill="#f6c945" />
        <path d={TRAIL[1]} fill="#eaa125" opacity="0.8" />
        <path d={TRAIL[2]} fill={INK} opacity="0.55" />
      </motion.svg>
      {SPARKS.map((s, i) => (
        <span
          key={i}
          className="stream__spark"
          style={{ left: `${(s.x / W) * 100}%`, top: `${((wave(s.x) + s.dy) / H) * 100}%`, width: s.s, height: s.s, animationDelay: `${i * 0.7}s` }}
        >
          <Sparkle />
        </span>
      ))}
      {ITEMS.map((item, i) => (
        <Floater key={i} item={item} progress={p} reduce={reduce} />
      ))}
    </div>
  )
}

function Floater({ item, progress, reduce }: { item: Item; progress: MotionValue<number>; reduce: boolean }) {
  const y = useTransform(progress, [0, 1], [item.depth, -item.depth])
  const rotate = useTransform(progress, [0, 1], [item.rot - 10, item.rot + 10])
  const { Art } = item
  return (
    <motion.div
      className={`stream__item ${item.hideSm ? 'hide-sm' : ''}`}
      style={{
        left: `${(item.x / W) * 100}%`,
        top: `${((wave(item.x) + item.dy) / H) * 100}%`,
        width: `clamp(${Math.round(item.size * 0.55)}px, ${((item.size / W) * 100).toFixed(2)}vw, ${item.size}px)`,
        y,
        rotate,
      }}
    >
      <motion.div
        className="stream__bob"
        animate={reduce ? undefined : { y: [0, -10, 0] }}
        transition={{ duration: item.bob, repeat: Infinity, ease: 'easeInOut' }}
        whileHover={reduce ? undefined : { scale: 1.14, rotate: 8 }}
      >
        <Art />
      </motion.div>
    </motion.div>
  )
}
