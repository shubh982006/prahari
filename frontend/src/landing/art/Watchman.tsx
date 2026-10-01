import {
  motion,
  useInView,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
  type MotionValue,
} from 'framer-motion'
import { useEffect, useRef } from 'react'
import { ART, INK } from './palette'
import { Sparkle } from './Stickers'

const W = 1200
const H = 520
const FACE = '#7140fd'
const SHADE = '#4a23c4'
const LINE = '#2a0f86'
const LID = '#6433ee'
const EYES = [
  { cx: 405, cy: 262, flip: 1 },
  { cx: 795, cy: 262, flip: -1 },
] as const

function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** Closed Catmull-Rom spline through the points, as cubic Béziers. */
function smoothClosed(pts: [number, number][]) {
  const n = pts.length
  let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`
  for (let i = 0; i < n; i++) {
    const [p0, p1, p2, p3] = [pts[(i - 1 + n) % n], pts[i], pts[(i + 1) % n], pts[(i + 2) % n]]
    const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6]
    const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6]
    d += `C${c1[0].toFixed(1)} ${c1[1].toFixed(1)} ${c2[0].toFixed(1)} ${c2[1].toFixed(1)} ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`
  }
  return d + 'Z'
}

function blob(cx: number, cy: number, rx: number, ry: number, n: number, wobble: number, seed: number) {
  const rnd = mulberry32(seed)
  const pts: [number, number][] = Array.from({ length: n }, (_, i) => {
    const a = (i / n) * Math.PI * 2
    const f = 1 - wobble + rnd() * wobble * 1.4
    return [cx + Math.cos(a) * rx * f, cy + Math.sin(a) * ry * f]
  })
  return smoothClosed(pts)
}

const FACE_D = blob(600, 262, 585, 215, 30, 0.2, 42)
const HOLES = [blob(600, 128, 46, 26, 9, 0.3, 3), blob(600, 432, 82, 24, 10, 0.3, 9), blob(172, 150, 30, 18, 8, 0.35, 5)]

const ALMOND = 'M-128 6C-84 -56 74 -64 132 -2C74 46 -80 50 -128 6Z'
const LID_OPEN = 'M-150 -110L150 -110L132 -2C76 -30 -64 -26 -128 6Z'
const LID_SHUT = 'M-150 -110L150 -110L132 -2C76 42 -64 46 -128 6Z'
const LASH_OPEN = 'M-128 6C-64 -26 76 -30 132 -2'
const LASH_SHUT = 'M-128 6C-64 46 76 42 132 -2'
const BROW = 'M-168 -58C-104 -128 44 -140 154 -84C152 -76 148 -70 140 -66C40 -106 -92 -98 -168 -58Z'

const STARS = [
  { x: 60, y: 60, s: 14 },
  { x: 1130, y: 90, s: 18 },
  { x: 250, y: 470, s: 10 },
  { x: 980, y: 480, s: 12 },
  { x: 1160, y: 330, s: 9 },
  { x: 40, y: 360, s: 11 },
  { x: 700, y: 30, s: 8 },
]

export function Watchman() {
  const ref = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const reduce = useReducedMotion() ?? false
  const inView = useInView(ref, { margin: '20% 0px' })
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'end start'] })
  const faceY = useTransform(scrollYProgress, [0, 1], reduce ? [0, 0] : [60, -60])

  const gx = useSpring(useMotionValue(0), { stiffness: 90, damping: 16 })
  const gy = useSpring(useMotionValue(0), { stiffness: 90, damping: 16 })

  useEffect(() => {
    if (reduce || !inView) return
    let last = 0
    const onMove = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse') return
      last = Date.now()
      const r = svgRef.current?.getBoundingClientRect()
      if (!r) return
      const cx = r.left + r.width / 2
      const cy = r.top + (262 / H) * r.height
      gx.set(Math.max(-1, Math.min(1, (e.clientX - cx) / (r.width * 0.45))))
      gy.set(Math.max(-1, Math.min(1, (e.clientY - cy) / (r.height * 0.9))))
    }
    // Without a mouse the watchman keeps scanning the room on its own.
    const wander = window.setInterval(() => {
      if (Date.now() - last < 3000) return
      gx.set(Math.random() * 2 - 1)
      gy.set(Math.random() * 1.2 - 0.4)
    }, 2200)
    window.addEventListener('pointermove', onMove)
    return () => {
      window.removeEventListener('pointermove', onMove)
      window.clearInterval(wander)
    }
  }, [reduce, inView, gx, gy])

  return (
    <div className="watchman" ref={ref} aria-hidden>
      <motion.svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} style={{ y: faceY }}>
        <defs>
          <pattern id="wm-dots" width="7" height="7" patternUnits="userSpaceOnUse">
            <circle cx="3.5" cy="3.5" r="1.7" fill={SHADE} />
          </pattern>
          <radialGradient id="wm-fade" cx="50%" cy="42%" r="60%">
            <stop offset="0.35" stopColor="#000" />
            <stop offset="1" stopColor="#fff" />
          </radialGradient>
          <mask id="wm-mask">
            <rect width={W} height={H} fill="url(#wm-fade)" />
          </mask>
          <clipPath id="wm-almond">
            <path d={ALMOND} />
          </clipPath>
        </defs>

        <path d={FACE_D} fill={FACE} />
        <path d={FACE_D} fill="url(#wm-dots)" mask="url(#wm-mask)" />
        {HOLES.map((d, i) => (
          <path key={i} d={d} fill="#09101c" />
        ))}

        <g fill="none" stroke={LINE} strokeWidth="6" strokeLinecap="round">
          <path d="M470 118C540 92 660 92 730 118" />
          <path d="M500 88C560 70 640 70 700 88" opacity="0.7" />
          <path d="M572 200C584 250 582 300 560 340" />
          <path d="M628 200C616 250 618 300 640 340" />
          <path d="M548 372C580 392 620 392 652 372" />
        </g>

        {EYES.map((eye) => (
          <Eye key={eye.cx} {...eye} gx={gx} gy={gy} reduce={reduce} />
        ))}

        {STARS.map((s, i) => (
          <g key={i} transform={`translate(${s.x - s.s / 2} ${s.y - s.s / 2})`} className="watchman__star" style={{ animationDelay: `${i * 0.6}s` }}>
            <Sparkle width={s.s} height={s.s} color="#fff" />
          </g>
        ))}
      </motion.svg>
    </div>
  )
}

function Eye({ cx, cy, flip, gx, gy, reduce }: { cx: number; cy: number; flip: 1 | -1; gx: MotionValue<number>; gy: MotionValue<number>; reduce: boolean }) {
  // Pupils track in page space; the mirrored eye undoes its own flip.
  const ix = useTransform(gx, (v) => v * 34 * flip)
  const iy = useTransform(gy, (v) => v * 13)
  const blink = reduce
    ? undefined
    : { duration: 6, times: [0, 0.9, 0.935, 0.97], repeat: Infinity, ease: 'easeInOut' as const, delay: 1.5 }

  return (
    <g transform={`translate(${cx} ${cy}) scale(${flip} 1)`}>
      <ellipse cx="0" cy="6" rx="164" ry="90" fill={SHADE} opacity="0.75" />
      <path d={ALMOND} fill="#f4f1ea" />
      <g clipPath="url(#wm-almond)">
        <motion.g style={{ x: ix, y: iy }}>
          <circle r="44" fill={ART.amber} />
          <circle r="44" fill="none" stroke={ART.amberDark} strokeWidth="6" />
          <circle r="20" fill={INK} />
          <circle cx="-12" cy="-13" r="7" fill="#fff" />
        </motion.g>
        <path d="M-128 6C-80 50 70 46 132 -2" fill="none" stroke="#d9d2c4" strokeWidth="10" opacity="0.6" />
        <motion.path fill={LID} initial={{ d: LID_OPEN }} animate={blink ? { d: [LID_OPEN, LID_OPEN, LID_SHUT, LID_OPEN] } : { d: LID_OPEN }} transition={blink} />
      </g>
      <motion.path
        initial={{ d: LASH_OPEN }}
        fill="none"
        stroke={INK}
        strokeWidth="8"
        strokeLinecap="round"
        animate={blink ? { d: [LASH_OPEN, LASH_OPEN, LASH_SHUT, LASH_OPEN] } : { d: LASH_OPEN }}
        transition={blink}
      />
      <path d="M-122 -34C-60 -76 70 -80 128 -40" fill="none" stroke={LINE} strokeWidth="5" strokeLinecap="round" />
      <path d="M-116 26C-60 60 60 58 118 22" fill="none" stroke={INK} strokeWidth="4.5" strokeLinecap="round" />
      <g fill="none" stroke={LINE} strokeWidth="5" strokeLinecap="round">
        <path d="M-104 58C-50 88 50 86 104 54" />
        <path d="M-80 84C-30 104 34 102 82 80" opacity="0.7" />
      </g>
      <path d={BROW} fill={INK} />
    </g>
  )
}
