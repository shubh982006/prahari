import { ArrowRight, FileText } from '@phosphor-icons/react'
import {
  motion,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
  type MotionValue,
} from 'framer-motion'
import { useRef, type PointerEvent } from 'react'
import { Button } from '../components/Button'
import { CohesionBadge } from '../components/CohesionBadge'
import { ComplianceClock } from '../components/ComplianceClock'
import { RingGauge } from '../components/RingGauge'
import { SeverityChip } from '../components/SeverityChip'
import { StageBar } from '../components/StageBar'
import { FEATURED, INCIDENTS } from '../data/seed'
import { PAGE_LOADED_AT, TRACKS, trackClock, useNow } from '../lib/clock'
import { EASE_OUT } from '../lib/motion'
import { WindowFrame } from './Frame'

const LINES = ['Three thousand alerts.', 'One thread worth pulling.']

function useLayer(scroll: MotionValue<number>, pointer: MotionValue<number>, travel: number, depth: number) {
  return useTransform([scroll, pointer], ([s, p]: number[]) => s * travel + p * depth)
}

export function Hero() {
  const ref = useRef<HTMLElement>(null)
  const reduce = useReducedMotion() ?? false
  const now = useNow()
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end start'] })
  const s = useTransform(scrollYProgress, (v) => (reduce ? 0 : v))

  const px = useSpring(useMotionValue(0), { stiffness: 60, damping: 18 })
  const py = useSpring(useMotionValue(0), { stiffness: 60, damping: 18 })
  const onMove = (e: PointerEvent<HTMLElement>) => {
    if (reduce || e.pointerType !== 'mouse') return
    const r = e.currentTarget.getBoundingClientRect()
    px.set(((e.clientX - r.left) / r.width - 0.5) * 2)
    py.set(((e.clientY - r.top) / r.height - 0.5) * 2)
  }

  const queueY = useLayer(s, py, -90, -6)
  const queueX = useTransform(px, (v) => v * -8)
  const gaugeY = useLayer(s, py, -220, -16)
  const gaugeX = useTransform(px, (v) => v * -18)
  const clockY = useLayer(s, py, -30, -3)
  const clockX = useTransform(px, (v) => v * -4)
  const orbA = useTransform(s, [0, 1], [0, 260])
  const orbB = useTransform(s, [0, 1], [0, 120])
  const copyY = useTransform(s, [0, 1], [0, 90])
  const copyO = useTransform(s, [0, 0.7], [1, 0.25])

  const top = INCIDENTS.slice(0, 5)
  const detectedAt = PAGE_LOADED_AT - (FEATURED.complianceMinutesAgo ?? 0) * 60_000

  return (
    <section ref={ref} className="hero on-dark" onPointerMove={onMove} aria-labelledby="hero-title">
      <motion.div className="orb orb--violet" style={{ y: orbA }} aria-hidden />
      <motion.div className="orb orb--blue" style={{ y: orbB }} aria-hidden />
      <motion.div className="orb orb--teal" style={{ y: orbA }} aria-hidden />

      <div className="wrap hero__grid">
        <motion.div className="hero__copy" style={{ y: copyY, opacity: copyO }}>
          <h1 id="hero-title" className="display">
            {LINES.map((line, i) => (
              <span className="line-mask" key={line}>
                <motion.span
                  className="line-mask__inner"
                  initial={reduce ? false : { y: '105%' }}
                  animate={{ y: 0 }}
                  transition={{ duration: 1.1, ease: EASE_OUT, delay: 0.1 + i * 0.12 }}
                >
                  {line}
                </motion.span>
              </span>
            ))}
          </h1>
          <motion.div
            className="hero__lede"
            initial={reduce ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: EASE_OUT, delay: 0.45 }}
          >
            <p>
              Prahari correlates a night of security alerts into a short, ranked list of incidents, explains every score
              with the smallest change that would flip it, and says so when it is not sure two alerts belong together.
            </p>
            <div className="hero__ctas">
              <Button to="/console" icon={ArrowRight}>
                Open the console
              </Button>
              <Button
                variant="secondary"
                icon={FileText}
                href="https://github.com/shubh982006/prahari/blob/main/docs/failure-analysis.md"
              >
                Read the failure analysis
              </Button>
            </div>
          </motion.div>
        </motion.div>

        <motion.div
          className="hero__stage"
          initial={reduce ? false : { opacity: 0, y: 60, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 1.3, ease: EASE_OUT, delay: 0.3 }}
          aria-label="Console preview with synthetic incidents"
          role="img"
        >
          <motion.div className="shot shot--queue" style={{ y: queueY, x: queueX }}>
            <WindowFrame title="Incident queue" meta="seed 42 · synthetic" tone="dark">
            <ol className="mini-queue">
              {top.map((inc) => (
                <li key={inc.id}>
                  <SeverityChip severity={inc.severity} priority={inc.priority} compact />
                  <span className="mini-queue__body">
                    <span className="mini-queue__id tnum">{inc.id}</span>
                    <span className="mini-queue__title">{inc.headline}</span>
                  </span>
                  <StageBar reached={inc.maxStage} severity={inc.severity} />
                  <span className="mini-queue__risk tnum">{inc.risk.toFixed(2)}</span>
                </li>
              ))}
            </ol>
            </WindowFrame>
          </motion.div>

          <motion.div className="shot shot--gauge" style={{ y: gaugeY, x: gaugeX }}>
            <span className="shot__label tnum">{FEATURED.id} · risk</span>
            <RingGauge value={FEATURED.risk} severity={FEATURED.severity} size={188} label={`Risk ${FEATURED.risk}`}>
              <span className="hero-gauge__value tnum">{FEATURED.risk.toFixed(2)}</span>
              <SeverityChip severity={FEATURED.severity} priority={FEATURED.priority} compact />
            </RingGauge>
            <CohesionBadge cohesion={FEATURED.cohesion} compact />
          </motion.div>

          <motion.div className="shot shot--clock" style={{ y: clockY, x: clockX }}>
            <ComplianceClock {...trackClock(TRACKS[0], detectedAt)} now={now} size={150} />
          </motion.div>
        </motion.div>
      </div>
    </section>
  )
}
