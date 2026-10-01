import { motion, useInView, useMotionValueEvent, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { useRef, useState } from 'react'
import { AttackGraph } from '../components/AttackGraph'
import { CohesionBadge } from '../components/CohesionBadge'
import { KillChainTimeline } from '../components/KillChainTimeline'
import { SeverityChip } from '../components/SeverityChip'
import { TechniqueTag } from '../components/TechniqueTag'
import { FEATURED, formatClock, STAGES } from '../data/seed'
import { graphFromIncident } from '../lib/graph'
import { rise, useParallax } from '../lib/motion'

const FEATURED_GRAPH = graphFromIncident(FEATURED)

const BY_STAGE = STAGES.map((name, i) => ({
  name,
  alerts: FEATURED.alerts.filter((a) => a.stage === i + 1 && a.onChain),
}))

export function ChainWalk() {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)
  const graphRef = useRef<HTMLDivElement>(null)
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start 60%', 'end 70%'] })
  const draw = useTransform(scrollYProgress, (v) => (reduce ? 1 : Math.min(1, v * 1.08)))
  const [active, setActive] = useState(0)
  useMotionValueEvent(scrollYProgress, 'change', (v) => setActive(Math.min(6, Math.floor(v * 7))))
  const graphY = useParallax(graphRef, 50)
  const graphSeen = useInView(graphRef, { once: true, margin: '0px 0px -25% 0px' })

  return (
    <section id="chain" className="chain on-dark" aria-labelledby="chain-title">
      <div className="wrap">
        <motion.div className="section-head" {...rise()}>
          <h2 id="chain-title" className="heading">
            Seven stages in under two hours.
          </h2>
          <p className="section-lede">
            Scenario A as Prahari reconstructs it. Scroll to walk the chain; the timeline draws as the attacker advances.
          </p>
        </motion.div>

        <div className="chain__grid" ref={ref}>
          <ol className="chain__stages">
            {BY_STAGE.map((s, i) => (
              <li key={s.name} className={`chain__stage ${i <= active ? 'is-reached' : ''} ${i === active ? 'is-active' : ''}`}>
                <span className="chain__num tnum">{i + 1}</span>
                <div>
                  <h3>{s.name}</h3>
                  {s.alerts.length ? (
                    s.alerts.map((a) => (
                      <p key={a.id} className="chain__alert">
                        <span className="tnum chain__time">{formatClock(a.t).slice(0, 5)}</span>
                        <span>{a.title}</span>
                        <TechniqueTag id={a.technique} />
                      </p>
                    ))
                  ) : (
                    <p className="chain__alert chain__alert--none">No alert at this stage.</p>
                  )}
                </div>
              </li>
            ))}
          </ol>

          <div className="chain__sticky">
            <div className="console-card">
              <div className="console-card__head">
                <span className="tnum console-card__id">{FEATURED.id}</span>
                <SeverityChip severity={FEATURED.severity} priority={FEATURED.priority} />
                <CohesionBadge cohesion={FEATURED.cohesion} compact />
                <span className="console-card__risk tnum">{FEATURED.risk.toFixed(2)}</span>
              </div>
              <p className="console-card__title">{FEATURED.headline}</p>
              <KillChainTimeline
                alerts={FEATURED.alerts}
                progress={draw}
                showPlay={false}
                label={`Kill-chain timeline for ${FEATURED.id}, drawn as you scroll`}
              />
            </div>
          </div>
        </div>

        <div className="chain__graph">
          <motion.div className="chain__graph-copy" {...rise()}>
            <h3 className="heading-sm">Every entity it touched.</h3>
            <p>
              Users, hosts, addresses, processes and file hashes, laid out by the links that joined them. fin-db-01 carries
              a red ring because the asset register marks it financial and pii. The spray source is dashed: it is outside
              the network.
            </p>
          </motion.div>
          <motion.div className="console-card console-card--graph" ref={graphRef} style={{ y: graphY }}>
            {graphSeen && <AttackGraph data={FEATURED_GRAPH} label={`Entity graph for ${FEATURED.id}`} />}
          </motion.div>
        </div>
      </div>
    </section>
  )
}
