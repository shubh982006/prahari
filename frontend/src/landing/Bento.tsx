import { motion, useReducedMotion } from 'framer-motion'
import { useState, type ReactNode } from 'react'
import { CohesionBadge } from '../components/CohesionBadge'
import { KillChainTimeline } from '../components/KillChainTimeline'
import { RingGauge } from '../components/RingGauge'
import { SeverityChip } from '../components/SeverityChip'
import { FEATURED, INCIDENTS, STAGES } from '../data/seed'
import { EASE_OUT, rise } from '../lib/motion'
import { useOutputHash } from '../lib/receipt'
import { whatIf } from '../lib/whatif'
import { severityOf } from '../lib/score'

const FRAGILE = INCIDENTS.find((i) => i.cohesion === 'fragile')!

export function Bento() {
  return (
    <div className="bento-section">
      <div className="wrap">
        <motion.div className="section-head" {...rise()}>
          <h2 id="evidence-title" className="heading">
            It shows its work, including the parts it is unsure of.
          </h2>
          <p className="section-lede">
            Four instruments sit behind every incident. Each one is live on this page: press, hover, replay.
          </p>
        </motion.div>

        <div className="bento">
          <Cell className="bento__a" delay={0}>
            <CellHead title="Correlation" body="Alerts link when they share a rare entity inside a two-hour window. The blue line is the forward chain; faded dots sit off it." />
            <KillChainTimeline alerts={FEATURED.alerts} label={`Kill-chain timeline for ${FEATURED.id}`} />
          </Cell>

          <Cell className="bento__b" delay={0.08}>
            <CellHead title="Cohesion" body="If one weak edge holds an incident together, Prahari says so and shows the two halves." />
            <CohesionSplit />
          </Cell>

          <Cell className="bento__c" delay={0.16}>
            <CellHead title="Counterfactuals" body="The smallest change that flips the priority. Press a row." />
            <MiniCounterfactuals />
          </Cell>

          <Cell className="bento__d" delay={0.24}>
            <CellHead title="Determinism receipt" body="Same seed, same bytes, on Postgres or SQLite. This hash was computed in your browser from the incidents on this page." />
            <Receipt />
          </Cell>
        </div>
      </div>
    </div>
  )
}

function Cell({ className, delay, children }: { className: string; delay: number; children: ReactNode }) {
  return (
    <motion.article className={`bento__cell ${className}`} {...rise(delay, 32)}>
      {children}
    </motion.article>
  )
}

function CellHead({ title, body }: { title: string; body: string }) {
  return (
    <header className="bento__head">
      <h3>{title}</h3>
      <p>{body}</p>
    </header>
  )
}

function CohesionSplit() {
  const reduce = useReducedMotion()
  const [open, setOpen] = useState(true)
  const { left, right } = FRAGILE.split!
  return (
    <div className="split">
      <div className="split__top">
        <span className="split__id tnum">{FRAGILE.id}</span>
        <CohesionBadge cohesion="fragile" onClick={() => setOpen((o) => !o)} expanded={open} />
      </div>
      <div className={`split__halves ${open ? 'is-open' : ''}`}>
        {[left, right].map((half, i) => (
          <motion.div
            key={half.headline}
            className="split__half"
            animate={{ y: open && !reduce ? (i ? 10 : -10) : 0 }}
            transition={{ duration: 0.5, ease: EASE_OUT }}
          >
            <span className="split__count tnum">{half.alerts} alerts</span>
            <span className="split__title">{half.headline}</span>
            <span className="split__stage">Reaches {STAGES[half.maxStage - 1].toLowerCase()}</span>
          </motion.div>
        ))}
        <span className="split__bridge tnum" aria-label="Bridge edge">
          {FRAGILE.bridge!.entity.replace('ip:', '')} · IDF {FRAGILE.bridge!.weight}
        </span>
      </div>
      <p className="split__note">
        Measured on ten seeds, the fragile flag is right <strong className="tnum">0.67 ± 0.16</strong> of the time. The
        analyst decides; the split is written to the audit chain.
      </p>
    </div>
  )
}

function MiniCounterfactuals() {
  const rows = FEATURED.counterfactuals.filter((c) => c.kind !== 'boundary').slice(0, 3)
  const [on, setOn] = useState<string | null>(null)
  const current = whatIf(FEATURED, rows.find((r) => r.id === on))
  return (
    <div className="mini-cf">
      <RingGauge value={current.risk} severity={severityOf(current.priority)} size={132} label={`Risk ${current.risk}`}>
        <span className="mini-cf__value tnum">{current.risk.toFixed(2)}</span>
        <SeverityChip severity={severityOf(current.priority)} priority={current.priority} compact />
      </RingGauge>
      <ul>
        {rows.map((r) => {
          const next = whatIf(FEATURED, r)
          return (
            <li key={r.id}>
              <button type="button" aria-pressed={on === r.id} onClick={() => setOn(on === r.id ? null : r.id)}>
                <span>{r.label}</span>
                <span className="tnum">{next.priority}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function Receipt() {
  const hash = useOutputHash(INCIDENTS)
  const groups = hash ? hash.match(/.{1,8}/g)! : Array.from({ length: 8 }, () => '········')
  return (
    <div className="receipt">
      <div className="receipt__row">
        <span>output_hash</span>
        <span className="receipt__algo">sha256 · v1</span>
      </div>
      <code className="receipt__hash tnum" aria-label={hash ? `SHA-256 ${hash}` : 'Computing hash'}>
        {groups.map((g, i) => (
          <motion.span
            key={`${g}-${i}`}
            initial={{ opacity: 0.2 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.06, duration: 0.4 }}
          >
            {g}
          </motion.span>
        ))}
      </code>
      <p className="receipt__foot">
        Proves the engine is a pure function of its input and config. It does not prove the answer is right; that is
        what the misses below are for.
      </p>
    </div>
  )
}
