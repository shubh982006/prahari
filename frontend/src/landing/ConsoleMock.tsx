import { ClockCountdown, GearSix, Graph, Scales, Tray } from '@phosphor-icons/react'
import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import { CohesionBadge } from '../components/CohesionBadge'
import { KillChainTimeline } from '../components/KillChainTimeline'
import { SeverityChip } from '../components/SeverityChip'
import { StageBar } from '../components/StageBar'
import { INCIDENTS } from '../data/seed'
import { EASE_OUT } from '../lib/motion'
import { WindowFrame } from './Frame'

const RAIL = [
  { Icon: Tray, label: 'Queue' },
  { Icon: Graph, label: 'Graph' },
  { Icon: ClockCountdown, label: 'Clocks' },
  { Icon: Scales, label: 'Counterfactuals' },
]

/** A working miniature of the console: pick an incident on the left, its chain draws on the right. */
export function ConsoleMock() {
  const list = INCIDENTS.slice(0, 5)
  const [id, setId] = useState(list[0].id)
  const inc = list.find((i) => i.id === id)!

  return (
    <WindowFrame title="Prahari" meta="seed 42 · synthetic">
      <div className="cmock">
        <nav className="cmock__rail" aria-label="Console sections (preview)">
          {RAIL.map(({ Icon, label }, i) => (
            <span key={label} className={i === 0 ? 'is-on' : ''} title={label}>
              <Icon size={18} weight={i === 0 ? 'fill' : 'regular'} aria-hidden />
            </span>
          ))}
          <span className="cmock__rail-end" title="Settings">
            <GearSix size={18} aria-hidden />
          </span>
        </nav>
        <ol className="cmock__queue" aria-label="Preview queue">
          {list.map((i) => (
            <li key={i.id}>
              <button type="button" className={i.id === id ? 'is-on' : ''} onClick={() => setId(i.id)} aria-pressed={i.id === id}>
                {i.id === id && <motion.span layoutId="cmock-sel" className="cmock__sel" transition={{ duration: 0.25, ease: EASE_OUT }} />}
                <span className="cmock__row-top">
                  <SeverityChip severity={i.severity} priority={i.priority} compact />
                  <span className="tnum cmock__risk">{i.risk.toFixed(2)}</span>
                </span>
                <span className="cmock__title">{i.headline}</span>
                <StageBar reached={i.maxStage} severity={i.severity} />
              </button>
            </li>
          ))}
        </ol>
        <div className="cmock__detail">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={inc.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, transition: { duration: 0.12 } }}
              transition={{ duration: 0.25, ease: EASE_OUT }}
            >
              <div className="cmock__meta">
                <span className="tnum">{inc.id}</span>
                <CohesionBadge cohesion={inc.cohesion} compact />
              </div>
              <h3 className="cmock__headline">{inc.headline}</h3>
              <KillChainTimeline alerts={inc.alerts} label={`Kill-chain timeline for ${inc.id}`} />
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </WindowFrame>
  )
}
