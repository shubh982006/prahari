import { ClockCountdown, Monitor } from '@phosphor-icons/react'
import { motion, useReducedMotion } from 'framer-motion'
import type { ComponentType, SVGProps } from 'react'
import { INCIDENTS } from '../data/seed'
import { rise } from '../lib/motion'
import { ChainIcon, DialIcon, SplitIcon } from './art/Stickers'
import { Stream } from './art/Stream'
import { Bento } from './Bento'
import { ComplianceMock } from './ComplianceMock'
import { ConsoleMock } from './ConsoleMock'
import { PillTag, ProductBlock, Sheet } from './Frame'

const FEATURES: { Icon: ComponentType<SVGProps<SVGSVGElement>>; title: string; body: string }[] = [
  {
    Icon: ChainIcon,
    title: 'Links alerts that belong together',
    body: 'Two alerts join when they share a rare entity inside a two-hour window. Busy servers are stop-listed, so they cannot glue the whole night into one blob.',
  },
  {
    Icon: SplitIcon,
    title: 'Says when a grouping is shaky',
    body: 'If a single weak link holds an incident together, it is flagged fragile and shown as the two halves it might really be.',
  },
  {
    Icon: DialIcon,
    title: 'Explains every score',
    body: 'Each priority comes with the smallest change that would flip it, computed from the same formula the engine ranks with.',
  },
]

const TECHNIQUES = [...new Set(INCIDENTS.flatMap((i) => i.techniques))].sort()

export function SheetOne() {
  return (
    <Sheet id="product" label="What Prahari does">
      <Stream />
      <div className="wrap">
        <div className="features">
          {FEATURES.map(({ Icon, title, body }, i) => (
            <motion.div key={title} className="feature" {...rise(i * 0.08, 20)}>
              <Icon className="feature__icon" />
              <h3>{title}</h3>
              <p>{body}</p>
            </motion.div>
          ))}
        </div>
      </div>
      <Marquee />
      <div className="wrap">
        <ProductBlock
          tag={<PillTag icon={Monitor}>Console</PillTag>}
          title="Work the queue, not the noise."
          body="Incidents arrive ranked by a risk score you can argue with. Open one and the kill chain, the entity graph, the counterfactuals and any running regulatory clock are already laid out."
          cards={[
            { title: 'Uncertainty is on screen', body: 'Cohesion tells you when an incident may really be two, before you spend an hour on it.' },
            { title: 'Every sentence cites an alert', body: 'The shift brief links each claim to the alert behind it. Hover a citation and the chain lights up.' },
          ]}
          mock={<ConsoleMock />}
        />
      </div>
    </Sheet>
  )
}

export function SheetTwo() {
  return (
    <Sheet id="evidence" label="Evidence and compliance">
      <Bento />
      <div className="wrap" id="compliance">
        <ProductBlock
          flip
          tag={<PillTag icon={ClockCountdown}>Compliance</PillTag>}
          title="Three clocks start when sensitive data is touched."
          body="When a P1 or P2 incident reaches collection or exfiltration and touches an asset tagged pii or financial, Prahari stamps the detection time once. Re-running the engine cannot move a deadline."
          cards={[
            { title: 'One hour comes first', body: 'DPDP intimation is the tightest obligation in the product, so it sits on the left.' },
            {
              title: 'Drafted from evidence, never the model',
              body: "CERT-In's six-hour rule has applied since 2022; DPDP breach-notice enforcement is expected from May 2027. Prahari drafts, a person submits. Not legal advice.",
            },
          ]}
          mock={<ComplianceMock />}
        />
      </div>
    </Sheet>
  )
}

function Marquee() {
  const reduce = useReducedMotion()
  const row = TECHNIQUES.map((t) => (
    <span key={t} className="tech-tag tnum">
      {t}
    </span>
  ))
  return (
    <div className="marquee" aria-label={`ATT&CK techniques in this excerpt: ${TECHNIQUES.join(', ')}`}>
      <p className="marquee__caption">
        <span className="tnum">{TECHNIQUES.length}</span> ATT&amp;CK techniques observed in this excerpt
      </p>
      <div className={`marquee__track ${reduce ? 'is-static' : ''}`} aria-hidden>
        <div className="marquee__row">{row}</div>
        {!reduce && <div className="marquee__row">{row}</div>}
      </div>
    </div>
  )
}
