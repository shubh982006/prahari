import type { Icon } from '@phosphor-icons/react'
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { useRef, type ReactNode } from 'react'
import { rise, useParallax } from '../lib/motion'

/** A light section inset on the midnight canvas; it settles into place as it arrives. */
export function Sheet({ id, label, children }: { id?: string; label: string; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null)
  const reduce = useReducedMotion()
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'start 25%'] })
  const scale = useTransform(scrollYProgress, [0, 1], reduce ? [1, 1] : [0.93, 1])
  const y = useTransform(scrollYProgress, [0, 1], reduce ? [0, 0] : [40, 0])
  return (
    <motion.section ref={ref} id={id} className="sheet on-light" aria-label={label} style={{ scale, y }}>
      {children}
    </motion.section>
  )
}

/** Desktop window chrome around a product mockup. */
export function WindowFrame({ title, meta, tone = 'light', children }: { title: string; meta?: string; tone?: 'light' | 'dark'; children: ReactNode }) {
  return (
    <div className={`window window--${tone}`}>
      <div className="window__bar">
        <span className="window__lights" aria-hidden>
          <i />
          <i />
          <i />
        </span>
        <span className="window__title">{title}</span>
        {meta && <span className="window__meta tnum">{meta}</span>}
      </div>
      <div className="window__body">{children}</div>
    </div>
  )
}

export function PillTag({ icon: I, children }: { icon: Icon; children: ReactNode }) {
  return (
    <span className="pill-tag">
      <I size={14} weight="bold" aria-hidden />
      {children}
    </span>
  )
}

interface ProductProps {
  tag: ReactNode
  title: string
  body: string
  cards: { title: string; body: string }[]
  mock: ReactNode
  flip?: boolean
}

/** Text on one side, a live mockup bleeding off the card edge on the other. */
export function ProductBlock({ tag, title, body, cards, mock, flip }: ProductProps) {
  const mockRef = useRef<HTMLDivElement>(null)
  const y = useParallax(mockRef, 30)
  return (
    <motion.article className={`product ${flip ? 'product--flip' : ''}`} {...rise(0, 40)}>
      <div className="product__copy">
        {tag}
        <h2 className="heading product__title">{title}</h2>
        <p className="product__body">{body}</p>
        <div className="product__cards">
          {cards.map((c, i) => (
            <motion.div key={c.title} className="info-card" {...rise(0.1 + i * 0.08, 16)}>
              <h3>{c.title}</h3>
              <p>{c.body}</p>
            </motion.div>
          ))}
        </div>
      </div>
      <motion.div className="product__mock" ref={mockRef} style={{ y }}>
        {mock}
      </motion.div>
    </motion.article>
  )
}
