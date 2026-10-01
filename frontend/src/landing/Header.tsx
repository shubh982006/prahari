import { ArrowRight } from '@phosphor-icons/react'
import { motion, useMotionValueEvent, useScroll } from 'framer-motion'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Logo } from '../components/Logo'
import { EASE_OUT } from '../lib/motion'

const LINKS = [
  { href: '#collapse', label: 'How it works' },
  { href: '#evidence', label: 'Evidence' },
  { href: '#compliance', label: 'Compliance' },
  { href: '#misses', label: 'Where it loses' },
]

/** Banner + nav. Past the fold the banner slides away and the nav takes the midnight fill. */
export function Header() {
  const { scrollY } = useScroll()
  const [scrolled, setScrolled] = useState(false)
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 48))

  return (
    <motion.header
      className={`site-header ${scrolled ? 'is-scrolled' : ''}`}
      animate={{ y: scrolled ? -36 : 0 }}
      transition={{ duration: 0.35, ease: EASE_OUT }}
    >
      <p className="banner">
        <strong>Synthetic data.</strong>
        <span className="banner__long"> Every incident here comes from the Prahari simulator,</span> not live telemetry.{' '}
        <a href="https://github.com/shubh982006/prahari/blob/main/docs/failure-analysis.md" target="_blank" rel="noreferrer">
          See how it is measured
        </a>
      </p>
      <nav className="nav on-dark" aria-label="Primary">
        <div className="nav__inner">
          <Logo />
          <ul className="nav__links">
            {LINKS.map((l) => (
              <li key={l.href}>
                <a href={l.href}>{l.label}</a>
              </li>
            ))}
          </ul>
          <Link to="/console" className="btn btn--secondary nav__cta">
            <span>Console</span>
            <ArrowRight size={14} aria-hidden />
          </Link>
        </div>
      </nav>
    </motion.header>
  )
}
