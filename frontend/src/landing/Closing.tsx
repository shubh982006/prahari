import { ArrowRight, Check, Copy, GithubLogo } from '@phosphor-icons/react'
import { motion } from 'framer-motion'
import { useState } from 'react'
import { Button } from '../components/Button'
import { Logo } from '../components/Logo'
import { AlertCoin, Stopwatch } from './art/Stickers'
import { rise } from '../lib/motion'

// Regenerates docs/failure-analysis.md, the source of the detection and adversary numbers above.
const CMD = 'git clone https://github.com/shubh982006/prahari && cd prahari/backend && go run ./cmd/cli failures'
const REPO = 'https://github.com/shubh982006/prahari'

export function Closing() {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(CMD)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopied(false)
    }
  }

  return (
    <section className="closing on-dark" aria-labelledby="closing-title">
      <div className="orb orb--blue orb--center" aria-hidden />
      <div className="wrap">
        <motion.div className="closing__inner" {...rise()}>
          <h2 id="closing-title" className="heading">
            Regenerate the{' '}
            <span className="inline-stickers" aria-hidden>
              <AlertCoin tone="critical" />
              <Stopwatch />
              <AlertCoin tone="lock" />
            </span>{' '}
            failure analysis on your own machine.
          </h2>
          <div className="closing__cmd">
            <code className="tnum">{CMD}</code>
            <button type="button" onClick={copy} aria-label={copied ? 'Copied' : 'Copy command'}>
              {copied ? <Check size={16} weight="bold" /> : <Copy size={16} />}
              <span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="closing__ctas">
            <Button to="/console" icon={ArrowRight}>
              Open the console
            </Button>
            <Button variant="secondary" icon={GithubLogo} href={REPO}>
              View on GitHub
            </Button>
          </div>
        </motion.div>
      </div>

      <footer className="footer wrap">
        <Logo />
        <ul>
          <li><a href={`${REPO}/blob/main/docs/design.md`} target="_blank" rel="noreferrer">Design</a></li>
          <li><a href={`${REPO}/blob/main/docs/failure-analysis.md`} target="_blank" rel="noreferrer">Failure analysis</a></li>
          <li><a href={`${REPO}/tree/main/docs/results/benchmarks`} target="_blank" rel="noreferrer">Benchmarks</a></li>
          <li><a href={`${REPO}/blob/main/docs/api-contract.md`} target="_blank" rel="noreferrer">API contract</a></li>
        </ul>
        <p>Synthetic data throughout. Prahari drafts regulatory reports; people file them.</p>
      </footer>
    </section>
  )
}
