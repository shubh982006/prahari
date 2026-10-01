import { useLenis } from '../lib/useLenis'
import { ChainWalk } from './ChainWalk'
import { Closing } from './Closing'
import { Collapse } from './Collapse'
import { Header } from './Header'
import { Hero } from './Hero'
import { Misses } from './Misses'
import { SheetOne, SheetTwo } from './Sheets'
import './landing.css'
import './sheets.css'

export default function Landing() {
  useLenis()
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <Header />
      <main id="main" className="landing">
        <Hero />
        <SheetOne />
        <Collapse />
        <SheetTwo />
        <ChainWalk />
        <Misses />
        <Closing />
      </main>
    </>
  )
}
