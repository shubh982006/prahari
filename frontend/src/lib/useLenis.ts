import Lenis from 'lenis'
import { useEffect } from 'react'

/** Smooth wheel scrolling for the landing page only; the console keeps native scroll. */
export function useLenis() {
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const lenis = new Lenis({ duration: 1.1, easing: (t) => 1 - Math.pow(1 - t, 4) })
    let frame = 0
    const raf = (time: number) => {
      lenis.raf(time)
      frame = requestAnimationFrame(raf)
    }
    frame = requestAnimationFrame(raf)
    return () => {
      cancelAnimationFrame(frame)
      lenis.destroy()
    }
  }, [])
}
