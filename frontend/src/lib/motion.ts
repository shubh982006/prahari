import { useReducedMotion, useScroll, useTransform, type MotionValue } from 'framer-motion'
import type { RefObject } from 'react'

export const EASE_OUT = [0.16, 1, 0.3, 1] as const
export const EASE_IN = [0.7, 0, 0.84, 0] as const

/** Entrance used for landing reveals; each call site picks its own distance and delay. */
export function rise(delay = 0, distance = 24) {
  return {
    initial: { opacity: 0, y: distance },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: '0px 0px -12% 0px' },
    transition: { duration: 0.9, ease: EASE_OUT, delay },
  }
}

/**
 * Scroll-linked vertical drift for parallax layers. `distance` is how far the
 * layer travels across the element's pass through the viewport; negative
 * values move against the scroll. Returns 0 under reduced motion.
 */
export function useParallax(ref: RefObject<HTMLElement | null>, distance: number): MotionValue<number> {
  const reduce = useReducedMotion()
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'end start'] })
  return useTransform(scrollYProgress, [0, 1], reduce ? [0, 0] : [distance, -distance])
}
