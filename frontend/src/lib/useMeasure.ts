import { useLayoutEffect, useRef, useState } from 'react'

export function useMeasure<T extends HTMLElement>(fallback = 640) {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setWidth(el.clientWidth || fallback)
    const ro = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width) || fallback))
    ro.observe(el)
    return () => ro.disconnect()
  }, [fallback])
  return [ref, width] as const
}
