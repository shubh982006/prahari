import { useEffect, useState } from 'react'
import type { Severity } from './score'

// Captured once so every clock on the page measures from the same instant,
// the way detected_at is stored once and never recomputed.
export const PAGE_LOADED_AT = Date.now()

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

export interface Track {
  key: 'dpdp_intimation' | 'certin' | 'dpdp_report'
  authority: string
  label: string
  hours: number
}

export const TRACKS: Track[] = [
  { key: 'dpdp_intimation', authority: 'DPDP Rules 2025, Rule 7', label: 'DPDP intimation', hours: 1 },
  { key: 'certin', authority: 'CERT-In Directions, 2022', label: 'CERT-In report', hours: 6 },
  { key: 'dpdp_report', authority: 'DPDP Rules 2025, Rule 7', label: 'DPDP detailed report', hours: 72 },
]

export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.floor(Math.abs(ms) / 1000))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
}

/** Threshold ramp per clock: green above 50% remaining, amber 20–50%, red below 20%. */
export function clockState(detectedAt: number, deadline: number, now: number) {
  const total = Math.max(1, deadline - detectedAt)
  const remaining = deadline - now
  const frac = remaining / total
  const severity: Severity = frac > 0.5 ? 'low' : frac > 0.2 ? 'high' : 'critical'
  return { remaining, frac, severity, overdue: remaining <= 0 }
}

/** Props for a synthetic track that started `detectedAt`. */
export function trackClock(t: Track, detectedAt: number) {
  return { label: t.label, authority: t.authority, detectedAt, deadline: detectedAt + t.hours * 3_600_000 }
}
