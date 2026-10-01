import { useEffect, useState } from 'react'
import type { Incident } from '../data/seed'

const US = '\x1f'
const RS = '\x1e'

/** output_hash exactly as design §10.1 specifies it, computed in the browser. */
export async function outputHash(incidents: Incident[]): Promise<string> {
  const body = [...incidents]
    .sort((a, b) => (a.id < b.id ? -1 : 1))
    .map((i) =>
      [i.id, i.priority, i.risk.toFixed(2), i.cohesion, i.alerts.map((a) => a.id).sort().join(',')].join(US) + RS,
    )
    .join('')
  const bytes = new TextEncoder().encode('v1\n' + body)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function useOutputHash(incidents: Incident[]): string | null {
  const [hash, setHash] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    outputHash(incidents).then((h) => live && setHash(h)).catch(() => live && setHash(null))
    return () => {
      live = false
    }
  }, [incidents])
  return hash
}
