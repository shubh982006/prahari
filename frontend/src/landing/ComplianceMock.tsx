import { ComplianceClock } from '../components/ComplianceClock'
import { FEATURED } from '../data/seed'
import { PAGE_LOADED_AT, TRACKS, trackClock, useNow } from '../lib/clock'
import { WindowFrame } from './Frame'

const hosts = FEATURED.entities.filter((e) => e.type === 'host')
const iocs = FEATURED.entities.filter((e) => e.external || e.type === 'hash').map((e) => e.label)

const DRAFT: [string, string][] = [
  ['Incident type', 'Unauthorised access; exfiltration of data'],
  ['Detected', `${FEATURED.complianceMinutesAgo} min before page load, stored once`],
  ['Affected systems', hosts.map((h) => h.label + (h.tags ? ` (${h.tags.join(', ')})` : '')).join(', ')],
  ['Techniques', FEATURED.techniques.slice(0, 6).join(', ') + ', …'],
  ['Indicators', iocs.join(', ')],
  ['Status', 'Draft. A person reviews and submits.'],
]

export function ComplianceMock() {
  const now = useNow()
  const detectedAt = PAGE_LOADED_AT - (FEATURED.complianceMinutesAgo ?? 0) * 60_000
  return (
    <WindowFrame title="CERT-In draft" meta={FEATURED.id}>
      <div className="comock">
        <div className="comock__clocks">
          {TRACKS.map((t) => (
            <ComplianceClock key={t.key} {...trackClock(t, detectedAt)} now={now} size={118} />
          ))}
        </div>
        <dl className="comock__draft">
          {DRAFT.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd className={k === 'Techniques' || k === 'Indicators' ? 'tnum' : undefined}>{v}</dd>
            </div>
          ))}
        </dl>
      </div>
    </WindowFrame>
  )
}
