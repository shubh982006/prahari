import { ArrowsSplit, CheckCircle, ProhibitInset, UserMinus, UserPlus } from '@phosphor-icons/react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import type { Schemas } from '../../api/client'
import { useFeedback, usePatchIncident, useSplit } from '../../api/mutations'
import { useAudit, useFeedbackHistory, useMe } from '../../api/queries'
import { summarise, useIsLead } from '../roles'
import { PanelError, Skeleton } from '../../components/Status'

type Status = Schemas['IncidentStatus']

// Mirrors the backend's transition table (app.transitions); the server still
// enforces it and answers 409 INVALID_STATE if the two ever drift.
const NEXT: Record<Status, Status[]> = {
  open: ['investigating', 'confirmed', 'false_positive', 'closed'],
  investigating: ['open', 'confirmed', 'false_positive', 'closed'],
  confirmed: ['investigating', 'closed'],
  false_positive: ['open', 'closed'],
  closed: ['open'],
}
const LABEL: Record<Status, string> = {
  open: 'Open',
  investigating: 'Investigating',
  confirmed: 'Confirmed attack',
  false_positive: 'False positive',
  closed: 'Closed',
}

/** Status, owner and verdict: the three things an analyst changes on an incident. */
export function TriageBar({ incident }: { incident: Schemas['IncidentDetail'] }) {
  const me = useMe(true).data
  const patch = usePatchIncident(incident.incident_id)
  const feedback = useFeedback(incident.incident_id)
  const [note, setNote] = useState('')
  const status = incident.status as Status
  const mine = !!me && incident.assignee === me.user_id

  const verdict = (v: 'confirmed' | 'false_positive') =>
    feedback.mutate({ verdict: v, note: note.trim() || undefined, run_id: incident.run_id }, { onSuccess: () => setNote('') })

  return (
    <div className="triage" aria-label="Triage">
      <label className="triage__field">
        <span>Status</span>
        <select
          value={status}
          disabled={patch.isPending}
          onChange={(e) => patch.mutate({ patch: { status: e.target.value as Status }, etag: incident.etag })}
        >
          <option value={status}>{LABEL[status]}</option>
          {NEXT[status].map((s) => (
            <option key={s} value={s}>
              {LABEL[s]}
            </option>
          ))}
        </select>
      </label>
      <div className="triage__field">
        <span>Owner</span>
        <div className="triage__owner">
          <span className="tnum">{incident.assignee ?? 'Unassigned'}</span>
          {me && (
            <button
              type="button"
              className="mini-btn"
              disabled={patch.isPending}
              onClick={() => patch.mutate({ patch: { assignee: mine ? null : me.user_id }, etag: incident.etag })}
            >
              {mine ? <UserMinus size={14} aria-hidden /> : <UserPlus size={14} aria-hidden />}
              {mine ? 'Release' : 'Take it'}
            </button>
          )}
        </div>
      </div>
      <div className="triage__field triage__verdict">
        <span>Verdict</span>
        <div>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Note for the record (optional)"
            aria-label="Verdict note"
            maxLength={500}
          />
          <button type="button" className="mini-btn" disabled={feedback.isPending} onClick={() => verdict('confirmed')}>
            <CheckCircle size={14} aria-hidden /> Real attack
          </button>
          <button type="button" className="mini-btn" disabled={feedback.isPending} onClick={() => verdict('false_positive')}>
            <ProhibitInset size={14} aria-hidden /> False positive
          </button>
        </div>
      </div>
    </div>
  )
}

/** Materialise the split the cohesion check proposes. Lead only; the result is a new run. */
export function SplitAction({ incidentId, cohesion }: { incidentId: string; cohesion: Schemas['Cohesion'] }) {
  const lead = useIsLead()
  const split = useSplit(incidentId)
  const bridge = cohesion.bridge_edges[0]
  if (!bridge) return null
  return (
    <div className="split-preview__actions">
      <button
        type="button"
        className="btn btn--secondary"
        disabled={!lead || split.isPending}
        title={lead ? undefined : 'Only a lead can split an incident'}
        onClick={() => split.mutate({ bridge: { alert_a: bridge.alert_a, alert_b: bridge.alert_b }, note: 'split from the console' })}
      >
        <ArrowsSplit size={16} aria-hidden />
        <span>{split.isPending ? 'Splitting…' : 'Split into two incidents'}</span>
      </button>
      {split.data && (
        <span className="split-preview__done">
          New run {split.data.run_id.slice(0, 8)}: {split.data.incidents.map((i) => i.incident_id).join(', ')}.{' '}
          <Link to={`/console/${split.data.incidents[0]?.incident_id}`}>Open the first half</Link>
        </span>
      )}
    </div>
  )
}

/** Drag an asset's criticality and watch every counterfactual recompute on the server. */
export function WhatIfCriticality({
  assets,
  value,
  onChange,
}: {
  assets: { hostname: string; criticality: number }[]
  value: string
  onChange: (whatIf: string) => void
}) {
  const [host, setHost] = useState(assets[0]?.hostname ?? '')
  const storedOf = (h: string) => assets.find((a) => a.hostname === h)?.criticality ?? 5
  const stored = storedOf(host)
  const [crit, setCrit] = useState(stored)
  const pickHost = (h: string) => {
    setHost(h)
    setCrit(storedOf(h))
  }
  // Debounce so a drag becomes one request, not ten.
  useEffect(() => {
    const t = window.setTimeout(() => onChange(host && crit !== stored ? `${host}:${crit}` : ''), 250)
    return () => window.clearTimeout(t)
  }, [host, crit, stored, onChange])

  if (!assets.length) return null
  return (
    <div className="whatif">
      <label>
        <span>Asset</span>
        <select value={host} onChange={(e) => pickHost(e.target.value)}>
          {assets.map((a) => (
            <option key={a.hostname} value={a.hostname}>
              {a.hostname} (stored C{a.criticality})
            </option>
          ))}
        </select>
      </label>
      <label className="whatif__slider">
        <span>
          What if its criticality were <strong className="tnum">{crit}</strong>
        </span>
        <input type="range" min={1} max={10} value={crit} onChange={(e) => setCrit(Number(e.target.value))} />
      </label>
      {value && (
        <button type="button" className="mini-btn" onClick={() => setCrit(stored)}>
          Reset
        </button>
      )}
    </div>
  )
}

/** Verdict history and the hash-chained audit trail for one incident. */
export function IncidentActivity({ id }: { id: string }) {
  const fb = useFeedbackHistory(id)
  const audit = useAudit(id)
  const entries = audit.data?.pages.flatMap((p) => p.data) ?? []
  return (
    <>
      <section className="panel">
        <h2 className="panel__title">Verdicts</h2>
        {fb.isPending ? (
          <Skeleton rows={2} />
        ) : fb.isError ? (
          <PanelError title="Could not load verdicts" error={fb.error} retry={() => fb.refetch()} inline />
        ) : fb.data.data.length === 0 ? (
          <p className="panel__lede">No verdict recorded yet.</p>
        ) : (
          <ul className="log">
            {fb.data.data.map((f) => (
              <li key={f.feedback_id}>
                <strong>{f.verdict === 'confirmed' ? 'Real attack' : 'False positive'}</strong>
                <span>
                  {f.user_id}
                  {f.note ? `: ${f.note}` : ''}
                </span>
                <time className="tnum">{new Date(f.created_at).toLocaleString('en-IN')}</time>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="panel">
        <h2 className="panel__title">Audit trail</h2>
        {audit.isPending ? (
          <Skeleton rows={4} />
        ) : audit.isError ? (
          <PanelError title="Could not load the audit trail" error={audit.error} retry={() => audit.refetch()} inline />
        ) : entries.length === 0 ? (
          <p className="panel__lede">Nothing recorded against this incident.</p>
        ) : (
          <ul className="log">
            {entries.map((e) => (
              <li key={e.seq}>
                <strong>{e.action}</strong>
                <span>
                  {e.actor}
                  {e.payload && Object.keys(e.payload).length ? ` · ${summarise(e.payload)}` : ''}
                </span>
                <time className="tnum">
                  #{e.seq} · {new Date(e.ts).toLocaleString('en-IN')}
                </time>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}

