import { Copy } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { caseClocks, istTime } from '../../api/adapt'
import type { Schemas } from '../../api/client'
import { useSubmitCase } from '../../api/mutations'
import { useActiveDataset, useCase, useCases, useDraft, useDraftMarkdown } from '../../api/queries'
import { toast } from '../../api/toast'
import { ComplianceClock } from '../../components/ComplianceClock'
import { SeverityChip } from '../../components/SeverityChip'
import { PanelError, Skeleton } from '../../components/Status'
import { clockState, formatDuration, useNow } from '../../lib/clock'
import { severityOf, type Priority } from '../../lib/score'
import { useIsLead } from '../roles'

const STATES = ['open', 'overdue', 'closed', 'all'] as const

export default function Compliance() {
  const { caseId } = useParams()
  const navigate = useNavigate()
  const ds = useActiveDataset()
  const [state, setState] = useState<(typeof STATES)[number]>('open')
  const cases = useCases(ds.data?.dataset_id, state)
  const now = useNow()
  const list = cases.data?.data ?? []
  const current = caseId ?? list[0]?.case_id

  return (
    <div className="page page--split">
      <aside className="page__list" aria-label="Compliance cases">
        <div className="queue__head">
          <h1>Compliance cases</h1>
          {cases.data && <span className="tnum">{list.length}</span>}
        </div>
        <div className="seg seg--4" role="group" aria-label="Case state">
          {STATES.map((s) => (
            <button key={s} type="button" aria-pressed={state === s} onClick={() => setState(s)}>
              {s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        {cases.isPending ? (
          <Skeleton rows={6} />
        ) : cases.isError ? (
          <PanelError title="Could not load cases" error={cases.error} retry={() => cases.refetch()} inline />
        ) : list.length === 0 ? (
          <p className="queue__empty">No {state === 'all' ? '' : state} cases on this dataset.</p>
        ) : (
          <ol className="rowlist">
            {list.map((c) => {
              const tightest = caseClocks(c)
                .filter((t) => t.status !== 'submitted')
                .map((t) => ({ ...t, s: clockState(t.detectedAt, t.deadline, now) }))
                .sort((a, b) => a.s.remaining - b.s.remaining)[0]
              return (
                <li key={c.case_id}>
                  <button type="button" className={`rowbtn ${c.case_id === current ? 'is-on' : ''}`} onClick={() => navigate(`/console/compliance/${c.case_id}`)}>
                    <span className="rowbtn__top">
                      {c.priority && <SeverityChip severity={severityOf(c.priority as Priority)} priority={c.priority as Priority} compact />}
                      <span className="tnum">{c.case_id}</span>
                      <span className="tnum rowbtn__right">{c.incident_id}</span>
                    </span>
                    <span className="rowbtn__title">{c.headline}</span>
                    <span className={`rowbtn__meta tnum ${tightest?.s.overdue ? 'is-overdue' : ''}`}>
                      {tightest
                        ? `${tightest.label}: ${tightest.s.overdue ? 'overdue by ' : ''}${formatDuration(tightest.s.remaining)}${tightest.s.overdue ? '' : ' left'}`
                        : 'All tracks submitted'}
                    </span>
                  </button>
                </li>
              )
            })}
          </ol>
        )}
      </aside>
      <main className="page__main">{current ? <CaseDetail id={current} /> : <p className="panel__lede">Pick a case.</p>}</main>
    </div>
  )
}

function CaseDetail({ id }: { id: string }) {
  const c = useCase(id)
  const now = useNow()
  const [track, setTrack] = useState<Schemas['TrackName']>('certin')
  if (c.isPending) return <Skeleton rows={10} />
  if (c.isError) return <PanelError title="Could not load the case" error={c.error} retry={() => c.refetch()} />
  const d = c.data
  const skew = d.server_time ? Date.parse(d.server_time) - c.dataUpdatedAt : 0
  const clocks = caseClocks(d)

  return (
    <article className="stack">
      <header className="page__head">
        <p className="page__eyebrow tnum">
          {d.case_id} · <Link to={`/console/${d.incident_id}`}>{d.incident_id}</Link> · {d.state}
        </p>
        <h2>{d.headline}</h2>
        <p className="panel__lede">
          Triggered at {istTime(Date.parse(d.detected_at))} IST on {new Date(d.detected_at).toLocaleDateString('en-IN')} by{' '}
          {d.trigger.priority}, reaching stage {d.trigger.max_stage + 1} of 7, touching {d.trigger.assets.join(', ')} (
          {d.trigger.data_classes.join(', ')}). The detection time is stored once and never recomputed.
        </p>
      </header>

      <section className="panel">
        <h3 className="panel__title">Clocks</h3>
        <div className="clocks-row">
          {clocks.map(({ key, status, ...clock }) =>
            status === 'submitted' ? (
              <div key={key} className="clock-done">
                <strong>{clock.label}</strong>
                <span>Submitted</span>
                <span className="tnum">{d.tracks.find((t) => t.track === key)?.reference}</span>
              </div>
            ) : (
              <ComplianceClock key={key} {...clock} now={now + skew} size={132} />
            ),
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel__bar">
          <h3 className="panel__title">Draft report</h3>
          <div className="seg seg--inline" role="tablist" aria-label="Track">
            {d.tracks.map((t) => (
              <button key={t.track} type="button" role="tab" aria-selected={track === t.track} aria-pressed={track === t.track} onClick={() => setTrack(t.track)}>
                {clocks.find((c) => c.key === t.track)?.label}
              </button>
            ))}
          </div>
        </div>
        <DraftView caseId={d.case_id} track={track} />
        <SubmissionForm caseId={d.case_id} track={d.tracks.find((t) => t.track === track)!} />
      </section>

      <section className="panel">
        <h3 className="panel__title">
          Evidence <span className="panel__count tnum">{d.evidence_hash.replace('sha256:', '').slice(0, 16)}…</span>
        </h3>
        <ul className="log">
          {d.evidence.map((e, i) => (
            <li key={i}>
              <strong>{e.kind}</strong>
              <span>
                <span className="tnum">{e.ref}</span>
                {e.summary ? ` · ${e.summary}` : ''}
              </span>
              <time className="tnum">
                {istTime(Date.parse(e.ts))} IST{e.audit_seq ? ` · #${e.audit_seq}` : ''}
              </time>
            </li>
          ))}
        </ul>
      </section>
    </article>
  )
}

function DraftView({ caseId, track }: { caseId: string; track: string }) {
  const [md, setMd] = useState(false)
  const draft = useDraft(caseId, track)
  const markdown = useDraftMarkdown(caseId, track, md)
  if (draft.isPending) return <Skeleton rows={6} />
  if (draft.isError) return <PanelError title="Could not build the draft" error={draft.error} retry={() => draft.refetch()} inline />
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(markdown.data ?? '')
      toast({ tone: 'success', title: 'Draft copied as Markdown' })
    } catch {
      toast({ tone: 'error', title: 'Clipboard blocked by the browser' })
    }
  }
  return (
    <div className="draft">
      <p className="draft__disclaimer">{draft.data.disclaimer}</p>
      <div className="draft__tools">
        <label className="toggle">
          <input type="checkbox" checked={md} onChange={(e) => setMd(e.target.checked)} /> Show as Markdown
        </label>
        {md && markdown.data && (
          <button type="button" className="mini-btn" onClick={copy}>
            <Copy size={14} aria-hidden /> Copy
          </button>
        )}
      </div>
      {md ? (
        markdown.isPending ? (
          <Skeleton rows={6} />
        ) : markdown.isError ? (
          <PanelError title="Could not render Markdown" error={markdown.error} retry={() => markdown.refetch()} inline />
        ) : (
          <pre className="draft__md">{markdown.data}</pre>
        )
      ) : (
        <dl className="kv">
          {Object.entries(draft.data.fields).map(([k, v]) => (
            <div key={k}>
              <dt>{k.replace(/_/g, ' ')}</dt>
              <dd>{renderValue(v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}

function renderValue(v: unknown): string {
  if (v == null) return 'None'
  const filled = (xs: unknown[]) => xs.filter((x) => x !== '' && x != null).map(String)
  if (Array.isArray(v))
    return v.map((x) => (x && typeof x === 'object' ? filled(Object.values(x as object)).join(' · ') : String(x))).join('; ')
  if (typeof v === 'object')
    return Object.entries(v as object)
      .filter(([, x]) => x !== '' && x != null)
      .map(([k, x]) => `${k}: ${String(x)}`)
      .join(', ')
  return String(v)
}

function toLocalInput(d: Date) {
  const off = d.getTimezoneOffset() * 60_000
  return new Date(d.getTime() - off).toISOString().slice(0, 16)
}

function SubmissionForm({ caseId, track }: { caseId: string; track: Schemas['TrackState'] }) {
  const lead = useIsLead()
  const submit = useSubmitCase(caseId)
  const [reference, setReference] = useState('')
  const [at, setAt] = useState(() => toLocalInput(new Date()))
  const [note, setNote] = useState('')

  if (track.status === 'submitted') {
    return (
      <p className="submitted">
        Submitted by {track.submitted_by} at {track.submitted_at && new Date(track.submitted_at).toLocaleString('en-IN')}, reference{' '}
        <span className="tnum">{track.reference}</span>.
      </p>
    )
  }
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    submit.mutate({ track: track.track, body: { reference: reference.trim(), submitted_at: new Date(at).toISOString(), note: note.trim() || undefined } })
  }
  return (
    <form className="form-row" onSubmit={onSubmit} aria-label="Record submission">
      <p className="form-row__lede">Prahari drafts; a person files the report with the authority and records it here.</p>
      <label>
        <span>Authority reference</span>
        <input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="CERTIN-2026-000123" required disabled={!lead} />
      </label>
      <label>
        <span>Submitted at</span>
        <input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} required disabled={!lead} />
      </label>
      <label className="form-row__grow">
        <span>Note</span>
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional" disabled={!lead} />
      </label>
      <button type="submit" className="btn btn--primary" disabled={!lead || !reference.trim() || submit.isPending} title={lead ? undefined : 'Only a lead can record a submission'}>
        <span>{submit.isPending ? 'Recording…' : 'Record submission'}</span>
      </button>
    </form>
  )
}
