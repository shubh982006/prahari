import { ArrowLeft } from '@phosphor-icons/react'
import { motion } from 'framer-motion'
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import type { Schemas } from '../../api/client'
import { useActiveDataset, useIncidents, useReceipt } from '../../api/queries'
import { CohesionBadge } from '../../components/CohesionBadge'
import { SeverityChip } from '../../components/SeverityChip'
import { StageBar } from '../../components/StageBar'
import { PanelError, Skeleton } from '../../components/Status'
import { EASE_OUT } from '../../lib/motion'
import { severityOf, type Priority } from '../../lib/score'
import { IncidentDetail } from '../incident/IncidentDetail'

const FILTERS = [
  { id: '', label: 'All' },
  { id: 'P1', label: 'P1' },
  { id: 'P2', label: 'P2' },
  { id: 'P3,P4', label: 'P3+' },
]

export default function Incidents() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [filter, setFilter] = useState('')
  const ds = useActiveDataset()
  const datasetId = ds.data?.dataset_id
  const list = useIncidents(datasetId, filter)
  const first = list.data?.pages[0]
  const incidents = useMemo(() => list.data?.pages.flatMap((p) => p.data) ?? [], [list.data])
  const receipt = useReceipt(first?.run_id)
  const currentId = id ?? incidents[0]?.incident_id
  const hash = receipt.data?.output_hash?.replace('sha256:', '')

  useEffect(() => {
    document.title = currentId ? `${currentId} · Prahari` : 'Incidents · Prahari'
  }, [currentId])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      if (el.closest('input, textarea, select, [contenteditable]') || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key !== 'j' && e.key !== 'k') return
      const idx = incidents.findIndex((i) => i.incident_id === currentId)
      const next = incidents[Math.min(incidents.length - 1, Math.max(0, (idx < 0 ? -1 : idx) + (e.key === 'j' ? 1 : -1)))]
      if (next) navigate(`/console/${next.incident_id}`)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [incidents, currentId, navigate])

  return (
    <div className="cbody" data-selected={id ? 'true' : 'false'}>
      <nav className="queue" aria-label="Incident queue">
        <div className="queue__head">
          <h1>Incidents</h1>
          {first && (
            <span className="tnum">
              {first.totals.incidents} from {first.totals.alerts.toLocaleString('en-IN')} alerts
            </span>
          )}
        </div>
        {hash && (
          <p className="queue__run tnum" title={`output_hash ${hash}`}>
            Run {first!.run_id.slice(0, 8)} · output {hash.slice(0, 8)}…{hash.slice(-4)}
          </p>
        )}
        <div className="seg" role="group" aria-label="Filter by priority">
          {FILTERS.map((f) => (
            <button key={f.label} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
              {f.label}
              {first && f.id && (
                <span className="seg__n tnum">
                  {f.id.split(',').reduce((n, p) => n + (first.totals.by_priority[p as Priority] ?? 0), 0)}
                </span>
              )}
            </button>
          ))}
        </div>
        <QueueBody
          loading={ds.isPending || list.isPending}
          error={ds.error ?? list.error}
          retry={() => (ds.isError ? ds.refetch() : list.refetch())}
          noDataset={ds.isSuccess && !ds.data}
          notRun={!!ds.data && !ds.data.current_run_id}
          incidents={incidents}
          currentId={currentId}
          stale={list.isPlaceholderData || (list.isFetching && !list.isFetchingNextPage)}
        />
        {list.hasNextPage && (
          <button type="button" className="queue__more" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
            {list.isFetchingNextPage ? 'Loading…' : `Show more (${incidents.length} of ${first?.totals.incidents})`}
          </button>
        )}
        <p className="queue__keys">
          <kbd>j</kbd> <kbd>k</kbd> to move through the queue
        </p>
      </nav>

      <main className="detail" id="incident">
        <Link to="/console" className="detail__back">
          <ArrowLeft size={14} aria-hidden /> Queue
        </Link>
        {currentId ? (
          <IncidentDetail key={currentId} id={currentId} thresholds={first?.thresholds} />
        ) : list.isSuccess ? (
          <div className="panel detail__missing">
            <h2>Nothing to show</h2>
            <p>No incident matches this filter.</p>
          </div>
        ) : null}
      </main>
    </div>
  )
}

function QueueBody({
  loading,
  error,
  retry,
  noDataset,
  notRun,
  incidents,
  currentId,
  stale,
}: {
  loading: boolean
  error: Error | null
  retry: () => void
  noDataset: boolean
  notRun: boolean
  incidents: Schemas['IncidentSummary'][]
  currentId?: string
  stale: boolean
}) {
  if (error) return <PanelError title="Could not load the queue" error={error} retry={retry} inline />
  if (noDataset)
    return (
      <p className="queue__empty">
        No dataset yet. <Link to="/console/runs">Simulate one on the Runs page</Link>.
      </p>
    )
  if (notRun)
    return (
      <p className="queue__empty">
        This dataset has not been correlated. <Link to="/console/runs">Start a run</Link>.
      </p>
    )
  if (loading) return <Skeleton rows={10} />
  if (incidents.length === 0) return <p className="queue__empty">No incidents at this priority. Try All.</p>
  return (
    <ol className={`queue__list ${stale ? 'is-stale' : ''}`}>
      {incidents.map((inc) => {
        const on = inc.incident_id === currentId
        const pri = inc.priority as Priority
        return (
          <li key={inc.incident_id}>
            <Link to={`/console/${inc.incident_id}`} className={`qrow ${on ? 'is-on' : ''}`} aria-current={on ? 'page' : undefined}>
              {on && <motion.span layoutId="qrow-active" className="qrow__bg" transition={{ duration: 0.25, ease: EASE_OUT }} />}
              <span className="qrow__top">
                <SeverityChip severity={severityOf(pri)} priority={pri} compact />
                <span className="qrow__id tnum">{inc.incident_id}</span>
                <span className="qrow__risk tnum">{inc.risk.toFixed(2)}</span>
              </span>
              <span className="qrow__title">{inc.headline}</span>
              <span className="qrow__foot">
                <StageBar reached={inc.max_stage + 1} severity={severityOf(pri)} />
                <span className="tnum">{inc.alert_count} alerts</span>
                {inc.status !== 'open' && <span className={`status-pill status-pill--${inc.status}`}>{inc.status.replace('_', ' ')}</span>}
                {inc.assignee && <span className="qrow__assignee">{inc.assignee}</span>}
                {inc.cohesion === 'fragile' && <CohesionBadge cohesion="fragile" compact />}
                {inc.has_case && <span className="qrow__case">Clock running</span>}
              </span>
            </Link>
          </li>
        )
      })}
    </ol>
  )
}
