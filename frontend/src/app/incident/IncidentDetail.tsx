import { ArrowClockwise, Check, Info, X } from '@phosphor-icons/react'
import { AnimatePresence, motion } from 'framer-motion'
import { useCallback, useMemo, useRef, useState } from 'react'
import { caseClocks, istTime, stageName, toCfRows, toTimeline } from '../../api/adapt'
import type { Schemas } from '../../api/client'
import { useRegenerateNarrative } from '../../api/mutations'
import {
  useCase,
  useCohesion,
  useCounterfactuals,
  useGraph,
  useIncident,
  useIncidentAlerts,
  useNarrative,
  useTimeline,
} from '../../api/queries'
import { AttackGraph } from '../../components/AttackGraph'
import { CitationChip } from '../../components/CitationChip'
import { CohesionBadge } from '../../components/CohesionBadge'
import { ComplianceClock } from '../../components/ComplianceClock'
import { CounterfactualList } from '../../components/CounterfactualList'
import { KillChainTimeline } from '../../components/KillChainTimeline'
import { RingGauge } from '../../components/RingGauge'
import { SeverityChip } from '../../components/SeverityChip'
import { PanelError, Skeleton } from '../../components/Status'
import { StageBar } from '../../components/StageBar'
import { TechniqueTag } from '../../components/TechniqueTag'
import { useNow } from '../../lib/clock'
import { graphFromApi } from '../../lib/graph'
import { EASE_OUT } from '../../lib/motion'
import { FACTOR_NAMES, severityOf, type FactorKey, type Priority } from '../../lib/score'
import { IncidentActivity, SplitAction, TriageBar, WhatIfCriticality } from './Actions'

const TABS = [
  { id: 'chain', label: 'Attack chain' },
  { id: 'risk', label: 'Risk' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'activity', label: 'Activity' },
] as const
type Tab = (typeof TABS)[number]['id']

interface Props {
  id: string
  thresholds?: Schemas['Bands']
}

export function IncidentDetail({ id, thresholds }: Props) {
  const inc = useIncident(id)
  const [whatIf, setWhatIf] = useState('')
  const onWhatIf = useCallback((v: string) => setWhatIf(v), [])
  const cfs = useCounterfactuals(id, whatIf)
  const cohesion = useCohesion(id)
  const alerts = useIncidentAlerts(id)
  const [tab, setTab] = useState<Tab>('chain')
  const [applied, setApplied] = useState<string | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [cite, setCite] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [splitOpen, setSplitOpen] = useState(false)
  const tabsRef = useRef<HTMLDivElement>(null)

  const rows = useMemo(() => (cfs.data ? toCfRows(cfs.data) : []), [cfs.data])
  const techniques = useMemo(
    () => [...new Set((alerts.data?.data ?? []).map((a) => a.technique_id).filter(Boolean) as string[])].sort(),
    [alerts.data],
  )

  if (inc.isPending) return <DetailSkeleton />
  if (inc.isError) return <PanelError title="Could not load this incident" error={inc.error} retry={() => inc.refetch()} />

  const d = inc.data
  const active = rows.find((r) => r.id === (preview ?? applied) && r.risk !== undefined)
  const base = whatIf && cfs.data ? cfs.data.current : { risk: d.risk, priority: d.priority }
  const score = active?.risk ?? base.risk
  const pri = (active?.priority ?? base.priority) as Priority
  const closes = !!rows.find((r) => r.id === applied)?.closesCase
  const highlight = cite ?? selected
  const bands = cfs.data?.current.thresholds ?? thresholds

  const focusAlert = (alertId: string) => {
    setSelected(alertId)
    setTab('chain')
    tabsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <article className="incident" aria-labelledby="incident-title">
      <header className="incident__head">
        <div className="incident__meta">
          <span className="tnum incident__id">{d.incident_id}</span>
          <SeverityChip severity={severityOf(d.priority as Priority)} priority={d.priority as Priority} />
          <CohesionBadge
            cohesion={d.cohesion}
            onClick={cohesion.data?.split_preview ? () => setSplitOpen((o) => !o) : undefined}
            expanded={cohesion.data?.split_preview ? splitOpen : undefined}
          />
          <span className="incident__stage">
            <StageBar reached={d.max_stage + 1} severity={severityOf(d.priority as Priority)} />
            <span>{stageName(d.max_stage)}</span>
          </span>
          <span className="tnum incident__span">
            {d.alert_count} alerts · {istTime(Date.parse(d.first_seen), false)}–{istTime(Date.parse(d.last_seen), false)} IST
          </span>
        </div>
        <h1 id="incident-title">{d.headline}</h1>
        <TriageBar incident={d} />
        <div className="incident__tags">
          {techniques.map((t) => (
            <TechniqueTag key={t} id={t} />
          ))}
        </div>
      </header>

      <AnimatePresence initial={false}>
        {splitOpen && cohesion.data?.split_preview && (
          <motion.section
            className="panel split-preview"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8, transition: { duration: 0.15 } }}
            transition={{ duration: 0.25, ease: EASE_OUT }}
            aria-label="Split preview"
          >
            <p className="split-preview__why">{cohesion.data.reason}</p>
            <div className="split-preview__halves">
              {[cohesion.data.split_preview.left, cohesion.data.split_preview.right].map((h) => (
                <div key={h.headline + h.alerts}>
                  <span className="tnum">
                    {h.alerts} alerts · reaches {stageName(h.max_stage).toLowerCase()}
                    {h.est_priority && ` · est. ${h.est_priority} at ${h.est_risk?.toFixed(2)}`}
                  </span>
                  <strong>{h.headline}</strong>
                </div>
              ))}
            </div>
            <p className="split-preview__note">
              Splitting writes both halves to a new run and records the decision in the audit chain.
            </p>
            <SplitAction incidentId={id} cohesion={cohesion.data} />
          </motion.section>
        )}
      </AnimatePresence>

      <div className="incident__top">
        <section className="panel risk-panel" aria-label="Risk">
          <RingGauge value={score} severity={severityOf(pri)} size={176} label={`Risk ${score}`}>
            <span className="risk-panel__value tnum">{score.toFixed(2)}</span>
            <SeverityChip severity={severityOf(pri)} priority={pri} compact />
          </RingGauge>
          <div className="risk-panel__side">
            <p className="risk-panel__state">
              {active ? (
                <>
                  <span className="risk-panel__whatif">{preview ? 'Previewing' : 'What-if applied'}</span> {active.label}
                </>
              ) : whatIf ? (
                <>
                  <span className="risk-panel__whatif">What-if</span> {whatIf.replace(':', ' at criticality ')}
                </>
              ) : (
                'Score as computed by the engine'
              )}
            </p>
            <Factors breakdown={d.breakdown} />
            {d.breakdown.overrides.map((o) => (
              <p key={o} className="risk-panel__override">
                <Info size={14} weight="bold" aria-hidden /> {o}
              </p>
            ))}
            {bands && (
              <p className="risk-panel__bands tnum">
                Bands this run: P1 ≥ {bands.P1.toFixed(2)} · P2 ≥ {bands.P2.toFixed(2)} · P3 ≥ {bands.P3.toFixed(2)}
              </p>
            )}
          </div>
        </section>
        <CompliancePanel incident={d} closes={closes} />
      </div>

      <div className="incident__body">
        <div className="incident__main" ref={tabsRef}>
          <div className="tabs" role="tablist" aria-label="Incident views">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                id={`tab-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`panel-${t.id}`}
                className="tabs__tab"
                onClick={() => setTab(t.id)}
              >
                {tab === t.id && <motion.span layoutId="tab-underline" className="tabs__line" transition={{ duration: 0.25, ease: EASE_OUT }} />}
                {t.label}
              </button>
            ))}
          </div>
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={tab}
              role="tabpanel"
              id={`panel-${tab}`}
              aria-labelledby={`tab-${tab}`}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, transition: { duration: 0.12 } }}
              transition={{ duration: 0.2, ease: EASE_OUT }}
              className="tabpanel"
            >
              {tab === 'chain' && (
                <ChainPanels id={id} alerts={alerts.data?.data} highlight={highlight} onHover={setCite} onSelect={setSelected} />
              )}
              {tab === 'risk' && (
                <section className="panel">
                  <h2 className="panel__title">What would change the priority</h2>
                  <p className="panel__lede">
                    Hover to preview, press to apply. Each row is the engine's own recomputation; boundaries are solved in
                    closed form and marked unreachable when no value from 0 to 1 gets there.
                  </p>
                  <WhatIfCriticality assets={d.breakdown.top_assets ?? []} value={whatIf} onChange={onWhatIf} />
                  {cfs.isPending ? (
                    <Skeleton rows={5} />
                  ) : cfs.isError ? (
                    <PanelError title="Could not load counterfactuals" error={cfs.error} retry={() => cfs.refetch()} inline />
                  ) : (
                    <CounterfactualList rows={rows} applied={applied} onApply={setApplied} onPreview={setPreview} />
                  )}
                </section>
              )}
              {tab === 'alerts' && (
                <AlertsTable query={alerts} total={d.alert_count} highlight={highlight} onSelect={setSelected} />
              )}
              {tab === 'activity' && <IncidentActivity id={id} />}
            </motion.div>
          </AnimatePresence>
        </div>

        <Brief id={id} highlight={highlight} onHover={setCite} onSelect={focusAlert} />
      </div>
    </article>
  )
}

function ChainPanels({
  id,
  alerts,
  highlight,
  onHover,
  onSelect,
}: {
  id: string
  alerts?: Schemas['IncidentAlert'][]
  highlight: string | null
  onHover: (id: string | null) => void
  onSelect: (id: string) => void
}) {
  const tl = useTimeline(id)
  const graph = useGraph(id)
  const timeline = useMemo(() => (tl.data && tl.data.points.length ? toTimeline(tl.data, alerts) : null), [tl.data, alerts])
  const gdata = useMemo(() => (graph.data ? graphFromApi(id, graph.data) : null), [id, graph.data])
  return (
    <>
      <section className="panel">
        <h2 className="panel__title">Kill-chain timeline</h2>
        {tl.isPending ? (
          <Skeleton rows={7} />
        ) : tl.isError ? (
          <PanelError title="Could not load the timeline" error={tl.error} retry={() => tl.refetch()} inline />
        ) : timeline ? (
          <KillChainTimeline
            alerts={timeline.alerts}
            clock={timeline.clock}
            highlight={highlight}
            onHover={onHover}
            onSelect={onSelect}
            label={`Kill-chain timeline for ${id}`}
          />
        ) : (
          <p className="panel__lede">No alerts on the timeline.</p>
        )}
      </section>
      <section className="panel">
        <h2 className="panel__title">Entity graph</h2>
        {graph.isPending ? (
          <Skeleton rows={6} />
        ) : graph.isError ? (
          <PanelError title="Could not load the graph" error={graph.error} retry={() => graph.refetch()} inline />
        ) : (
          gdata && <AttackGraph data={gdata} highlight={highlight} label={`Entity graph for ${id}`} />
        )}
      </section>
    </>
  )
}

function Factors({ breakdown }: { breakdown: Schemas['Breakdown'] }) {
  return (
    <dl className="factors">
      {(['C', 'S', 'A', 'Q'] as FactorKey[]).map((k) => (
        <div key={k}>
          <dt>
            {FACTOR_NAMES[k]} <span className="tnum">^{breakdown.weights[k]}</span>
          </dt>
          <dd>
            <span className="factors__bar" aria-hidden>
              <motion.span initial={{ scaleX: 0 }} animate={{ scaleX: breakdown[k] }} transition={{ duration: 0.5, ease: EASE_OUT }} />
            </span>
            <span className="tnum">{breakdown[k].toFixed(2)}</span>
          </dd>
        </div>
      ))}
    </dl>
  )
}

function CompliancePanel({ incident, closes }: { incident: Schemas['IncidentDetail']; closes: boolean }) {
  const kase = useCase(incident.case_id)
  const now = useNow()

  if (!incident.has_case || !incident.case_id) {
    const sensitive = (incident.breakdown.top_assets ?? []).filter((a) =>
      (a.data_classes ?? []).some((c) => c === 'pii' || c === 'financial'),
    )
    const conditions = [
      { ok: incident.priority === 'P1' || incident.priority === 'P2', text: `Priority P1 or P2 (is ${incident.priority})` },
      { ok: incident.max_stage >= 5, text: `Reaches collection or exfiltration (reached ${stageName(incident.max_stage).toLowerCase()})` },
      {
        ok: sensitive.length > 0,
        text: sensitive.length ? `Touches ${sensitive.map((a) => a.hostname).join(', ')}` : 'Touches an asset tagged pii or financial',
      },
    ]
    return (
      <section className="panel compliance-panel" aria-label="Compliance">
        <h2 className="panel__title">No regulatory clock running</h2>
        <ul className="trigger">
          {conditions.map((c) => (
            <li key={c.text} className={c.ok ? 'is-ok' : ''}>
              {c.ok ? <Check size={14} weight="bold" aria-label="met" /> : <X size={14} weight="bold" aria-label="not met" />}
              {c.text}
            </li>
          ))}
        </ul>
      </section>
    )
  }

  // Measure against the server's clock, not the laptop's.
  const skew = kase.data?.server_time ? Date.parse(kase.data.server_time) - kase.dataUpdatedAt : 0
  return (
    <section className={`panel compliance-panel ${closes ? 'is-closing' : ''}`} aria-label="Compliance clocks">
      <h2 className="panel__title">
        Compliance clocks <span className="panel__count tnum">{incident.case_id}</span>
      </h2>
      {closes && (
        <p className="compliance-panel__closes">
          <Info size={14} weight="bold" aria-hidden /> This what-if closes the case: the trigger would no longer hold.
        </p>
      )}
      {kase.isPending ? (
        <Skeleton rows={3} />
      ) : kase.isError ? (
        <PanelError title="Could not load the case" error={kase.error} retry={() => kase.refetch()} inline />
      ) : (
        <div className="compliance-panel__clocks">
          {caseClocks(kase.data).map(({ key, ...c }) => (
            <ComplianceClock key={key} {...c} now={now + skew} size={124} />
          ))}
        </div>
      )}
    </section>
  )
}

function Brief({
  id,
  highlight,
  onHover,
  onSelect,
}: {
  id: string
  highlight: string | null
  onHover: (id: string | null) => void
  onSelect: (id: string) => void
}) {
  const n = useNarrative(id)
  const regen = useRegenerateNarrative(id)
  const source =
    n.data?.source === 'llm' || n.data?.model
      ? `Written by ${n.data?.model ?? 'the narrator'} from computed facts and checked against citations.`
      : 'Deterministic template from computed facts. No language model was called.'
  const cited = (items: Schemas['CitedText'][]) =>
    items.map((s, i) => (
      <p key={i} className="brief__p">
        {s.text}{' '}
        {s.citations.map((c) => (
          <CitationChip key={c} id={c} active={highlight === c} onHover={onHover} onSelect={onSelect} />
        ))}
      </p>
    ))
  return (
    <aside className="panel brief" aria-labelledby="brief-title">
      <div className="brief__head">
        <h2 id="brief-title" className="panel__title">
          Shift brief
        </h2>
        <button type="button" className="mini-btn" onClick={() => regen.mutate()} disabled={regen.isPending} title="Bypass the cache and write the brief again">
          <ArrowClockwise size={14} className={regen.isPending ? 'spin' : undefined} aria-hidden />
          {regen.isPending ? 'Writing…' : 'Regenerate'}
        </button>
      </div>
      {n.isPending ? (
        <Skeleton rows={6} />
      ) : n.isError ? (
        <PanelError title="Could not load the brief" error={n.error} retry={() => n.refetch()} inline />
      ) : (
        <>
          <p className="brief__source">{source}</p>
          {cited(n.data.sentences)}
          {n.data.recommended_actions.length > 0 && (
            <>
              <h3 className="brief__sub">Recommended actions</h3>
              {cited(n.data.recommended_actions)}
            </>
          )}
        </>
      )}
    </aside>
  )
}

function AlertsTable({
  query,
  total,
  highlight,
  onSelect,
}: {
  query: ReturnType<typeof useIncidentAlerts>
  total: number
  highlight: string | null
  onSelect: (id: string) => void
}) {
  const rows = query.data?.data ?? []
  return (
    <section className="panel">
      <h2 className="panel__title">
        Alerts{' '}
        {query.data && (
          <span className="tnum panel__count">
            {rows.length} shown of {total}
          </span>
        )}
      </h2>
      {query.isPending ? (
        <Skeleton rows={8} />
      ) : query.isError ? (
        <PanelError title="Could not load alerts" error={query.error} retry={() => query.refetch()} inline />
      ) : (
        <div className="table-wrap">
          <table className="alerts">
            <thead>
              <tr>
                <th scope="col">Alert</th>
                <th scope="col">Time (IST)</th>
                <th scope="col">Severity</th>
                <th scope="col">Stage</th>
                <th scope="col">Rule</th>
                <th scope="col">Technique</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className={highlight === a.id ? 'is-hl' : ''} onClick={() => onSelect(a.id)}>
                  <td className="tnum">{a.id}</td>
                  <td className="tnum">{istTime(Date.parse(a.timestamp))}</td>
                  <td>
                    <SeverityChip severity={a.severity} />
                  </td>
                  <td>{a.stage == null ? 'Unmapped' : stageName(a.stage)}</td>
                  <td>
                    {a.rule_name}
                    {!a.on_chain && <span className="alerts__off"> off chain</span>}
                  </td>
                  <td>{a.technique_id && <TechniqueTag id={a.technique_id} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function DetailSkeleton() {
  return (
    <div className="incident">
      <div className="panel">
        <Skeleton rows={3} />
      </div>
      <div className="incident__top">
        <div className="panel">
          <Skeleton rows={6} />
        </div>
        <div className="panel">
          <Skeleton rows={6} />
        </div>
      </div>
    </div>
  )
}
