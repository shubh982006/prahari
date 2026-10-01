import { Gauge } from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { useEvaluate } from '../../api/mutations'
import { useActiveDataset, useEvaluation } from '../../api/queries'
import { SeverityChip } from '../../components/SeverityChip'
import { PanelError, Skeleton } from '../../components/Status'
import { severityOf, type Priority } from '../../lib/score'
import { useIsLead } from '../roles'

const METRICS: { key: string; label: string; fmt?: (v: number) => string; hint: string }[] = [
  { key: 'scenario_recall', label: 'Scenario recall', hint: 'planted attacks found as one incident holding ≥ 70% of their alerts' },
  { key: 'precision_at_5', label: 'Precision at 5', hint: 'share of the top five incidents that are real attacks' },
  { key: 'pairwise_precision', label: 'Pairwise precision', hint: 'alert pairs grouped together that truly belong together' },
  { key: 'pairwise_recall', label: 'Pairwise recall', hint: 'alert pairs that belong together and were grouped' },
  { key: 'mean_purity', label: 'Mean purity', hint: 'of incidents holding scenario alerts' },
  { key: 'cohesion_accuracy', label: 'Fragile flag accuracy', hint: 'fragile incidents that really spanned two truth groups' },
  { key: 'noise_in_top10', label: 'Noise in top 10', hint: 'top-ten incidents dominated by background alerts' },
  { key: 'compression_ratio', label: 'Compression', fmt: (v) => `${v.toFixed(1)}×`, hint: 'alerts in per incident out' },
  { key: 'triage_time_reduction', label: 'Time to first attack, reduced by', fmt: (v) => `${Math.round(v * 100)}%`, hint: 'against the baseline below' },
  { key: 'correlate_ms', label: 'Correlation time', fmt: (v) => `${v} ms`, hint: 'engine, this run' },
]

export default function Evaluation() {
  const ds = useActiveDataset()
  const ev = useEvaluation(ds.data?.dataset_id)
  const evaluate = useEvaluate()
  const lead = useIsLead()
  const runId = ds.data?.current_run_id
  const noTruth = ds.data && !ds.data.has_truth
  const missing = ev.error instanceof ApiError && ev.error.status === 404

  return (
    <div className="page">
      <header className="page__head page__head--row">
        <div>
          <h1>Evaluation</h1>
          <p className="panel__lede">The current run scored against the planted ground truth, which the engine never reads.</p>
        </div>
        <button
          type="button"
          className="btn btn--primary"
          disabled={!lead || !runId || noTruth || evaluate.isPending}
          onClick={() => runId && evaluate.mutate(runId)}
          title={noTruth ? 'Ingested datasets have no ground truth' : lead ? undefined : 'Only a lead can run an evaluation'}
        >
          <Gauge size={16} weight="bold" aria-hidden />
          <span>{evaluate.isPending ? 'Scoring…' : 'Score the current run'}</span>
        </button>
      </header>

      {noTruth ? (
        <p className="panel">This dataset was ingested, so there is no truth to score against.</p>
      ) : ev.isPending ? (
        <Skeleton rows={10} />
      ) : missing ? (
        <p className="panel">No evaluation for this dataset yet. Score the current run to produce one.</p>
      ) : ev.isError ? (
        <PanelError title="Could not load the evaluation" error={ev.error} retry={() => ev.refetch()} />
      ) : (
        <>
          <section className="panel">
            <p className="panel__lede">
              Run <span className="tnum">{ev.data.run_id.slice(0, 8)}</span> scored {new Date(ev.data.created_at).toLocaleString('en-IN')}.
              Baseline: {ev.data.baseline}.
            </p>
            <dl className="metrics">
              {METRICS.filter((m) => (ev.data.metrics as Record<string, number | undefined>)[m.key] !== undefined).map((m) => {
                const v = (ev.data.metrics as Record<string, number>)[m.key]
                return (
                  <div key={m.key}>
                    <dt>{m.label}</dt>
                    <dd className="tnum">{m.fmt ? m.fmt(v) : v.toFixed(2)}</dd>
                    <p>{m.hint}</p>
                  </div>
                )
              })}
            </dl>
          </section>
          <section className="panel">
            <h2 className="panel__title">Planted scenarios</h2>
            <div className="table-wrap">
              <table className="alerts">
                <thead>
                  <tr>
                    <th scope="col">Scenario</th>
                    <th scope="col">Detected</th>
                    <th scope="col">Coverage</th>
                    <th scope="col">Rank</th>
                    <th scope="col">Priority (expected)</th>
                    <th scope="col">Incident or miss reason</th>
                  </tr>
                </thead>
                <tbody>
                  {ev.data.scenarios.map((s) => (
                    <tr key={s.scenario}>
                      <td>
                        <strong>{s.scenario}</strong> {s.name}
                      </td>
                      <td>{s.detected ? 'yes' : 'no'}</td>
                      <td className="tnum">{s.coverage.toFixed(2)}</td>
                      <td className="tnum">{s.rank ?? '–'}</td>
                      <td>
                        {s.actual_priority ? (
                          <SeverityChip severity={severityOf(s.actual_priority as Priority)} priority={s.actual_priority as Priority} compact />
                        ) : (
                          '–'
                        )}{' '}
                        <span className="muted">({s.expected_priority})</span>
                      </td>
                      <td>{s.incident_id ? <Link to={`/console/${s.incident_id}`}>{s.incident_id}</Link> : s.miss_reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
