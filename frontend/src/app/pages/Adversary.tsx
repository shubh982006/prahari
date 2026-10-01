import { Play } from '@phosphor-icons/react'
import { useMemo, useState, type FormEvent } from 'react'
import type { Schemas } from '../../api/client'
import { useCampaignStream } from '../../api/live'
import { useCreateCampaign } from '../../api/mutations'
import { useActiveDataset, useCampaign, useCampaigns, useCurve } from '../../api/queries'
import { PanelError, Skeleton } from '../../components/Status'
import { ADVERSARY } from '../../data/seed'
import { EvasionChart, type StrategySeries } from '../../landing/EvasionChart'
import { useIsLead } from '../roles'

const STRATEGIES: { key: Schemas['Strategy']; name: string }[] = [
  { key: 'temporal_dilation', name: 'Temporal dilation' },
  { key: 'supernode_laundering', name: 'Supernode laundering' },
  { key: 'entity_rotation', name: 'Entity rotation' },
  { key: 'noise_flood', name: 'Noise flood' },
]
const BUDGETS = [0, 0.25, 0.5, 0.75, 1]

export default function Adversary() {
  const ds = useActiveDataset()
  const dsId = ds.data?.dataset_id
  const curve = useCurve(dsId)
  const campaigns = useCampaigns(dsId)
  const [open, setOpen] = useState<string | null>(null)
  const [following, setFollowing] = useState<string | null>(null)

  const series = useMemo<StrategySeries[]>(() => {
    if (!curve.data) return []
    return STRATEGIES.filter((s) => curve.data.series.some((x) => x.strategy === s.key)).map((s) => {
      const on = curve.data.series.find((x) => x.strategy === s.key && x.mitigated)
      const off = curve.data.series.find((x) => x.strategy === s.key && !x.mitigated)
      const lead = on ?? off!
      return {
        key: s.key,
        name: s.name,
        note: ADVERSARY.find((a) => a.key === s.key)?.note,
        floorAt: lead.crosses_floor_at == null ? null : String(lead.crosses_floor_at),
        on: on?.values ?? off?.values ?? [],
        off: off?.values ?? [],
      }
    })
  }, [curve.data])

  return (
    <div className="page">
      <header className="page__head">
        <h1>Adversary bench</h1>
        <p className="panel__lede">
          An attacker who knows how Prahari links alerts spends a budget β to hide. Each point is a full correlation run on a
          mutated copy of this dataset, scored against its planted truth. The curve updates the moment a campaign finishes.
        </p>
      </header>

      <section className="panel">
        {curve.isPending ? (
          <Skeleton rows={8} />
        ) : curve.isError ? (
          <PanelError title="Could not load the curve" error={curve.error} retry={() => curve.refetch()} inline />
        ) : series.length === 0 ? (
          <p className="panel__lede">No finished campaigns on this dataset yet. Launch one below.</p>
        ) : (
          <div className="on-dark-chart">
            <EvasionChart data={series} betas={curve.data.budgets} floor={curve.data.floor} caption={curve.data.note ?? ''} />
          </div>
        )}
      </section>

      <div className="grid-2">
        <Launcher datasetId={dsId} onLaunched={setFollowing} />
        {following && <CampaignProgress id={following} />}
      </div>

      <section className="panel">
        <h2 className="panel__title">Campaigns</h2>
        {campaigns.isPending ? (
          <Skeleton rows={5} />
        ) : campaigns.isError ? (
          <PanelError title="Could not load campaigns" error={campaigns.error} retry={() => campaigns.refetch()} inline />
        ) : (
          <div className="table-wrap">
            <table className="alerts">
              <thead>
                <tr>
                  <th scope="col">Campaign</th>
                  <th scope="col">Strategy</th>
                  <th scope="col">Laundering pass</th>
                  <th scope="col">Status</th>
                  <th scope="col">By</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {campaigns.data.data.map((c) => (
                  <tr key={c.campaign_id} onClick={() => setOpen(open === c.campaign_id ? null : c.campaign_id)} className={open === c.campaign_id ? 'is-hl' : ''}>
                    <td className="tnum">{c.campaign_id}</td>
                    <td>{STRATEGIES.find((s) => s.key === c.strategy)?.name ?? c.strategy}</td>
                    <td>{c.mitigated ? 'on' : 'off'}</td>
                    <td>
                      <span className={`status-pill status-pill--${c.status}`}>{c.status}</span>
                    </td>
                    <td>{c.created_by}</td>
                    <td className="tnum">{new Date(c.created_at).toLocaleString('en-IN')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {open && <CampaignResults id={open} />}
      </section>
    </div>
  )
}

function Launcher({ datasetId, onLaunched }: { datasetId?: string; onLaunched: (id: string) => void }) {
  const lead = useIsLead()
  const create = useCreateCampaign()
  const [strategy, setStrategy] = useState<Schemas['Strategy']>('supernode_laundering')
  const [mitigated, setMitigated] = useState(true)
  const [seed, setSeed] = useState(42)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!datasetId) return
    create.mutate({ base_dataset: datasetId, strategy, mitigated, budgets: BUDGETS, seed }, { onSuccess: (c) => onLaunched(c.campaign_id) })
  }
  return (
    <form className="panel form-grid" onSubmit={submit} aria-label="Launch a campaign">
      <h2 className="panel__title">Launch a campaign</h2>
      <label>
        <span>Strategy</span>
        <select value={strategy} onChange={(e) => setStrategy(e.target.value as Schemas['Strategy'])} disabled={!lead}>
          {STRATEGIES.map((s) => (
            <option key={s.key} value={s.key}>
              {s.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Seed</span>
        <input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} disabled={!lead} />
      </label>
      <label className="toggle">
        <input type="checkbox" checked={mitigated} onChange={(e) => setMitigated(e.target.checked)} disabled={!lead} /> Laundering pass on
      </label>
      <p className="form-grid__note tnum">Budgets {BUDGETS.join(', ')}. Six campaigns a minute per user.</p>
      <button type="submit" className="btn btn--primary" disabled={!lead || !datasetId || create.isPending} title={lead ? undefined : 'Only a lead can launch campaigns'}>
        <Play size={16} weight="fill" aria-hidden />
        <span>{create.isPending ? 'Queuing…' : 'Run campaign'}</span>
      </button>
    </form>
  )
}

function CampaignProgress({ id }: { id: string }) {
  const p = useCampaignStream(id)
  return (
    <section className="panel" aria-live="polite">
      <h2 className="panel__title">
        Live: <span className="tnum">{id}</span>
      </h2>
      <ol className="budget-steps">
        {BUDGETS.map((b) => {
          const fin = p.finished.find((f) => f.budget === b)
          const started = p.started.includes(b)
          return (
            <li key={b} className={fin ? 'is-done' : started ? 'is-running' : ''}>
              <span className="tnum">β {b}</span>
              <span className="budget-steps__bar">
                <span style={{ transform: `scaleX(${fin ? fin.scenario_recall : 0})` }} />
              </span>
              <span className="tnum">{fin ? `recall ${fin.scenario_recall.toFixed(2)}` : started ? 'running…' : 'queued'}</span>
            </li>
          )
        })}
      </ol>
      {p.error && <p className="form-error">{p.error}</p>}
      {p.done && !p.error && <p className="panel__lede">Finished. The curve above now includes it.</p>}
    </section>
  )
}

function CampaignResults({ id }: { id: string }) {
  const c = useCampaign(id)
  if (c.isPending) return <Skeleton rows={4} />
  if (c.isError) return <PanelError title="Could not load results" error={c.error} retry={() => c.refetch()} inline />
  return (
    <div className="table-wrap nested">
      <table className="alerts">
        <thead>
          <tr>
            <th scope="col">β</th>
            <th scope="col">Recall</th>
            <th scope="col">Detected</th>
            <th scope="col">Incidents</th>
            <th scope="col">Top rank</th>
            <th scope="col">Variant dataset</th>
          </tr>
        </thead>
        <tbody>
          {c.data.results.map((r) => (
            <tr key={r.budget}>
              <td className="tnum">{r.budget}</td>
              <td className="tnum">{r.scenario_recall.toFixed(2)}</td>
              <td>{r.detected ? 'yes' : 'no'}</td>
              <td className="tnum">{r.incidents}</td>
              <td className="tnum">{r.top_rank ?? '–'}</td>
              <td className="tnum">{r.variant_dataset}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {c.data.error && <p className="form-error">{c.data.error}</p>}
    </div>
  )
}
