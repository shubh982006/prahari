import { Play, Plus, Stop } from '@phosphor-icons/react'
import { useState, type FormEvent } from 'react'
import type { Schemas } from '../../api/client'
import { useLive, useRunStream } from '../../api/live'
import { useCancelRun, useSimulate, useStartRun } from '../../api/mutations'
import { chooseDataset, useActiveDataset, useReceipt, useRun, useRuns } from '../../api/queries'
import { PanelError, Skeleton } from '../../components/Status'
import { useIsLead } from '../roles'

const STAGES = ['load', 'filter', 'entities', 'link', 'launder', 'group', 'shape', 'cohesion', 'score', 'compliance', 'commit']

export default function Runs() {
  const ds = useActiveDataset()
  const dsId = ds.data?.dataset_id
  const runs = useRuns(dsId)
  const live = useLive((s) => s.runningRuns)
  const [started, setFollow] = useState<string | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const list = runs.data?.data ?? []
  // Follow the run this user started; otherwise any run in flight, wherever it came from.
  const inFlight = list.find((r) => r.status === 'running' || r.status === 'queued')?.run_id
  const follow = started ?? live[live.length - 1] ?? inFlight ?? null

  const current = list.find((r) => r.is_current)

  return (
    <div className="page">
      <header className="page__head">
        <h1>Runs</h1>
        <p className="panel__lede">
          Every correlation is a pure function of the dataset and the configuration. Start one, watch each engine stage report
          as it finishes, and compare the receipts.
        </p>
      </header>

      <div className="grid-2">
        <StartRun datasetId={dsId} onFollow={setFollow} />
        {follow ? <RunProgressPanel runId={follow} /> : <Simulate />}
      </div>
      {follow && <Simulate />}

      <section className="panel">
        <h2 className="panel__title">History {ds.data && <span className="panel__count tnum">{ds.data.dataset_id}</span>}</h2>
        {runs.isPending ? (
          <Skeleton rows={5} />
        ) : runs.isError ? (
          <PanelError title="Could not load runs" error={runs.error} retry={() => runs.refetch()} inline />
        ) : list.length === 0 ? (
          <p className="panel__lede">No runs on this dataset yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="alerts">
              <thead>
                <tr>
                  <th scope="col">Run</th>
                  <th scope="col">Status</th>
                  <th scope="col">By</th>
                  <th scope="col">Started</th>
                  <th scope="col">Duration</th>
                  <th scope="col">Incidents</th>
                  <th scope="col">P1 / P2</th>
                </tr>
              </thead>
              <tbody>
                {list.map((r) => (
                  <tr key={r.run_id} onClick={() => setOpen(open === r.run_id ? null : r.run_id)} className={open === r.run_id ? 'is-hl' : ''}>
                    <td className="tnum">
                      {r.run_id.slice(0, 8)} {r.is_current && <span className="status-pill status-pill--current">current</span>}
                    </td>
                    <td>
                      <span className={`status-pill status-pill--${r.status}`}>{r.status}</span>
                    </td>
                    <td>{r.requested_by}</td>
                    <td className="tnum">{new Date(r.started_at ?? r.created_at).toLocaleString('en-IN')}</td>
                    <td className="tnum">{r.summary ? `${r.summary.duration_ms} ms` : '–'}</td>
                    <td className="tnum">{r.summary?.incidents ?? '–'}</td>
                    <td className="tnum">{r.summary ? `${r.summary.by_priority.P1 ?? 0} / ${r.summary.by_priority.P2 ?? 0}` : '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(open ?? current?.run_id) && <RunDetail runId={(open ?? current?.run_id)!} />}
      </section>
    </div>
  )
}

function StartRun({ datasetId, onFollow }: { datasetId?: string; onFollow: (id: string) => void }) {
  const lead = useIsLead()
  const start = useStartRun(onFollow)
  const [linkWindow, setLinkWindow] = useState('2h')
  const [laundering, setLaundering] = useState(true)
  const [p1, setP1] = useState(5)
  const [p2, setP2] = useState(10)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!datasetId) return
    const body: Schemas['RunCreate'] = {
      dataset_id: datasetId,
      overrides: { link_window: linkWindow, laundering_pass: laundering, capacity: { p1_per_shift: p1, p2_per_shift: p2 } },
    }
    start.mutate(body, { onSuccess: (r) => onFollow(r.run_id) })
  }
  return (
    <form className="panel form-grid" onSubmit={submit} aria-label="Start a correlation run">
      <h2 className="panel__title">Correlate this dataset</h2>
      <label>
        <span>Link window</span>
        <select value={linkWindow} onChange={(e) => setLinkWindow(e.target.value)} disabled={!lead}>
          {['1h', '2h', '3h', '6h'].map((w) => (
            <option key={w}>{w}</option>
          ))}
        </select>
      </label>
      <label>
        <span>P1 per shift</span>
        <input type="number" min={1} max={50} value={p1} onChange={(e) => setP1(Number(e.target.value))} disabled={!lead} />
      </label>
      <label>
        <span>P2 per shift</span>
        <input type="number" min={1} max={100} value={p2} onChange={(e) => setP2(Number(e.target.value))} disabled={!lead} />
      </label>
      <label className="toggle">
        <input type="checkbox" checked={laundering} onChange={(e) => setLaundering(e.target.checked)} disabled={!lead} /> Laundering pass
      </label>
      <button type="submit" className="btn btn--primary" disabled={!lead || !datasetId || start.isPending} title={lead ? undefined : 'Only a lead can start runs'}>
        <Play size={16} weight="fill" aria-hidden />
        <span>{start.isPending ? 'Queuing…' : 'Start run'}</span>
      </button>
    </form>
  )
}

function RunProgressPanel({ runId }: { runId: string }) {
  const p = useRunStream(runId)
  const cancel = useCancelRun()
  const lead = useIsLead()
  const max = Math.max(1, ...p.stages.map((s) => s.elapsed_ms))
  const running = !p.done && (p.status === 'running' || p.status === 'queued')
  return (
    <section className="panel" aria-live="polite">
      <div className="panel__bar">
        <h2 className="panel__title">
          Run <span className="tnum">{runId.slice(0, 8)}</span>{' '}
          <span className={`status-pill status-pill--${p.error ? 'failed' : p.status}`}>{p.error ? 'failed' : p.status}</span>
        </h2>
        {running && lead && (
          <button type="button" className="mini-btn" onClick={() => cancel.mutate(runId)} disabled={cancel.isPending}>
            <Stop size={14} weight="fill" aria-hidden /> Cancel
          </button>
        )}
      </div>
      <ol className="stage-steps">
        {STAGES.map((st) => {
          const s = p.stages.find((x) => x.stage === st)
          return (
            <li key={st} className={s ? 'is-done' : ''}>
              <span>{st}</span>
              <span className="stage-steps__bar">
                <span style={{ transform: `scaleX(${s ? Math.max(0.03, s.elapsed_ms / max) : 0})` }} />
              </span>
              <span className="tnum">{s ? `${s.count.toLocaleString('en-IN')} · ${s.elapsed_ms} ms` : '–'}</span>
            </li>
          )
        })}
      </ol>
      {p.error && <p className="form-error">{p.error}</p>}
    </section>
  )
}

function RunDetail({ runId }: { runId: string }) {
  const run = useRun(runId)
  const receipt = useReceipt(run.data?.status === 'succeeded' ? runId : null)
  if (run.isPending) return <Skeleton rows={4} />
  if (run.isError) return <PanelError title="Could not load the run" error={run.error} retry={() => run.refetch()} inline />
  const s = run.data.summary
  return (
    <div className="run-detail">
      {s && (
        <dl className="kv kv--wide">
          <div>
            <dt>Alerts in</dt>
            <dd className="tnum">{s.alerts_in.toLocaleString('en-IN')}</dd>
          </div>
          <div>
            <dt>Incidents</dt>
            <dd className="tnum">
              {s.incidents} · compression {s.compression_ratio?.toFixed(1)}×
            </dd>
          </div>
          <div>
            <dt>By priority</dt>
            <dd className="tnum">{Object.entries(s.by_priority).map(([k, v]) => `${k} ${v}`).join(' · ')}</dd>
          </div>
          <div>
            <dt>By cohesion</dt>
            <dd className="tnum">{Object.entries(s.by_cohesion ?? {}).map(([k, v]) => `${k} ${v}`).join(' · ')}</dd>
          </div>
          <div>
            <dt>Stop-listed</dt>
            <dd className="tnum">{s.stoplisted_entities?.join(', ') || 'none'}</dd>
          </div>
          <div>
            <dt>Cases opened</dt>
            <dd className="tnum">{s.cases_opened ?? 0}</dd>
          </div>
        </dl>
      )}
      {run.data.error && <p className="form-error">{run.data.error}</p>}
      {receipt.data && (
        <dl className="kv receipt-kv">
          {(['input_hash', 'config_hash', 'output_hash'] as const).map((k) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd className="tnum">{receipt.data[k].replace('sha256:', '')}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}

const SCENARIOS = ['A', 'B', 'C', 'D', 'E', 'F'] as const

function Simulate() {
  const lead = useIsLead()
  const sim = useSimulate()
  const [seed, setSeed] = useState(7)
  const [hours, setHours] = useState(24)
  const [users, setUsers] = useState(60)
  const [noise, setNoise] = useState<Schemas['SimulationRequest']['noise_level']>('normal')
  const [scen, setScen] = useState<string[]>([...SCENARIOS])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    sim.mutate(
      { seed, hours, users, noise_level: noise, scenarios: scen as Schemas['SimulationRequest']['scenarios'] },
      { onSuccess: (d) => chooseDataset(d.dataset_id) },
    )
  }
  return (
    <form className="panel form-grid" onSubmit={submit} aria-label="Simulate a dataset">
      <h2 className="panel__title">Simulate a new dataset</h2>
      <label>
        <span>Seed</span>
        <input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} disabled={!lead} />
      </label>
      <label>
        <span>Hours</span>
        <input type="number" min={1} max={168} value={hours} onChange={(e) => setHours(Number(e.target.value))} disabled={!lead} />
      </label>
      <label>
        <span>Users</span>
        <input type="number" min={10} max={2000} value={users} onChange={(e) => setUsers(Number(e.target.value))} disabled={!lead} />
      </label>
      <label>
        <span>Noise</span>
        <select value={noise} onChange={(e) => setNoise(e.target.value as typeof noise)} disabled={!lead}>
          {['low', 'normal', 'high'].map((n) => (
            <option key={n}>{n}</option>
          ))}
        </select>
      </label>
      <fieldset className="checks">
        <legend>Planted scenarios</legend>
        {SCENARIOS.map((s) => (
          <label key={s} className="toggle">
            <input
              type="checkbox"
              checked={scen.includes(s)}
              disabled={!lead}
              onChange={(e) => setScen(e.target.checked ? [...scen, s].sort() : scen.filter((x) => x !== s))}
            />
            {s}
          </label>
        ))}
      </fieldset>
      <button type="submit" className="btn btn--secondary" disabled={!lead || sim.isPending || scen.length === 0} title={lead ? undefined : 'Only a lead can simulate'}>
        <Plus size={16} aria-hidden />
        <span>{sim.isPending ? 'Generating…' : 'Generate and switch to it'}</span>
      </button>
    </form>
  )
}
