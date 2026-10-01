import { Trash } from '@phosphor-icons/react'
import { useMemo, useState } from 'react'
import type { Schemas } from '../../api/client'
import { useDeleteSuppression, usePutAsset } from '../../api/mutations'
import { useAssets, useRules, useSuppressions } from '../../api/queries'
import { PanelError, Skeleton } from '../../components/Status'
import { useIsLead } from '../roles'

const CLASSES: Schemas['DataClass'][] = ['pii', 'financial', 'credentials', 'source_code']

export default function Assets() {
  const [q, setQ] = useState('')
  const assets = useAssets()
  const rows = useMemo(
    () =>
      (assets.data?.data ?? [])
        .filter((a) => !q || a.hostname.includes(q.toLowerCase()) || a.role.includes(q.toLowerCase()))
        .sort((a, b) => b.criticality - a.criticality || a.hostname.localeCompare(b.hostname)),
    [assets.data, q],
  )
  return (
    <div className="page">
      <header className="page__head">
        <h1>Assets &amp; rules</h1>
        <p className="panel__lede">
          The asset register feeds the asset-impact factor and the compliance trigger. Rule precision is learned from analyst
          verdicts. Changes apply from the next run; counterfactuals update at once.
        </p>
      </header>

      <section className="panel">
        <div className="panel__bar">
          <h2 className="panel__title">
            Asset register <span className="panel__count tnum">{assets.data?.data.length}</span>
          </h2>
          <input className="search" placeholder="Filter by host or role" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter assets" />
        </div>
        {assets.isPending ? (
          <Skeleton rows={8} />
        ) : assets.isError ? (
          <PanelError title="Could not load assets" error={assets.error} retry={() => assets.refetch()} inline />
        ) : (
          <div className="table-wrap table-wrap--tall">
            <table className="alerts">
              <thead>
                <tr>
                  <th scope="col">Host</th>
                  <th scope="col">Role</th>
                  <th scope="col">Criticality</th>
                  <th scope="col">Data classes</th>
                  <th scope="col">Owner</th>
                  <th scope="col" aria-label="Save" />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <AssetRow key={a.hostname + a.updated_at} asset={a} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="grid-2 grid-2--wide-left">
        <Rules />
        <Suppressions />
      </div>
    </div>
  )
}

function AssetRow({ asset }: { asset: Schemas['Asset'] }) {
  const lead = useIsLead()
  const put = usePutAsset()
  const [crit, setCrit] = useState(asset.criticality)
  const [classes, setClasses] = useState<Schemas['DataClass'][]>(asset.data_classes)
  const dirty = crit !== asset.criticality || classes.slice().sort().join() !== asset.data_classes.slice().sort().join()
  return (
    <tr>
      <td className="tnum">{asset.hostname}</td>
      <td>{asset.role.replace(/_/g, ' ')}</td>
      <td>
        <select value={crit} onChange={(e) => setCrit(Number(e.target.value))} disabled={!lead} aria-label={`Criticality of ${asset.hostname}`}>
          {Array.from({ length: 10 }, (_, i) => i + 1).map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </td>
      <td>
        <span className="chips">
          {CLASSES.map((c) => (
            <label key={c} className={`chip-toggle ${classes.includes(c) ? 'is-on' : ''}`}>
              <input
                type="checkbox"
                checked={classes.includes(c)}
                disabled={!lead}
                onChange={(e) => setClasses(e.target.checked ? [...classes, c] : classes.filter((x) => x !== c))}
              />
              {c.replace('_', ' ')}
            </label>
          ))}
        </span>
      </td>
      <td>{asset.owner ?? '–'}</td>
      <td>
        {dirty && (
          <button
            type="button"
            className="mini-btn"
            disabled={put.isPending}
            onClick={() =>
              put.mutate({ hostname: asset.hostname, body: { role: asset.role, criticality: crit, data_classes: classes, owner: asset.owner ?? undefined } })
            }
          >
            {put.isPending ? 'Saving…' : 'Save'}
          </button>
        )}
      </td>
    </tr>
  )
}

function Rules() {
  const rules = useRules()
  return (
    <section className="panel">
      <h2 className="panel__title">Detection rules</h2>
      {rules.isPending ? (
        <Skeleton rows={6} />
      ) : rules.isError ? (
        <PanelError title="Could not load rules" error={rules.error} retry={() => rules.refetch()} inline />
      ) : (
        <div className="table-wrap">
          <table className="alerts">
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Source</th>
                <th scope="col">Precision (learned)</th>
                <th scope="col">Confirmed / false</th>
              </tr>
            </thead>
            <tbody>
              {rules.data.data.map((r) => (
                <tr key={r.rule_id}>
                  <td>
                    <span className="tnum">{r.rule_id}</span>
                    <span className="muted"> {r.rule_name}</span>
                  </td>
                  <td>{r.source}</td>
                  <td>
                    <span className="precision">
                      <span className="factors__bar" aria-hidden>
                        <span style={{ transform: `scaleX(${r.precision})` }} />
                      </span>
                      <span className="tnum" title={`Beta(${r.alpha}, ${r.beta})`}>
                        {r.precision.toFixed(2)}
                      </span>
                    </span>
                  </td>
                  <td className="tnum">
                    {r.confirmed ?? 0} / {r.false_positives ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function Suppressions() {
  const lead = useIsLead()
  const sup = useSuppressions()
  const del = useDeleteSuppression()
  return (
    <section className="panel">
      <h2 className="panel__title">Suppressions</h2>
      {sup.isPending ? (
        <Skeleton rows={3} />
      ) : sup.isError ? (
        <PanelError title="Could not load suppressions" error={sup.error} retry={() => sup.refetch()} inline />
      ) : sup.data.data.length === 0 ? (
        <p className="panel__lede">None. A lead can suppress a rule for one entity when recording a false positive.</p>
      ) : (
        <ul className="log">
          {sup.data.data.map((s) => (
            <li key={s.suppression_id}>
              <strong className="tnum">
                {s.rule_id} on {s.entity_key}
              </strong>
              <span>
                {s.created_by}
                {s.reason ? `: ${s.reason}` : ''}
                {s.expires_at ? ` · until ${new Date(s.expires_at).toLocaleDateString('en-IN')}` : ''}
              </span>
              {lead && (
                <button type="button" className="mini-btn" onClick={() => del.mutate(s.suppression_id)} disabled={del.isPending}>
                  <Trash size={14} aria-hidden /> Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
