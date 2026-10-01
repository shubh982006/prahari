import { ArrowClockwise, LinkBreak, SealCheck } from '@phosphor-icons/react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAudit, useAuditVerify, useRetention } from '../../api/queries'
import { PanelError, Skeleton } from '../../components/Status'
import { summarise } from '../roles'

export default function Audit() {
  const [subject, setSubject] = useState('')
  const [applied, setApplied] = useState('')
  const verify = useAuditVerify()
  const retention = useRetention()
  const log = useAudit(applied)
  const entries = log.data?.pages.flatMap((p) => p.data) ?? []

  return (
    <div className="page">
      <header className="page__head">
        <h1>Audit</h1>
        <p className="panel__lede">
          Every action is appended to a log where each record's hash includes the previous one. Change any record and every hash
          after it breaks. Tamper-evident, not tamper-proof: export the head hash somewhere the database cannot reach.
        </p>
      </header>

      <div className="grid-2">
        <section className={`panel verify ${verify.data && !verify.data.ok ? 'is-broken' : ''}`} aria-live="polite">
          <div className="panel__bar">
            <h2 className="panel__title">Hash chain</h2>
            <button type="button" className="mini-btn" onClick={() => verify.refetch()} disabled={verify.isFetching}>
              <ArrowClockwise size={14} className={verify.isFetching ? 'spin' : undefined} aria-hidden /> Verify now
            </button>
          </div>
          {verify.isPending ? (
            <Skeleton rows={3} />
          ) : verify.isError ? (
            <PanelError title="Could not verify" error={verify.error} retry={() => verify.refetch()} inline />
          ) : (
            <>
              <p className="verify__state">
                {verify.data.ok ? <SealCheck size={20} weight="fill" aria-hidden /> : <LinkBreak size={20} weight="bold" aria-hidden />}
                {verify.data.ok
                  ? `Intact across ${verify.data.checked.toLocaleString('en-IN')} records`
                  : `Broken at record #${verify.data.broken_seq}`}
              </p>
              <dl className="kv">
                <div>
                  <dt>Head hash</dt>
                  <dd className="tnum break">{verify.data.head_hash}</dd>
                </div>
                <div>
                  <dt>Checked at</dt>
                  <dd className="tnum">{new Date(verify.data.verified_at).toLocaleString('en-IN')}</dd>
                </div>
              </dl>
            </>
          )}
        </section>

        <section className="panel">
          <h2 className="panel__title">Retention</h2>
          {retention.isPending ? (
            <Skeleton rows={3} />
          ) : retention.isError ? (
            <PanelError title="Could not load retention" error={retention.error} retry={() => retention.refetch()} inline />
          ) : (
            <>
              <p className="panel__lede">
                {retention.data.policy_days} days ({retention.data.basis}). {retention.data.dialect} uses{' '}
                {retention.data.mechanism.replace(/_/g, ' ')}; next sweep {new Date(retention.data.next_run_at).toLocaleString('en-IN')}.
              </p>
              <ul className="log">
                {retention.data.units.slice(0, 6).map((u) => (
                  <li key={u.table + u.name}>
                    <strong className="tnum">{u.name}</strong>
                    <span className="tnum">{u.rows.toLocaleString('en-IN')} rows</span>
                    <time className="tnum">drops {new Date(u.drop_after).toLocaleDateString('en-IN')}</time>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>

      <section className="panel">
        <form
          className="panel__bar"
          onSubmit={(e) => {
            e.preventDefault()
            setApplied(subject.trim())
          }}
        >
          <h2 className="panel__title">Trail</h2>
          <input className="search" placeholder="Subject, e.g. INC-… or CASE-…" value={subject} onChange={(e) => setSubject(e.target.value)} aria-label="Filter by subject" />
        </form>
        {log.isPending ? (
          <Skeleton rows={10} />
        ) : log.isError ? (
          <PanelError title="Could not load the trail" error={log.error} retry={() => log.refetch()} inline />
        ) : entries.length === 0 ? (
          <p className="panel__lede">No records{applied ? ` for ${applied}` : ''}.</p>
        ) : (
          <ol className="log log--audit">
            {entries.map((e) => (
              <li key={e.seq}>
                <span className="tnum log__seq">#{e.seq}</span>
                <strong>{e.action}</strong>
                <span>
                  {e.actor}
                  {e.subject && (
                    <>
                      {' · '}
                      {e.subject.startsWith('INC-') ? (
                        <Link to={`/console/${e.subject}`}>{e.subject}</Link>
                      ) : e.subject.startsWith('CASE-') ? (
                        <Link to={`/console/compliance/${e.subject}`}>{e.subject}</Link>
                      ) : (
                        <span className="tnum">{e.subject}</span>
                      )}
                    </>
                  )}
                  {Object.keys(e.payload ?? {}).length ? ` · ${summarise(e.payload)}` : ''}
                </span>
                <time className="tnum" title={`hash ${e.hash}`}>
                  {new Date(e.ts).toLocaleString('en-IN')}
                </time>
              </li>
            ))}
          </ol>
        )}
        {log.hasNextPage && (
          <button type="button" className="queue__more" onClick={() => log.fetchNextPage()} disabled={log.isFetchingNextPage}>
            {log.isFetchingNextPage ? 'Loading…' : 'Older records'}
          </button>
        )}
      </section>
    </div>
  )
}
