import { ArrowLeft, Bell, CircleNotch, Moon, SignOut, Sun, X } from '@phosphor-icons/react'
import { useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'framer-motion'
import { Suspense, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { setToken } from '../api/client'
import { markActivityRead, useLive, useLiveConnection, type LiveEvent, type LiveStatus } from '../api/live'
import { chooseDataset, useActiveDataset, useDatasets, useMe } from '../api/queries'
import { dismiss, useToasts } from '../api/toast'
import { useToken } from '../api/useToken'
import { Logo } from '../components/Logo'
import { Skeleton } from '../components/Status'
import { EASE_OUT } from '../lib/motion'
import './console.css'
import './pages.css'

const NAV = [
  { to: '/console', label: 'Incidents' },
  { to: '/console/compliance', label: 'Compliance' },
  { to: '/console/adversary', label: 'Adversary bench' },
  { to: '/console/evaluation', label: 'Evaluation' },
  { to: '/console/runs', label: 'Runs' },
  { to: '/console/assets', label: 'Assets & rules' },
  { to: '/console/audit', label: 'Audit' },
]

function useTheme() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? 'dark')
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('prahari.theme', theme)
    } catch {
      /* storage blocked: the toggle still works for this visit */
    }
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))] as const
}

export default function ConsoleLayout() {
  const token = useToken()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [theme, toggleTheme] = useTheme()
  const me = useMe(!!token)
  const { pathname } = useLocation()
  const onIncidents = /^\/console(\/INC-[^/]+)?\/?$/.test(pathname)
  useLiveConnection(!!token)

  const signOut = () => {
    setToken(null)
    qc.clear()
    navigate('/login', { replace: true })
  }

  return (
    <div className="console">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <div className="chead">
        <header className="cbar">
          <Logo />
          <DatasetSwitcher />
          <span className="cbar__spacer" />
          <RunningChip />
          <LiveIndicator />
          <Activity />
          {me.data && (
            <span className="cbar__user">
              {me.data.display_name} <span>{me.data.role}</span>
            </span>
          )}
          <button type="button" className="icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button type="button" className="icon-btn" onClick={signOut} aria-label="Sign out">
            <SignOut size={18} />
          </button>
          <Link to="/" className="cbar__back">
            <ArrowLeft size={14} aria-hidden /> Site
          </Link>
        </header>
        <nav className="cnav" aria-label="Console sections">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end
              className={({ isActive }) => `cnav__link ${(n.to === '/console' ? onIncidents : isActive) ? 'is-active' : ''}`}
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
      </div>
      <div id="main">
        <Suspense
          fallback={
            <div className="page">
              <Skeleton rows={8} />
            </div>
          }
        >
          <Outlet />
        </Suspense>
      </div>
      <Toasts />
    </div>
  )
}

function DatasetSwitcher() {
  const all = useDatasets()
  const active = useActiveDataset()
  const options = (all.data ?? []).filter((d) => d.kind !== 'adversarial')
  if (!active.data) return null
  const label = (d: (typeof options)[number]) =>
    `${d.kind === 'simulated' ? `Seed ${d.seed}` : d.dataset_id} · ${d.counts.alerts.toLocaleString('en-IN')} alerts${d.current_run_id ? '' : ' · not run'}`
  return (
    <label className="cbar__dataset">
      <span className="cbar__dot" aria-hidden />
      <span className="sr-only">Dataset</span>
      <select value={active.data.dataset_id} onChange={(e) => chooseDataset(e.target.value)} title={active.data.dataset_id}>
        {options.map((d) => (
          <option key={d.dataset_id} value={d.dataset_id}>
            {label(d)}
          </option>
        ))}
      </select>
    </label>
  )
}

const STATUS_TEXT: Record<LiveStatus, string> = {
  connecting: 'Connecting',
  live: 'Live',
  reconnecting: 'Reconnecting',
  offline: 'Offline',
}

function LiveIndicator() {
  const status = useLive((s) => s.status)
  return (
    <span
      className={`live live--${status}`}
      role="status"
      title={status === 'live' ? 'Receiving updates from the server as they happen' : 'Updates paused; the console refreshes when the stream returns'}
    >
      <span className="live__dot" aria-hidden />
      {STATUS_TEXT[status]}
    </span>
  )
}

function RunningChip() {
  const runs = useLive((s) => s.runningRuns.length)
  const camps = useLive((s) => s.runningCampaigns.length)
  if (!runs && !camps) return null
  return (
    <Link to={runs ? '/console/runs' : '/console/adversary'} className="running-chip">
      <CircleNotch size={14} className="spin" aria-hidden />
      {runs ? 'Correlating' : `Campaign running`}
    </Link>
  )
}

const EVENT_TEXT: Record<string, (e: LiveEvent) => string> = {
  'run.started': () => 'Correlation run started',
  'run.finished': () => 'Correlation run finished',
  'case.opened': (e) => `Compliance clock started for ${e.incident_id}`,
  'case.updated': (e) => `Submission recorded on ${e.case_id} (${e.track})`,
  'incident.updated': (e) => `${e.incident_id} updated`,
  'narrative.updated': (e) => `Brief regenerated for ${e.incident_id}`,
  'campaign.started': (e) => `Campaign ${e.campaign_id} started`,
  'campaign.finished': (e) => `Campaign ${e.campaign_id} finished`,
  'dataset.created': (e) => `Dataset ${e.dataset_id} created`,
  'dataset.updated': (e) => `Alerts ingested into ${e.dataset_id}`,
  'evaluation.finished': () => 'Evaluation finished',
  'asset.updated': (e) => `Asset ${e.hostname} changed`,
  'rules.updated': () => 'Rule statistics changed',
}

function eventHref(e: LiveEvent) {
  if (e.case_id) return `/console/compliance/${e.case_id}`
  if (e.incident_id) return `/console/${e.incident_id}`
  if (e.type.startsWith('campaign')) return '/console/adversary'
  if (e.type.startsWith('run')) return '/console/runs'
  if (e.type === 'evaluation.finished') return '/console/evaluation'
  if (e.type === 'asset.updated' || e.type === 'rules.updated') return '/console/assets'
  return '/console'
}

function Activity() {
  const [open, setOpen] = useState(false)
  const items = useLive((s) => s.activity)
  const unread = useLive((s) => s.unread)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    markActivityRead()
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open, items.length])

  return (
    <div className="activity" ref={ref}>
      <button
        type="button"
        className="icon-btn"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label={`Activity${unread ? `, ${unread} new` : ''}`}
      >
        <Bell size={18} />
        {unread > 0 && <span className="activity__badge tnum">{unread > 9 ? '9+' : unread}</span>}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            className="activity__panel"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6, transition: { duration: 0.12 } }}
            transition={{ duration: 0.2, ease: EASE_OUT }}
          >
            <h2>Live activity</h2>
            {items.length === 0 ? (
              <p className="activity__empty">Nothing yet. Runs, triage, submissions and campaigns appear here the moment they happen.</p>
            ) : (
              <ol>
                {items.map((e, i) => (
                  <li key={`${e.id}-${i}`}>
                    <Link to={eventHref(e)} onClick={() => setOpen(false)}>
                      <span>{(EVENT_TEXT[e.type] ?? ((x: LiveEvent) => x.type))(e)}</span>
                      <time className="tnum" dateTime={e.at}>
                        {new Date(e.at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </time>
                    </Link>
                  </li>
                ))}
              </ol>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Toasts() {
  const toasts = useToasts()
  return (
    <div className="toasts" aria-live="polite">
      <AnimatePresence initial={false} mode="popLayout">
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            layout
            className={`toast toast--${t.tone}`}
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, x: 24, transition: { duration: 0.15 } }}
            transition={{ duration: 0.25, ease: EASE_OUT }}
            role={t.tone === 'error' ? 'alert' : 'status'}
          >
            <div>
              <strong>{t.title}</strong>
              {t.body && <span>{t.body}</span>}
              {t.href && (
                <Link to={t.href} onClick={() => dismiss(t.id)}>
                  Open
                </Link>
              )}
            </div>
            <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss">
              <X size={14} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
