// Real-time layer. One EventSource per console session on GET /events; every
// event invalidates exactly the cached queries it can change, so open screens
// refresh without polling. Per-run and per-campaign streams drive progress UI.

import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore } from 'react'
import { apiUrl, getToken, type Schemas } from './client'
import { toast } from './toast'

export type LiveStatus = 'connecting' | 'live' | 'reconnecting' | 'offline'

export interface LiveEvent {
  id: string
  type: string
  at: string
  dataset_id?: string
  run_id?: string
  incident_id?: string
  case_id?: string
  campaign_id?: string
  track?: string
  hostname?: string
}

const GLOBAL_TYPES = [
  'run.started',
  'run.finished',
  'case.opened',
  'case.updated',
  'incident.updated',
  'narrative.updated',
  'campaign.started',
  'campaign.finished',
  'dataset.created',
  'dataset.updated',
  'evaluation.finished',
  'asset.updated',
  'rules.updated',
] as const

/* ---------- tiny external store: connection status, activity, active runs ---------- */

interface LiveState {
  status: LiveStatus
  activity: LiveEvent[]
  unread: number
  runningRuns: string[]
  runningCampaigns: string[]
}

let state: LiveState = { status: 'offline', activity: [], unread: 0, runningRuns: [], runningCampaigns: [] }
const subs = new Set<() => void>()
function set(patch: Partial<LiveState>) {
  state = { ...state, ...patch }
  subs.forEach((f) => f())
}
const subscribe = (f: () => void) => {
  subs.add(f)
  return () => {
    subs.delete(f)
  }
}

export function useLive<T>(select: (s: LiveState) => T): T {
  return useSyncExternalStore(subscribe, () => select(state), () => select(state))
}

export function markActivityRead() {
  if (state.unread) set({ unread: 0 })
}

/* ---------- what each event invalidates ---------- */

function invalidate(qc: QueryClient, ev: LiveEvent) {
  const inv = (queryKey: readonly unknown[]) => qc.invalidateQueries({ queryKey })
  inv(['audit'])
  switch (ev.type) {
    case 'run.started':
      inv(['runs'])
      break
    case 'run.finished':
      inv(['runs'])
      inv(['datasets'])
      inv(['incidents'])
      inv(['incident'])
      inv(['cases'])
      inv(['case'])
      inv(['rules'])
      break
    case 'case.opened':
    case 'case.updated':
      inv(['cases'])
      if (ev.case_id) inv(['case', ev.case_id])
      inv(['draft'])
      if (ev.incident_id) inv(['incident', ev.incident_id])
      inv(['incidents'])
      break
    case 'incident.updated':
      if (ev.incident_id) inv(['incident', ev.incident_id])
      inv(['incidents'])
      break
    case 'narrative.updated':
      if (ev.incident_id) inv(['incident', ev.incident_id, 'narrative'])
      break
    case 'campaign.started':
    case 'campaign.finished':
      inv(['campaigns'])
      if (ev.campaign_id) inv(['campaign', ev.campaign_id])
      inv(['curve'])
      inv(['datasets'])
      break
    case 'dataset.created':
    case 'dataset.updated':
      inv(['datasets'])
      break
    case 'evaluation.finished':
      inv(['evaluation'])
      break
    case 'asset.updated':
      inv(['assets'])
      // Asset criticality feeds counterfactuals and the next run's scores.
      inv(['incident'])
      break
    case 'rules.updated':
      inv(['rules'])
      inv(['suppressions'])
      break
  }
}

/**
 * Adversary campaigns correlate mutated copies of a dataset; those runs open
 * their own cases. They belong to the bench, not to the analyst's queue, so the
 * console neither refetches for them nor announces them.
 */
function isBackground(qc: QueryClient, ev: LiveEvent) {
  if (!ev.dataset_id || ev.type.startsWith('campaign.')) return false
  const list = qc.getQueryData<{ data: Schemas['Dataset'][] }>(['datasets'])
  const d = list?.data.find((x) => x.dataset_id === ev.dataset_id)
  return d ? d.kind === 'adversarial' : ev.dataset_id.startsWith('ds_adv_')
}

function track(ev: LiveEvent) {
  const without = (xs: string[], x?: string) => xs.filter((y) => y !== x)
  if (ev.type === 'run.started' && ev.run_id) set({ runningRuns: [...without(state.runningRuns, ev.run_id), ev.run_id] })
  if (ev.type === 'run.finished') set({ runningRuns: without(state.runningRuns, ev.run_id) })
  if (ev.type === 'campaign.started' && ev.campaign_id)
    set({ runningCampaigns: [...without(state.runningCampaigns, ev.campaign_id), ev.campaign_id] })
  if (ev.type === 'campaign.finished') set({ runningCampaigns: without(state.runningCampaigns, ev.campaign_id) })
}

function announce(ev: LiveEvent) {
  if (ev.type === 'case.opened') {
    toast({ tone: 'alert', title: `Compliance clock started: ${ev.case_id}`, body: `${ev.incident_id} tripped the trigger.`, href: `/console/compliance/${ev.case_id}` })
  } else if (ev.type === 'run.finished') {
    toast({ tone: 'info', title: 'Correlation run finished', body: 'The queue now shows the new run.', href: '/console/runs' })
  } else if (ev.type === 'campaign.finished') {
    toast({ tone: 'info', title: 'Adversary campaign finished', body: ev.campaign_id, href: '/console/adversary' })
  }
}

/**
 * Mount once in the console shell. The browser reconnects on its own after a
 * dropped stream (the server sends retry: 3000) and resumes with Last-Event-ID,
 * but it gives up for good on any non-200 answer, which is what a proxy returns
 * while the API restarts. So a closed stream is reopened here with backoff, and
 * every reconnect refetches everything, because the global stream keeps only a
 * short replay window.
 */
export function useLiveConnection(enabled: boolean) {
  const qc = useQueryClient()
  useEffect(() => {
    if (!enabled || typeof EventSource === 'undefined') return
    let es: EventSource | null = null
    let retry: number | undefined
    let attempt = 0
    let dropped = false
    let stopped = false

    const handler = (e: MessageEvent) => {
      let data: Partial<LiveEvent> = {}
      try {
        data = JSON.parse(e.data)
      } catch {
        return
      }
      const ev: LiveEvent = { ...data, id: e.lastEventId, type: e.type, at: data.at ?? new Date().toISOString() }
      if (isBackground(qc, ev)) return
      invalidate(qc, ev)
      track(ev)
      announce(ev)
      set({ activity: [ev, ...state.activity].slice(0, 60), unread: state.unread + 1 })
    }

    const connect = () => {
      const token = getToken()
      if (stopped || !token) return
      window.clearTimeout(retry)
      es?.close()
      set({ status: attempt ? 'reconnecting' : 'connecting' })
      es = new EventSource(apiUrl(`/events?access_token=${encodeURIComponent(token)}`))
      es.onopen = () => {
        if (dropped) qc.invalidateQueries()
        dropped = false
        attempt = 0
        set({ status: 'live' })
      }
      es.onerror = () => {
        dropped = true
        if (es?.readyState === EventSource.CLOSED) {
          attempt += 1
          set({ status: 'reconnecting' })
          retry = window.setTimeout(connect, Math.min(15_000, 1000 * 2 ** Math.min(attempt - 1, 4)))
        } else {
          set({ status: 'reconnecting' })
        }
      }
      GLOBAL_TYPES.forEach((t) => es!.addEventListener(t, handler as EventListener))
    }

    const online = () => {
      attempt = 0
      connect()
    }
    const offline = () => set({ status: 'offline' })
    window.addEventListener('online', online)
    window.addEventListener('offline', offline)
    connect()
    return () => {
      stopped = true
      window.clearTimeout(retry)
      window.removeEventListener('online', online)
      window.removeEventListener('offline', offline)
      es?.close()
      set({ status: 'offline' })
    }
  }, [enabled, qc])
}

/* ---------- per-run and per-campaign progress streams ---------- */

export interface RunProgress {
  status: string
  stages: { stage: string; count: number; elapsed_ms: number }[]
  error?: string
  done: boolean
}

/** Streams one run's lifecycle. Connecting to a finished run replays it and closes. */
const RUN_START: RunProgress = { status: 'queued', stages: [], done: false }

export function useRunStream(runId: string | null | undefined): RunProgress {
  // State is keyed by run so switching runs starts clean without an effect-time reset.
  const [keyed, setKeyed] = useState<{ id: string; p: RunProgress } | null>(null)
  const p = keyed && keyed.id === runId ? keyed.p : RUN_START
  useEffect(() => {
    const token = getToken()
    if (!runId || !token) return
    const setP = (f: (s: RunProgress) => RunProgress) =>
      setKeyed((k) => ({ id: runId, p: f(k && k.id === runId ? k.p : RUN_START) }))
    const es = new EventSource(apiUrl(`/runs/${runId}/events?access_token=${encodeURIComponent(token)}`))
    const parse = (e: Event) => JSON.parse((e as MessageEvent).data)
    es.addEventListener('status', (e) => setP((s) => ({ ...s, status: parse(e).status })))
    es.addEventListener('stage', (e) => {
      const d = parse(e)
      setP((s) => ({ ...s, stages: [...s.stages.filter((x) => x.stage !== d.stage), d] }))
    })
    es.addEventListener('done', () => {
      setP((s) => ({ ...s, status: 'succeeded', done: true }))
      es.close()
    })
    es.addEventListener('error', (e) => {
      const me = e as MessageEvent
      if (me.data) {
        const d = JSON.parse(me.data)
        setP((s) => ({ ...s, error: d.message || d.code, done: true }))
        es.close()
      }
    })
    return () => es.close()
  }, [runId])
  return p
}

export interface CampaignProgress {
  started: number[]
  finished: { budget: number; scenario_recall: number; detected: boolean }[]
  done: boolean
  error?: string
}

const CAMPAIGN_START: CampaignProgress = { started: [], finished: [], done: false }

export function useCampaignStream(campaignId: string | null | undefined): CampaignProgress {
  const [keyed, setKeyed] = useState<{ id: string; p: CampaignProgress } | null>(null)
  const p = keyed && keyed.id === campaignId ? keyed.p : CAMPAIGN_START
  useEffect(() => {
    const token = getToken()
    if (!campaignId || !token) return
    const setP = (f: (s: CampaignProgress) => CampaignProgress) =>
      setKeyed((k) => ({ id: campaignId, p: f(k && k.id === campaignId ? k.p : CAMPAIGN_START) }))
    const es = new EventSource(apiUrl(`/adversary/campaigns/${campaignId}/events?access_token=${encodeURIComponent(token)}`))
    const parse = (e: Event) => JSON.parse((e as MessageEvent).data)
    es.addEventListener('budget.started', (e) => setP((s) => ({ ...s, started: [...s.started, parse(e).budget] })))
    es.addEventListener('budget.finished', (e) => {
      const d = parse(e)
      setP((s) => ({ ...s, finished: [...s.finished.filter((x) => x.budget !== d.budget), d] }))
    })
    es.addEventListener('done', () => {
      setP((s) => ({ ...s, done: true }))
      es.close()
    })
    es.addEventListener('error', (e) => {
      const me = e as MessageEvent
      if (me.data) {
        setP((s) => ({ ...s, error: JSON.parse(me.data).message, done: true }))
        es.close()
      }
    })
    return () => es.close()
  }, [campaignId])
  return p
}
