import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useSyncExternalStore } from 'react'
import { api, apiUrl, getToken, type Schemas } from './client'

type Page<T> = { data: T[]; page?: Schemas['PageInfo'] }

export type IncidentList = Page<Schemas['IncidentSummary']> & {
  run_id: string
  thresholds: Schemas['Bands']
  totals: Schemas['IncidentTotals']
}

export const qk = {
  me: ['me'] as const,
  meta: ['meta'] as const,
  datasets: ['datasets'] as const,
  incidents: (ds: string, priority: string) => ['incidents', ds, priority] as const,
  incident: (id: string) => ['incident', id] as const,
  sub: (id: string, ...what: string[]) => ['incident', id, ...what] as const,
  cases: (ds: string, state: string) => ['cases', ds, state] as const,
  case: (id: string) => ['case', id] as const,
  draft: (id: string, track: string, format: string) => ['draft', id, track, format] as const,
  runs: (ds: string) => ['runs', ds] as const,
  run: (id: string) => ['runs', 'one', id] as const,
  receipt: (id: string) => ['receipt', id] as const,
  campaigns: (ds: string) => ['campaigns', ds] as const,
  campaign: (id: string) => ['campaign', id] as const,
  curve: (ds: string) => ['curve', ds] as const,
  evaluation: (ds: string) => ['evaluation', ds] as const,
  assets: ['assets'] as const,
  rules: ['rules'] as const,
  suppressions: ['suppressions'] as const,
  audit: (subject: string) => ['audit', subject] as const,
  auditVerify: ['audit', 'verify'] as const,
  retention: ['retention'] as const,
}

export function useMe(enabled: boolean) {
  return useQuery({ queryKey: qk.me, queryFn: () => api<Schemas['User']>('/auth/me'), enabled, retry: false, staleTime: Infinity })
}

export function useMeta() {
  return useQuery({ queryKey: qk.meta, queryFn: () => api<Schemas['Meta']>('/meta'), staleTime: 5 * 60_000 })
}

/* ---------- datasets: the console's working set ---------- */

const DS_KEY = 'prahari.dataset'
let chosen: string | null = (() => {
  try {
    return localStorage.getItem(DS_KEY)
  } catch {
    return null
  }
})()
const dsSubs = new Set<() => void>()

export function chooseDataset(id: string | null) {
  chosen = id
  try {
    if (id) localStorage.setItem(DS_KEY, id)
    else localStorage.removeItem(DS_KEY)
  } catch {
    /* storage blocked: the choice lasts this visit */
  }
  dsSubs.forEach((f) => f())
}

export function useDatasets() {
  return useQuery({
    queryKey: qk.datasets,
    queryFn: () => api<Page<Schemas['Dataset']>>('/datasets', { query: { limit: 200 } }),
    select: (res) => [...res.data].sort((a, b) => b.created_at.localeCompare(a.created_at)),
    staleTime: 60_000,
  })
}

/**
 * The dataset the console works on: the analyst's choice if it still exists,
 * else the newest non-adversarial dataset with a finished run.
 */
export function useActiveDataset() {
  const pick = useSyncExternalStore(
    (f) => {
      dsSubs.add(f)
      return () => {
        dsSubs.delete(f)
      }
    },
    () => chosen,
    () => chosen,
  )
  const q = useDatasets()
  const all = q.data ?? []
  const picked = all.find((d) => d.dataset_id === pick)
  const fallback = all.find((d) => d.kind !== 'adversarial' && d.current_run_id) ?? null
  return { ...q, data: q.data ? (picked ?? fallback) : undefined }
}

/* ---------- incidents ---------- */

/** The ranked queue, a page of 100 at a time along the API's cursor. */
export function useIncidents(datasetId: string | undefined, priority: string) {
  return useInfiniteQuery({
    queryKey: qk.incidents(datasetId ?? '', priority),
    queryFn: ({ signal, pageParam }) =>
      api<IncidentList>('/incidents', {
        query: { dataset_id: datasetId, priority: priority || undefined, limit: 100, cursor: pageParam },
        signal,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.page?.next_cursor ?? undefined,
    enabled: !!datasetId,
    placeholderData: keepPreviousData,
  })
}

export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: qk.incident(id ?? ''),
    queryFn: ({ signal }) => api<Schemas['IncidentDetail']>(`/incidents/${id}`, { signal }),
    enabled: !!id,
  })
}

function useSub<T>(id: string | undefined, what: string, query?: Record<string, string | number>, extraKey: string[] = []) {
  return useQuery({
    queryKey: qk.sub(id ?? '', what, ...extraKey),
    queryFn: ({ signal }) => api<T>(`/incidents/${id}/${what}`, { query, signal }),
    enabled: !!id,
    placeholderData: extraKey.length ? keepPreviousData : undefined,
  })
}

export const useTimeline = (id?: string) => useSub<Schemas['IncidentTimeline']>(id, 'timeline')
export const useGraph = (id?: string) => useSub<Schemas['IncidentGraph']>(id, 'graph')
export const useCohesion = (id?: string) => useSub<Schemas['Cohesion']>(id, 'cohesion')
export const useNarrative = (id?: string) => useSub<Schemas['Narrative']>(id, 'narrative')
export const useIncidentAlerts = (id?: string) => useSub<Page<Schemas['IncidentAlert']>>(id, 'alerts', { limit: 200 })
export const useFeedbackHistory = (id?: string) => useSub<Page<Schemas['Feedback']>>(id, 'feedback')

/** `whatIf` is `host:criticality`, e.g. `fin-db-01:3`; empty means the stored CMDB. */
export function useCounterfactuals(id: string | undefined, whatIf = '') {
  return useSub<Schemas['CounterfactualSet']>(
    id,
    'counterfactuals',
    whatIf ? { what_if_criticality: whatIf } : undefined,
    whatIf ? [whatIf] : [],
  )
}

/* ---------- compliance ---------- */

export function useCases(datasetId: string | undefined, state: string) {
  return useQuery({
    queryKey: qk.cases(datasetId ?? '', state),
    queryFn: ({ signal }) =>
      api<Page<Schemas['ComplianceCase']> & { server_time: string }>('/compliance/cases', {
        query: { dataset_id: datasetId, state },
        signal,
      }),
    enabled: !!datasetId,
    refetchInterval: 60_000,
  })
}

export function useCase(caseId: string | null | undefined) {
  return useQuery({
    queryKey: qk.case(caseId ?? ''),
    queryFn: ({ signal }) => api<Schemas['ComplianceCaseDetail']>(`/compliance/cases/${caseId}`, { signal }),
    enabled: !!caseId,
    refetchInterval: 60_000,
  })
}

export function useDraft(caseId: string | undefined, track: string) {
  return useQuery({
    queryKey: qk.draft(caseId ?? '', track, 'json'),
    queryFn: ({ signal }) => api<Schemas['Draft']>(`/compliance/cases/${caseId}/drafts/${track}`, { signal }),
    enabled: !!caseId && !!track,
  })
}

/** The same draft rendered by the server as Markdown, ready to paste into the portal. */
export function useDraftMarkdown(caseId: string | undefined, track: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.draft(caseId ?? '', track, 'markdown'),
    queryFn: ({ signal }) => fetchText(`/compliance/cases/${caseId}/drafts/${track}?format=markdown`, signal),
    enabled: enabled && !!caseId && !!track,
  })
}

async function fetchText(path: string, signal?: AbortSignal) {
  const res = await fetch(apiUrl(path), { headers: { Authorization: `Bearer ${getToken()}`, Accept: 'text/markdown' }, signal })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.text()
}

export function useRetention() {
  return useQuery({ queryKey: qk.retention, queryFn: () => api<Schemas['RetentionState']>('/governance/retention') })
}

/* ---------- runs ---------- */

export function useRuns(datasetId: string | undefined) {
  return useQuery({
    queryKey: qk.runs(datasetId ?? ''),
    queryFn: ({ signal }) => api<Page<Schemas['Run']>>('/runs', { query: { dataset_id: datasetId, limit: 50 }, signal }),
    enabled: !!datasetId,
  })
}

export function useRun(runId: string | null | undefined) {
  return useQuery({
    queryKey: qk.run(runId ?? ''),
    queryFn: ({ signal }) => api<Schemas['Run']>(`/runs/${runId}`, { signal }),
    enabled: !!runId,
  })
}

export function useReceipt(runId: string | null | undefined) {
  return useQuery({
    queryKey: qk.receipt(runId ?? ''),
    queryFn: () => api<Schemas['Receipt']>(`/runs/${runId}/receipt`),
    enabled: !!runId,
    staleTime: Infinity,
  })
}

/* ---------- adversary bench and evaluation ---------- */

export function useCampaigns(datasetId: string | undefined) {
  return useQuery({
    queryKey: qk.campaigns(datasetId ?? ''),
    queryFn: ({ signal }) => api<Page<Schemas['Campaign']>>('/adversary/campaigns', { query: { base_dataset: datasetId, limit: 100 }, signal }),
    enabled: !!datasetId,
  })
}

export function useCampaign(id: string | null | undefined) {
  return useQuery({
    queryKey: qk.campaign(id ?? ''),
    queryFn: ({ signal }) => api<Schemas['CampaignDetail']>(`/adversary/campaigns/${id}`, { signal }),
    enabled: !!id,
  })
}

export function useCurve(datasetId: string | undefined) {
  return useQuery({
    queryKey: qk.curve(datasetId ?? ''),
    queryFn: ({ signal }) => api<Schemas['EvasionCurve']>('/adversary/curve', { query: { base_dataset: datasetId }, signal }),
    enabled: !!datasetId,
  })
}

export function useEvaluation(datasetId: string | undefined) {
  return useQuery({
    queryKey: qk.evaluation(datasetId ?? ''),
    queryFn: ({ signal }) => api<Schemas['Evaluation']>('/evaluations/latest', { query: { dataset_id: datasetId }, signal }),
    enabled: !!datasetId,
  })
}

/* ---------- assets, rules, audit ---------- */

export function useAssets() {
  return useQuery({ queryKey: qk.assets, queryFn: () => api<Page<Schemas['Asset']>>('/assets', { query: { limit: 500 } }) })
}

export function useRules() {
  return useQuery({ queryKey: qk.rules, queryFn: () => api<Page<Schemas['RuleStat']>>('/rules') })
}

export function useSuppressions() {
  return useQuery({ queryKey: qk.suppressions, queryFn: () => api<Page<Schemas['Suppression']>>('/suppressions') })
}

export function useAudit(subject = '') {
  return useInfiniteQuery({
    queryKey: qk.audit(subject),
    queryFn: ({ signal, pageParam }) =>
      api<Page<Schemas['AuditEntry']>>('/audit', { query: { subject: subject || undefined, limit: 50, cursor: pageParam }, signal }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.page?.next_cursor ?? undefined,
  })
}

export function useAuditVerify() {
  return useQuery({ queryKey: qk.auditVerify, queryFn: () => api<Schemas['AuditVerifyResult']>('/audit/verify') })
}
