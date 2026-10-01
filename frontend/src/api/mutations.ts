import { useMutation, useQueryClient, type QueryKey } from '@tanstack/react-query'
import { api, ApiError, type Schemas } from './client'
import { qk } from './queries'
import { toast } from './toast'

const key = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`)

interface Opts<T> {
  invalidate?: QueryKey[]
  success?: string | ((data: T) => string)
  /** Handle an error code yourself; return true to suppress the default toast. */
  onError?: (err: ApiError) => boolean | void
}

function useWrite<V, T>(fn: (v: V) => Promise<T>, opts: Opts<T> = {}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (data) => {
      opts.invalidate?.forEach((queryKey) => qc.invalidateQueries({ queryKey }))
      qc.invalidateQueries({ queryKey: ['audit'] })
      if (opts.success) toast({ tone: 'success', title: typeof opts.success === 'function' ? opts.success(data) : opts.success })
    },
    onError: (err) => {
      if (err instanceof ApiError && opts.onError?.(err)) return
      const e = err as ApiError
      const title =
        e.status === 403 ? 'Your role cannot do that' : e.status === 429 ? 'Rate limited: try again in a minute' : 'That did not go through'
      toast({ tone: 'error', title, body: e.message })
    },
  })
}

/* ---------- incident triage ---------- */

export function usePatchIncident(id: string) {
  const qc = useQueryClient()
  return useWrite(
    ({ patch, etag }: { patch: Schemas['IncidentPatch']; etag?: string }) =>
      api<Schemas['IncidentDetail']>(`/incidents/${id}`, { method: 'PATCH', body: patch, headers: { 'If-Match': etag ?? '*' } }),
    {
      invalidate: [['incidents'], qk.incident(id)],
      success: (d) => `${d.incident_id} is now ${d.status.replace('_', ' ')}`,
      onError: (e) => {
        if (e.status === 412) {
          qc.invalidateQueries({ queryKey: qk.incident(id) })
          toast({ tone: 'alert', title: 'Someone else changed this incident', body: 'Showing the latest version. Apply your change again if it still holds.' })
          return true
        }
      },
    },
  )
}

export function useFeedback(id: string) {
  return useWrite(
    (body: Schemas['FeedbackCreate']) =>
      api<Schemas['FeedbackResult']>(`/incidents/${id}/feedback`, { method: 'POST', body, headers: { 'Idempotency-Key': key() } }),
    {
      invalidate: [qk.incident(id), ['incidents'], ['rules'], ['suppressions']],
      success: (r) =>
        `Verdict recorded${r.rule_updates.length ? `; ${r.rule_updates.length} rule precision${r.rule_updates.length > 1 ? 's' : ''} updated` : ''}. Re-run to apply.`,
    },
  )
}

export function useSplit(id: string) {
  return useWrite(
    (body: Schemas['SplitRequest']) => api<Schemas['SplitResult']>(`/incidents/${id}/split`, { method: 'POST', body }),
    { invalidate: [['incidents'], ['runs'], ['datasets']], success: (r) => `Split into ${r.incidents.length} incidents in a new run` },
  )
}

/** The narrative is not invalidated but replaced: the response is the new brief. */
export function useRegenerateNarrative(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api<Schemas['Narrative']>(`/incidents/${id}/narrative/regenerate`, { method: 'POST' }),
    onSuccess: (n) => {
      qc.setQueryData(qk.sub(id, 'narrative'), n)
      qc.invalidateQueries({ queryKey: ['audit'] })
      toast({ tone: 'success', title: 'Brief regenerated', body: n.source === 'llm' ? `by ${n.model}` : 'from the deterministic template' })
    },
    onError: (e) =>
      toast({ tone: 'error', title: (e as ApiError).status === 429 ? 'Rate limited: try again in a minute' : 'Could not regenerate the brief', body: (e as Error).message }),
  })
}

/* ---------- runs and datasets ---------- */

export function useStartRun(onAttach: (runId: string) => void) {
  return useWrite(
    (body: Schemas['RunCreate']) => api<Schemas['Run']>('/runs', { method: 'POST', body, headers: { 'Idempotency-Key': key() } }),
    {
      invalidate: [['runs']],
      success: 'Correlation run queued',
      onError: (e) => {
        const active = (e.problem as { active_run_id?: string } | null)?.active_run_id
        if (e.code === 'RUN_IN_PROGRESS' && active) {
          onAttach(active)
          toast({ tone: 'info', title: 'A run is already in progress', body: 'Following that run instead.' })
          return true
        }
      },
    },
  )
}

export function useCancelRun() {
  return useWrite((runId: string) => api<Schemas['Run']>(`/runs/${runId}/cancel`, { method: 'POST' }), {
    invalidate: [['runs']],
    success: 'Run cancelled',
  })
}

export function useSimulate() {
  return useWrite((body: Schemas['SimulationRequest']) => api<Schemas['Dataset']>('/simulations', { method: 'POST', body }), {
    invalidate: [['datasets']],
    success: (d) => `Dataset ${d.dataset_id} created with ${d.counts.alerts.toLocaleString('en-IN')} alerts`,
  })
}

/* ---------- adversary, evaluation, compliance, CMDB, rules ---------- */

export function useCreateCampaign() {
  return useWrite(
    (body: Schemas['CampaignCreate']) =>
      api<Schemas['Campaign']>('/adversary/campaigns', { method: 'POST', body, headers: { 'Idempotency-Key': key() } }),
    { invalidate: [['campaigns']], success: (c) => `Campaign ${c.campaign_id} queued` },
  )
}

export function useEvaluate() {
  return useWrite((runId: string) => api<Schemas['Evaluation']>('/evaluations', { method: 'POST', body: { run_id: runId } }), {
    invalidate: [['evaluation']],
    success: 'Run scored against ground truth',
  })
}

export function useSubmitCase(caseId: string) {
  return useWrite(
    ({ track, body }: { track: Schemas['TrackName']; body: Schemas['SubmissionCreate'] }) =>
      api<Schemas['ComplianceCase']>(`/compliance/cases/${caseId}/tracks/${track}/submission`, { method: 'POST', body }),
    { invalidate: [['cases'], qk.case(caseId)], success: 'Submission recorded; the clock for that track has stopped' },
  )
}

export function usePutAsset() {
  return useWrite(
    ({ hostname, body }: { hostname: string; body: Schemas['AssetUpsert'] }) =>
      api<Schemas['Asset']>(`/assets/${hostname}`, { method: 'PUT', body }),
    { invalidate: [['assets'], ['incident']], success: (a) => `${a.hostname} saved at criticality ${a.criticality}` },
  )
}

export function useDeleteSuppression() {
  return useWrite((id: number) => api<void>(`/suppressions/${id}`, { method: 'DELETE' }), {
    invalidate: [['suppressions'], ['rules']],
    success: 'Suppression removed; it stops applying from the next run',
  })
}
