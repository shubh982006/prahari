// API responses → the props the shared components take. The backend numbers
// kill-chain stages 0..6; components and STAGES are one-based.

import type { CfRow } from '../components/CounterfactualList'
import { STAGES, type Alert } from '../data/seed'
import type { Priority } from '../lib/score'
import type { Schemas } from './client'

const IST_MS = 5.5 * 3_600_000

export function istTime(ms: number, withSeconds = true) {
  return new Date(ms + IST_MS).toISOString().slice(11, withSeconds ? 19 : 16)
}

export function stageName(apiStage: number) {
  return STAGES[Math.max(0, Math.min(6, apiStage))]
}

/** Timeline points as the kill-chain chart's alerts, with a clock that prints real IST times. */
export function toTimeline(tl: Schemas['IncidentTimeline'], alerts?: Schemas['IncidentAlert'][]) {
  const technique = new Map(alerts?.map((a) => [a.id, a.technique_id ?? '']))
  const base = Math.min(...tl.points.map((p) => Date.parse(p.ts)))
  const points: Alert[] = tl.points.map((p) => ({
    id: p.alert_id,
    t: (Date.parse(p.ts) - base) / 1000,
    stage: p.stage + 1,
    severity: p.severity,
    title: p.rule_name,
    technique: technique.get(p.alert_id) ?? '',
    entities: [],
    onChain: p.on_chain,
  }))
  return { alerts: points, clock: (t: number) => istTime(base + t * 1000) }
}

export function toCfRows(set: Schemas['CounterfactualSet']): CfRow[] {
  return set.counterfactuals.map((c, i) => ({
    id: `cf-${i}`,
    kind: c.kind,
    label: c.label,
    risk: c.kind === 'boundary' ? undefined : c.risk,
    priority: c.kind === 'boundary' ? undefined : (c.priority as Priority | undefined),
    delta: c.delta,
    closesCase: c.closes_case,
    reachable: c.reachable,
  }))
}

const TRACK_ORDER: Schemas['TrackName'][] = ['dpdp_intimation', 'certin', 'dpdp_report']
const TRACK_LABEL: Record<Schemas['TrackName'], string> = {
  dpdp_intimation: 'DPDP intimation',
  certin: 'CERT-In report',
  dpdp_report: 'DPDP detailed report',
}

/** Clock props for a case, tightest obligation first. */
export function caseClocks(c: Schemas['ComplianceCase']) {
  const detectedAt = Date.parse(c.detected_at)
  return [...c.tracks]
    .sort((a, b) => TRACK_ORDER.indexOf(a.track) - TRACK_ORDER.indexOf(b.track))
    .map((t) => ({
      key: t.track,
      label: TRACK_LABEL[t.track],
      authority: t.deadline_kind === 'internal_sla' ? `${t.authority} · internal 1 h SLA` : t.authority,
      detectedAt,
      deadline: Date.parse(t.deadline),
      status: t.status,
    }))
}
