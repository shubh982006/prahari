import type { Schemas } from '../api/client'
import type { EntityType, Incident } from '../data/seed'

export interface GNode {
  key: string
  type: EntityType
  label: string
  criticality?: number | null
  crownJewel?: boolean
  external?: boolean
  tags?: string[]
}

export interface GEdge {
  source: string
  target: string
  /** first time the link was seen, for draw order */
  t: number
  bridge?: boolean
}

/** What the attack graph draws, from either the synthetic seed or GET /incidents/{id}/graph. */
export interface GraphData {
  id: string
  nodes: GNode[]
  edges: GEdge[]
  /** alert id → entity keys it touched, so a highlighted alert lights its nodes */
  alertEntities: Record<string, string[]>
}

const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`)

export function graphFromIncident(inc: Incident): GraphData {
  const edges = new Map<string, GEdge>()
  const alertEntities: Record<string, string[]> = {}
  for (const a of inc.alerts) {
    alertEntities[a.id] = a.entities
    for (let i = 0; i < a.entities.length - 1; i++) {
      const k = pairKey(a.entities[i], a.entities[i + 1])
      if (!edges.has(k)) edges.set(k, { source: a.entities[i], target: a.entities[i + 1], t: a.t })
    }
  }
  return {
    id: inc.id,
    nodes: inc.entities.map((e) => ({ ...e })),
    edges: [...edges.values()].sort((a, b) => a.t - b.t),
    alertEntities,
  }
}

const SENSITIVE = new Set(['pii', 'financial'])

export function graphFromApi(id: string, g: Schemas['IncidentGraph']): GraphData {
  const edges = new Map<string, GEdge>()
  const alertEntities: Record<string, string[]> = {}
  for (const e of g.edges) {
    const list = (alertEntities[e.alert_id] ??= [])
    if (!list.includes(e.source)) list.push(e.source)
    if (!list.includes(e.target)) list.push(e.target)
    const k = pairKey(e.source, e.target)
    const t = Date.parse(e.ts) / 1000
    const prev = edges.get(k)
    if (!prev) edges.set(k, { source: e.source, target: e.target, t, bridge: !!e.is_bridge })
    else if (e.is_bridge) prev.bridge = true
  }
  return {
    id,
    nodes: g.nodes.map((n) => ({
      key: n.id,
      type: n.type,
      label: n.label,
      criticality: n.criticality,
      external: n.external,
      tags: n.data_classes,
      crownJewel: (n.criticality ?? 0) >= 9 && (n.data_classes ?? []).some((c) => SENSITIVE.has(c)),
    })),
    edges: [...edges.values()].sort((a, b) => a.t - b.t),
    alertEntities,
  }
}
