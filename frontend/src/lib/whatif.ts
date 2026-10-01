import type { Counterfactual, Incident } from '../data/seed'
import { priorityOf, risk } from './score'

/** Score and priority with one counterfactual's patch applied. */
export function whatIf(incident: Incident, cf: Counterfactual | undefined) {
  if (!cf?.patch) return { risk: incident.risk, priority: incident.priority }
  const r = risk({ ...incident.factors, ...cf.patch })
  return { risk: r, priority: priorityOf(r) }
}
