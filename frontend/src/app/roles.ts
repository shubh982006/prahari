import { useMe } from '../api/queries'

/** Leads may start runs, split, launch campaigns, score, submit and edit the CMDB. */
export function useIsLead() {
  return useMe(true).data?.role === 'lead'
}

/** One line for an audit payload: `status open → investigating, assignee none → u_meow`. */
export function summarise(payload: Record<string, unknown>) {
  return Object.entries(payload)
    .slice(0, 3)
    .map(([k, v]) => {
      if (v && typeof v === 'object' && 'from' in (v as object) && 'to' in (v as object)) {
        const o = v as { from: unknown; to: unknown }
        return `${k} ${o.from ?? 'none'} → ${o.to ?? 'none'}`
      }
      return `${k} ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`
    })
    .join(', ')
}
