// Synthetic excerpt shaped like a seed-42 run. Scenario incidents follow the
// planted scenarios in docs/failure-analysis.md; the rest is background noise,
// which is honest: 0.64 of a real top 10 is noise. Nothing here is live telemetry.

import {
  bandFloor,
  priorityOf,
  risk,
  severityOf,
  solveFactor,
  type FactorKey,
  type Factors,
  type Priority,
  type Severity,
} from '../lib/score'

export type Cohesion = 'solid' | 'moderate' | 'fragile'
export type EntityType = 'user' | 'host' | 'ip' | 'process' | 'hash'

// The backend's seven kill-chain lanes (GET /incidents/{id}/timeline), one-based here.
export const STAGES = [
  'Recon',
  'Initial access',
  'Execution & persistence',
  'Privilege & credentials',
  'Discovery & lateral movement',
  'Collection & C2',
  'Exfiltration & impact',
] as const

export interface Entity {
  key: string
  type: EntityType
  label: string
  criticality?: number
  tags?: string[]
  crownJewel?: boolean
  external?: boolean
}

export interface Alert {
  id: string
  /** seconds after the run window opens */
  t: number
  stage: number
  severity: Severity
  title: string
  technique: string
  entities: string[]
  onChain: boolean
}

export type BriefPart = string | { cite: string }

export interface Counterfactual {
  id: string
  kind: 'asset' | 'factor' | 'alert' | 'boundary'
  label: string
  patch?: Partial<Factors>
  closesCase?: boolean
  /** boundary rows */
  factor?: FactorKey
  target?: number | null
}

export interface SplitHalf {
  alerts: number
  maxStage: number
  headline: string
}

export interface Incident {
  id: string
  headline: string
  factors: Factors
  risk: number
  priority: Priority
  severity: Severity
  cohesion: Cohesion
  bridge?: { a: string; b: string; entity: string; weight: number }
  split?: { left: SplitHalf; right: SplitHalf }
  alertCount: number
  alerts: Alert[]
  entities: Entity[]
  maxStage: number
  techniques: string[]
  counterfactuals: Counterfactual[]
  brief: BriefPart[][]
  briefSource: 'narrator' | 'template'
  /** minutes before page load that the compliance trigger fired */
  complianceMinutesAgo?: number
}

/** 01:12:00 IST on the night of the run. */
export const WINDOW_START = Date.UTC(2026, 8, 28, 19, 42, 0)

const ENTITIES: Record<string, Entity> = {
  'ip:185.220.101.47': { key: 'ip:185.220.101.47', type: 'ip', label: '185.220.101.47', external: true },
  'ip:45.9.148.21': { key: 'ip:45.9.148.21', type: 'ip', label: '45.9.148.21', external: true },
  'ip:91.215.85.12': { key: 'ip:91.215.85.12', type: 'ip', label: '91.215.85.12', external: true },
  'ip:10.1.0.53': { key: 'ip:10.1.0.53', type: 'ip', label: '10.1.0.53' },
  'ip:10.4.2.19': { key: 'ip:10.4.2.19', type: 'ip', label: '10.4.2.19' },
  'host:vpn-gw-01': { key: 'host:vpn-gw-01', type: 'host', label: 'vpn-gw-01', criticality: 7 },
  'host:ws-fin-14': { key: 'host:ws-fin-14', type: 'host', label: 'ws-fin-14', criticality: 4 },
  'host:fin-db-01': {
    key: 'host:fin-db-01', type: 'host', label: 'fin-db-01', criticality: 9,
    tags: ['financial', 'pii'], crownJewel: true,
  },
  'host:fs-01': { key: 'host:fs-01', type: 'host', label: 'fs-01', criticality: 8, tags: ['pii'], crownJewel: true },
  'host:ws-ops-22': { key: 'host:ws-ops-22', type: 'host', label: 'ws-ops-22', criticality: 3 },
  'host:ws-mkt-03': { key: 'host:ws-mkt-03', type: 'host', label: 'ws-mkt-03', criticality: 2 },
  'host:hr-files-02': { key: 'host:hr-files-02', type: 'host', label: 'hr-files-02', criticality: 7, tags: ['pii'] },
  'host:jump-02': { key: 'host:jump-02', type: 'host', label: 'jump-02', criticality: 6 },
  'host:build-07': { key: 'host:build-07', type: 'host', label: 'build-07', criticality: 5 },
  'host:build-08': { key: 'host:build-08', type: 'host', label: 'build-08', criticality: 5 },
  'host:prn-vlan-gw': { key: 'host:prn-vlan-gw', type: 'host', label: 'prn-vlan-gw', criticality: 2 },
  'host:it-ops-07': { key: 'host:it-ops-07', type: 'host', label: 'it-ops-07', criticality: 4 },
  'host:m365-tenant': { key: 'host:m365-tenant', type: 'host', label: 'm365-tenant', criticality: 8, tags: ['pii'] },
  'user:r.mehta': { key: 'user:r.mehta', type: 'user', label: 'r.mehta' },
  'user:svc-backup': { key: 'user:svc-backup', type: 'user', label: 'svc-backup' },
  'user:k.nair': { key: 'user:k.nair', type: 'user', label: 'k.nair' },
  'user:a.iyer': { key: 'user:a.iyer', type: 'user', label: 'a.iyer' },
  'user:p.das': { key: 'user:p.das', type: 'user', label: 'p.das' },
  'user:admin-ops': { key: 'user:admin-ops', type: 'user', label: 'admin-ops' },
  'user:s.rao': { key: 'user:s.rao', type: 'user', label: 's.rao' },
  'process:powershell.exe': { key: 'process:powershell.exe', type: 'process', label: 'powershell.exe' },
  'process:schtasks.exe': { key: 'process:schtasks.exe', type: 'process', label: 'schtasks.exe' },
  'process:procdump64.exe': { key: 'process:procdump64.exe', type: 'process', label: 'procdump64.exe' },
  'process:sqlcmd.exe': { key: 'process:sqlcmd.exe', type: 'process', label: 'sqlcmd.exe' },
  'process:vssadmin.exe': { key: 'process:vssadmin.exe', type: 'process', label: 'vssadmin.exe' },
  'process:winword.exe': { key: 'process:winword.exe', type: 'process', label: 'winword.exe' },
  'process:rundll32.exe': { key: 'process:rundll32.exe', type: 'process', label: 'rundll32.exe' },
  'hash:9f2c41e0': { key: 'hash:9f2c41e0', type: 'hash', label: 'sha256 9f2c41e0' },
  'hash:c07a88d1': { key: 'hash:c07a88d1', type: 'hash', label: 'sha256 c07a88d1' },
  'hash:5be19f30': { key: 'hash:5be19f30', type: 'hash', label: 'sha256 5be19f30' },
}

type AlertTuple = [id: string, t: number, stage: number, sev: Severity, title: string, technique: string, entities: string[], onChain?: boolean]

function alerts(rows: AlertTuple[]): Alert[] {
  return rows
    .map(([id, t, stage, severity, title, technique, entities, onChain = true]) => ({
      id, t, stage, severity, title, technique, entities, onChain,
    }))
    .sort((a, b) => a.t - b.t || a.id.localeCompare(b.id))
}

interface Spec {
  id: string
  headline: string
  factors: Factors
  cohesion: Cohesion
  alertCount?: number
  alerts: Alert[]
  bridge?: Incident['bridge']
  split?: Incident['split']
  counterfactuals?: Counterfactual[]
  brief?: BriefPart[][]
  complianceMinutesAgo?: number
}

export function formatClock(t: number): string {
  const d = new Date(WINDOW_START + t * 1000 + 5.5 * 3600 * 1000)
  return d.toISOString().slice(11, 19)
}

function boundaryRows(f: Factors, pri: Priority): Counterfactual[] {
  const rows: Counterfactual[] = []
  const order: Priority[] = ['P1', 'P2', 'P3', 'P4']
  const idx = order.indexOf(pri)
  if (idx < 3) {
    const next = order[idx + 1]
    const target = bandFloor(pri) - 0.01
    const a = solveFactor(f, 'A', target)
    rows.push({
      id: 'b-down', kind: 'boundary', factor: 'A', target: a,
      label: a === null
        ? `asset impact alone cannot move this to ${next}`
        : `to fall to ${next}, asset impact would need to be ≤ ${a.toFixed(2)}`,
    })
  }
  if (idx > 0) {
    const up = order[idx - 1]
    const c = solveFactor(f, 'C', bandFloor(up))
    rows.push({
      id: 'b-up', kind: 'boundary', factor: 'C', target: c,
      label: c === null
        ? `no chain, however complete, lifts this to ${up}`
        : `to reach ${up}, chain completeness would need to be ≥ ${c.toFixed(2)}`,
    })
  }
  return rows
}

function templateCounterfactuals(spec: Spec, ents: Entity[], pri: Priority): Counterfactual[] {
  const f = spec.factors
  const host = ents.filter((e) => e.type === 'host').sort((a, b) => (b.criticality ?? 0) - (a.criticality ?? 0))[0]
  const rows: Counterfactual[] = []
  if (host) {
    rows.push({ id: 'cf-asset', kind: 'asset', label: `if ${host.label} were criticality 1`, patch: { A: Math.max(0.05, f.A * 0.35) } })
  }
  const last = spec.alerts[spec.alerts.length - 1]
  rows.push({ id: 'cf-alert', kind: 'alert', label: `remove ${last.id}`, patch: { C: Math.max(0.1, f.C - 0.14), S: Math.max(0.1, f.S - 0.05) } })
  rows.push({ id: 'cf-q', kind: 'factor', label: 'if detector confidence were 0.30', patch: { Q: 0.3 } })
  return [...rows, ...boundaryRows(f, pri)]
}

function templateBrief(a: Alert[], ents: Entity[]): BriefPart[][] {
  const first = a[0]
  const deepest = [...a].sort((x, y) => y.stage - x.stage || x.t - y.t)[0]
  const hosts = ents.filter((e) => e.type === 'host').map((e) => e.label)
  const stages = new Set(a.map((x) => x.stage)).size
  return [
    [
      `${a.length} alerts across ${stages} kill-chain stage${stages === 1 ? '' : 's'} between ${formatClock(first.t)} and ${formatClock(a[a.length - 1].t)} IST. The first was “${first.title}” `,
      { cite: first.id },
      '.',
    ],
    [
      `The furthest stage reached is ${STAGES[deepest.stage - 1].toLowerCase()}: “${deepest.title}” `,
      { cite: deepest.id },
      `. Hosts involved: ${hosts.join(', ') || 'none'}.`,
    ],
  ]
}

function build(spec: Spec): Incident {
  const score = risk(spec.factors)
  const pri = priorityOf(score)
  const keys = [...new Set(spec.alerts.flatMap((a) => a.entities))]
  const ents = keys.map((k) => ENTITIES[k]).filter(Boolean)
  const triggered =
    (pri === 'P1' || pri === 'P2') &&
    Math.max(...spec.alerts.map((a) => a.stage)) >= 6 &&
    ents.some((e) => e.tags?.some((t) => t === 'pii' || t === 'financial'))
  if (import.meta.env.DEV && triggered !== (spec.complianceMinutesAgo !== undefined)) {
    console.error(`${spec.id}: compliance trigger is ${triggered} but the seed says otherwise`)
  }
  return {
    id: spec.id,
    headline: spec.headline,
    factors: spec.factors,
    risk: score,
    priority: pri,
    severity: severityOf(pri),
    cohesion: spec.cohesion,
    bridge: spec.bridge,
    split: spec.split,
    alertCount: spec.alertCount ?? spec.alerts.length,
    alerts: spec.alerts,
    entities: ents,
    maxStage: Math.max(...spec.alerts.map((a) => a.stage)),
    techniques: [...new Set(spec.alerts.map((a) => a.technique))],
    counterfactuals: spec.counterfactuals ?? templateCounterfactuals(spec, ents, pri),
    brief: spec.brief ?? templateBrief(spec.alerts, ents),
    briefSource: spec.brief ? 'narrator' : 'template',
    complianceMinutesAgo: spec.complianceMinutesAgo,
  }
}

const A_FACTORS: Factors = { C: 1, S: 1, A: 1, Q: 0.93 }

const scenarioA = build({
  id: 'INC-3f9a1c2e',
  headline: 'Password spray to finance database exfiltration',
  factors: A_FACTORS,
  cohesion: 'solid',
  complianceMinutesAgo: 38,
  alerts: alerts([
    ['ALR-000118', 0, 1, 'low', 'Port sweep against the VPN gateway', 'T1595.001', ['ip:185.220.101.47', 'host:vpn-gw-01']],
    ['ALR-000137', 420, 2, 'medium', 'Password spray: 41 accounts, one password', 'T1110.003', ['ip:185.220.101.47', 'host:vpn-gw-01']],
    ['ALR-000142', 610, 2, 'high', 'VPN login succeeds after 40 failures', 'T1078', ['user:r.mehta', 'ip:185.220.101.47', 'host:vpn-gw-01']],
    ['ALR-000203', 1500, 3, 'medium', 'Encoded PowerShell under r.mehta', 'T1059.001', ['user:r.mehta', 'host:ws-fin-14', 'process:powershell.exe']],
    ['ALR-000207', 1640, 3, 'medium', 'Scheduled task created for persistence', 'T1053.005', ['host:ws-fin-14', 'process:schtasks.exe']],
    ['ALR-000512', 2280, 3, 'low', 'Unsigned binary written to temp', 'T1204.002', ['host:ws-fin-14', 'hash:9f2c41e0'], false],
    ['ALR-000311', 2900, 4, 'high', 'LSASS memory read by procdump64', 'T1003.001', ['host:ws-fin-14', 'process:procdump64.exe', 'hash:9f2c41e0']],
    ['ALR-000455', 3600, 4, 'high', 'svc-backup used outside its 02:00 window', 'T1078.002', ['user:svc-backup', 'host:ws-fin-14']],
    ['ALR-000731', 4380, 5, 'high', 'Admin share on fin-db-01 opened from a workstation', 'T1021.002', ['user:svc-backup', 'host:ws-fin-14', 'host:fin-db-01']],
    ['ALR-000736', 4500, 5, 'critical', 'Remote service created on fin-db-01', 'T1569.002', ['user:svc-backup', 'host:fin-db-01']],
    ['ALR-000958', 5900, 6, 'high', 'Database dump staged: 2.3 GB', 'T1005', ['host:fin-db-01', 'process:sqlcmd.exe']],
    ['ALR-001102', 6800, 7, 'critical', 'Outbound 2.3 GB to the spray source', 'T1048.003', ['host:fin-db-01', 'ip:185.220.101.47']],
  ]),
  counterfactuals: [
    { id: 'cf-1', kind: 'asset', label: 'if fin-db-01 were not tagged financial', patch: { A: 0.2 }, closesCase: true },
    { id: 'cf-2', kind: 'alert', label: 'remove ALR-001102', patch: { A: 0.42 }, closesCase: true },
    { id: 'cf-3', kind: 'factor', label: 'if the chain stopped at lateral movement', patch: { C: 0.73 } },
    { id: 'cf-4', kind: 'factor', label: 'if detector confidence were 0.30', patch: { Q: 0.3 } },
    ...boundaryRows(A_FACTORS, 'P1'),
  ],
  brief: [
    [
      'At 01:19 IST an external address, 185.220.101.47, sprayed one password across 41 VPN accounts ',
      { cite: 'ALR-000137' },
      '. Three minutes later r.mehta logged in from that address ',
      { cite: 'ALR-000142' },
      ', and within fifteen minutes an encoded PowerShell command ran on ws-fin-14 under the same account ',
      { cite: 'ALR-000203' },
      '.',
    ],
    [
      'LSASS memory was read on ws-fin-14 ',
      { cite: 'ALR-000311' },
      '. The svc-backup account, which normally runs only at 02:00, was then used from that workstation ',
      { cite: 'ALR-000455' },
      ' to open the admin share on fin-db-01 ',
      { cite: 'ALR-000731' },
      '.',
    ],
    [
      'A 2.3 GB database dump was staged ',
      { cite: 'ALR-000958' },
      ' and sent to the address that started the spray ',
      { cite: 'ALR-001102' },
      '. fin-db-01 is tagged financial and pii, so the CERT-In and DPDP clocks started at detection.',
    ],
  ],
})

const scenarioD = build({
  id: 'INC-8c21d0b7',
  headline: 'Ransomware staging on the file server',
  factors: { C: 0.95, S: 1, A: 0.9, Q: 0.88 },
  cohesion: 'solid',
  complianceMinutesAgo: 295,
  alerts: alerts([
    ['ALR-000402', 900, 2, 'medium', 'Phishing link clicked on ws-ops-22', 'T1566.002', ['user:k.nair', 'host:ws-ops-22']],
    ['ALR-000418', 1260, 3, 'high', 'rundll32 loading a DLL from AppData', 'T1218.011', ['host:ws-ops-22', 'process:rundll32.exe', 'hash:c07a88d1']],
    ['ALR-000466', 2100, 4, 'high', 'Kerberoasting burst from ws-ops-22', 'T1558.003', ['host:ws-ops-22', 'user:admin-ops']],
    ['ALR-000603', 3300, 5, 'high', 'admin-ops logs on to fs-01 over RDP', 'T1021.001', ['user:admin-ops', 'host:ws-ops-22', 'host:fs-01']],
    ['ALR-000640', 3720, 7, 'critical', 'Shadow copies deleted on fs-01', 'T1490', ['host:fs-01', 'process:vssadmin.exe', 'user:admin-ops']],
    ['ALR-000644', 3790, 7, 'critical', '14,000 files renamed in 90 seconds', 'T1486', ['host:fs-01', 'hash:c07a88d1']],
    ['ALR-000651', 3200, 1, 'low', 'SMB share listing from ws-ops-22', 'T1135', ['host:ws-ops-22', 'host:fs-01'], false],
  ]),
})

const scenarioC = build({
  id: 'INC-51e0aa94',
  headline: 'MFA fatigue to cloud mailbox export',
  factors: { C: 0.86, S: 0.8, A: 0.55, Q: 0.9 },
  cohesion: 'moderate',
  complianceMinutesAgo: 52,
  alerts: alerts([
    ['ALR-000220', 1800, 2, 'medium', '23 MFA pushes to a.iyer in 6 minutes', 'T1621', ['user:a.iyer', 'ip:45.9.148.21', 'host:m365-tenant']],
    ['ALR-000233', 2230, 2, 'high', 'MFA approved from a new country', 'T1078.004', ['user:a.iyer', 'ip:45.9.148.21', 'host:m365-tenant']],
    ['ALR-000260', 2700, 3, 'medium', 'Inbox forwarding rule to external address', 'T1114.003', ['user:a.iyer', 'host:m365-tenant']],
    ['ALR-000318', 3900, 4, 'medium', 'OAuth app granted mail.read', 'T1528', ['user:a.iyer', 'host:m365-tenant']],
    ['ALR-000377', 5100, 7, 'high', 'Mailbox export job: 4.1 GB', 'T1114.002', ['user:a.iyer', 'host:m365-tenant', 'ip:45.9.148.21']],
  ]),
})

const scenarioB = build({
  id: 'INC-0d7f3b62',
  headline: 'Phishing attachment to C2 beacon on a workstation',
  factors: { C: 0.72, S: 0.8, A: 0.4, Q: 0.85 },
  cohesion: 'solid',
  alerts: alerts([
    ['ALR-000604', 3400, 2, 'medium', 'Macro document opened by p.das', 'T1566.001', ['user:p.das', 'host:ws-mkt-03', 'process:winword.exe']],
    ['ALR-000611', 3460, 3, 'high', 'Word spawned PowerShell', 'T1059.001', ['host:ws-mkt-03', 'process:winword.exe', 'process:powershell.exe']],
    ['ALR-000615', 3530, 3, 'medium', 'Run key added for a signed-looking binary', 'T1547.001', ['host:ws-mkt-03', 'hash:5be19f30']],
    ['ALR-000690', 4100, 3, 'high', 'Beacon every 60 s ±2 s to 91.215.85.12', 'T1071.001', ['host:ws-mkt-03', 'ip:91.215.85.12', 'hash:5be19f30']],
  ]),
})

const fragile = build({
  id: 'INC-a4402e19',
  headline: 'VPN access and lateral SMB on the 10.1 subnet',
  factors: { C: 0.8, S: 0.6, A: 0.5, Q: 0.7 },
  cohesion: 'fragile',
  alertCount: 37,
  complianceMinutesAgo: 170,
  bridge: { a: 'ALR-002455', b: 'ALR-002731', entity: 'ip:10.1.0.53', weight: 3.11 },
  split: {
    left: { alerts: 22, maxStage: 3, headline: 'Password spray to VPN access' },
    right: { alerts: 15, maxStage: 6, headline: 'Lateral movement to hr-files-02' },
  },
  alerts: alerts([
    ['ALR-002401', 600, 2, 'medium', 'Password spray against VPN', 'T1110.003', ['host:vpn-gw-01', 'ip:10.1.0.53']],
    ['ALR-002433', 1300, 2, 'medium', 'VPN login from a shared NAT address', 'T1078', ['user:s.rao', 'ip:10.1.0.53', 'host:vpn-gw-01']],
    ['ALR-002455', 2000, 3, 'low', 'Script host started by s.rao', 'T1059.005', ['user:s.rao', 'ip:10.1.0.53']],
    ['ALR-002731', 4400, 5, 'high', 'SMB session to hr-files-02 from 10.1.0.53', 'T1021.002', ['ip:10.1.0.53', 'host:hr-files-02', 'user:admin-ops']],
    ['ALR-002760', 4900, 5, 'high', 'admin-ops enumerates HR shares', 'T1135', ['user:admin-ops', 'host:hr-files-02']],
    ['ALR-002788', 5600, 6, 'medium', 'Credential file read on hr-files-02', 'T1552.001', ['user:admin-ops', 'host:hr-files-02']],
  ]),
})

const noise = [
  build({
    id: 'INC-e603b2f8', headline: 'Impossible travel for a.iyer', factors: { C: 0.45, S: 0.8, A: 0.6, Q: 0.8 }, cohesion: 'solid',
    alerts: alerts([
      ['ALR-001210', 7200, 2, 'high', 'Sign-in from two countries 40 minutes apart', 'T1078.004', ['user:a.iyer', 'ip:45.9.148.21', 'host:m365-tenant']],
      ['ALR-001214', 7400, 2, 'medium', 'Legacy auth protocol used', 'T1078', ['user:a.iyer', 'host:m365-tenant']],
    ]),
  }),
  build({
    id: 'INC-7b19c3e0', headline: 'Repeated failed logins on jump-02', factors: { C: 0.3, S: 0.5, A: 0.6, Q: 0.6 }, cohesion: 'solid',
    alerts: alerts([
      ['ALR-000981', 5000, 2, 'medium', '118 failed SSH logins in 10 minutes', 'T1110.001', ['host:jump-02', 'ip:10.4.2.19']],
      ['ALR-000990', 5600, 1, 'low', 'Host discovery from 10.4.2.19', 'T1018', ['ip:10.4.2.19', 'host:jump-02']],
      ['ALR-001004', 6100, 2, 'medium', 'Failed sudo by admin-ops', 'T1548.003', ['host:jump-02', 'user:admin-ops']],
    ]),
  }),
  build({
    id: 'INC-c2e8f471', headline: 'Unsigned driver loaded on two build agents', factors: { C: 0.35, S: 0.6, A: 0.4, Q: 0.5 }, cohesion: 'moderate',
    alerts: alerts([
      ['ALR-001305', 8000, 3, 'medium', 'Unsigned kernel driver loaded', 'T1543.003', ['host:build-07', 'hash:5be19f30']],
      ['ALR-001311', 8120, 3, 'medium', 'Same driver hash on a second host', 'T1543.003', ['host:build-08', 'hash:5be19f30']],
      ['ALR-001340', 8600, 3, 'low', 'Service registered at boot', 'T1543.003', ['host:build-08']],
    ]),
  }),
  build({
    id: 'INC-19aa6d05', headline: 'DNS tunnelling heuristic on the printer VLAN', factors: { C: 0.25, S: 0.5, A: 0.2, Q: 0.4 }, cohesion: 'solid',
    alerts: alerts([
      ['ALR-001502', 9100, 7, 'medium', 'Long TXT queries from the printer gateway', 'T1071.004', ['host:prn-vlan-gw', 'ip:91.215.85.12']],
      ['ALR-001533', 9800, 7, 'low', 'High-entropy subdomains, 312 queries', 'T1048', ['host:prn-vlan-gw']],
    ]),
  }),
  build({
    id: 'INC-2f5c9e1a', headline: 'Admin share enumeration from it-ops-07', factors: { C: 0.2, S: 0.4, A: 0.3, Q: 0.5 }, cohesion: 'solid',
    alerts: alerts([
      ['ALR-001620', 10200, 1, 'low', 'net view against 44 hosts', 'T1135', ['host:it-ops-07', 'user:admin-ops']],
      ['ALR-001628', 10260, 1, 'low', 'Remote registry queried', 'T1012', ['host:it-ops-07']],
    ]),
  }),
]

export const INCIDENTS: Incident[] = [scenarioA, scenarioD, scenarioC, fragile, noise[0], scenarioB, ...noise.slice(1)].sort(
  (a, b) => b.risk - a.risk || a.id.localeCompare(b.id),
)

export const FEATURED = scenarioA

export function getIncident(id: string | undefined): Incident | undefined {
  return INCIDENTS.find((i) => i.id === id)
}

export function entityOf(key: string): Entity | undefined {
  return ENTITIES[key]
}

// Measured numbers from docs/failure-analysis.md and docs/results.
export const ADVERSARY = [
  { key: 'temporal_dilation', name: 'Temporal dilation', note: 'Stretches the gaps between stages past the link window.', on: [1, 0.5, 0, 0, 0], off: [1, 0.5, 0, 0, 0], floorAt: '0.15' },
  { key: 'supernode_laundering', name: 'Supernode laundering', note: 'Routes the shared entity through a stop-listed one.', on: [1, 0.8, 0.55, 0.25, 0.35], off: [1, 0.8, 0.5, 0.1, 0], floorAt: '0.35' },
  { key: 'entity_rotation', name: 'Entity rotation', note: 'Fresh account and IP at each stage with probability β.', on: [1, 0.9, 0.95, 0.7, 0.5], off: [1, 0.9, 0.95, 0.7, 0.5], floorAt: '0.75' },
  { key: 'noise_flood', name: 'Noise flood', note: '400 decoy alerts on a criticality-9 asset at β = 1.', on: [1, 1, 1, 1, 1], off: [1, 1, 1, 1, 1], floorAt: null },
] as const

export const BETAS = [0, 0.25, 0.5, 0.75, 1]
export const RECALL_FLOOR = 0.7

export const SCENARIO_RESULTS = [
  { id: 'A', name: 'Password spray to finance database exfiltration', detected: 10, rank: '1–2' },
  { id: 'B', name: 'Phishing to C2 beacon on a workstation', detected: 10, rank: '4–14' },
  { id: 'C', name: 'MFA fatigue to cloud data theft', detected: 10, rank: '4–7' },
  { id: 'D', name: 'Ransomware on the file server', detected: 10, rank: '1–2' },
  { id: 'E', name: 'Low-and-slow credential theft', detected: 0, rank: null, why: 'Steps are further apart than the 2 h link window.' },
  { id: 'F', name: 'Entity switching across stages', detected: 0, rank: null, why: 'Each stage uses a different account and IP.' },
] as const
