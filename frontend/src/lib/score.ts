// Closed-form risk from design §9. The console recomputes what-ifs with the same
// formula the engine uses, so a counterfactual on screen is arithmetic, not copy.

export type Priority = 'P1' | 'P2' | 'P3' | 'P4'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FactorKey = 'C' | 'S' | 'A' | 'Q'
export type Factors = Record<FactorKey, number>

export const EXPONENTS: Factors = { C: 0.35, S: 0.2, A: 0.3, Q: 0.15 }

export const FACTOR_NAMES: Record<FactorKey, string> = {
  C: 'Chain completeness',
  S: 'Severity',
  A: 'Asset impact',
  Q: 'Detector confidence',
}

// Capacity-calibrated: P1 holds what one shift can work (design §8.2).
export const BANDS: { priority: Priority; min: number }[] = [
  { priority: 'P1', min: 76.3 },
  { priority: 'P2', min: 50 },
  { priority: 'P3', min: 30 },
  { priority: 'P4', min: 0 },
]

export function risk(f: Factors): number {
  const r =
    100 * f.C ** EXPONENTS.C * f.S ** EXPONENTS.S * f.A ** EXPONENTS.A * f.Q ** EXPONENTS.Q
  return Math.round(r * 100) / 100
}

export function priorityOf(score: number): Priority {
  return (BANDS.find((b) => score >= b.min) ?? BANDS[BANDS.length - 1]).priority
}

export function severityOf(p: Priority): Severity {
  return ({ P1: 'critical', P2: 'high', P3: 'medium', P4: 'low' } as const)[p]
}

export function bandFloor(p: Priority): number {
  return BANDS.find((b) => b.priority === p)!.min
}

/** Solve one factor for a target score. Returns null when no value in [0,1] reaches it. */
export function solveFactor(f: Factors, key: FactorKey, target: number): number | null {
  let rest = 100
  for (const k of Object.keys(EXPONENTS) as FactorKey[]) {
    if (k !== key) rest *= f[k] ** EXPONENTS[k]
  }
  if (rest <= 0) return null
  const v = (target / rest) ** (1 / EXPONENTS[key])
  return v >= 0 && v <= 1 ? Math.round(v * 100) / 100 : null
}
