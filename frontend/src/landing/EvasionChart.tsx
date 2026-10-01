import { useState } from 'react'
import { ADVERSARY, BETAS, RECALL_FLOOR } from '../data/seed'
import { useMeasure } from '../lib/useMeasure'

const H = 170
const M = { top: 12, right: 12, bottom: 28, left: 34 }

export interface StrategySeries {
  key: string
  name: string
  note?: string
  floorAt: string | null
  on: readonly number[]
  off: readonly number[]
}
type Strategy = StrategySeries

/** One small multiple per strategy: recall against attacker budget β, with the 0.70 floor. */
function Multiple({ s, betas, floor }: { s: Strategy; betas: readonly number[]; floor: number }) {
  const [ref, width] = useMeasure<HTMLDivElement>(260)
  const [hover, setHover] = useState<number | null>(null)
  const iw = width - M.left - M.right
  const ih = H - M.top - M.bottom
  const x = (b: number) => M.left + b * iw
  const has = (vals: readonly number[]) => vals.length === betas.length
  const y = (r: number) => M.top + (1 - r) * ih
  const line = (vals: readonly number[]) => vals.map((v, i) => `${i ? 'L' : 'M'}${x(betas[i])} ${y(v)}`).join('')
  const same = !has(s.off) || !has(s.on) || s.on.every((v, i) => v === s.off[i])

  return (
    <figure className="evasion__fig">
      <figcaption>
        <strong>{s.name}</strong>
        <span>{s.floorAt ? `Below the floor at β = ${s.floorAt}` : 'Never below the floor'}</span>
      </figcaption>
      <div ref={ref} className="evasion__plot" onMouseLeave={() => setHover(null)}>
        <svg width={width} height={H} role="img" aria-label={`${s.name}: recall from ${s.on[0]} at β 0 to ${s.on[4]} at β 1 with the laundering pass on`}>
          {[0, 0.5, 1].map((r) => (
            <g key={r}>
              <line x1={M.left} x2={width - M.right} y1={y(r)} y2={y(r)} className="evasion__grid" />
              <text x={M.left - 8} y={y(r) + 4} textAnchor="end" className="evasion__tick tnum">
                {r.toFixed(1)}
              </text>
            </g>
          ))}
          {betas.filter((_, i) => i % 2 === 0).map((b) => (
            <text key={b} x={x(b)} y={H - 8} textAnchor="middle" className="evasion__tick tnum">
              {b}
            </text>
          ))}
          <line x1={M.left} x2={width - M.right} y1={y(floor)} y2={y(floor)} className="evasion__floor" />
          <text x={width - M.right} y={y(floor) - 5} textAnchor="end" className="evasion__floor-label tnum">
            floor {floor.toFixed(2)}
          </text>
          {hover !== null && (
            <line x1={x(betas[hover])} x2={x(betas[hover])} y1={M.top} y2={M.top + ih} className="evasion__cross" />
          )}
          {!same && <path d={line(s.off)} className="evasion__line evasion__line--off" />}
          <path d={line(s.on)} className="evasion__line evasion__line--on" />
          {!same &&
            s.off.map((v, i) => <circle key={`off${i}`} cx={x(betas[i])} cy={y(v)} r={4} className="evasion__pt evasion__pt--off" />)}
          {s.on.map((v, i) => (
            <circle key={`on${i}`} cx={x(betas[i])} cy={y(v)} r={hover === i ? 5.5 : 4} className="evasion__pt evasion__pt--on" />
          ))}
          {betas.map((b, i) => (
            <rect
              key={b}
              x={x(b) - iw / 8}
              y={M.top}
              width={iw / 4}
              height={ih}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
            />
          ))}
        </svg>
        {hover !== null && (
          <div className="evasion__tip tnum" style={{ left: Math.min(Math.max(x(betas[hover]), 70), width - 70) }}>
            <span>β = {betas[hover]}</span>
            <span>
              <i className="key key--on" aria-hidden /> on {s.on[hover].toFixed(2)}
            </span>
            <span>
              <i className="key key--off" aria-hidden /> off {s.off[hover].toFixed(2)}
            </span>
          </div>
        )}
      </div>
      {s.note && <p className="evasion__note">{s.note}</p>}
    </figure>
  )
}

interface ChartProps {
  data?: readonly StrategySeries[]
  betas?: readonly number[]
  floor?: number
  caption?: string
}

export function EvasionChart({ data = ADVERSARY, betas = BETAS, floor = RECALL_FLOOR, caption = 'Seeds 1 to 5.' }: ChartProps) {
  return (
    <div className="evasion">
      <div className="evasion__legend" aria-label="Legend">
        <span>
          <i className="key key--on" aria-hidden /> Laundering pass on
        </span>
        <span>
          <i className="key key--off" aria-hidden /> Laundering pass off (hidden where identical)
        </span>
        <span className="evasion__axes">Recall of detected scenarios (y) against attacker budget β (x). {caption}</span>
      </div>
      <div className="evasion__grid-wrap">
        {data.map((s) => (
          <Multiple key={s.key} s={s} betas={betas} floor={floor} />
        ))}
      </div>
      <details className="evasion__table">
        <summary>Show the numbers as a table</summary>
        <table>
          <thead>
            <tr>
              <th scope="col">Strategy</th>
              <th scope="col">Pass</th>
              {betas.map((b) => (
                <th key={b} scope="col">
                  β {b}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.flatMap((s) =>
              (['on', 'off'] as const).map((k) => (
                <tr key={s.key + k}>
                  <th scope="row">{s.name}</th>
                  <td>{k}</td>
                  {s[k].map((v, i) => (
                    <td key={i}>{v.toFixed(2)}</td>
                  ))}
                </tr>
              )),
            )}
          </tbody>
        </table>
      </details>
    </div>
  )
}
