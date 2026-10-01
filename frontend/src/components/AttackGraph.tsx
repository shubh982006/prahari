import { Desktop, Fingerprint, Globe, Hash, User, type Icon } from '@phosphor-icons/react'
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationNodeDatum } from 'd3-force'
import { motion, useReducedMotion } from 'framer-motion'
import { useMemo } from 'react'
import type { EntityType } from '../data/seed'
import type { GEdge, GNode, GraphData } from '../lib/graph'
import { EASE_OUT } from '../lib/motion'

const GLYPH: Record<EntityType, Icon> = { user: User, host: Desktop, ip: Globe, process: Fingerprint, hash: Hash }

interface Node extends SimulationNodeDatum {
  key: string
  entity: GNode
  text: string
  w: number
}

const W = 760
const NODE_H = 34
const MAX_LABEL = 22

function shorten(s: string) {
  return s.length > MAX_LABEL ? s.slice(0, MAX_LABEL - 1) + '…' : s
}

function layout(data: GraphData) {
  const H = Math.max(400, Math.min(680, data.nodes.length * 26))
  const nodes: Node[] = data.nodes.map((e) => {
    const text = shorten(e.label)
    return { key: e.key, entity: e, text, w: 44 + text.length * 6.8 + (e.criticality ? 34 : 0) }
  })
  const byKey = new Map(nodes.map((n) => [n.key, n]))
  const edges: GEdge[] = data.edges.filter((e) => byKey.has(e.source) && byKey.has(e.target))
  const links = edges.map((e) => ({ source: e.source, target: e.target }))

  forceSimulation(nodes)
    .force('link', forceLink<Node, { source: string; target: string }>(links).id((n) => n.key).distance(110).strength(0.6))
    .force('charge', forceManyBody().strength(-520))
    .force('collide', forceCollide<Node>((n) => n.w / 2 + 12))
    .force('x', forceX(0).strength(0.05))
    .force('y', forceY(0).strength(0.16))
    .stop()
    .tick(320)

  const xs = nodes.flatMap((n) => [n.x! - n.w / 2, n.x! + n.w / 2])
  const ys = nodes.flatMap((n) => [n.y! - NODE_H / 2, n.y! + NODE_H / 2])
  const [minX, maxX, minY, maxY] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)]
  const s = Math.min(1.35, (W - 40) / (maxX - minX || 1), (H - 40) / (maxY - minY || 1))
  const cx = (minX + maxX) / 2
  const cy = (minY + maxY) / 2
  for (const n of nodes) {
    n.x = W / 2 + (n.x! - cx) * s
    n.y = H / 2 + (n.y! - cy) * s
  }
  return { nodes, edges, byKey, H }
}

interface Props {
  data: GraphData
  /** Alert id whose entities should stand out. */
  highlight?: string | null
  label: string
}

export function AttackGraph({ data, highlight, label }: Props) {
  const reduce = useReducedMotion()
  const { nodes, edges, byKey, H } = useMemo(() => layout(data), [data])
  const focus = useMemo(() => {
    const keys = highlight ? data.alertEntities[highlight] : undefined
    return keys ? new Set(keys) : null
  }, [data, highlight])
  const hasBridge = edges.some((e) => e.bridge)

  if (nodes.length === 0) {
    return <p className="graph__empty">No entities recorded for this incident.</p>
  }

  return (
    <div className="graph">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label}>
        {edges.map((e, i) => {
          const a = byKey.get(e.source)!
          const b = byKey.get(e.target)!
          const lit = !focus || (focus.has(e.source) && focus.has(e.target))
          return (
            <motion.line
              key={`${data.id}-${e.source}-${e.target}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              className={`graph__edge ${e.bridge ? 'is-bridge' : ''}`}
              initial={reduce ? false : { pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: lit ? 1 : 0.15 }}
              transition={{
                pathLength: { duration: 0.5, delay: 0.25 + Math.min(i, 30) * 0.06, ease: EASE_OUT },
                opacity: { duration: 0.2 },
              }}
            />
          )
        })}
        {nodes.map((n, i) => {
          const G = GLYPH[n.entity.type] ?? Hash
          const lit = !focus || focus.has(n.key)
          const cls = ['graph__node', n.entity.crownJewel && 'is-jewel', n.entity.external && 'is-external']
            .filter(Boolean)
            .join(' ')
          return (
            <motion.g
              key={`${data.id}-${n.key}`}
              className={cls}
              initial={reduce ? false : { opacity: 0, scale: 0.9 }}
              animate={{ opacity: lit ? 1 : 0.28, scale: 1 }}
              transition={{ duration: 0.4, delay: reduce || focus ? 0 : Math.min(i, 30) * 0.03, ease: EASE_OUT }}
              style={{ transformOrigin: `${n.x}px ${n.y}px` }}
            >
              <title>
                {n.entity.type}: {n.entity.label}
                {n.entity.tags?.length ? ` · tagged ${n.entity.tags.join(', ')}` : ''}
              </title>
              <g transform={`translate(${n.x! - n.w / 2} ${n.y! - NODE_H / 2})`}>
                <rect width={n.w} height={NODE_H} rx={12} className="graph__box" />
                <g transform="translate(11 9)" className="graph__glyph">
                  <G size={16} />
                </g>
                <text x={33} y={NODE_H / 2 + 4} className="graph__label tnum">
                  {n.text}
                </text>
                {n.entity.criticality ? (
                  <g transform={`translate(${n.w - 36} 8)`}>
                    <rect width={30} height={18} rx={9} className="graph__crit" />
                    <text x={15} y={13} textAnchor="middle" className="graph__crit-text tnum">
                      C{n.entity.criticality}
                    </text>
                  </g>
                ) : null}
              </g>
            </motion.g>
          )
        })}
      </svg>
      <ul className="graph__legend" aria-label="Graph legend">
        <li>
          <span className="lg lg--jewel" aria-hidden /> Crown-jewel asset
        </li>
        <li>
          <span className="lg lg--ext" aria-hidden /> External address
        </li>
        {hasBridge && (
          <li>
            <span className="lg lg--bridge" aria-hidden /> Bridge: the only link between two parts
          </li>
        )}
        <li>
          <span className="lg lg--crit tnum" aria-hidden>
            C9
          </span>{' '}
          Asset criticality, 1–10
        </li>
      </ul>
    </div>
  )
}
