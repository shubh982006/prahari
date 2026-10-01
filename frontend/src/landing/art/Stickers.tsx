// Flat, thick-outlined sticker illustrations with halftone shading.
// Illustration colours are art, not UI: severity hues appear only on alert coins,
// where they still encode severity.

import { useId, type SVGProps } from 'react'
import { ART, INK } from './palette'

type Props = SVGProps<SVGSVGElement>

function useSafeId(prefix: string) {
  return prefix + useId().replace(/[^a-zA-Z0-9]/g, '')
}

function Halftone({ id, color, gap = 5, r = 1.1 }: { id: string; color: string; gap?: number; r?: number }) {
  return (
    <pattern id={id} width={gap} height={gap} patternUnits="userSpaceOnUse">
      <circle cx={gap / 2} cy={gap / 2} r={r} fill={color} />
    </pattern>
  )
}

function polygon(n: number, r: number, rot = 0) {
  return Array.from({ length: n }, (_, i) => {
    const a = rot + (i * 2 * Math.PI) / n
    return `${(Math.cos(a) * r).toFixed(2)},${(Math.sin(a) * r).toFixed(2)}`
  }).join(' ')
}

const TONES = {
  critical: { face: ART.red, rim: ART.redDark, glyph: 'octagon' },
  high: { face: ART.amber, rim: ART.amberDark, glyph: 'triangle' },
  low: { face: ART.green, rim: ART.greenDark, glyph: 'circle' },
  lock: { face: ART.blue, rim: ART.blueDark, glyph: 'lock' },
} as const

/** A tilted coin carrying a severity glyph: one alert. */
export function AlertCoin({ tone = 'high', ...props }: Props & { tone?: keyof typeof TONES }) {
  const t = TONES[tone]
  const dots = useSafeId('coin')
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <defs>
        <Halftone id={dots} color={INK} gap={4} r={0.9} />
      </defs>
      <ellipse cx="50" cy="60" rx="41" ry="24" fill={t.rim} stroke={INK} strokeWidth="3" />
      <rect x="9" y="46" width="82" height="14" fill={t.rim} />
      <rect x="9" y="46" width="82" height="14" fill={`url(#${dots})`} opacity="0.35" />
      <path d="M9 46v14M91 46v14" stroke={INK} strokeWidth="3" />
      <ellipse cx="50" cy="46" rx="41" ry="24" fill={t.face} stroke={INK} strokeWidth="3" />
      <ellipse cx="50" cy="46" rx="31" ry="17" fill="none" stroke={t.rim} strokeWidth="2.5" />
      <g transform="translate(50 46) scale(1 0.6)" fill={tone === 'lock' ? '#fff' : INK}>
        {t.glyph === 'octagon' && <polygon points={polygon(8, 15, Math.PI / 8)} />}
        {t.glyph === 'triangle' && <path d="M0 -16 L16 12 H-16 Z" />}
        {t.glyph === 'circle' && <circle r="13" />}
        {t.glyph === 'lock' && (
          <>
            <rect x="-11" y="-4" width="22" height="16" rx="3" />
            <path d="M-6 -4 v-5 a6 6 0 0 1 12 0 v5" fill="none" stroke="#fff" strokeWidth="4" />
          </>
        )}
      </g>
      {t.glyph !== 'lock' && (
        <g transform="translate(50 46) scale(1 0.6)" fill={t.face}>
          {t.glyph === 'octagon' && <rect x="-2.5" y="-9" width="5" height="18" rx="2" />}
          {t.glyph === 'triangle' && <rect x="-2" y="-6" width="4" height="12" rx="2" />}
        </g>
      )}
    </svg>
  )
}

export function Padlock(props: Props) {
  const dots = useSafeId('lock')
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <defs>
        <Halftone id={dots} color={ART.violetDark} gap={4} r={1.2} />
        <clipPath id={`${dots}c`}>
          <rect x="20" y="42" width="60" height="46" rx="9" />
        </clipPath>
      </defs>
      <path d="M34 46V33a16 16 0 0 1 32 0v13" fill="none" stroke={INK} strokeWidth="13" strokeLinecap="round" />
      <path d="M34 46V33a16 16 0 0 1 32 0v13" fill="none" stroke={ART.steel} strokeWidth="6.5" strokeLinecap="round" />
      <rect x="20" y="42" width="60" height="46" rx="9" fill={ART.violet} />
      <rect x="54" y="42" width="30" height="50" fill={`url(#${dots})`} clipPath={`url(#${dots}c)`} />
      <rect x="20" y="42" width="60" height="46" rx="9" fill="none" stroke={INK} strokeWidth="3" />
      <rect x="27" y="49" width="6" height="30" rx="3" fill={ART.violetLight} />
      <circle cx="50" cy="61" r="6.5" fill={INK} />
      <path d="M46.5 63 L44.5 76 H55.5 L53.5 63 Z" fill={INK} />
    </svg>
  )
}

export function Stopwatch(props: Props) {
  const dots = useSafeId('watch')
  const ticks = Array.from({ length: 12 }, (_, i) => i * 30)
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <defs>
        <Halftone id={dots} color={ART.amberDark} gap={4} r={1.1} />
      </defs>
      <rect x="41" y="3" width="18" height="8" rx="3" fill={INK} />
      <rect x="45" y="9" width="10" height="10" fill={ART.amber} stroke={INK} strokeWidth="3" />
      <path d="M73 21l8-7 6 7-8 7z" fill={ART.amber} stroke={INK} strokeWidth="2.5" strokeLinejoin="round" />
      <circle cx="50" cy="57" r="37" fill={ART.amber} stroke={INK} strokeWidth="3" />
      <circle cx="50" cy="57" r="37" fill={`url(#${dots})`} opacity="0.6" />
      <circle cx="50" cy="57" r="28" fill={ART.cream} stroke={INK} strokeWidth="2.5" />
      <path d="M50 57 L50 29 A28 28 0 0 1 74.2 71 Z" fill={ART.pink} opacity="0.28" />
      {ticks.map((a) => (
        <line key={a} x1="50" y1="32" x2="50" y2={a % 90 === 0 ? 37 : 35} stroke={INK} strokeWidth="2" transform={`rotate(${a} 50 57)`} />
      ))}
      <line x1="50" y1="57" x2="50" y2="36" stroke={INK} strokeWidth="3.5" strokeLinecap="round" />
      <line x1="50" y1="57" x2="66" y2="66" stroke={ART.pink} strokeWidth="3" strokeLinecap="round" />
      <circle cx="50" cy="57" r="3.5" fill={INK} />
    </svg>
  )
}

export function Magnifier(props: Props) {
  const dots = useSafeId('lens')
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <defs>
        <Halftone id={dots} color={ART.tealDark} gap={4} r={0.9} />
      </defs>
      <line x1="61" y1="62" x2="86" y2="87" stroke={INK} strokeWidth="15" strokeLinecap="round" />
      <line x1="62" y1="63" x2="85" y2="86" stroke={ART.pink} strokeWidth="8" strokeLinecap="round" />
      <circle cx="42" cy="42" r="30" fill={INK} />
      <circle cx="42" cy="42" r="24.5" fill="#cdeef5" />
      <circle cx="42" cy="42" r="24.5" fill={`url(#${dots})`} opacity="0.45" />
      <path d="M30 50 L41 36 L54 47" fill="none" stroke={INK} strokeWidth="2.5" strokeLinejoin="round" />
      <circle cx="30" cy="50" r="4.5" fill={ART.amber} stroke={INK} strokeWidth="2" />
      <circle cx="41" cy="36" r="4.5" fill={ART.red} stroke={INK} strokeWidth="2" />
      <circle cx="54" cy="47" r="4.5" fill={ART.amber} stroke={INK} strokeWidth="2" />
      <path d="M26 31a19 19 0 0 1 12-9" fill="none" stroke="#fff" strokeWidth="4" strokeLinecap="round" />
    </svg>
  )
}

export function ReportDoc(props: Props) {
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <path d="M20 8H62L82 28V92H20Z" fill="#fff" stroke={INK} strokeWidth="3" strokeLinejoin="round" />
      <path d="M62 8V28H82" fill="#e6e9ee" stroke={INK} strokeWidth="3" strokeLinejoin="round" />
      <rect x="29" y="20" width="24" height="6" rx="2" fill={INK} />
      {[38, 47, 56, 65].map((y, i) => (
        <rect key={y} x="29" y={y} width={[44, 36, 42, 26][i]} height="4" rx="2" fill="#c3c9d2" />
      ))}
      <g transform="rotate(-14 64 76)">
        <circle cx="64" cy="76" r="14" fill={ART.pink} stroke={INK} strokeWidth="2.5" />
        <text x="64" y="80.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#fff" fontFamily="Helvetica, Arial, sans-serif">
          6h
        </text>
      </g>
    </svg>
  )
}

export function Crystal({ tone = 'teal', ...props }: Props & { tone?: 'teal' | 'violet' }) {
  const [a, b] = tone === 'teal' ? [ART.teal, ART.tealDark] : [ART.violetLight, ART.violet]
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <path d="M50 6L80 34L60 94H40L20 34Z" fill={a} />
      <path d="M60 34H80L60 94H50Z" fill={b} />
      <path d="M50 6L80 34L60 94H40L20 34Z" fill="none" stroke={INK} strokeWidth="3" strokeLinejoin="round" />
      <path d="M20 34H80M50 6L40 34L50 94M50 6L60 34L50 94" fill="none" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
    </svg>
  )
}

export function Sparkle(props: Props) {
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <path d="M50 0C54 36 64 46 100 50C64 54 54 64 50 100C46 64 36 54 0 50C36 46 46 36 50 0Z" fill="currentColor" />
    </svg>
  )
}

export function Starburst({ spikes = 18, ...props }: Props & { spikes?: number }) {
  const pts = Array.from({ length: spikes * 2 }, (_, i) => {
    const a = (i * Math.PI) / spikes - Math.PI / 2
    const r = i % 2 === 0 ? 48 - ((i * 7) % 5) : 30 + ((i * 3) % 4)
    return `${(50 + Math.cos(a) * r).toFixed(2)},${(50 + Math.sin(a) * r).toFixed(2)}`
  }).join(' ')
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <polygon points={pts} fill={ART.pink} />
    </svg>
  )
}

export function AsteriskBadge(props: Props) {
  return (
    <svg viewBox="0 0 100 100" aria-hidden {...props}>
      <circle cx="50" cy="50" r="48" fill="#fff" />
      <g fill={ART.pink} transform="rotate(12 50 50)">
        {[0, 60, 120].map((a) => (
          <rect key={a} x="43" y="22" width="14" height="56" rx="7" transform={`rotate(${a} 50 50)`} />
        ))}
      </g>
    </svg>
  )
}

/* ---- 40px feature icons ---- */

export function ChainIcon(props: Props) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden {...props}>
      <rect x="4" y="16" width="24" height="14" rx="7" fill="none" stroke={INK} strokeWidth="6" />
      <rect x="4" y="16" width="24" height="14" rx="7" fill="none" stroke={ART.amber} strokeWidth="2.5" />
      <rect x="20" y="18" width="24" height="14" rx="7" fill="none" stroke={INK} strokeWidth="6" />
      <rect x="20" y="18" width="24" height="14" rx="7" fill="none" stroke={ART.blue} strokeWidth="2.5" />
    </svg>
  )
}

export function SplitIcon(props: Props) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden {...props}>
      <path d="M13 24H21M27 24H35" stroke={INK} strokeWidth="3" strokeLinecap="round" strokeDasharray="0.1 6" />
      <path d="M22 18L26 30" stroke={ART.pink} strokeWidth="3" strokeLinecap="round" />
      <circle cx="10" cy="24" r="7" fill={ART.teal} stroke={INK} strokeWidth="2.5" />
      <circle cx="38" cy="24" r="7" fill={ART.amber} stroke={INK} strokeWidth="2.5" />
    </svg>
  )
}

export function DialIcon(props: Props) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden {...props}>
      <path d="M6 34a18 18 0 0 1 36 0Z" fill={ART.cream} stroke={INK} strokeWidth="2.5" strokeLinejoin="round" />
      <path d="M6 34a18 18 0 0 1 9-15.6L24 34Z" fill={ART.violetLight} />
      <path d="M6 34a18 18 0 0 1 36 0Z" fill="none" stroke={INK} strokeWidth="2.5" strokeLinejoin="round" />
      <line x1="24" y1="34" x2="34" y2="20" stroke={INK} strokeWidth="3" strokeLinecap="round" />
      <circle cx="24" cy="34" r="3.5" fill={ART.pink} stroke={INK} strokeWidth="2" />
    </svg>
  )
}
