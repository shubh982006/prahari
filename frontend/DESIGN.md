# Prahari: Design

> encrypted vault behind midnight glass: a dark security console where the only color is a single violet signal lamp

The source of truth for values is `src/styles/tokens.css`. This file records the system and every place the implementation deliberately departs from the original style reference, with the reason.

## Overrides of the style reference

| Reference said | Shipped | Why |
|---|---|---|
| Inter everywhere | Helvetica Neue / Helvetica / Arial | Requested by the team. Helvetica's figures are tabular by default; `tabular-nums` is still set explicitly. |
| Nav inactive + link text in Steel Edge `#1b273d` | Ash Light `#a1abbd`; Steel Edge stays the underline/border color | Steel Edge on Midnight Ink is 1.3:1, unreadable. |
| Slate Mist `#647084` for muted body on dark | `--ink-3: #7c879a` on dark, Slate Mist on light | Slate Mist on Midnight Ink is 3.8:1, below AA for body text. |
| Prahari Violet `#7140fd` as text on dark | `--violet-text: #a58bff` on dark, `#7140fd` on light | `#7140fd` on Midnight Ink is 3.5:1. |
| 3px severity rail on queue rows | Severity chip + stage bar only | Rail duplicates the chip and is a side-stripe accent (impeccable ban). |
| Amber / red text on light sections | `--sev-*-ink` darker steps on light surfaces | `#f6b03c` on white is 1.9:1. |
| Shadow on dark showcase cards | 1px line border on dark, shadow only on light | An 8% midnight shadow is invisible on a midnight canvas; border and wide shadow are never combined. |

## Visual language (from the Status reference, 2026-09-30)

- **Inset sheets.** Light sections are rounded panels (`.sheet`, 20-32px radius) inset 8-20px from the viewport on the midnight canvas; they scale from 0.93 to 1 as they arrive.
- **Product blocks.** Pill tag, headline, body and 1px-bordered info cards beside a live mockup in window chrome. The console mockup bleeds off the card edge; a mockup carrying content that would be cut (compliance draft) stays inside.
- **Sticker illustrations** (`src/landing/art/`). Flat fills, 3px ink outlines, halftone shading. Original Prahari subjects: alert coins (severity glyph on each, so their colour still encodes severity), padlock, stopwatch, magnifier, CERT-In draft, crystals, a glitter stream, and the watchman: a violet face whose eyes follow the cursor and blink. Starburst and asterisk stickers use the pink stop of the brand gradient. Illustration colours live in `art/palette.ts`, never in UI tokens.
- **Page rhythm.** Dark hero, light sheet (stream, features, technique marquee, console), dark pinned collapse, light sheet (evidence bento, compliance), dark chain walk, dark watchman and misses, dark close.

## Color

Restrained. Tinted-slate neutrals, violet for brand + ATT&CK technique text, Signal Blue only on the single filled primary action per view. Severity tokens (`--sev-critical`, `--sev-high`, `--sev-medium`, `--sev-low`, `--sev-info`) encode severity and nothing else.

Chart categorical pair (adversary bench, validated with the dataviz validator against `#09101c`, all six checks pass): laundering pass on `#8b6dff` solid, off `#0e9fd8` dashed.

## Surfaces

Landing alternates dark and light sections at section boundaries only (`.on-dark`, `.on-light` re-scope the semantic tokens). The console follows the theme toggle (`data-theme` on `<html>`, dark default for the projector).

## Type

One family. Display 88px / 0.95 / -0.021em, heading 64px / -0.02em, heading-sm 27px, subheading 19px, body 15-16px, caption 11-13px. Console uses a fixed rem scale, never clamp.

## Shape

Buttons 12px, cards 20px (landing), panels 12px (console), tags and chips full pill, citation chips 4px.

## Motion

Framer Motion. Ease-out expo `[0.16, 1, 0.3, 1]` for entrances, 150-250ms for console state changes, no bounce. Landing: Lenis smooth scroll, scroll-linked parallax on the hero console and gradient orbs, a sticky scroll-scrubbed collapse (3,000 alerts to one thread) and a sticky kill-chain walk. Console: motion conveys state only (what-if score change, tab switch, clock pulse under 20%). `prefers-reduced-motion` renders every scrubbed or parallax element in its final state.
