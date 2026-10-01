# Product

## Register

product

## Users

SOC analysts on a night shift in a dim room, working a queue of correlated incidents, and hackathon judges watching the same console on a projector. The analyst's job is to decide, fast, which incident to work first, whether the grouping can be trusted, and whether a regulatory clock is running. The judge's job is to decide whether the team really built what it claims.

A short public landing page at `/` serves the judges and links into the console. That page is the only brand-register surface; everything under `/console` is product register.

## Product Purpose

Prahari correlates thousands of security alerts into a short, ranked list of incidents, explains every score with counterfactuals, reports its own uncertainty about each grouping (cohesion), and starts the CERT-In and DPDP clocks when sensitive data is touched. Success is an analyst reaching the first real attack sooner, and a judge leaving convinced the numbers on screen are measured, not invented.

## Brand Personality

Precise, candid, calm. Exact numbers with their error bars. States its own misses plainly (the failure analysis is a feature, not a footnote). Never alarmist: severity color is rationed so that when red appears it means something.

## Anti-references

- Generic SIEM dashboards: walls of donut charts, neon-on-black "hacker" styling, stock photos of hooded figures.
- SaaS landing templates: hero metric strips, identical three-card feature grids, gradient headline text.
- Overconfident AI copy ("detects every attack", "zero false positives").

## Design Principles

1. **Show the measured number.** Every claim on screen links to a figure from `docs/failure-analysis.md` or the benchmarks, including the unflattering ones.
2. **Uncertainty is a first-class output.** Cohesion, error bars and unreachable counterfactuals are rendered, never hidden.
3. **Color means something or it is absent.** Severity tokens encode severity only; violet marks brand and ATT&CK; blue marks the one primary action.
4. **The product is the imagery.** Real console components, not screenshots of mockups and not stock art.
5. **Density for the analyst, air for the judge.** The console is dense and fast; the landing page breathes.

## Accessibility & Inclusion

WCAG 2.2 AA. Severity is always glyph + label + color (amber and red are hard to tell apart for roughly 1 in 12 men). Tabular figures on every identifier and number. Full keyboard support in the queue (j/k, Enter). `prefers-reduced-motion` disables parallax, smooth scrolling and scroll-scrubbed drawing; content renders in its final state. Projector contrast: body text at 4.5:1 minimum on the midnight canvas.
