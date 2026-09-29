# Adversary bench — measured results

Every number on this page was produced by running the code and copied by script from the files next to it. Nothing is estimated.

## Provenance

- Code: commit `3ef5033` on `feat/backend-completion`; engine `2.0.0`, ATT&CK `19.0`, SQLite dialect (`meta.json`).
- Config: link window `2h`, supernode ratio `0.05` (min df 20), calibrated bands, weights C 0.35 · S 0.20 · A 0.30 · Q 0.15. `mitigated` toggles the laundering pass (design §6.4) and nothing else.
- Run on 29 Sep 2026, LLM disabled, no network.

## 1. API campaigns on the demo dataset (seed 42)

`POST /api/v1/adversary/campaigns` with `base_dataset=ds_20260929_s42`, `seed=42`, budgets `0, 0.25, 0.5, 0.75, 1`, once per (strategy, mitigated). `curve.json` is the verbatim `GET /adversary/curve` response; `campaigns.json` is each `GET /adversary/campaigns/{id}`.

Scenario recall (over the 4 scenarios detected at β=0; floor 0.70):

| strategy | mitigated | β=0 | β=0.25 | β=0.5 | β=0.75 | β=1 | crosses floor at β |
| --- | --- | --- | --- | --- | --- | --- | --- |
| temporal_dilation | no | 1.00 | 0.50 | 0.00 | 0.00 | 0.00 | 0.15 |
| temporal_dilation | yes | 1.00 | 0.50 | 0.00 | 0.00 | 0.00 | 0.15 |
| supernode_laundering | no | 1.00 | 1.00 | 0.50 | 0.00 | 0.00 | 0.4 |
| supernode_laundering | yes | 1.00 | 1.00 | 0.75 | 0.75 | 0.50 | 0.8 |

Per-budget detail (pairwise precision / recall over alert pairs, total incidents, whether scenario A was detected and its rank):

| strategy | mitigated | β | recall | pair P | pair R | incidents | A detected | A rank |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| temporal_dilation | no | 0 | 1.00 | 0.52 | 0.90 | 147 | yes | 2 |
| temporal_dilation | no | 0.25 | 0.50 | 0.47 | 0.36 | 157 | no | — |
| temporal_dilation | no | 0.5 | 0.00 | 0.04 | 0.13 | 164 | no | — |
| temporal_dilation | no | 0.75 | 0.00 | 0.07 | 0.12 | 165 | no | — |
| temporal_dilation | no | 1 | 0.00 | 0.10 | 0.11 | 168 | no | — |
| temporal_dilation | yes | 0 | 1.00 | 0.52 | 0.90 | 146 | yes | 1 |
| temporal_dilation | yes | 0.25 | 0.50 | 0.47 | 0.36 | 156 | no | — |
| temporal_dilation | yes | 0.5 | 0.00 | 0.04 | 0.13 | 163 | no | — |
| temporal_dilation | yes | 0.75 | 0.00 | 0.07 | 0.12 | 164 | no | — |
| temporal_dilation | yes | 1 | 0.00 | 0.10 | 0.11 | 167 | no | — |
| supernode_laundering | no | 0 | 1.00 | 0.52 | 0.90 | 147 | yes | 1 |
| supernode_laundering | no | 0.25 | 1.00 | 0.48 | 0.67 | 151 | yes | 2 |
| supernode_laundering | no | 0.5 | 0.50 | 0.43 | 0.56 | 155 | yes | 1 |
| supernode_laundering | no | 0.75 | 0.00 | 0.26 | 0.21 | 164 | no | — |
| supernode_laundering | no | 1 | 0.00 | 0.11 | 0.05 | 172 | no | — |
| supernode_laundering | yes | 0 | 1.00 | 0.52 | 0.90 | 146 | yes | 2 |
| supernode_laundering | yes | 0.25 | 1.00 | 0.40 | 0.69 | 145 | yes | 2 |
| supernode_laundering | yes | 0.5 | 0.75 | 0.43 | 0.69 | 145 | yes | 1 |
| supernode_laundering | yes | 0.75 | 0.75 | 0.14 | 0.52 | 144 | yes | 2 |
| supernode_laundering | yes | 1 | 0.50 | 0.31 | 0.48 | 145 | no | — |

## 2. CLI over seeds 1–5

The same generators and scoring averaged over five base datasets (`cli-seeds-1-5.txt`, verbatim). One seed is an anecdote; this is the number to quote alongside the demo curve.

```
$ go run ./cmd/cli adversary --strategy temporal_dilation --seeds 1-5 --budgets 0,0.25,0.5,0.75,1
scenario recall over scenarios detected at β=0, mean of 5 seeds (top rank of scenario A in brackets)
strategy               mitig  β=0.00        β=0.25        β=0.50        β=0.75        β=1.00      
temporal_dilation      false  1.00 [1,2,2,1,2]  0.50 [-,-,-,-,-]  0.00 [-,-,-,-,-]  0.00 [-,-,-,-,-]  0.00 [-,-,-,-,-]
temporal_dilation      true   1.00 [1,2,2,1,1]  0.50 [-,-,-,-,-]  0.00 [-,-,-,-,-]  0.00 [-,-,-,-,-]  0.00 [-,-,-,-,-]

$ go run ./cmd/cli adversary --strategy supernode_laundering --seeds 1-5 --budgets 0,0.25,0.5,0.75,1
scenario recall over scenarios detected at β=0, mean of 5 seeds (top rank of scenario A in brackets)
strategy               mitig  β=0.00        β=0.25        β=0.50        β=0.75        β=1.00      
supernode_laundering   false  1.00 [1,2,2,1,2]  0.80 [1,1,2,-,1]  0.50 [1,1,-,1,2]  0.10 [-,-,-,-,-]  0.00 [-,-,-,-,-]
supernode_laundering   true   1.00 [1,2,2,1,1]  0.80 [1,1,2,-,1]  0.55 [1,2,-,1,1]  0.25 [-,-,-,-,-]  0.35 [-,-,-,-,-]
```

## Reading it honestly

- **temporal_dilation breaks us and the mitigation does nothing** — identical series with and without the laundering pass, on seed 42 and on the 5-seed mean. Stretching gaps past the 2 h link window is a real, unfixed limit at a fixed window, as design §11.4 predicted.
- **supernode_laundering is partly closed by the laundering pass.** On seed 42 the mitigated line holds 0.75 through β=0.75 where the unmitigated one is at 0.00, and still reaches 0.50 at β=1. On the 5-seed mean the recovery is smaller (β=0.75: 0.10 → 0.25; β=1: 0.00 → 0.35) and at β=0.5 the gain is only 0.50 → 0.55. "Recovers substantially" in design §11.4 is true for the demo seed and overstated for the mean; quote the mean.
- The mitigated series never falls below the unmitigated one at any budget; `TestLaunderingPassBeatsSupernodeLaundering` enforces that shape over seeds 1–5.
- **Top rank between tied incidents is not meaningful.** At β=0 the input is unchanged, yet scenario A's rank is 1 or 2 across campaigns: the top two incidents both score 100.00 and ties break by incident ID, which hashes the variant dataset's name. Recall is unaffected.
- Pairwise precision at β=0 is 0.52: over-merging exists before any attack. Cohesion's fragile flag is the engine's answer to that; it is not measured here.

## Reproduce

```bash
cd backend
go run ./cmd/api &    # seeds ds_20260929_s42 on startup
# login meow / prahari-lead, then for each strategy × mitigated:
#   POST /api/v1/adversary/campaigns {"base_dataset":"ds_20260929_s42","strategy":"…","budgets":[0,0.25,0.5,0.75,1],"mitigated":…,"seed":42}
#   GET  /api/v1/adversary/curve?base_dataset=ds_20260929_s42
go run ./cmd/cli adversary --strategy supernode_laundering --seeds 1-5
go run ./cmd/cli adversary --strategy temporal_dilation --seeds 1-5
```
