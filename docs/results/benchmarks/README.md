# Engine benchmarks — measured, including where it fell over

`BenchmarkRun` in `backend/internal/core/correlate/bench_test.go` times the whole pure engine (filter → compliance) on N alerts built by laying simulated days end to end, each with its own seed. Dataset generation is outside the timer. No database is involved: this is the engine, not the API.

Machine: 12th Gen Intel Core i5-1235U (laptop), Windows 11, Go 1.27. Every number below is copied from the raw `.txt` files in this folder.

## Before and after the cohesion fix

| Alerts | Before (29 Sep) | After (30 Sep) | Speed-up | Allocated per run, before → after |
|---:|---:|---:|---:|---:|
| 3,000 | 37.8 ms | 49.9 ms (see note) | — | 10.8 MB → 11.0 MB |
| 50,000 | 4.68 s | 1.64 s | 2.8× | 254 MB → 200 MB |
| 300,000 | 202.1 s | 9.06 s | 22.3× | 3.06 GB → 1.43 GB (15× fewer allocations) |

Scaling exponent (time ∝ n^k, from the table): before k = 1.71 (3k→50k) and 2.10 (50k→300k); after k = 1.24 and 0.95.

**The two columns were measured on different days and this laptop was not equally loaded.** Re-running 3k five times on 30 Sep gave 56.6–112.5 ms (`after-bench.txt`) — that spread, not the change, explains 3k looking slower. The fair comparison is the same-session A/B below.

### Same-session A/B

`BenchmarkSimilarity` (`backend/internal/core/correlate/similarity_test.go`) runs the whole engine with the old and the new bridge similarity back to back (`ab-similarity.txt`, 3 × 5 runs each):

| Alerts | Old (direct) | New (indexed) | Speed-up |
|---:|---:|---:|---:|
| 3,895 (2 days) | 78–108 ms | 53–66 ms | 1.5× |
| 48,477 (25 days) | 10.5–11.4 s | 1.05 s | 10.4× |

The old implementation took 10.5 s at ~48k alerts in this session versus 4.68 s at 50k the day before: the machine was roughly twice as slow on 30 Sep, so the cross-day speed-ups above understate the gain.

## What was wrong, and the fix

At 50k alerts **92% of engine time was the cohesion stage, 90% in `(*build).similarity`** (`before-profile-50k.txt`). For every weak bridge it rebuilt the entity sets of both sides over the whole component — O(bridges × component size) — and large recurring components have thousands of weak bridges.

The fix computes all of them at once. It builds a spanning tree of the component and merges subtree entity counts small-to-large (O(K log V) for K entity references), after which each bridge is an O(1) lookup. It is exact, not approximate: Jaccard is symmetric in the two sides, their union is every linkable entity in the component, and an entity is on both sides exactly when 0 < (holders in the subtree) < (holders in the component).

Proof of equality, all in `similarity_test.go`:

- every one of 10,582 bridge comparisons (seeds 1–5 and 42, plus a 10-day window) returns the **identical float** from both implementations;
- the full incidents and the receipt `output_hash` are identical with either;
- 500 random connected graphs, with stop-listed and once-seen entities, agree on every bridge;
- `TestGoldenSeed42` passes against the unchanged golden file.

After the fix, cohesion is 19% of engine time at 50k and similarity 8% (`after-profile-50k.txt`); garbage collection and building each incident's graph, timeline and entity projections now lead.

## Reading it

- **NFR-1 holds at demo scale**: 3,000 alerts took 37.8–112.5 ms in every run measured here, against a 500 ms p95 target.
- **The engine is now close to linear from 50k to 300k** (k ≈ 0.95 on that step). 300k alerts take 9 s, not 3½ minutes.
- The 50k and 300k datasets are 25 and 150 simulated days correlated as one window, which is not how the product runs (one day per run). They measure the engine's scaling, not a realistic workload.

## Reproduce

```bash
cd backend
go test ./internal/core/correlate -run '^$' -bench 'Run/alerts=(3000|50000)$' -benchmem -benchtime 3x -timeout 20m
go test ./internal/core/correlate -run '^$' -bench 'Run/alerts=300000$' -benchmem -benchtime 1x -timeout 60m
go test ./internal/core/correlate -run '^$' -bench Similarity -benchtime 5x -count 3
```
