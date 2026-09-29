# Engine benchmarks — measured, including where it falls over

`BenchmarkRun` in `backend/internal/core/correlate/bench_test.go` times the whole pure engine (filter → compliance) on N alerts built by laying simulated days end to end, each with its own seed. Dataset generation is outside the timer. No database is involved: this is the engine, not the API.

Machine: 12th Gen Intel Core i5-1235U (laptop), Windows 11, Go 1.27. Raw output is in the `.txt` files next to this page.

| Alerts | Time per run | Throughput | Incidents | Allocated per run | Iterations |
|---:|---:|---:|---:|---:|---:|
| 3,000 | 37.8 ms | 79,283 alerts/s | 212 | 10.8 MB | 3 |
| 50,000 | 4.68 s | 10,691 alerts/s | 3,668 | 254 MB | 3 |
| 300,000 | 202.1 s | 1,484 alerts/s | 22,215 | 3.06 GB | 1 |

## Reading it

- **NFR-1 holds at demo scale.** 3,000 alerts correlate in 37.8 ms against a 500 ms p95 target (mean of 3 runs, not a p95).
- **It does not scale the way design §6.3 says.** Linking is O(n log n), but the run as a whole is not: time grows roughly as n^1.7 from 3k to 50k and n^2.1 from 50k to 300k (computed from the table: ×124 for ×16.7 alerts, ×43 for ×6). At 300k one run takes over three minutes. That is where it falls over.
- **The cause is cohesion, not linking.** At 50k, 92% of engine time is in the cohesion stage, 90% in `(*build).similarity` (`profile-50k.txt`). For every bridge it rebuilds the entity sets of the whole component to compare the two sides, so the stage costs O(bridges × component size) — quadratic on the large merged components that appear when many days share entities. Bridge finding itself (Tarjan) is linear and is not among the top nodes of the profile.
- **Memory** grows faster than linear too: 3.06 GB allocated for one 300k run (allocation, not peak working set).

## Not fixed here

The fix is local to `similarity`: build each side's entity set once per component with a prefix pass over the DFS tree, or cap the comparison at the entities within a hop or two of the bridge. Either changes cohesion grades on large components and therefore the golden seed-42 output, so it is left as a decision rather than slipped into a benchmark change.

The 50k and 300k datasets are 25 and 150 simulated days correlated as one window, which is not how the product runs (one day per run). They measure the engine's scaling, not a realistic workload.

## Reproduce

```bash
cd backend
go test ./internal/core/correlate -run '^$' -bench 'Run/alerts=(3000|50000)$' -benchmem -benchtime 3x -timeout 20m
go test ./internal/core/correlate -run '^$' -bench 'Run/alerts=300000$' -benchmem -benchtime 1x -timeout 60m
```
