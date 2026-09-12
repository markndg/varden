# Predictive Authority performance notes

Measured locally (CPython 3.13) via
`python -m varden.predictive_authority.benchmarks`:

| Case | median (ms) | p95 (ms) | p99 (ms) |
|------|-------------|----------|----------|
| PA off | 0.001 | 0.002 | 0.002 |
| PA observe (repeat read) | 0.063 | 0.106 | 0.111 |
| PA observe graph-changing | 0.232 | 0.422 | 0.465 |
| PA enforce hazardous transition | 1.299 | 1.484 | 1.868 |
| Reachability n=10–1000, depth 1–3 | ≤0.004 | ≤0.015 | ≤0.032 |

CI keeps generous upper-bound smoke tests
(`tests/predictive_authority/test_pa_performance.py`). Disabled mode remains a
near-no-op on the evaluate path. Do not treat microsecond noise as a regression
without median/p95 context from this harness.
