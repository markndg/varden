# Varden OSS operations

## Runtime checks

- `/health` for bootstrap and current mode
- `/health/live` for liveness
- `/health/ready` for readiness
- `/metrics` and `/metrics/json` for runtime metrics

## Low-overhead guidance

Use `VARDEN_SCAN_MODE=fast` unless you specifically need deeper enrichment.
The dashboard overview shows average decision latency so you can validate overhead in your own environment.

## Policy workflow

- edit centrally in `/ui/rules`
- validate via `/policy/validate`
- publish via `/policy`
