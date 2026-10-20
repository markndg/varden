# UI follow-ups

No control-plane HTML or frontend change is part of hardening pass 2, phase 1.

- Event, trace and stream views already render API JSON. Redacted fields appear as `[REDACTED:<label>:<id>]`. A dedicated badge is optional and not required for the security fix.
- `/health` now returns only `{"status":"ok"}`. A screen that read bootstrap credentials or environment fields from that payload needs an authenticated call to `/health/detail` or `/sdk/bootstrap` on loopback dev. The HTML was not changed in this phase.
