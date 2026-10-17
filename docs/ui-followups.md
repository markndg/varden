# UI follow-ups

No control-plane HTML or frontend change is part of hardening pass 2, phase 1.

- Event, trace and stream views already render API JSON. Redacted fields appear as `[REDACTED:<label>:<id>]`. A dedicated badge is optional and not required for the security fix.
- `/health` will stop returning bootstrap credentials (P0-7). Any screen that read those fields from the health payload needs to use an authenticated settings endpoint instead. That screen was not changed in this phase.
