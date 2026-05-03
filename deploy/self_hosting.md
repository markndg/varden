# Self-hosting Varden OSS

Varden OSS is designed to be run by your own team.

## Recommended deployment

1. Use `deploy/docker-compose.yml` for a single-node self-hosted deployment.
2. Set a strong signing secret and disable dev bootstrap auth outside local evaluation.
3. Mount persistent storage for the application database and policy file.
4. Set `VARDEN_SCAN_MODE=fast` for low overhead, or `deep` when you want richer inspection.

## Notes

- This OSS release is intentionally single-tenant.
- Policy is managed centrally through `/ui/rules` and `/policy`.
- Developers cannot override the control-plane scan mode from application code.
