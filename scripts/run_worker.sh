#!/usr/bin/env bash
set -e
python -m sentinel.worker_service --config examples/dev.env
