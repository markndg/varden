#!/bin/sh
set -eu
cd "$(dirname "$0")/frontend"
npm install
npm run build
cd ../../..
exec python demos/security-gauntlet/serve.py
