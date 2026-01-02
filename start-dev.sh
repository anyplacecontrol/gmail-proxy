#!/bin/sh
# Development starter: installs deps, loads .env (if present) and runs nodemon
set -e
if [ -f .env ]; then
  # export simple KEY=VALUE pairs (no quotes)
  export $(grep -v '^#' .env | xargs)
fi
npm install
npm run dev
