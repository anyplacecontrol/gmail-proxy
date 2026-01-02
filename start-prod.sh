#!/bin/sh
# Production starter: loads .env, installs prod deps, runs node
set -e
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi
npm ci --only=production
node server.js
