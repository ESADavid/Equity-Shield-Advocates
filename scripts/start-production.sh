#!/usr/bin/env sh
set -eu

echo "Starting Equity Shield Advocates API in production mode..."

if [ ! -f ".env.production" ]; then
  echo ".env.production not found. Create it from .env.production.example and set real secrets."
  exit 1
fi

export NODE_ENV=production

# shellcheck disable=SC2046
export $(grep -v '^\s*#' .env.production | grep -v '^\s*$' | xargs)

node src/server.js
