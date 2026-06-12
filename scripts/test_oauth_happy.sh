#!/usr/bin/env bash
set -euo pipefail

echo "[OAuth Happy Path]"
curl --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
echo
