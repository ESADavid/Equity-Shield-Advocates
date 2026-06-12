#!/usr/bin/env bash
set -euo pipefail

echo "[OAuth Error - Expected with invalid credentials]"
curl --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
echo
echo "Tip: set wrong JPM_CLIENT_SECRET in .env before running this test."
