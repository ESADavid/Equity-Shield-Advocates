#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

echo "1) Health"
curl -i "$BASE_URL/health"
echo -e "\n"

echo "2) OAuth happy"
curl -i --location "$BASE_URL/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
echo -e "\n"

echo "3) Banking malformed payload"
curl -i -X POST "$BASE_URL/api/banking/setup" \
  -H "Content-Type: application/json" \
  -d '{"entityName":123}'
echo -e "\n"

echo "4) Unauthorized ping"
curl -i "$BASE_URL/api/jpm/ping"
echo -e "\n"

echo "5) Authorized ping"
curl -i "$BASE_URL/api/jpm/ping" \
  -H "x-api-key: ${INTERNAL_API_KEY:-missing}"
echo -e "\n"
