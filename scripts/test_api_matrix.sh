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

echo "6) Unauthorized transactions list"
curl -i "$BASE_URL/api/banking/transactions"
echo -e "\n"

echo "7) Authorized transactions list"
curl -i "$BASE_URL/api/banking/transactions" \
  -H "x-api-key: ${INTERNAL_API_KEY:-missing}"
echo -e "\n"

echo "8) Authorized transactions list with filters"
curl -i "$BASE_URL/api/banking/transactions?accountId=acct_operating_001&type=credit&minAmount=1000&limit=5" \
  -H "x-api-key: ${INTERNAL_API_KEY:-missing}"
echo -e "\n"

echo "9) Transactions invalid amount range"
curl -i "$BASE_URL/api/banking/transactions?minAmount=5000&maxAmount=100" \
  -H "x-api-key: ${INTERNAL_API_KEY:-missing}"
echo -e "\n"
