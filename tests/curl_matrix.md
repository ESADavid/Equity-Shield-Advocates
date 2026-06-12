# Curl Test Matrix

## 1) Health

```bash
curl -i http://localhost:8080/health
```

## 2) OAuth Happy

```bash
curl --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 3) OAuth Invalid Credentials

Set wrong `JPM_CLIENT_SECRET` in `.env`:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 4) Missing Scope

Unset/empty `JPM_SCOPE` and restart service:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 5) Timeout/Unreachable OAuth URL

Set unreachable `JPM_OAUTH_URL`:

```bash
curl -i --location "http://localhost:8080/api/oauth/token" \
  --header "Content-Type: application/json" \
  --data "{}"
```

## 6) Malformed Banking Payload

```bash
curl -i -X POST http://localhost:8080/api/banking/setup \
  -H "Content-Type: application/json" \
  -d '{"entityName":123}'
```

## 7) Unauthorized Ping

```bash
curl -i http://localhost:8080/api/jpm/ping
```

## 8) Authorized Ping

```bash
curl -i http://localhost:8080/api/jpm/ping -H "x-api-key: <INTERNAL_API_KEY>"
