# Blackbox.ai Multi-Agent Integration

## Setup

1. Get API key: <https://cloud.blackbox.ai> → Profile → BLACKBOX API Token (bb_xxx)
2. Copy .env.example to .env and add your key:

```
BLACKBOX_API_KEY=bb_your_key_here
BLACKBOX_REPO_URL=https://github.com/bsean/OSCAR-BROOME-REVENUE.git
BLACKBOX_BRANCH=main
```

1. Routes auto-mounted in server-enhanced.js at /api/multi-agent ✅
2. Restart server: `npm start`
3. Test UI button in Control Dashboard → "🤖 AI Multi-Agent Optimize"
4. Run `node scripts/test-blackbox-multi-agent.js`
5. Run `npm test` (includes blackbox-multiagent.test.js)

## Usage

### API Endpoints

```
POST /api/multi-agent/create
  Body: { "prompt": "Optimize security services", "selectedAgents": [...] }

GET /api/multi-agent/status/:taskId

POST /api/multi-agent/poll/:taskId - Polls until complete

POST /api/multi-agent/optimize - Repo optimization with default prompt
```

### Test

```bash
node scripts/test-blackbox-multi-agent.js

```

## Example Response

```json
{
  "taskId": "abc123",
  "taskUrl": "https://cloud.blackbox.ai/tasks/abc123"
}
```

Agents run in parallel on repo, create PRs for comparison. Monitor dashboard for results.
