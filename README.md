# secrets-rot

Automated secret rotation orchestrator. Rotates credentials across multiple services, pushes new values to Doppler, and rolls back on failure.

---

## How It Works

```
uv run main.py
```

Select a service from the menu. The rotator:
1. Generates a new credential using the service's API
2. Validates the new credential works
3. Pushes new values to Doppler
4. Revokes / deletes the old credential
5. On any failure — rolls back Doppler to the pre-rotation snapshot

Output is written to `envs/.env.last` after each successful rotation.

---

## Rotation Pattern: Master Token

Some services (e.g. Cloudflare) use a **two-token pattern** because a credential cannot create its own replacement:

```
MASTER TOKEN  ─────────────────────────────────────────────────
  Permanent. Never rotated. Has permission to create/delete tokens.
  Used by: the rotator only.

APP TOKEN  ────────────────────────────────────────────────────
  Rotated on every run. Used by your actual application.
  Has only the permissions your app needs (e.g. Zone Read).
  NO token-management permissions.
```

On each rotation run:
1. Master token reads the app token's current policies
2. Master token creates a new app token with the same policies
3. New token is validated and pushed to Doppler
4. Master token revokes the old app token

**Bootstrap (first run):** if `CLOUDFLARE_API_TOKEN` is not set, the rotator creates the first app token from scratch using `CLOUDFLARE_TOKEN_POLICY_JSON`.

---

## Services

| # | Service | Strategy | Notes |
|---|---------|----------|-------|
| 1 | AWS ElastiCache (Redis) | Rotate Redis user password via AWS API | |
| 2 | GCP Kafka | Rotate GCP service account key | |
| 3 | Firebase | — | Needs research |
| 4 | Cloudflare | Two-token pattern (master + app token) | See above |
| 5 | MongoDB Atlas | Rotate Atlas database user password | |
| 6 | Apple APNS | Manual only | Programmatic rotation not supported by Apple |
| 7 | Deepgram | Simple API key rotation | |
| 8 | Anthropic | Manual only | No rotation API |
| 9 | OpenAI | Manual only | No rotation API |
| 10 | Gemini | Manual only | No rotation API |
| 11 | Elasticsearch | Rotate Elasticsearch API key | |

---

## Setup

```bash
# 1. Install dependencies
uv sync

# 2. Copy env template and fill in values
cp .env.example .env

# 3. Run
uv run main.py
```

---

## Doppler

All rotated secrets are pushed to Doppler after each successful rotation. Configure:

```
DOPPLER_TOKEN=...
DOPPLER_PROJECT=...
DOPPLER_CONFIG=...
```

The rotator takes a Doppler snapshot before rotating and rolls back to it on failure.

---

## Cloudflare Setup

**Step 1 — Create a master token** in the Cloudflare dashboard:
- Permissions: `User > API Tokens > Read` + `User > API Tokens > Edit`
- This token never changes. Store it as `CLOUDFLARE_MASTER_TOKEN`.

**Step 2 — First run (bootstrap):**
- Leave `CLOUDFLARE_API_TOKEN` unset
- Set `CLOUDFLARE_TOKEN_POLICY_JSON` with the permissions your app token needs
- Run `uv run main.py` → option 4
- The rotator creates the first app token and writes it to `envs/.env.last`
- Copy the new `CLOUDFLARE_API_TOKEN` value into `.env`

**Step 3 — Subsequent runs:**
- `CLOUDFLARE_API_TOKEN` is set → rotator clones its policies, creates replacement, deletes old
- `CLOUDFLARE_TOKEN_POLICY_JSON` no longer needed

**Getting permission group IDs:**
```bash
curl -s "https://api.cloudflare.com/client/v4/user/tokens/permission_groups" \
  -H "Authorization: Bearer <CLOUDFLARE_MASTER_TOKEN>" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pg in data['result']:
    print(pg['id'], '-', pg['name'])
"
```

---

## Testing (Cloudflare demo app)

```bash
# Fill in app/.env with current CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID
cp app/.env.example app/.env

# Run before rotation — should show all ✅
uv run app/demo.py

# Rotate
uv run main.py   # option 4

# Update app/.env with new token from envs/.env.last
# Re-run — should still show all ✅
uv run app/demo.py
```

---

## File Structure

```
main.py                  ← CLI menu + orchestration
resources/               ← one file per service
  cloudflare.py
  elasticache.py
  elasticsearch.py
  ...
validator.py             ← credential validation helpers
doppler.py               ← Doppler push/snapshot/rollback
rollback.py              ← session + rollback logic
app/                     ← demo app for testing Cloudflare rotation
envs/                    ← output dir (gitignored)
  .env.last              ← most recent rotated credentials
```
