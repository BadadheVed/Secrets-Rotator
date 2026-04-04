# secrets-get.md — How to Obtain Every Secret

This doc explains where each credential comes from and how to get it.
Never commit real values — use `.env` (gitignored).

---

## Doppler

| Var | Value |
|-----|-------|
| `DOPPLER_TOKEN` | Personal token — **must be Personal, not Service** (Service tokens can't rollback) |
| `DOPPLER_PROJECT` | Name of the Doppler project (e.g. `secret-rotator`) |
| `DOPPLER_CONFIG` | Target config/environment: `dev`, `stg`, or `prd` |

**How to get `DOPPLER_TOKEN`:**
1. Go to doppler.com → click your avatar → **Tokens**
2. Click the **Personal** tab → **Create a personal token**
3. Name it `secrets-rotator-local`
4. Copy the value (starts with `dp.pt.`)

> `DOPPLER_CONFIG` controls which environment secrets are pushed to. Change it to `prd` when running production rotation.

---

## 1. AWS ElastiCache (Redis)

| Var | Where to get it |
|-----|----------------|
| `AWS_ACCESS_KEY_ID` | IAM → Users → your user → Security credentials → Create access key |
| `AWS_SECRET_ACCESS_KEY` | Same — shown once on creation |
| `AWS_REGION` | The region your ElastiCache cluster is in (e.g. `ap-south-1`) |
| `ELASTICACHE_USER_GROUP_ID` | ElastiCache console → User Groups → your group ID |
| `REDIS_AWS_URL` | ElastiCache console → your cluster → Primary endpoint (use `rediss://` for TLS) |
| `REDIS_AWS_USERNAME` | ElastiCache console → Users → username |
| `REDIS_AWS_PASSWORD` | The current password for that user |

**IAM permissions needed for the AWS key:**
- `elasticache:DescribeUsers`
- `elasticache:ModifyUser`

---

## 2. GCP Kafka

| Var | Where to get it |
|-----|----------------|
| `GCP_PROJECT_ID` | GCP console → project selector (top bar) |
| `GCP_KAFKA_CLUSTER_ID` | GCP console → Managed Kafka → your cluster → ID |
| `GCP_KAFKA_LOCATION` | Region where the cluster is deployed (e.g. `us-central1`) |
| `GCP_SA_ROTATER_KEY_JSON` | Base64-encoded JSON key for `kafka-rotation-admin` SA (see below) |
| `GCP_SA_KEY_JSON` | Base64-encoded JSON key for the Kafka access SA (the one being rotated) |

**Two-SA architecture:**
- `kafka-rotation-admin` — has `Service Account Key Admin` role. Rotates keys for the Kafka access SA.
- `kafka-access-sa` — the SA whose key is used as `sasl.password` in Kafka clients.

**How to create and encode a key:**
```bash
# Download key from GCP console → IAM → Service Accounts → your SA → Keys → Add Key → JSON
base64 -i kafka-rotation-admin-key.json | tr -d '\n'   # → GCP_SA_ROTATER_KEY_JSON
base64 -i kafka-access-sa-key.json | tr -d '\n'        # → GCP_SA_KEY_JSON
```

**How `sasl.password` works:**
The Kafka SASL/PLAIN password = base64 of the SA key JSON. The rotator pushes this as `KAFKA_SASL_PASSWORD` to Doppler after each rotation.

---

## 3. Firebase / Firestore ✅ done

| Var | Where to get it |
|-----|----------------|
| `FIRE_CREDS_ROTATER_JSON` | Base64-encoded JSON key for `firebase-rotation-admin` SA |
| `FIRE_CREDS_JSON` | Base64-encoded JSON key for `ved-710` (the app SA being rotated) |

**Two-SA architecture:**
- `firebase-rotation-admin` — has `Service Account Key Admin` role. Creates/deletes keys for `ved-710`.
- `ved-710` — the app SA with `firebase-backend-service` custom role (Firestore CRUD + Firebase Auth, no delete-database permission).

**Custom role `firebase-backend-service` permissions:**
- `datastore.databases.get`
- `datastore.entities.*` (create, delete, get, list, update)
- `datastore.indexes.*`
- `datastore.namespaces.*`
- `datastore.statistics.*`
- `firebaseauth.users.*` (create, delete, get, list, sendEmail, update, createSession)
- `firebaseauth.configs.get`

**How to create and encode a key:**
```bash
# GCP console → IAM → Service Accounts → select SA → Keys → Add Key → JSON → Download
base64 -i firebase-rotation-admin-key.json | tr -d '\n'  # → FIRE_CREDS_ROTATER_JSON
base64 -i ved-710-key.json | tr -d '\n'                  # → FIRE_CREDS_JSON
```

**Key propagation:** New GCP SA keys take ~10–60s to activate. The rotator retries 3x automatically (10s, 20s, 30s delays).

**GCP APIs that must be enabled:**
- Cloud Firestore API (`firestore.googleapis.com`)
- Firebase Authentication must be initialized in Firebase Console (Authentication → Get Started)

**Validation logic (`validator.py`):**
- Calls `GET /v1/projects/{id}/databases` via Firestore API
- Uses `datastore.databases.get` permission (not IAM — `ved-710` has no IAM list permissions)

**Post-rotation check (`app/fire_verify.py`):**
```bash
# Set FIRE_CREDS_JSON in app/fire_verify.py or app/.env, then:
python app/fire_verify.py
```
Checks:
1. Firestore — lists databases via Firestore API
2. Firebase Auth — calls `GET /v2/projects/{id}/config` via Identity Toolkit API

**Key dump:** During rotation, new key is immediately written to `firestore/creds.json` (gitignored) before validation — useful if you need the key even if validation times out.

---

## 4. Cloudflare

| Var | Where to get it |
|-----|----------------|
| `CF_MASTER_TOKEN` | Cloudflare dashboard → My Profile → API Tokens → Create token with **Account > API Tokens > Edit** permission |
| `CF_API_TOKEN` | Leave blank on first run (bootstrap mode) — rotator creates it automatically |
| `CF_ACCOUNT_ID` | Cloudflare dashboard → right sidebar on any domain page → Account ID |
| `CF_TOKEN_POLICY_JSON` | JSON policy array — defines permissions for the rotated token (see below) |
| `CF_KV_NAMESPACE_ID` | Cloudflare dashboard → Workers & Pages → KV → your namespace → ID (static, never rotated) |

**Account vs User tokens:**
Always use account-owned tokens (`/accounts/{id}/tokens`), not user tokens (`/user/tokens`). Account tokens are not tied to a user and survive user changes.

**Two-token architecture:**
- `CF_MASTER_TOKEN` — permanent master token with `Account > API Tokens > Edit`. Never rotated.
- `CF_API_TOKEN` — rotated app token. Must NOT have token-management permissions (Cloudflare forbids it).

**Rotated token policy (Zone Read + KV Read + KV Write):**
```json
[{
  "effect": "allow",
  "resources": {
    "com.cloudflare.api.account.YOUR_ACCOUNT_ID": {
      "com.cloudflare.api.account.zone.*": "*"
    }
  },
  "permission_groups": [
    {"id": "c8fed203ed3043cba015a93ad1616f1f"},
    {"id": "8b47d2786a534c08a1f94ee8f9f599ef"},
    {"id": "f7f0eda5697f475c90846e879bab8666"}
  ]
}]
```

Permission group IDs:
- `c8fed203ed3043cba015a93ad1616f1f` — Zone Read
- `8b47d2786a534c08a1f94ee8f9f599ef` — Workers KV Storage Read
- `f7f0eda5697f475c90846e879bab8666` — Workers KV Storage Write

**Bootstrap (first run):** Leave `CF_API_TOKEN` empty. The rotator creates the first token using `CF_MASTER_TOKEN` + `CF_TOKEN_POLICY_JSON`.

---

## 5. MongoDB Atlas

| Var | Where to get it |
|-----|----------------|
| `MONGODB_ATLAS_PUBLIC_KEY` | Atlas → Organization/Project → Access Manager → API Keys → Create |
| `MONGODB_ATLAS_PRIVATE_KEY` | Same — shown once on creation |
| `MONGODB_ATLAS_GROUP_ID` | Atlas → Project Settings → Project ID |
| `MONGODB_ATLAS_USERNAME` | Atlas → Database Access → the username to rotate |
| `MONGODB_URI` | Atlas → your cluster → Connect → connection string (include current password) |

---

## 6. PostgreSQL

| Var | Where to get it |
|-----|----------------|
| `POSTGRES_HOST` | Your DB host (RDS endpoint, etc.) |
| `POSTGRES_PORT` | Default `5432` |
| `POSTGRES_DB` | Database name |
| `POSTGRES_USER` | Username to rotate |
| `POSTGRES_PASSWORD` | Current password for that user |

---

## 7. Apple APNs

| Var | Where to get it |
|-----|----------------|
| `APNS_TEAM_ID` | Apple Developer → Membership → Team ID |
| `APNS_KEY_ID` | Apple Developer → Certificates, IDs & Profiles → Keys → your key |
| `APNS_BUNDLE_ID` | Apple Developer → Identifiers → your app bundle ID |
| `APNS_AUTH_KEY` | The `.p8` private key content (full `-----BEGIN PRIVATE KEY-----` block) |

---

## 8. Simple API Keys (Anthropic, OpenAI, Gemini, Deepgram)

### Anthropic
| Var | Where |
|-----|-------|
| `ANTHROPIC_API_KEY` | console.anthropic.com → API Keys |
| `ANTHROPIC_API_KEY_ID` | Same page — the key ID shown next to the key |

### OpenAI
| Var | Where |
|-----|-------|
| `OPENAI_API_KEY` | platform.openai.com → API keys |

### Gemini
| Var | Where |
|-----|-------|
| `GEMINI_API_KEY` | aistudio.google.com → Get API key |

### Deepgram
| Var | Where |
|-----|-------|
| `DEEPGRAM_MASTER_KEY` | Deepgram console → your project → API Keys → create a key with **Admin** scope |
| `DEEPGRAM_PROJECT_ID` | Deepgram console → your project → Settings → Project ID |
| `DEEPGRAM_API_KEY_ID` | The ID of the currently active rotated key (shown in Deepgram console) |

---

## 9. Elasticsearch

| Var | Where to get it |
|-----|----------------|
| `ELASTICSEARCH_HOST` | Elastic Cloud → your deployment → Endpoint |
| `ELASTICSEARCH_API_KEY` | `POST /_security/api_key` → use the `encoded` field (base64 of `id:secret`) |
| `ELASTICSEARCH_API_KEY_ID` | Same response → `id` field |
| `ELASTICSEARCH_MASTER_KEY` | A separate API key with `manage_api_key` cluster privilege — used to create/delete rotated keys |
| `ELASTICSEARCH_USERNAME` | Superuser username (for fallback validation) |
| `ELASTICSEARCH_PASSWORD` | Superuser password |
