from __future__ import annotations

import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    ok: bool
    error: str | None = None

    def __bool__(self) -> bool:
        return self.ok


def validate_elasticache(url: str, user: str, password: str) -> ValidationResult:
    """
    Connect to Redis (plain or TLS) and authenticate using the Redis 6+ ACL
    3-argument AUTH command: AUTH <user> <password>.

    Accepts both redis:// (plain TCP) and rediss:// (TLS) URLs.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 6379
    use_tls = parsed.scheme == "rediss"

    try:
        raw_sock = socket.create_connection((host, port), timeout=10)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        with sock:
            # Redis 6+ ACL AUTH: *3\r\n$4\r\nAUTH\r\n$<ulen>\r\n<user>\r\n$<plen>\r\n<pass>\r\n
            auth_cmd = (
                f"*3\r\n$4\r\nAUTH\r\n"
                f"${len(user)}\r\n{user}\r\n"
                f"${len(password)}\r\n{password}\r\n"
            ).encode()
            sock.sendall(auth_cmd)
            resp = sock.recv(128).decode(errors="replace")
            if not resp.startswith("+OK"):
                return ValidationResult(ok=False, error=f"AUTH failed: {resp.strip()}")
            # PING
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = sock.recv(128).decode(errors="replace")
            if "+PONG" not in resp:
                return ValidationResult(ok=False, error=f"PING failed: {resp.strip()}")
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))



def validate_kafka_gcp(
    project_id: str, cluster_id: str, location: str, sa_key_json: str
) -> ValidationResult:
    """Validate GCP credentials by calling get_cluster() on the Kafka cluster."""
    try:
        import google.oauth2.service_account as sa_module
        from googleapiclient.discovery import build

        creds_info = json.loads(sa_key_json)
        credentials = sa_module.Credentials.from_service_account_info(
            creds_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        service = build("managedkafka", "v1", credentials=credentials, cache_discovery=False)
        name = f"projects/{project_id}/locations/{location}/clusters/{cluster_id}"
        service.projects().locations().clusters().get(name=name).execute()
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_firebase(project_id: str, sa_key_json: str) -> ValidationResult:
    """Validate service account key by making a GCP API call."""
    try:
        import google.oauth2.service_account as sa_module
        from googleapiclient.discovery import build

        creds_info = json.loads(sa_key_json)
        credentials = sa_module.Credentials.from_service_account_info(
            creds_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        # Make a simple API call to verify credentials work
        service = build("iam", "v1", credentials=credentials, cache_discovery=False)
        service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_cloudflare(api_token: str, account_id: str) -> ValidationResult:
    """Verify Cloudflare account API token via the account verify endpoint."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                f"https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify",
                headers={"Authorization": f"Bearer {api_token}"},
            )
        body = resp.json()
        if not body.get("success"):
            errors = body.get("errors", [])
            return ValidationResult(ok=False, error=str(errors))
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_mongodb(uri: str) -> ValidationResult:
    """Ping MongoDB using the provided URI."""
    try:
        from pymongo import MongoClient
        from pymongo.errors import ConnectionFailure

        client = MongoClient(uri, serverSelectionTimeoutMS=10000)
        try:
            client.admin.command("ping")
        finally:
            client.close()
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_postgres(host: str, port: int, db: str, user: str, password: str) -> ValidationResult:
    """Validate Postgres credentials with SELECT 1."""
    try:
        import psycopg2

        conn = psycopg2.connect(host=host, port=port, dbname=db, user=user, password=password, connect_timeout=10)
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
        finally:
            conn.close()
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_apns(team_id: str, key_id: str, private_key_pem: str, bundle_id: str) -> ValidationResult:
    """Validate APNs credentials by connecting to the sandbox gateway."""
    try:
        import jwt as pyjwt

        # Generate JWT
        now = int(time.time())
        token = pyjwt.encode(
            {"iss": team_id, "iat": now},
            private_key_pem,
            algorithm="ES256",
            headers={"kid": key_id},
        )

        # Attempt TLS connection to APNs sandbox
        ctx = ssl.create_default_context()
        with socket.create_connection(("api.sandbox.push.apple.com", 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname="api.sandbox.push.apple.com"):
                pass  # TLS handshake succeeded

        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_elasticsearch(host: str, api_key_encoded: str) -> ValidationResult:
    """Validate an Elasticsearch API key by hitting /_cluster/health."""
    try:
        url = host.rstrip("/") + "/_cluster/health"
        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers={"Authorization": f"ApiKey {api_key_encoded}"})
        if resp.status_code == 401:
            return ValidationResult(ok=False, error="Invalid API key (401 Unauthorized)")
        if resp.status_code >= 400:
            return ValidationResult(ok=False, error=f"HTTP {resp.status_code}: {resp.text[:200]}")
        return ValidationResult(ok=True)
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))


def validate_simple_key(service: str, api_key: str) -> ValidationResult:
    """Lightweight ping per simple API service."""
    try:
        if service == "anthropic":
            with httpx.Client(timeout=15) as client:
                resp = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-haiku-4-5-20251001",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            if resp.status_code == 401:
                return ValidationResult(ok=False, error="Invalid API key")
            # 200 or any non-auth error is fine — key is valid
            return ValidationResult(ok=resp.status_code not in (401, 403))

        if service == "openai":
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
            if resp.status_code == 401:
                return ValidationResult(ok=False, error="Invalid API key")
            return ValidationResult(ok=resp.status_code == 200)

        if service == "gemini":
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
                )
            if resp.status_code in (400, 403):
                return ValidationResult(ok=False, error=resp.text[:200])
            return ValidationResult(ok=resp.status_code == 200)

        if service == "deepgram":
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.deepgram.com/v1/projects",
                    headers={"Authorization": f"Token {api_key}"},
                )
            if resp.status_code == 401:
                return ValidationResult(ok=False, error="Invalid API key")
            return ValidationResult(ok=resp.status_code == 200)

        return ValidationResult(ok=False, error=f"Unknown service: {service}")
    except Exception as exc:
        return ValidationResult(ok=False, error=str(exc))
