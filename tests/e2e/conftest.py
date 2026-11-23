"""Isolated, real-HTTP Shadow Hunter server for headless browser E2E tests.

The server binds only to loopback, uses a temporary SQLite file and synthetic
identities, and has no connection to AWS, payment services or hosted models.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from shadow_hunter.store import SQLiteStore

ROOT = Path(__file__).resolve().parents[2]
CUSTOMER_TOKEN = "synthetic-test-customer-alpha"
FOREIGN_TOKEN = "synthetic-test-customer-beta"
OPERATOR_TOKEN = "synthetic-test-operator"
OWN_ORDER = "synthetic-owned-order"
FOREIGN_ORDER = "synthetic-foreign-order"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def local_server(tmp_path):
    database = tmp_path / "only-synthetic-browser-e2e.sqlite3"
    store = SQLiteStore(database)
    store.add_order(
        order_id=OWN_ORDER,
        tenant_id="tenant-alpha",
        customer_id="customer-alpha",
        currency="USD",
        refundable_minor=25_000,
    )
    store.add_order(
        order_id=FOREIGN_ORDER,
        tenant_id="tenant-beta",
        customer_id="customer-beta",
        currency="USD",
        refundable_minor=33_000,
    )
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update({
        "SHADOW_HUNTER_AUTH_MODE": "local",
        "SHADOW_HUNTER_STORE_BACKEND": "sqlite",
        "SHADOW_HUNTER_DB_PATH": str(database),
        "SHADOW_HUNTER_DEMO_MODE": "false",
        "SHADOW_HUNTER_EVAL_ENABLED": "false",
        "SHADOW_HUNTER_CUSTOMER_TOKENS": json.dumps({
            CUSTOMER_TOKEN: {
                "subject_id": "subject-alpha",
                "tenant_id": "tenant-alpha",
                "customer_id": "customer-alpha",
            },
            FOREIGN_TOKEN: {
                "subject_id": "subject-beta",
                "tenant_id": "tenant-beta",
                "customer_id": "customer-beta",
            },
        }),
        "SHADOW_HUNTER_OPERATOR_TOKENS": json.dumps({
            OPERATOR_TOKEN: {"subject_id": "operator-synthetic"},
        }),
        # Forcefully disable optional cloud integrations even on a developer's
        # computer with AWS credentials. No provider/model calls in E2E.
        "SHADOW_HUNTER_HARNESS_ARN": "",
        "SHADOW_HUNTER_NIM_API_KEY_SECRET_ARN": "",
        "SHADOW_HUNTER_A2A_KEYS_SECRET_ARN": "",
        "SHADOW_HUNTER_LYZR_API_KEY": "",
        "SHADOW_HUNTER_BAND_API_KEY": "",
        "AWS_EC2_METADATA_DISABLED": "true",
        "PYTHONPATH": str(ROOT / "src"),
    })
    log_path = tmp_path / "uvicorn.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn", "shadow_hunter.api:app",
                "--host", "127.0.0.1", "--port", str(port),
                "--no-access-log",
            ],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(150):
                if process.poll() is not None:
                    break
                try:
                    with urlopen(base_url + "/health", timeout=0.3) as response:
                        if response.status == 200:
                            break
                except (URLError, TimeoutError, ConnectionError):
                    time.sleep(0.2)
            else:
                raise RuntimeError("Isolated Shadow Hunter HTTP server did not start")
            if process.poll() is not None:
                raise RuntimeError("Isolated Shadow Hunter HTTP server exited early")
            yield base_url
        except Exception as exc:
            # Log only local app initialization errors; never JWTs or user data.
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-2500:]
            raise RuntimeError(f"Browser E2E server startup failed: {tail}") from exc
        finally:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
