"""Keyless AWS developer sign-in for Shadow Hunter staging.

Uses the native AWS CLI v2 browser flow. Never asks for or records an access
key, secret key, MFA seed, customer token or client secret. Deployment runtimes
must use IAM execution roles, not this interactive command.

Examples:
    python scripts/connect_aws.py
    python scripts/connect_aws.py --profile shadow-hunter-staging
    python scripts/connect_aws.py --check --verify-staging
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REGION = "ap-southeast-2"
ROOT = Path(__file__).resolve().parents[1]
MIN_AWS_VERSION = (2, 32, 0)


class ConnectionFailure(RuntimeError):
    """Safe error that does not include credentials or SDK response bodies."""


def _aws_command(*parts: str, profile: str | None) -> list[str]:
    command = ["aws", *parts]
    if profile:
        command.extend(["--profile", profile])
    return command


def _aws_env() -> dict[str, str]:
    """Prevent stale long-lived environment credentials taking precedence."""
    env = os.environ.copy()
    for name in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    ):
        env.pop(name, None)
    return env


def _checked_output(parts: list[str], *, env: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            parts, env=env, capture_output=True, text=True, timeout=25,
            check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConnectionFailure("AWS CLI verification could not complete") from exc
    if result.returncode != 0:
        # AWS stderr can contain service metadata. Do not echo it or cache it.
        raise ConnectionFailure("AWS session is unavailable or access was denied")
    return result.stdout.strip()


def _verify_cli_version() -> None:
    version = _checked_output(["aws", "--version"], env=_aws_env())
    match = re.search(r"aws-cli/(\d+)\.(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < MIN_AWS_VERSION:
        raise ConnectionFailure("AWS CLI v2.32.0 or later is required for browser login")


def check_session(
    *, profile: str | None, region: str, expected_account: str | None = None,
) -> str:
    """Verify the active session using STS, without returning its role or token."""
    response = _checked_output(
        _aws_command(
            "sts", "get-caller-identity", "--query", "Account",
            "--output", "text", "--region", region, profile=profile,
        ),
        env=_aws_env(),
    )
    if not re.fullmatch(r"\d{12}", response):
        raise ConnectionFailure("STS returned an invalid account identifier")
    if expected_account and response != expected_account:
        raise ConnectionFailure("Authenticated AWS account is not the expected staging account")
    return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="Named AWS CLI browser-login profile")
    parser.add_argument("--region", default=REGION)
    parser.add_argument(
        "--check", action="store_true",
        help="Check an existing AWS session without opening the browser",
    )
    parser.add_argument(
        "--expected-account", help="Refuse to proceed if STS uses another AWS account",
    )
    parser.add_argument(
        "--verify-staging", action="store_true",
        help="After login, run the existing read-only staging Cognito smoke check",
    )
    args = parser.parse_args(argv)
    if args.profile and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.profile):
        parser.error("Profile name must be alphanumeric, underscore or hyphen")
    if not re.fullmatch(r"[a-z]{2}-[a-z-]+-\d", args.region):
        parser.error("Invalid AWS region")
    if args.expected_account and not re.fullmatch(r"\d{12}", args.expected_account):
        parser.error("--expected-account must be a 12-digit account ID")
    if args.verify_staging and args.region != REGION:
        parser.error("Staging checks are restricted to ap-southeast-2")
    try:
        if not shutil.which("aws"):
            raise ConnectionFailure("AWS CLI v2 is not installed")
        _verify_cli_version()
        env = _aws_env()
        if not args.check:
            print("Opening AWS browser sign-in with the native AWS CLI…", flush=True)
            try:
                completed = subprocess.run(
                    _aws_command("login", profile=args.profile),
                    env=env, check=False, shell=False,
                )
            except OSError as exc:
                raise ConnectionFailure("AWS browser login could not start") from exc
            if completed.returncode != 0:
                raise ConnectionFailure("AWS browser sign-in was not completed")
        account = check_session(
            profile=args.profile, region=args.region,
            expected_account=args.expected_account,
        )
        print(f"PASS: AWS session verified for account …{account[-4:]} ({args.region})")
        if args.verify_staging:
            # Never mutate a Cognito pool or create users in this read-only flow.
            print("Verifying existing staging Cognito configuration (read-only)…")
            smoke_env = env.copy()
            smoke_env["AWS_DEFAULT_REGION"] = args.region
            if args.profile:
                smoke_env["AWS_PROFILE"] = args.profile
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "smoke_cognito_identity.py")],
                cwd=ROOT, env=smoke_env, check=False, shell=False,
            )
            if completed.returncode:
                raise ConnectionFailure("Staging identity verification did not pass")
        return 0
    except ConnectionFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
