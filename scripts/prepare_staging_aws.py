"""Generate staging-only SAM templates from reviewed production sources.

The generated templates stay untracked; production templates remain unchanged.
No AWS calls, credentials, secrets, or live resources are involved.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Expected exactly one instance of {before[:64]!r}")
    return text.replace(before, after, 1)


def generate() -> tuple[Path, Path]:
    identity = (ROOT / "infra/cognito/identity-stack.yaml").read_text(encoding="utf-8")
    identity = replace_once(
        identity,
        "    Default: production\n    AllowedValues: [production]",
        "    Default: staging\n    AllowedValues: [staging]",
    )
    # Staging uses Cognito's built-in low-volume email sending; production
    # retains its verified SES identity requirement and unchanged template.
    identity, count = re.subn(
        r"(?ms)^  SesSourceArn:\n.*?(?=^  CustomerCallbackUrl:\n)",
        "",
        identity,
    )
    if count != 1:
        raise ValueError("Could not remove staging-only SES parameters")
    identity = replace_once(
        identity,
        "      EmailConfiguration:\n"
        "        EmailSendingAccount: DEVELOPER\n"
        "        SourceArn: !Ref SesSourceArn\n"
        "        From: !Ref SesFromAddress",
        "      EmailConfiguration:\n"
        "        EmailSendingAccount: COGNITO_DEFAULT",
    )
    if "SesSourceArn" in identity or "SesFromAddress" in identity:
        raise ValueError("Staging Cognito template must not depend on SES identities")
    identity_path = ROOT / "infra/cognito/identity-stack.staging-generated.yaml"
    identity_path.write_text(identity, encoding="utf-8")

    app = (ROOT / "infra/app/template.yaml").read_text(encoding="utf-8")
    app = replace_once(
        app,
        "    Default: production\n    AllowedValues: [production]",
        "    Default: staging\n    AllowedValues: [staging]",
    )
    app = replace_once(
        app,
        "          SHADOW_HUNTER_EVAL_ENABLED: 'true'",
        "          SHADOW_HUNTER_EVAL_ENABLED: 'false'",
    )
    # Conservative staging limits reduce accidental hosted-service costs.
    app = replace_once(app, "ThrottlingBurstLimit: 40", "ThrottlingBurstLimit: 3")
    app = replace_once(app, "ThrottlingRateLimit: 20", "ThrottlingRateLimit: 2")
    app = replace_once(
        app, "ReservedConcurrentExecutions: 10", "ReservedConcurrentExecutions: 2"
    )
    app_path = ROOT / "infra/app/template.staging-generated.yaml"
    app_path.write_text(app, encoding="utf-8")
    return identity_path, app_path


if __name__ == "__main__":
    for generated in generate():
        print(f"Generated {generated.relative_to(ROOT)}")
