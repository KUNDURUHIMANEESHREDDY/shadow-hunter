"""Validate a Linux Lambda ZIP and prepare the staging SAM package template."""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".aws-sam/staging-app-manual"
ARCHIVE = BUILD / "ShadowHunterApiFunction.zip"
SOURCE = ROOT / "infra/app/template.staging-generated.yaml"
DEST = BUILD / "template.yaml"


def main() -> None:
    if not ARCHIVE.is_file():
        raise RuntimeError("Build the Linux ZIP using scripts/build_staging_lambda_linux.sh first")
    with zipfile.ZipFile(ARCHIVE) as bundle:
        names = bundle.namelist()
        expected = (
            "shadow_hunter/api.py",
            "shadow_hunter/lambda_handler.py",
            "mangum/__init__.py",
            "fastapi/__init__.py",
            "boto3/__init__.py",
        )
        if any(name not in names for name in expected):
            raise RuntimeError("Lambda ZIP missing required application dependencies")
        if not any(name.startswith("pydantic_core/") and name.endswith(".so") for name in names):
            raise RuntimeError("Linux Python 3.12 Pydantic binary not found")
        if any(name.endswith(".pyd") for name in names):
            raise RuntimeError("Windows-only binary detected in Lambda ZIP")

    text = SOURCE.read_text(encoding="utf-8")
    needle = "      CodeUri: ../../src/"
    if text.count(needle) != 1:
        raise RuntimeError("Expected exactly one Lambda CodeUri")
    DEST.write_text(
        text.replace(needle, "      CodeUri: ShadowHunterApiFunction.zip"),
        encoding="utf-8",
    )
    print(f"Prepared {DEST.relative_to(ROOT)}")
    print(f"Verified Linux ZIP ({len(names)} entries, {ARCHIVE.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
