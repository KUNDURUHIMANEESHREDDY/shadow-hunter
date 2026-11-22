#!/usr/bin/env bash
# Build Python 3.12 / manylinux Lambda package entirely on WSL native storage.
# The only Windows-mounted write is the final ZIP.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$(mktemp -d /tmp/shadow-hunter-staging-lambda.XXXXXXXX)"
trap 'rm -rf "$TARGET"' EXIT

python3 -m pip install   --target "$TARGET"   --only-binary=:all:   --platform manylinux2014_x86_64   --python-version 3.12   --implementation cp   --abi cp312   --no-warn-script-location   -r "$ROOT/src/requirements.txt"
cp -a "$ROOT/src/shadow_hunter" "$TARGET/"

mkdir -p "$ROOT/.aws-sam/staging-app-manual"
python3 - "$TARGET" "$ROOT/.aws-sam/staging-app-manual/ShadowHunterApiFunction.zip" <<'PY'
import pathlib
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for path in source.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            archive.write(path, path.relative_to(source).as_posix())
print(f"Linux Lambda package written: {destination} ({destination.stat().st_size} bytes)")
PY
