from __future__ import annotations

import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
required = [
    "README.md",
    "LICENSE",
    "AGENTS.md",
    ".codex/config.toml",
    ".github/workflows/engineering-cycle.yml",
]
missing = [name for name in required if not (ROOT / name).is_file()]
if missing:
    raise SystemExit(f"Missing required files: {', '.join(missing)}")

codex_root = ROOT / ".codex"
toml_files = sorted(codex_root.rglob("*.toml"))
for path in toml_files:
    with path.open("rb") as handle:
        parsed = tomllib.load(handle)
    if path.parent.name == "agents":
        for key in ("name", "description", "developer_instructions"):
            if not parsed.get(key):
                raise SystemExit(f"{path.relative_to(ROOT)} is missing {key}")

try:
    import yaml  # type: ignore[import-not-found]
except ImportError as exc:
    raise SystemExit("PyYAML is required to validate workflow and Copilot agent YAML.") from exc

workflow_files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
workflow_files += sorted((ROOT / ".github" / "workflows").glob("*.yaml"))
for path in workflow_files:
    yaml.safe_load(path.read_text(encoding="utf-8"))

copilot_agents = sorted((ROOT / ".github" / "agents").glob("*.agent.md"))
if len(copilot_agents) < 6:
    raise SystemExit(f"Expected at least 6 Copilot agents, found {len(copilot_agents)}")

for path in copilot_agents:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise SystemExit(f"{path.relative_to(ROOT)} is missing YAML frontmatter")
    parts = text.split("---", 2)
    if len(parts) != 3:
        raise SystemExit(f"{path.relative_to(ROOT)} has malformed frontmatter")
    metadata = yaml.safe_load(parts[1])
    for key in ("name", "description"):
        if not metadata.get(key):
            raise SystemExit(f"{path.relative_to(ROOT)} is missing {key}")
    if not isinstance(metadata.get("tools"), list):
        raise SystemExit(f"{path.relative_to(ROOT)} must declare a constrained tools list")

print(f"Validated {len(toml_files)} Codex TOML files.")
print(f"Validated {len(workflow_files)} GitHub Actions workflow YAML files.")
print(f"Validated {len(copilot_agents)} GitHub Copilot agent profiles.")
print(f"Validated {len(required)} required project files.")
