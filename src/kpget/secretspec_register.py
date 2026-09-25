"""Register the kpget endpoint with SecretSpec (user-level claim).

Writes the claim file SecretSpec discovers out-of-tree providers by
(``<scheme>.secretspec.json`` in ``providers.d``) and tightens permissions so
the loader's group-writable-ancestor check passes. Idempotent: re-run after
every ``uv sync`` -- uv rebuilds ``.venv`` with your umask, which reintroduces
group-write bits the SecretSpec loader rejects.

Usage: ``uv run kpget-secretspec-register``
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

CLAIM_ENVIRONMENT = ["KPGET_*"]
CLAIM_NAME = "kpget.secretspec.json"


def claim_dir() -> Path:
    config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config) if config else Path.home() / ".config"
    return base / "secretspec" / "providers.d"


def provider_executable() -> Path:
    """The endpoint console script, next to this venv's interpreter."""
    exe = Path(sys.executable).parent / "kpget-secretspec-provider"
    if not exe.is_file():
        raise SystemExit(
            f"kpget: provider endpoint not found at {exe}; run 'uv sync' first"
        )
    return exe


def write_claim(directory: Path, executable: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    claim = directory / CLAIM_NAME
    payload = {"executable": str(executable), "environment": CLAIM_ENVIRONMENT}
    claim.write_text(json.dumps(payload) + "\n")
    claim.chmod(0o600)
    directory.chmod(directory.stat().st_mode & ~0o022)
    return claim


def tighten_executable(executable: Path, project_root: Path) -> None:
    """Strip group/other write bits along the whole ancestor chain: the
    SecretSpec loader rejects a provider whose path is group-writable
    anywhere above the executable, and `uv sync` recreates .venv with the
    caller's umask."""
    for path in (project_root, project_root / ".venv", project_root / ".venv" / "bin"):
        if path.is_dir():
            path.chmod(path.stat().st_mode & ~0o022)
    if executable.is_file():
        executable.chmod(executable.stat().st_mode & ~0o022)


def main(argv: list[str] | None = None, project_root: Path | None = None) -> int:
    project_root = project_root or Path(__file__).resolve().parents[2]
    executable = provider_executable()
    tighten_executable(executable, project_root)
    claim = write_claim(claim_dir(), executable)
    print(f"kpget: claim written to {claim}")
    print(f"kpget: endpoint {executable}")
    print("kpget: declare secrets with providers = [\"kpget\"] and")
    print('kpget:   refs = { kpget = { item = "<entry url>", field = "password" } }')
    print("kpget: re-run this command after every 'uv sync'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
