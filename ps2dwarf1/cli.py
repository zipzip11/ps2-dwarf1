from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional


def parse_int(text: str) -> int:
    return int(text, 0)


def resolve_input_path(value: Optional[str], prompt: str = "Path to PS2 ELF: ") -> Path:
    if value:
        path = Path(value.strip('"')).expanduser()
    else:
        try:
            raw = input(prompt).strip()
        except EOFError:
            raw = ""
        if not raw:
            raise SystemExit("error: input path is required")
        path = Path(raw.strip('"')).expanduser()
    if not path.is_file():
        raise SystemExit(f"error: file not found: {path}")
    return path


def default_output(input_path: Path, suffix: str) -> Path:
    return Path("out") / f"{input_path.stem}.{suffix}"


def resolve_output_path(value: Optional[str], default_path: Path) -> Path:
    path = Path(value).expanduser() if value else default_path
    if path.exists() and path.is_dir():
        path = path / default_path.name
    return path


def write_json(path: Path, payload: Any, indent: Optional[int] = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent)
        handle.write("\n")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fail(exc: BaseException) -> None:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1)
