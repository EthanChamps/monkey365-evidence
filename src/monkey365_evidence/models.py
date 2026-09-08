from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Control:
    cis: str
    title: str
    start_url: str
    steps: tuple[dict[str, Any], ...]
    screenshot_selector: str | None = None
    full_page: bool = True
    enabled: bool = True

    @property
    def filename(self) -> str:
        safe = "".join(c if c.isalnum() or c in " ._-" else "_" for c in self.title)
        return f"{self.cis} {safe.strip()}.png"


@dataclass(frozen=True)
class CaptureResult:
    cis: str
    status: str
    path: Path | None = None
    detail: str | None = None

