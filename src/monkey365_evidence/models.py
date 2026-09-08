from __future__ import annotations

import re
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
    expected_url: str | None = None
    ready_selector: str | None = None
    highlight_selectors: tuple[str, ...] = ()
    expected_checks: tuple[dict[str, Any], ...] = ()
    frame_selector: str | None = None

    @property
    def filename(self) -> str:
        safe = "".join(c if c.isalnum() or c in " ._-" else "_" for c in self.title)
        cis = re.sub(r"[^A-Za-z0-9._-]", "_", self.cis)
        return f"{cis} {safe.strip()[:140]}.png"


@dataclass(frozen=True)
class CaptureResult:
    cis: str
    status: str
    path: Path | None = None
    detail: str | None = None
    highlighted: bool = False
    sha256: str | None = None
    url: str | None = None

