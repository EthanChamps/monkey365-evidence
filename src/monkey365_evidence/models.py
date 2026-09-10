from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def evidence_filename(cis: str, title: str, extension: str) -> str:
    safe = "".join(c if c.isalnum() or c in " ._-" else "_" for c in title)
    number = re.sub(r"[^A-Za-z0-9._-]", "_", cis)
    return f"{number} {safe.strip()[:140].rstrip(' .')}.{extension}"


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
    expected_any_checks: tuple[tuple[dict[str, Any], ...], ...] = ()
    frame_selector: str | None = None
    expected_url_pattern: str | None = None

    @property
    def filename(self) -> str:
        return evidence_filename(self.cis, self.title, "png")


@dataclass(frozen=True)
class CaptureResult:
    cis: str
    status: str
    path: Path | None = None
    detail: str | None = None
    highlighted: bool = False
    sha256: str | None = None
    url: str | None = None

