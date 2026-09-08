from __future__ import annotations

import html
import re
from collections.abc import Iterable
from pathlib import Path

from playwright.sync_api import Page


def _marked(value: object, terms: Iterable[str]) -> str:
    raw = str(value)
    choices = sorted({str(term) for term in terms if str(term)}, key=len, reverse=True)
    if not choices:
        return html.escape(raw, quote=True)
    pattern = re.compile("|".join(re.escape(term) for term in choices))
    chunks: list[str] = []
    end = 0
    for match in pattern.finditer(raw):
        chunks.append(html.escape(raw[end:match.start()], quote=True))
        chunks.append(f"<mark>{html.escape(match.group(0), quote=True)}</mark>")
        end = match.end()
    chunks.append(html.escape(raw[end:], quote=True))
    return "".join(chunks)


def render_command_evidence(
    page: Page,
    cis: str,
    title: str,
    command: str,
    output: str,
    destination: Path,
    highlight_terms: Iterable[str] = (),
) -> Path:
    """Render inert, local command/output evidence into a PNG screenshot."""
    terms = tuple(highlight_terms)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing evidence: {destination}")
    document = f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
body {{ margin: 0; background: #f4f6f8; color: #17202a; font: 16px Segoe UI, sans-serif; }}
#evidence {{ box-sizing: border-box; width: 1100px; padding: 32px 40px 40px; background: white; }}
h1 {{ margin: 0 0 8px; font-size: 24px; }} h2 {{ margin: 24px 0 8px; font-size: 17px; }}
pre {{ margin: 0; padding: 16px; border: 1px solid #c8d0d8; border-radius: 4px;
       background: #f8fafb; font: 14px Consolas, monospace; line-height: 1.45;
       white-space: pre-wrap; overflow-wrap: anywhere; }}
mark {{ outline: 3px solid #e00000; outline-offset: 2px; background: #fff0f0; color: inherit; }}
</style></head><body><main id="evidence">
<h1>{html.escape(str(cis), quote=True)} — {html.escape(str(title), quote=True)}</h1>
<h2>Command</h2><pre>{html.escape(str(command), quote=True)}</pre>
<h2>Output</h2><pre>{_marked(output, terms)}</pre>
</main></body></html>"""
    page.set_content(document, wait_until="domcontentloaded")
    destination.parent.mkdir(parents=True, exist_ok=True)
    page.locator("#evidence").screenshot(path=str(destination))
    return destination
