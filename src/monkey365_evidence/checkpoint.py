"""Atomic run-report writes that tolerate a missing output directory."""

import json
import os
import tempfile
from pathlib import Path


def write_checkpoint(destination: Path, report: dict) -> None:
    payload = json.dumps(report, indent=2)
    for attempt in range(3):
        temporary = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=".run-manifest-", suffix=".tmp",
                                        dir=destination.parent)
            temporary = Path(name)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
            temporary.replace(destination)
            return
        except FileNotFoundError:
            if attempt == 2:
                raise
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
