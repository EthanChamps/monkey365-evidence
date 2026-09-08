"""Check and optionally install the fixed PowerShell audit dependencies."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence

from .powershell_audit import powershell_executable

EXCHANGE_MODULES = ("ExchangeOnlineManagement",)
GRAPH_MODULES = (
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Reports",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
)


def required_modules(*, exchange: bool, graph: bool) -> tuple[str, ...]:
    return (EXCHANGE_MODULES if exchange else ()) + (GRAPH_MODULES if graph else ())


def missing_modules(
    modules: Sequence[str], *, pwsh: str = "pwsh",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str, ...]:
    """Return fixed audit modules unavailable to the selected PowerShell executable."""
    if not modules:
        return ()
    quoted = ", ".join(f"'{module}'" for module in modules)
    command = (
        f"$modules=@({quoted}); $missing=@($modules | Where-Object {{ -not "
        "(Get-Module -ListAvailable -Name $_) }); "
        "[pscustomobject]@{missing=$missing} | ConvertTo-Json -Compress"
    )
    completed = runner(
        [powershell_executable(pwsh), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "PowerShell module check failed").strip()
        raise OSError(detail)
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as error:
        raise OSError("PowerShell returned an invalid module check result") from error
    missing = payload.get("missing", []) if isinstance(payload, dict) else []
    return tuple(module for module in missing if module in modules)


def install_modules(
    modules: Sequence[str], *, pwsh: str = "pwsh",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Install fixed, public PowerShell Gallery modules for the current user."""
    quoted = ", ".join(f"'{module}'" for module in modules)
    command = (
        "$ErrorActionPreference='Stop'; "
        "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null; "
        f"Install-Module -Name @({quoted}) -Scope CurrentUser -Repository PSGallery -Force -AllowClobber"
    )
    completed = runner(
        [powershell_executable(pwsh), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        check=False,
    )
    if completed.returncode:
        raise OSError("PowerShell module installation failed")


def ensure_modules(
    *, exchange: bool, graph: bool, interactive: bool,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> None:
    """Prompt before installing missing dependencies, then verify the installation."""
    required = required_modules(exchange=exchange, graph=graph)
    missing = missing_modules(required)
    if not missing:
        return
    names = ", ".join(missing)
    output_fn(f"Missing PowerShell modules: {names}")
    if not interactive:
        raise ValueError(f"Install these PowerShell modules before using --non-interactive: {names}")
    answer = input_fn("Install these modules for the current user from PSGallery? [y/N]: ").strip().casefold()
    if answer not in {"y", "yes"}:
        raise ValueError("PowerShell module installation was declined; capture was not started")
    install_modules(missing)
    still_missing = missing_modules(required)
    if still_missing:
        raise OSError("PowerShell modules are still unavailable: " + ", ".join(still_missing))
