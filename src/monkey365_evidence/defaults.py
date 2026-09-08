from pathlib import Path


def resource_path(name: str) -> Path:
    """Find bundled defaults in a wheel or the editable source checkout."""
    packaged = Path(__file__).parent / "data" / name
    if packaged.is_file():
        return packaged
    source = Path(__file__).resolve().parents[2] / name
    if source.is_file():
        return source
    raise FileNotFoundError(f"Bundled resource is missing: {name}")
