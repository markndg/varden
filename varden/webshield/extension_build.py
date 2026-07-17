from __future__ import annotations

import zipfile
from pathlib import Path


def _repo_extension_dir() -> Path:
    # varden/webshield/extension_build.py -> repo_root/extension
    return Path(__file__).resolve().parent.parent.parent / "extension"


def extension_path() -> str:
    """Return the path to the unpacked development extension.

    Load it in Chrome/Edge via chrome://extensions -> "Load unpacked" with
    Developer Mode enabled, pointed at this directory.
    """
    path = _repo_extension_dir()
    if not path.exists():
        raise FileNotFoundError(
            "extension/ directory not found. This command only works from a source checkout of the "
            "Varden repository (it is not packaged into the PyPI 'varden' wheel)."
        )
    return str(path)


def build_extension(out: str | None = None) -> int:
    """Build a reproducible zip of the unpacked extension directory.

    Reproducible = deterministic file order (sorted paths) and a fixed
    modification time for every entry, so re-running this on identical
    source produces a byte-identical zip.
    """
    src = _repo_extension_dir()
    if not src.exists():
        print(f"extension/ directory not found at {src}; nothing to build.")
        return 1
    out_path = Path(out) if out else src.parent / "dist" / "varden-web-shield-extension.zip"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    files = sorted(p for p in src.rglob("*") if p.is_file())
    fixed_date_time = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in files:
            arcname = file_path.relative_to(src).as_posix()
            info = zipfile.ZipInfo(arcname, date_time=fixed_date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, file_path.read_bytes())

    print(f"Built {out_path} ({len(files)} files).")
    return 0
