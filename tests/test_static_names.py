"""
test_static_names.py — no undefined names anywhere in the source.

Four separate times this project shipped a NameError into code that only runs against a
live target: `re` used in loop.py without the import, `urljoin` referenced above its
import inside confirm_surface, `quote` imported only inside another method, and `json`
used by a new proof in a module that never imported it. Each survived the unit suite
because the surrounding branch needed a real engagement to execute, and each cost part
of a live run to diagnose.

Vigilance is not a control. A name-resolution check reads every branch whether or not a
test happens to drive it, which is exactly the property the test suite lacks.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _source_files() -> list[str]:
    """Our own source only — never a vendored virtualenv."""
    out: list[str] = []
    for pattern in ("brukal/*.py", "benchmarks/*.py", "tests/*.py", "run_*.py",
                    "brukal_cli.py"):
        out += [str(p) for p in ROOT.glob(pattern) if ".venv" not in p.parts]
    return sorted(out)


def test_no_undefined_names_in_the_source():
    try:
        import pyflakes  # noqa: F401
    except ImportError:                       # pragma: no cover - optional dev dependency
        pytest.skip("pyflakes not installed (pip install -e '.[dev]')")

    proc = subprocess.run([sys.executable, "-m", "pyflakes", *_source_files()],
                          capture_output=True, text=True, cwd=ROOT)
    undefined = [l for l in proc.stdout.splitlines() if "undefined name" in l]
    assert not undefined, (
        "undefined name(s) — these raise only when the branch runs, which for this "
        "project means during a live engagement:\n  " + "\n  ".join(undefined))


def test_the_check_would_have_caught_the_real_bugs():
    """Proof the guard earns its place: the exact shapes that shipped are detected."""
    try:
        import pyflakes  # noqa: F401
    except ImportError:                       # pragma: no cover
        pytest.skip("pyflakes not installed")

    import tempfile
    broken = (
        "def gate(surface):\n"
        "    return any(re.search(r'x', r) for r in surface)\n"       # missing import
        "\n"
        "def build(base, route):\n"
        "    url = _urljoin(base, route)\n"                           # used before import
        "    from urllib.parse import urljoin as _urljoin\n"
        "    return url\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "broken.py"
        f.write_text(broken)
        proc = subprocess.run([sys.executable, "-m", "pyflakes", str(f)],
                              capture_output=True, text=True)
        assert "undefined name 're'" in proc.stdout, proc.stdout
        assert "_urljoin" in proc.stdout, proc.stdout
