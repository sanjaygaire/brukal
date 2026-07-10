"""
test_cli_target.py — the `brukal target` scope command.

Validates the address, normalises a bare host to /32, keeps the static scope
fields (engagement / tools / rate), replaces by default and accumulates with
--add, refuses a broader-than-one-host range without confirmation, and logs
every change. No Docker or LLM needed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.cli import main


def _scope(tmp):
    return {"scope": str(tmp / "scope.json"), "log": str(tmp / "runs" / "eng.log")}


def _read(tmp):
    return json.loads((tmp / "scope.json").read_text(encoding="utf-8"))


def test_bare_host_becomes_slash_32_and_keeps_static_fields(tmp_path):
    p = _scope(tmp_path)
    rc = main(["target", "10.10.10.5", "--scope", p["scope"], "--log", p["log"]])
    assert rc == 0
    data = _read(tmp_path)
    assert data["authorized_cidrs"] == ["10.10.10.5/32"]
    assert "nmap" in data["allowlisted_tools"]     # static fields preserved
    assert data["rate_limit_per_min"] == 30
    assert Path(p["log"]).exists()                 # change was logged


def test_replace_is_default_and_add_accumulates(tmp_path):
    p = _scope(tmp_path)
    main(["target", "10.10.10.5", "--scope", p["scope"], "--log", p["log"]])
    main(["target", "127.0.0.1", "--scope", p["scope"], "--log", p["log"]])  # replaces
    assert _read(tmp_path)["authorized_cidrs"] == ["127.0.0.1/32"]
    main(["target", "10.0.0.9", "--add", "--scope", p["scope"], "--log", p["log"]])
    assert _read(tmp_path)["authorized_cidrs"] == ["127.0.0.1/32", "10.0.0.9/32"]


def test_invalid_address_is_rejected(tmp_path):
    p = _scope(tmp_path)
    assert main(["target", "not-an-ip", "--scope", p["scope"], "--log", p["log"]]) == 2
    assert not (tmp_path / "scope.json").exists()


def test_broad_range_needs_confirmation(tmp_path):
    p = _scope(tmp_path)
    # non-interactive (pytest): input() raises EOFError -> treated as "no" -> abort
    rc = main(["target", "10.0.0.0/8", "--scope", p["scope"], "--log", p["log"]])
    assert rc == 1
    assert not (tmp_path / "scope.json").exists()   # scope unchanged


def test_broad_range_with_yes_is_written(tmp_path):
    p = _scope(tmp_path)
    rc = main(["target", "10.10.10.0/24", "--yes", "--scope", p["scope"], "--log", p["log"]])
    assert rc == 0
    assert _read(tmp_path)["authorized_cidrs"] == ["10.10.10.0/24"]
