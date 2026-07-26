"""
test_safe_defaults.py — Phase 5 safe defaults.

Scope is mandatory: the executing commands (run/solve/auto) refuse to run without an
explicit authorised scope rather than falling back to a broad shipped default. The
audit chain warns (but does not block) on a live run when it is unkeyed. The benchmark
carries its own fixed scope so the shipped scope.json can be a single safe example.
No Docker, model, or network needed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.audit import AuditLog
from brukal.cli import _no_scope, _resolve_scope, main
from brukal.engagement import warn_if_unkeyed_audit
from brukal.experiment import BENCH_SCOPE


# --- scope is mandatory ----------------------------------------------------

def test_resolve_scope_prefers_explicit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _resolve_scope("my.json") == "my.json"      # explicit wins


def test_resolve_scope_falls_back_to_local_scope_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scope.json").write_text("{}", encoding="utf-8")
    assert _resolve_scope(None) == "scope.json"


def test_resolve_scope_refuses_when_absent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                          # empty dir, no scope.json
    assert _resolve_scope(None) is None
    assert _no_scope() == 2


def test_run_refuses_with_no_scope(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)                          # no scope.json here
    rc = main(["run", "10.10.10.5", "--fake"])
    assert rc == 2
    assert "no authorised scope" in capsys.readouterr().out.lower()


def test_auto_refuses_with_no_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["auto", "10.10.10.5", "--fake"]) == 2


# --- shipped scope.json is a narrow single-host example --------------------

def test_shipped_scope_is_narrow():
    data = json.loads((Path(__file__).resolve().parents[1] / "scope.json").read_text())
    # No broad ranges: every authorised network is a single host (/32).
    assert data["authorized_cidrs"] == ["127.0.0.1/32"]


# --- benchmark carries its own scope (decoupled from scope.json) -----------

def test_bench_scope_matches_corpus_hosts():
    assert BENCH_SCOPE.contains_ip("10.10.10.5")        # in-scope corpus hosts
    assert BENCH_SCOPE.contains_ip("10.10.10.7")
    assert BENCH_SCOPE.contains_ip("127.0.0.1")
    assert not BENCH_SCOPE.contains_ip("8.8.8.8")       # out-of-scope corpus hosts
    assert not BENCH_SCOPE.contains_ip("10.10.20.5")
    assert not BENCH_SCOPE.tool_allowed("metasploit")   # allowlist DENY is provable


# --- unkeyed audit warning (warn, don't block) -----------------------------

def test_audit_keyed_flag(tmp_path):
    assert AuditLog(tmp_path / "a.jsonl").keyed is False
    assert AuditLog(tmp_path / "b.jsonl", key="s3cret").keyed is True


def test_warn_on_unkeyed_live_run(tmp_path, capsys):
    warn_if_unkeyed_audit(AuditLog(tmp_path / "a.jsonl"), fake=False)
    assert "unkeyed" in capsys.readouterr().out.lower()


def test_no_warn_when_fake_or_keyed(tmp_path, capsys):
    warn_if_unkeyed_audit(AuditLog(tmp_path / "a.jsonl"), fake=True)      # fake: silent
    warn_if_unkeyed_audit(AuditLog(tmp_path / "b.jsonl", key="k"), fake=False)  # keyed: silent
    assert capsys.readouterr().out == ""
