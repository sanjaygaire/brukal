"""
tui.py — the live engagement dashboard (optional; needs `rich`).

A real-time view of a running engagement: the task tree advancing, each gate
verdict colour-coded (green ALLOW / yellow ESCALATE / red DENY), per-agent trust
meters that move as agents behave, and a scrolling activity log.

It is a pure OBSERVER. The orchestrator emits fire-and-forget events; the
dashboard only renders them. It never affects what runs — a display glitch can
never change an engagement's behaviour. Escalations pause the live view, prompt
on the console (fail-closed), and resume.
"""
from __future__ import annotations

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .tasktree import TaskStatus

_STATUS = {
    TaskStatus.PENDING: ("○", "grey50"),
    TaskStatus.IN_PROGRESS: ("▶", "cyan"),
    TaskStatus.DONE: ("✔", "green"),
    TaskStatus.FAILED: ("✗", "red"),
    TaskStatus.BLOCKED: ("⛔", "yellow"),
}
_VERDICT = {"ALLOW": "green", "ESCALATE": "yellow", "DENY": "red", "BLOCKED": "grey50"}


def _bar(value: float, width: int = 12) -> Text:
    filled = max(0, min(width, round(value * width)))
    colour = "green" if value >= 0.7 else "yellow" if value >= 0.4 else "red"
    return Text("█" * filled + "░" * (width - filled), style=colour)


class Dashboard:
    def __init__(self, engagement: str, target: str, cage: str, tree, trust,
                 n_skills: int = 0):
        self._eng = engagement
        self._target = target
        self._cage = cage
        self._tree = tree
        self._trust = trust
        self._skills = n_skills
        self._log: list[Text] = []
        self._counts = {"executed": 0, "failed": 0, "blocked": 0}
        self._console = Console()
        self._live: Live | None = None

    # -- observer ------------------------------------------------------------ #

    def on_event(self, kind: str, payload: dict) -> None:
        if kind == "turn":
            self._log.append(self._turn_line(payload))
        elif kind == "end":
            self._counts = {k: payload.get(k, 0) for k in self._counts}
        if self._live is not None:
            self._live.update(self._render())

    def _turn_line(self, payload: dict) -> Text:
        task = payload.get("task")
        decision = payload.get("decision")
        result = payload.get("result")
        agent = getattr(task, "agent", "?")
        if decision is None:
            return Text(f"  {agent:<8} BLOCKED  (no agent for role)", style="grey50")
        colour = _VERDICT.get(decision.verdict, "white")
        ran = "ran" if result is not None else "—"
        line = Text(f"  {agent:<8} ", style="bold")
        line.append(f"{decision.verdict:<9}", style=colour)
        line.append(f"{ran:<4} ", style="grey50")
        line.append(str(decision.action)[:56])
        return line

    # -- rendering ----------------------------------------------------------- #

    def _agents(self) -> list[str]:
        seen: list[str] = []
        for t in self._tree.all_tasks():
            if t.agent not in seen:
                seen.append(t.agent)
        return seen

    def _render(self) -> Group:
        header = Panel(
            Text.assemble(("BRUKAL ", "bold cyan"), ("· let's hunt   ", "cyan"),
                          (f"engagement={self._eng}  target={self._target}  "
                           f"cage={self._cage}  skills={self._skills}", "white")),
            border_style="cyan")

        tree_tbl = Table.grid(padding=(0, 1))
        tree_tbl.add_column(); tree_tbl.add_column(); tree_tbl.add_column()
        for t in self._tree.all_tasks():
            icon, colour = _STATUS.get(t.status, ("?", "white"))
            tree_tbl.add_row(Text(icon, style=colour),
                             Text(t.agent, style="magenta"),
                             Text(t.description[:60]))
        tree_panel = Panel(tree_tbl, title="task tree", border_style="grey37")

        trust_tbl = Table.grid(padding=(0, 1))
        for a in self._agents():
            v = self._trust.of(a) if self._trust is not None else 1.0
            trust_tbl.add_row(Text(f"{a:<8}", style="magenta"), _bar(v),
                              Text(f"{v:.2f}"))
        trust_panel = Panel(trust_tbl, title="trust", border_style="grey37")

        log_panel = Panel(Group(*self._log[-9:]) if self._log else Text("…"),
                          title="activity", border_style="grey37")

        foot = Text.assemble(
            ("executed ", "grey50"), (str(self._counts["executed"]), "green"),
            ("   failed ", "grey50"), (str(self._counts["failed"]), "red"),
            ("   blocked ", "grey50"), (str(self._counts["blocked"]), "yellow"))

        return Group(header, tree_panel, trust_panel, log_panel, foot)

    # -- run + approve ------------------------------------------------------- #

    def run(self, run_fn):
        """Run `run_fn` (the orchestrator) inside a live display; return its value."""
        with Live(self._render(), console=self._console, refresh_per_second=8,
                  screen=False) as live:
            self._live = live
            try:
                return run_fn()
            finally:
                live.update(self._render())
                self._live = None

    def approver(self, decision) -> bool:
        """Escalation sign-off: pause the live view, prompt, resume. Fail-closed."""
        live = self._live
        if live is not None:
            live.stop()
        try:
            self._console.print(Panel(
                Text.assemble(
                    ("ESCALATION — sign-off required\n", "bold yellow"),
                    (f"action : {decision.action}\n", "white"),
                    (f"target : {decision.target}   agent: {decision.agent}\n", "white"),
                    (f"risk   : {decision.risk_band}  ({decision.reason})", "grey62")),
                border_style="yellow"))
            if not self._console.file.isatty():
                self._console.print("  non-interactive; declined (fail-closed)")
                ans = ""
            else:
                ans = self._console.input("  approve this action? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        finally:
            if live is not None:
                live.start(refresh=True)
        return ans in ("y", "yes")
