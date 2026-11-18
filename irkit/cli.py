"""Command-line interface for Linux-IR-Toolkit.

The CLI is intentionally thin: it validates arguments, constructs a
:class:`~irkit.context.Investigation`, and presents results.  Every collection
command is read-only.  Human-readable output goes to stdout; ``--json`` emits a
single JSON document to stdout so the tool can be scripted safely.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from irkit.collectors import COLLECTOR_ORDER
from irkit.config import DEFAULT_OUTPUT_DIR, TOOL_NAME, TOOL_VERSION, SystemPaths, ToolkitConfig
from irkit.context import Investigation, InvestigationError, load_document
from irkit.iocfile import load_indicators
from irkit.models import Severity
from irkit.report import ReportError, write_report

LOGGER = logging.getLogger("irkit.cli")
_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "informational": "dim",
}
_STATUS_STYLE = {
    "ok": "green",
    "partial": "yellow",
    "error": "red",
    "skipped": "dim",
}


class CLIError(RuntimeError):
    """Raised for user-facing CLI validation failures."""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for every supported command."""
    parser = argparse.ArgumentParser(
        prog="ir.py",
        description=(
            "Read-only Linux incident response and forensic triage toolkit. "
            "Collectors never modify, delete, quarantine or kill anything."
        ),
        epilog=(
            "Examples:\n"
            "  python3 ir.py system\n"
            "  python3 ir.py collect --output reports/\n"
            "  python3 ir.py report --input reports/latest.json\n"
            "  python3 ir.py ioc --ioc-file indicators.json --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--root",
        default="/",
        metavar="PATH",
        help="Collection root (default: /). Useful for offline mounted images; "
        "process and network data always describe the live host.",
    )
    common.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable credential redaction. Not recommended; reports may contain secrets.",
    )
    common.add_argument(
        "--ioc-file",
        metavar="FILE",
        help="JSON or text file of analyst-supplied indicators for the IOC analyser.",
    )
    common.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON document to stdout instead of human-readable tables.",
    )
    common.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        metavar="SEVERITY",
        help="Exit with status 2 when any finding is at or above this severity.",
    )
    common.add_argument("--verbose", "-v", action="count", default=0, help="Increase log verbosity.")
    common.add_argument("--quiet", "-q", action="store_true", help="Suppress informational output.")
    common.add_argument("--log-file", metavar="FILE", help="Also write logs to this file.")
    common.add_argument("--no-color", action="store_true", help="Disable ANSI colour in terminal output.")

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    descriptions = {
        "system": "Host identity, OS, kernel, uptime, mounts and security posture",
        "processes": "Running processes, execution paths, command lines and privilege",
        "network": "Listening ports, established connections and owning processes",
        "users": "Accounts, UID 0 aliases, sudo privileges and login history",
        "ssh": "sshd configuration, authorized keys and authentication activity",
        "persistence": "Cron, systemd, linker preload, profiles and startup persistence",
        "filesystem": "SUID/SGID, writable configuration, temp executables and recent changes",
        "logs": "Authentication, syslog and journal analysis",
        "ioc": "Correlate analyst-supplied indicators against collected evidence",
    }
    for name in COLLECTOR_ORDER:
        command = subparsers.add_parser(
            name,
            parents=[common],
            help=descriptions[name],
            description=descriptions[name],
        )
        command.add_argument(
            "--output",
            metavar="DIR",
            help="Write the investigation JSON to this directory (latest.json is refreshed).",
        )

    collect = subparsers.add_parser(
        "collect",
        parents=[common],
        help="Run a full investigation and preserve structured evidence JSON",
        description="Run all collectors (or a selected subset) and write JSON evidence.",
    )
    collect.add_argument(
        "--modules",
        nargs="+",
        metavar="NAME",
        help=f"Collectors to run (default: all). Available: {', '.join(COLLECTOR_ORDER)}",
    )
    collect.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        metavar="DIR",
        help=f"Output directory for JSON evidence (default: {DEFAULT_OUTPUT_DIR}/)",
    )

    report = subparsers.add_parser(
        "report",
        parents=[common],
        help="Generate professional HTML and JSON reports from an investigation",
        description="Render an HTML report and a normalised JSON report from a saved investigation.",
    )
    report.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help="Investigation JSON, for example reports/latest.json",
    )
    report.add_argument(
        "--output",
        metavar="DIR",
        help="Report output directory (default: the input file's directory).",
    )
    return parser


def _configure_logging(args: argparse.Namespace) -> None:
    if args.quiet:
        level = logging.ERROR
    elif args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        try:
            Path(args.log_file).expanduser().parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(Path(args.log_file).expanduser(), encoding="utf-8"))
        except OSError as exc:
            raise CLIError(f"cannot open log file {args.log_file}: {exc}") from exc
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def _load_ioc_config(config: ToolkitConfig, ioc_file: str | None) -> ToolkitConfig:
    if not ioc_file:
        return config
    indicators, errors = load_indicators(ioc_file)
    for error in errors:
        LOGGER.warning("indicator file: %s", error)
    if errors and not indicators:
        raise CLIError(f"no usable indicators could be loaded from {ioc_file}")
    if not indicators:
        raise CLIError(f"indicator file contains no indicators: {ioc_file}")
    LOGGER.info("loaded %d indicator(s) from %s", len(indicators), ioc_file)
    return config.with_iocs([indicator.to_dict() for indicator in indicators], str(ioc_file))


def _config_from_args(args: argparse.Namespace) -> ToolkitConfig:
    root = Path(args.root).expanduser()
    if not root.exists():
        raise CLIError(f"collection root does not exist: {root}")
    paths = SystemPaths.from_root(root)
    config = ToolkitConfig(paths=paths, redact_output=not args.no_redact)
    return _load_ioc_config(config, args.ioc_file)


def _fail_on_exit(document: dict[str, Any], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = Severity.from_str(fail_on)
    findings = document.get("findings", [])
    if not findings:
        return 0
    highest = Severity.highest(
        Severity.from_str(str(item.get("severity", "informational"))) for item in findings
    )
    return 2 if highest.rank >= threshold.rank else 0


def _severity_style(value: str) -> str:
    return _SEVERITY_STYLE.get(value, "")


def _print_summary(document: dict[str, Any], console: Console, *, show_evidence: bool = True) -> None:
    investigation = document.get("investigation", {})
    summary = document.get("summary", {})
    risk = summary.get("risk", {})
    console.print()
    console.print(
        Panel.fit(
            f"[bold]{TOOL_NAME}[/bold] v{TOOL_VERSION}\n"
            f"Investigation [cyan]{investigation.get('id', 'unknown')}[/cyan] · "
            f"host [bold]{investigation.get('hostname', 'unknown')}[/bold]\n"
            f"Mode: read-only · Root: {investigation.get('root', '/')} · "
            f"Privilege: {'root' if investigation.get('is_root') else 'unprivileged'}",
            border_style="blue",
        )
    )
    console.print(
        f"Risk: [bold]{risk.get('rating', 'unknown')}[/bold] "
        f"({risk.get('score', 0)}/100) · Overall severity: "
        f"[{_severity_style(str(risk.get('overall_severity', 'informational')))}]"
        f"{risk.get('overall_severity', 'informational')}[/]"
    )

    collectors = document.get("collectors", [])
    if collectors:
        table = Table(title="Collectors", box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Collector", style="bold")
        table.add_column("Status")
        table.add_column("Duration", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Evidence", justify="right")
        for item in collectors:
            status = str(item.get("status", "unknown"))
            table.add_row(
                str(item.get("name", "")),
                f"[{_STATUS_STYLE.get(status, '')}]{status}[/]",
                f"{item.get('duration_ms', 0)} ms",
                str(len(item.get("finding_ids", []))),
                str(len(item.get("evidence_ids", []))),
            )
        console.print(table)

    findings = document.get("findings", [])
    if findings:
        table = Table(title=f"Findings ({len(findings)})", box=box.SIMPLE_HEAD)
        table.add_column("ID", style="dim")
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("Collector", style="dim")
        for item in findings[:50]:
            severity = str(item.get("severity", "informational"))
            table.add_row(
                str(item.get("finding_id", "")),
                f"[{_severity_style(severity)}]{severity}[/]",
                str(item.get("title", "")),
                str(item.get("collector", "")),
            )
        console.print(table)
        if len(findings) > 50:
            console.print(f"[dim]Showing 50 of {len(findings)} findings; use --json for the full document.[/dim]")
    else:
        console.print("[green]No findings were produced.[/green] [dim]This does not prove the host is clean.[/dim]")

    errors = summary.get("errors", [])
    warnings = summary.get("warnings", [])
    if errors:
        console.print(f"[red]{len(errors)} collector error(s) recorded; use --json for details.[/red]")
    if warnings and not document.get("investigation", {}).get("is_root"):
        console.print(
            f"[yellow]{len(warnings)} warning(s) recorded. Re-run as root for fuller visibility where authorised.[/yellow]"
        )
    if show_evidence:
        console.print(f"[dim]Evidence records: {summary.get('evidence', 0)}[/dim]")


def _run_collection(args: argparse.Namespace, console: Console) -> int:
    if args.root != "/":
        LOGGER.warning(
            "collection root is %s; file-based collectors use it, but process/network data still "
            "describes the live host",
            args.root,
        )
    if args.no_redact:
        LOGGER.warning("redaction disabled: reports may contain credentials or private material")
    if os.geteuid() != 0 and not args.quiet:
        LOGGER.warning(
            "running as uid %d without root: some processes, sockets, logs and account databases "
            "may be unreadable",
            os.geteuid(),
        )

    config = _config_from_args(args)
    investigation = Investigation(config, command=sys.argv)
    requested = None
    if args.command == "collect":
        requested = args.modules
    else:
        requested = [args.command]
    document = investigation.run(requested)

    output = getattr(args, "output", None)
    if output:
        written = investigation.save(output)
        document = written["document"]
        if not args.json and not args.quiet:
            console.print(f"[green]JSON evidence written:[/green] {written['json_path']}")
            console.print(f"[green]Latest pointer updated:[/green] {written['latest_path']}")

    if args.json:
        sys.stdout.write(json.dumps(document, indent=2, ensure_ascii=False, default=str) + "\n")
    elif not args.quiet:
        _print_summary(document, console)
    return _fail_on_exit(document, args.fail_on)


def _run_report(args: argparse.Namespace, console: Console) -> int:
    try:
        document = load_document(args.input)
    except InvestigationError as exc:
        raise CLIError(str(exc)) from exc
    try:
        result = write_report(args.input, args.output, redact=not args.no_redact)
    except (ReportError, InvestigationError) as exc:
        raise CLIError(str(exc)) from exc

    if args.json:
        payload = {key: value for key, value in result.items() if key != "document"}
        payload["risk"] = document.get("summary", {}).get("risk", {})
        payload["integrity_valid"] = result.get("integrity_valid", False)
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")
    elif not args.quiet:
        console.print(f"[green]HTML report written:[/green] {result['html_path']}")
        console.print(f"[green]JSON report written:[/green] {result['json_path']}")
        console.print(f"[green]Latest HTML:[/green] {result['latest_html']}")
        if not result.get("integrity_valid"):
            console.print(
                "[yellow]Warning: the input document's integrity digest could not be verified.[/yellow]"
            )
        _print_summary(result["document"], console)
    return _fail_on_exit(document, args.fail_on)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(no_color=getattr(args, "no_color", False), highlight=False)
    try:
        _configure_logging(args)
        if args.command == "report":
            return _run_report(args, console)
        return _run_collection(args, console)
    except (CLIError, InvestigationError, ReportError, KeyError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted; no changes were made.[/yellow]")
        return 130
    except OSError as exc:
        console.print(f"[bold red]System error:[/bold red] {exc}", style="red")
        return 1


__all__ = ["build_parser", "main"]
