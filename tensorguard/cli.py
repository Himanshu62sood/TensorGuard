import os
import sys
import uuid
import click
from rich.console import Console
from rich.table import Table

from tensorguard.rules import Vulnerability
from tensorguard.scanners.ast_scanner import scan_python_script
from tensorguard.scanners.pickle_scanner import PickleScanner
from tensorguard.scanners.tensor_scanner import SafeTensorsScanner
from tensorguard.remote.hf_scanner import RemoteHFScanner
from tensorguard.database import log_scan_results, get_scan_history

console = Console()
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def render_report(findings: list[Vulnerability], scan_id: str):
    table = Table(title=f"TensorGuard Security Report (Scan ID: {scan_id[:8]})")
    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("File", style="magenta")
    table.add_column("Details", style="white")

    for v in findings:
        color = "red" if v.severity in ("CRITICAL", "HIGH") else "yellow" if v.severity == "MEDIUM" else "blue"
        table.add_row(f"[{color}]{v.severity}[/{color}]", v.rule_id, v.file_path, v.message)

    console.print(table)


def evaluate_gate(findings: list[Vulnerability], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 3)
    return any(SEVERITY_ORDER.get(v.severity, 1) >= threshold for v in findings)


@click.group()
def main():
    """TensorGuard: AI Model Supply Chain & Serialization Security Scanner."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--fail-on", default="HIGH", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False))
def scan(path: str, fail_on: str):
    """Scan a local model directory or file for serialization exploits."""
    console.print(f"[bold cyan]TensorGuard Scanner[/bold cyan] - Scanning target: [green]{path}[/green]")

    findings: list[Vulnerability] = []
    scan_id = str(uuid.uuid4())

    targets = []
    if os.path.isfile(path):
        targets.append(path)
    else:
        for root, _, files in os.walk(path):
            for f in files:
                targets.append(os.path.join(root, f))

    for target in targets:
        if target.endswith(".py"):
            findings.extend(scan_python_script(target))
        elif any(target.endswith(ext) for ext in (".bin", ".pt", ".pkl")):
            findings.extend(PickleScanner(target).scan())
        elif target.endswith(".safetensors"):
            findings.extend(SafeTensorsScanner(target).scan())

    _handle_scan_output(findings, scan_id, path, fail_on)


@main.command(name="scan-hf")
@click.argument("repo_id")
@click.option("--revision", default="main", help="Git branch, tag, or commit hash.")
@click.option("--token", default=None, help="Hugging Face API token for private repos.")
@click.option("--fail-on", default="HIGH", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False))
def scan_hf(repo_id: str, revision: str, token: str, fail_on: str):
    """Scan a remote Hugging Face repository in-memory via HTTP range requests."""
    console.print(f"[bold cyan]TensorGuard Remote[/bold cyan] - Inspecting Hugging Face repo: [green]{repo_id}[/green] ({revision})")

    scan_id = str(uuid.uuid4())
    try:
        remote_scanner = RemoteHFScanner(repo_id=repo_id, revision=revision, auth_token=token)
        findings = remote_scanner.scan_remote_repo()
    except Exception as e:
        console.print(f"[bold red]Remote Scan Error:[/bold red] {str(e)}")
        sys.exit(2)

    _handle_scan_output(findings, scan_id, f"hf://{repo_id}", fail_on)


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output .safetensors path.")
def sanitize(input_path: str, output: str):
    """Convert an unsafe PyTorch/Pickle model into a secure .safetensors file."""
    from tensorguard.remediation.sanitizer import sanitize_pickle_to_safetensors

    if not output:
        base, _ = os.path.splitext(input_path)
        output = f"{base}_clean.safetensors"

    console.print(f"[bold cyan]TensorGuard Sanitizer[/bold cyan] - Processing: [yellow]{input_path}[/yellow]")
    try:
        sanitize_pickle_to_safetensors(input_path, output)
        console.print(f"[bold green]✓ Successfully converted to secure format:[/bold green] [magenta]{output}[/magenta]")
    except Exception as e:
        console.print(f"[bold red]Sanitization Failed:[/bold red] {str(e)}")
        sys.exit(1)


@main.command()
@click.option("--limit", "-n", default=10, help="Number of past scan records to display.")
def history(limit: int):
    """View recent scan audit records stored in the SQLite database."""
    try:
        records = get_scan_history(limit=limit)
    except Exception as e:
        console.print(f"[bold red]Failed to read audit log:[/bold red] {str(e)}")
        sys.exit(1)

    if not records:
        console.print("[dim yellow]No scan records found in tensorguard_audit.db[/dim yellow]")
        return

    table = Table(title="TensorGuard Scan Audit History")
    table.add_column("Scan ID", style="cyan", no_wrap=True)
    table.add_column("Timestamp", style="dim")
    table.add_column("Target", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Findings", justify="right")

    for rec in records:
        status_color = "green" if rec["status"] == "PASSED" else "red"
        status_display = f"[{status_color}]{rec['status']}[/{status_color}]"
        table.add_row(
            rec["scan_id"][:8],
            str(rec["timestamp"]),
            rec["target_path"],
            status_display,
            str(rec["findings_count"]),
        )

    console.print(table)


@main.command()
@click.option("--scan-id", default=None, help="Specific Scan ID (defaults to most recent).")
@click.option("--output", "-o", default="tensorguard_report.html", help="Output HTML file path.")
def report(scan_id: str, output: str):
    """Export an executive HTML compliance report for past scans."""
    from tensorguard.database import get_scan_details
    from tensorguard.reporting.html_reporter import generate_html_report

    scan_data = get_scan_details(scan_id=scan_id)
    if not scan_data:
        console.print("[bold red]Error:[/bold red] No matching scan found in database.")
        sys.exit(1)

    try:
        generate_html_report(scan_data, output_path=output)
        abs_path = os.path.abspath(output)
        console.print(f"[bold green]✓ Executive report exported successfully:[/bold green] [cyan]{abs_path}[/cyan]")
    except Exception as e:
        console.print(f"[bold red]Failed to generate report:[/bold red] {str(e)}")
        sys.exit(1)


def _handle_scan_output(findings: list[Vulnerability], scan_id: str, target: str, fail_on: str):
    failed = evaluate_gate(findings, fail_on)
    status = "FAILED" if failed else "PASSED"

    if findings:
        render_report(findings, scan_id)
    else:
        console.print("[bold green]✓ No vulnerabilities detected.[/bold green]")

    try:
        log_scan_results(target, status, findings)
        console.print("[dim]✓ Audit record logged in SQLite database (tensorguard_audit.db)[/dim]")
    except Exception as db_err:
        console.print(f"[dim yellow]Warning: Failed to write to audit log: {db_err}[/dim yellow]")

    if failed:
        console.print(f"[bold red]SCAN FAILED: Found issues meeting or exceeding {fail_on.upper()}[/bold red]")
        sys.exit(1)
    else:
        console.print(f"[bold green]SCAN PASSED: Model is clean.[/bold green]")
        sys.exit(0)


if __name__ == "__main__":
    main()