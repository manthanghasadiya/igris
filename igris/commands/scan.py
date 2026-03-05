"""
Scan Command for igris
======================

Orchestrates the scanning process across different modules.
"""

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from igris.connectors import HTTPConnector, AgentCapabilities
from igris.modules import PromptInjectionScanner, ToolChainScanner, ExfiltrationScanner
from igris.modules.prompt_injection import Finding, Severity, Confidence
from igris.ai.classifier import AIResultClassifier

app = typer.Typer()
console = Console()


@app.callback(invoke_without_command=True)
def main(
    url: str = typer.Option(None, "--http", help="HTTP endpoint of the agent"),
    modules: str = typer.Option("injection,chain,exfil", "-m", "--modules", help="Comma-separated list of modules to run (injection, chain, exfil)"),
    output: str = typer.Option(None, "-o", "--output", help="Save report to JSON file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed output"),
    ai: bool = typer.Option(False, "--ai", help="Use AI to re-classify ambiguous findings"),
    provider: str = typer.Option("auto", "--provider", help="AI provider to use (groq, deepseek, openai, ollama, etc.)"),
    force: bool = typer.Option(False, "--force", help="Force run all modules even if capabilities not detected"),
):
    """Scan an AI agent for vulnerabilities."""
    
    if not url:
        console.print("[red]Error: Must specify an agent endpoint with --http[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit("🔒 [bold blue]Scan Starting[/bold blue]", border_style="blue"))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # 1. Connect and Discover
        task_id = progress.add_task(description="Connecting to agent...", total=1)
        connector = HTTPConnector(url)
        caps = connector.discover_capabilities()
        progress.update(task_id, completed=1, description="Agent connected and mapped")
        
        selected_modules = [m.strip() for m in modules.split(",")]
        all_findings = []
        
        # 2. Run Scanners
        
        # --- Prompt Injection ---
        if "injection" in selected_modules:
            task_id = progress.add_task(description="Running Prompt Injection tests...", total=1)
            scanner = PromptInjectionScanner(connector, verbose=verbose)
            findings = scanner.scan_all()
            all_findings.extend(findings)
            progress.update(task_id, completed=1, description=f"Prompt Injection: {len(findings)} findings")

        # --- Tool Chain Analysis ---
        if "chain" in selected_modules:
            task_id = progress.add_task(description="Analyzing Tool Chains...", total=1)
            # If no capabilities discovered and not forced, warn and skip (or run if forced)
            has_caps = caps.has_file_access or caps.has_code_execution or caps.has_web_access
            if not has_caps and not force:
                progress.update(task_id, completed=1, description="Tool Chain: Skipped (no capabilities detected, use --force to override)")
            else:
                if not has_caps and force:
                    console.print("[yellow]Warning: Running tool chains despite no detected capabilities (--force)[/yellow]")
                
                scanner = ToolChainScanner(connector, caps, verbose=verbose)
                findings = scanner.scan_all()
                all_findings.extend(findings)
                progress.update(task_id, completed=1, description=f"Tool Chain: {len(findings)} findings")

        # --- Data Exfiltration ---
        if "exfil" in selected_modules:
            task_id = progress.add_task(description="Testing Data Exfiltration...", total=1)
            scanner = ExfiltrationScanner(connector, verbose=verbose)
            findings = scanner.scan_all()
            all_findings.extend(findings)
            progress.update(task_id, completed=1, description=f"Exfiltration: {len(findings)} findings")

        # 3. AI Re-classification
        if ai and all_findings:
            task_id = progress.add_task(description=f"AI Re-classification ({provider})...", total=1)
            try:
                classifier = AIResultClassifier(provider=provider)
                all_findings = classifier.reclassify_findings(all_findings)
                progress.update(task_id, completed=1, description="AI Classification complete")
            except Exception as e:
                progress.update(task_id, completed=1, description=f"AI Classification failed: {e}")
                if verbose:
                    console.print(f"[red]Error during AI classification: {e}[/red]")

    # 4. Filter findings (remove SAFE findings from display)
    final_findings = [f for f in all_findings if f.confidence != Confidence.SAFE]

    # 5. Reporting
    _print_summary(final_findings)
    
    if output:
        _save_report(url, caps, final_findings, output)
        console.print(f"\n[green]Report saved to {output}[/green]")

    # Exit code 1 if critical findings found
    if any(f.severity == Severity.CRITICAL for f in final_findings):
        raise typer.Exit(1)


def _print_summary(findings: list[Finding]):
    """Print a summary table of findings"""
    from rich.table import Table
    
    if not findings:
        console.print("\n[bold green]No vulnerabilities found! ✨[/bold green]")
        return

    table = Table(title="Vulnerability Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Confidence", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Title")
    
    # Sort findings: Critical -> High -> Medium -> Low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 99))
    
    for f in sorted_findings:
        color = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "white"
        }.get(f.severity.value, "white")
        
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.confidence.value.upper(),
            f.category,
            f.title
        )
    
    console.print(table)
    
    # Severity counts
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    
    summary_text = ", ".join([f"{count} {sev.upper()}" for sev, count in counts.items()])
    console.print(f"\n[bold]Total: {len(findings)} findings ({summary_text})[/bold]")


def _save_report(target: str, caps: AgentCapabilities, findings: list[Finding], path: str):
    """Save scan results to a JSON file"""
    report = {
        "target": target,
        "capabilities": {
            "file_access": caps.has_file_access,
            "code_execution": caps.has_code_execution,
            "web_access": caps.has_web_access,
            "memory": caps.has_memory,
        },
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in findings if f.severity == Severity.LOW]),
        }
    }
    
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2))
