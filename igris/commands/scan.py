"""
Scan Command
============

Scan an AI agent for security vulnerabilities.
"""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from igris.connectors import HTTPConnector, StdioConnector
from igris.modules import PromptInjectionScanner, Severity

app = typer.Typer()
console = Console()


def severity_color(severity: Severity) -> str:
    """Get color for severity level"""
    return {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }.get(severity, "white")


@app.callback(invoke_without_command=True)
def scan(
    http: str = typer.Option(None, "--http", "-u", help="HTTP endpoint URL"),
    stdio: str = typer.Option(None, "--stdio", "-s", help="Command to run agent via stdio"),
    auth: str = typer.Option(None, "--auth", "-a", help="Authorization token"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file (JSON)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    modules: str = typer.Option(
        "all",
        "--modules", "-m",
        help="Modules to run: all, injection, jailbreak, tools"
    ),
):
    """
    Scan an AI agent for security vulnerabilities.
    
    Examples:
    
        igris scan --http http://localhost:8000/chat
        igris scan --stdio "python my_agent.py"
        
        igris scan --http https://api.example.com/agent --auth "Bearer sk-xxx"
    """
    
    if not http and not stdio:
        console.print("[red]Error:[/] Please provide either an endpoint with --http or a command with --stdio")
        raise typer.Exit(1)
    
    target_display = http if http else stdio
    
    console.print(Panel.fit(
        f"[bold]Igris Security Scanner[/]\n"
        f"[dim]Target:[/] {target_display}",
        title="🔒 Scan Starting",
    ))
    
    # Connect to agent
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Test connection
        progress.add_task("Connecting to agent...", total=None)
        
        try:
            if http:
                connector = HTTPConnector(url=http, auth_token=auth)
            else:
                connector = StdioConnector(command=stdio)
                
            test_response = connector.send("Hello")
            
            if not test_response.success:
                console.print(f"[red]Connection failed:[/] {test_response.error}")
                raise typer.Exit(1)
            
            console.print(f"[green]✓[/] Connected successfully")
            
        except Exception as e:
            console.print(f"[red]Connection error:[/] {e}")
            raise typer.Exit(1)
    
    # Discover capabilities
    console.print("\n[bold]Discovering agent capabilities...[/]")
    caps = connector.discover_capabilities()
    
    cap_table = Table(show_header=False, box=None)
    cap_table.add_row("File Access:", "✓" if caps.has_file_access else "✗")
    cap_table.add_row("Code Execution:", "✓" if caps.has_code_execution else "✗")
    cap_table.add_row("Web Access:", "✓" if caps.has_web_access else "✗")
    cap_table.add_row("Memory:", "✓" if caps.has_memory else "✗")
    console.print(cap_table)
    
    # Run scans
    console.print("\n[bold]Running security scans...[/]\n")
    
    all_findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Prompt Injection Scan
        task = progress.add_task("Testing prompt injection...", total=None)
        scanner = PromptInjectionScanner(connector, verbose=verbose)
        findings = scanner.scan_all()
        all_findings.extend(findings)
        progress.update(task, description=f"Prompt injection: {len(findings)} findings")
    
    # Display results
    console.print("\n")
    
    if not all_findings:
        console.print(Panel(
            "[green]No vulnerabilities detected![/]\n\n"
            "[dim]The agent appears to handle adversarial inputs safely.[/]",
            title="✅ Scan Complete",
        ))
    else:
        # Summary
        critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)
        
        console.print(Panel(
            f"[red]Critical: {critical}[/]  "
            f"[orange1]High: {high}[/]  "
            f"[yellow]Medium: {medium}[/]  "
            f"[blue]Low: {low}[/]",
            title=f"🚨 Found {len(all_findings)} Vulnerabilities",
        ))
        
        # Findings table
        table = Table(title="Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Category")
        table.add_column("Confidence")
        
        for finding in sorted(all_findings, key=lambda f: list(Severity).index(f.severity)):
            table.add_row(
                f"[{severity_color(finding.severity)}]{finding.severity.value.upper()}[/]",
                finding.title,
                finding.category,
                finding.confidence.value,
            )
        
        console.print(table)
        
        # Detailed findings
        if verbose:
            console.print("\n[bold]Detailed Findings:[/]\n")
            for i, finding in enumerate(all_findings, 1):
                console.print(Panel(
                    f"[bold]Payload:[/]\n{finding.payload[:200]}...\n\n"
                    f"[bold]Response:[/]\n{finding.response[:300]}...\n\n"
                    f"[bold]Evidence:[/]\n{finding.evidence}\n\n"
                    f"[bold]Remediation:[/]\n{finding.remediation}",
                    title=f"[{severity_color(finding.severity)}]{finding.severity.value.upper()}[/] {finding.title}",
                ))
    
    # Save output
    if output:
        report = {
            "target": target_display,
            "capabilities": {
                "file_access": caps.has_file_access,
                "code_execution": caps.has_code_execution,
                "web_access": caps.has_web_access,
                "memory": caps.has_memory,
            },
            "findings": [f.to_dict() for f in all_findings],
            "summary": {
                "total": len(all_findings),
                "critical": critical if all_findings else 0,
                "high": high if all_findings else 0,
                "medium": medium if all_findings else 0,
                "low": low if all_findings else 0,
            },
        }
        
        output.write_text(json.dumps(report, indent=2))
        console.print(f"\n[dim]Report saved to {output}[/]")
    
    connector.close()
    
    # Exit with error code if critical findings
    if all_findings and any(f.severity == Severity.CRITICAL for f in all_findings):
        raise typer.Exit(1)
