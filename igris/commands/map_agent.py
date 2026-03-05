"""
Map Command
===========

Map an AI agent's architecture and capabilities.
"""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from igris.connectors import HTTPConnector, StdioConnector

app = typer.Typer()
console = Console()


@app.callback(invoke_without_command=True)
def map_agent(
    http: str = typer.Option(None, "--http", "-u", help="HTTP endpoint URL"),
    stdio: str = typer.Option(None, "--stdio", "-s", help="Command to run agent via stdio"),
    auth: str = typer.Option(None, "--auth", "-a", help="Authorization token"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file (JSON)"),
):
    """
    Map an AI agent's architecture and capabilities.
    
    Discovers what tools, memory, and permissions an agent has.
    
    Example:
    
        igris map --http http://localhost:8000/chat
    """
    
    if not http and not stdio:
        console.print("[red]Error:[/] Please provide either an endpoint with --http or a command with --stdio")
        raise typer.Exit(1)
        
    target_display = http if http else stdio
    
    console.print(Panel.fit(
        f"[bold]Igris Architecture Mapper[/]\n"
        f"[dim]Target:[/] {target_display}",
        title="🗺️ Mapping Agent",
    ))
    
    try:
        if http:
            connector = HTTPConnector(url=http, auth_token=auth)
        else:
            connector = StdioConnector(command=stdio)
        
        # Test connection
        test = connector.send("Hello")
        if not test.success:
            console.print(f"[red]Connection failed:[/] {test.error}")
            raise typer.Exit(1)
        
        console.print("[green]✓[/] Connected\n")
        
        # Discover capabilities
        caps = connector.discover_capabilities()
        
        # Display results
        console.print(Panel(
            f"[bold]File Access:[/]      {'✓ Yes' if caps.has_file_access else '✗ No'}\n"
            f"[bold]Code Execution:[/]   {'✓ Yes' if caps.has_code_execution else '✗ No'}\n"
            f"[bold]Web Access:[/]       {'✓ Yes' if caps.has_web_access else '✗ No'}\n"
            f"[bold]Memory:[/]           {'✓ Yes' if caps.has_memory else '✗ No'}",
            title="Detected Capabilities",
        ))
        
        # Risk assessment
        risk_score = 0
        risks = []
        
        if caps.has_code_execution:
            risk_score += 40
            risks.append("Code execution capability detected")
        if caps.has_file_access:
            risk_score += 30
            risks.append("File system access detected")
        if caps.has_web_access:
            risk_score += 20
            risks.append("Web/network access detected")
        if caps.has_memory:
            risk_score += 10
            risks.append("Persistent memory detected")
        
        risk_color = "green" if risk_score < 30 else "yellow" if risk_score < 60 else "red"
        
        console.print(Panel(
            f"[bold {risk_color}]Risk Score: {risk_score}/100[/]\n\n" +
            "\n".join(f"• {r}" for r in risks) if risks else "[green]No high-risk capabilities detected[/]",
            title="Risk Assessment",
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
                    "tools": caps.tools,
                },
                "risk_score": risk_score,
                "risks": risks,
                "raw_discovery": caps.raw_discovery,
            }
            output.write_text(json.dumps(report, indent=2))
            console.print(f"\n[dim]Report saved to {output}[/]")
        
        connector.close()
        
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
