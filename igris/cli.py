"""
igris - Security Scanner for AI Agent Workflows
===================================================

Find vulnerabilities in LangChain, CrewAI, OpenAI Agents SDK, and other agent frameworks.

Usage:
    igris scan --http http://localhost:8000/chat
    igris scan --stdio "python my_agent.py"
    igris map --http http://localhost:8000/chat
"""

import typer
from rich.console import Console
from rich.panel import Panel

from igris.commands import scan, map_agent

app = typer.Typer(
    name="igris",
    help="Security scanner for AI agent workflows",
    no_args_is_help=True,
)

console = Console()

# Register commands
app.add_typer(scan.app, name="scan", help="Scan an agent for vulnerabilities")
app.add_typer(map_agent.app, name="map", help="Map agent architecture and capabilities")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """igris - Security scanner for AI agent workflows"""
    if version:
        console.print(Panel.fit(
            "[bold green]igris[/] v0.1.0\n"
            "[dim]Security scanner for AI agents[/]\n"
            "[dim]https://github.com/manthanghasadiya/igris[/]",
            title="Version",
        ))
        raise typer.Exit()


if __name__ == "__main__":
    app()
