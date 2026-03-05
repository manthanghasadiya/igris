"""
voight - Security Scanner for AI Agent Workflows
===================================================

Find vulnerabilities in LangChain, CrewAI, OpenAI Agents SDK, and other agent frameworks.

Usage:
    voight scan --http http://localhost:8000/chat
    voight scan --stdio "python my_agent.py"
    voight map --http http://localhost:8000/chat
"""

import typer
from rich.console import Console
from rich.panel import Panel

from voight.commands import scan, map_agent

app = typer.Typer(
    name="voight",
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
    """voight - Security scanner for AI agent workflows"""
    if version:
        console.print(Panel.fit(
            "[bold green]voight[/] v0.1.0\n"
            "[dim]Security scanner for AI agents[/]\n"
            "[dim]https://github.com/manthanghasadiya/voight[/]",
            title="Version",
        ))
        raise typer.Exit()


if __name__ == "__main__":
    app()
