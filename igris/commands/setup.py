"""
Setup Command for igris
========================

Interactive setup to configure AI providers and API keys.
"""

import os
import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from igris.ai.providers import PROVIDERS, CONFIG_DIR, CONFIG_FILE, get_config

app = typer.Typer()
console = Console()


@app.callback(invoke_without_command=True)
def main():
    """Configure igris settings and AI providers."""
    console.print("[bold blue]Igris Configuration Setup[/bold blue]\n")
    
    config = get_config()
    api_keys = config.get("api_keys", {})
    
    table = Table(title="AI Providers Status")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Env Var", style="magenta")
    table.add_column("Configured", style="yellow")
    
    for name, info in PROVIDERS.items():
        env_key = info.get("env_key")
        env_status = "[green]✓ Found[/green]" if env_key and os.environ.get(env_key) else "[red]✗ Missing[/red]"
        config_status = "[green]✓ Yes[/green]" if api_keys.get(name) else "[red]✗ No[/red]"
        
        status = "[green]Active[/green]" if (env_key and os.environ.get(env_key)) or api_keys.get(name) or name == "ollama" else "[red]Inactive[/red]"
        
        table.add_row(name, status, env_key or "N/A", config_status)
    
    console.print(table)
    
    if not typer.confirm("\nWould you like to configure a provider?"):
        return

    provider = typer.prompt("Enter provider name", default="openai")
    if provider not in PROVIDERS:
        console.print(f"[red]Error: Unknown provider '{provider}'[/red]")
        return
        
    if provider == "ollama":
        console.print("[yellow]Ollama doesn't require an API key by default.[/yellow]")
        return

    api_key = typer.prompt(f"Enter API key for {provider}", hide_input=True)
    
    # Update config
    if "api_keys" not in config:
        config["api_keys"] = {}
    config["api_keys"][provider] = api_key
    
    # Save config
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    
    console.print(f"\n[bold green]✓ Configuration saved to {CONFIG_FILE}[/bold green]")
