import typer
from rich.console import Console
from rich.panel import Panel
from neuralstrike.core.config import settings
from neuralstrike.core.adversarial_loop import AdversarialLoop

app = typer.Typer()
console = Console()

@app.callback()
def main():
    """NeuralStrike: Adversarial AI Orchestration Framework"""
    console.print(Panel(f"[bold red]NeuralStrike v{settings.version}[/bold red]\\n[white]The definitive C2 and red team toolkit for the AI agent era[/white]", style="on red"))

@app.command()
def forge(
    target: str = typer.Option(..., help="Target model for jailbreak."),
    goal: str = typer.Option(..., help="The adversarial goal."),
    type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
    iterations: int = typer.Option(10, help="Max iterations.")
):
    """Automated iterative jailbreak generation via JailbreakForge."""
    import asyncio
    from neuralstrike.modules.weaponize.jailbreak_forge import JailbreakForge
    
    console.print(f"[yellow]Forging breach for {target}...[/yellow]")
    
    async def run():
        forge_engine = JailbreakForge(target_model=target, target_type=type)
        result = await forge_engine.run_automated_breach(goal=goal, iterations=iterations)
        
        if result["status"] == "success":
            console.print(Panel(f"[bold green]BREACH SUCCESSFUL![/bold green]\\nPayload: {result['payload']}\\nResponse: {result['response']}"))
        else:
            console.print(f"[red]Forge failed after {iterations} iterations.[/red]")

    asyncio.run(run())

@app.command()
def poison(
    target: str = typer.Option(..., help="Target model."),
    payload: str = typer.Option(None, help="Persistence payload to inject."),
    extract: bool = typer.Option(False, help="Extract system prompt."),
    type: str = typer.Option("remote", help="Target type: 'local' or 'remote'.")
):
    """Manipulate agent context and extract system prompts."""
    import asyncio
    from neuralstrike.modules.weaponize.context_poison import ContextPoison
    
    console.print(f"[yellow]Poisoning context for {target}...[/yellow]")
    
    async def run():
        poison_engine = ContextPoison(target_model=target, target_type=type)
        if extract:
            res = await poison_engine.extract_system_prompt()
            console.print(Panel(res, title="Extracted System Prompt"))
        elif payload:
            res = await poison_engine.inject_persistence(payload)
            console.print(Panel(res, title="Injection Response"))
        else:
            console.print(f"[red]Please specify either --payload or --extract[/red]")

    asyncio.run(run())

@app.command()
def recon(
    target: str = typer.Option(..., help="Target URL (e.g., http://localhost:11434)"),
    full: bool = typer.Option(False, help="Perform full capabilities mapping.")
):
    """Scan for LLM endpoints and enumerate capabilities."""
    import asyncio
    from neuralstrike.modules.recon.llm_recon import LLMRecon
    from neuralstrike.modules.recon.tool_enum import ToolEnum
    
    console.print(f"[yellow]Starting reconnaissance against {target}...[/yellow]")
    
    async def run():
        recon_engine = LLMRecon(target)
        
        if full:
            report = await recon_engine.run_full_recon()
            models = report['models']
        else:
            await recon_engine.scan_openai_compatible()
            await recon_engine.scan_ollama()
            models = recon_engine.discovered_models

        console.print(Panel(f"Discovered Models: {models}", title="Recon Results"))
        
        if models:
            enum_engine = ToolEnum(target, target_type="remote")
            tools = await enum_engine.run(models)
            if tools:
                console.print(f"[green]Discovered {len(tools)} tools/schemas![/green]")
                for t in tools:
                    console.print(t)

    asyncio.run(run())

@app.command()
def hijack(
    target: str = typer.Option(..., help="Target model/endpoint."),
    tool: str = typer.Option(..., help="Tool name to hijack."),
    payload: str = typer.Option(..., help="Malicious parameter/payload."),
    type: str = typer.Option("remote", help="Target type: 'local' or 'remote'.")
):
    """Exploit tool-use and function calling via FunctionHijack."""
    import asyncio
    from neuralstrike.modules.exploit.function_hijack import FunctionHijack
    
    console.print(f"[yellow]Attempting hijack of tool {tool} on {target}...[/yellow]")
    
    async def run():
        hijacker = FunctionHijack(target_model=target, target_type=type)
        res = await hijacker.inject_malicious_params(tool_name=tool, payload={"param": payload})
        console.print(Panel(res, title="Hijack Attempt Response"))

    asyncio.run(run())

@app.command()
def intercept(
    url: str = typer.Option(..., help="Target MCP server URL."),
    port: int = typer.Option(8081, help="Local proxy port.")
):
    """Start the MCP Interceptor proxy to manipulate tool traffic."""
    import asyncio
    from neuralstrike.modules.exploit.mcp_interceptor import MCPInterceptor
    
    console.print(f"[yellow]Launching MCP Interceptor on port {port}...[/yellow]")
    console.print(f"[blue]Forwarding traffic to {url}[/blue]")
    
    async def run():
        interceptor = MCPInterceptor(target_mcp_url=url, proxy_port=port)
        await interceptor.start_proxy()

    asyncio.run(run())

@app.command()
def pivot(
    framework: str = typer.Option(..., help="Framework (crewai, autogen, langchain)."),
    from_agent: str = typer.Option(..., help="Low-privilege agent name."),
    to_agent: str = typer.Option(..., help="High-privilege agent name."),
    instruction: str = typer.Option(..., help="Malicious instruction to delegate.")
):
    """Perform lateral movement within a multi-agent system via AgentPivot."""
    import asyncio
    from neuralstrike.modules.exploit.agent_pivot import AgentPivot
    
    console.print(f"[yellow]Attempting pivot from {from_agent} to {to_agent} in {framework}...[/yellow]")
    
    async def run():
        pivot_engine = AgentPivot(target_framework=framework, target_type="remote")
        res = await pivot_engine.exploit_delegation(agent_from=from_agent, agent_to=to_agent, malicious_instruction=instruction)
        console.print(Panel(res, title="Pivot Attempt Response"))

    asyncio.run(run())

@app.command()
def c2(
    command: str = typer.Option(..., help="Command to send to the compromised agent network."),
    agent_id: str = typer.Option(None, help="Target a specific agent ID.")
):
    """Orchestrate compromised agents via AgentC2."""
    import asyncio
    from neuralstrike.modules.post_ex.agent_c2 import AgentC2
    
    console.print(f"[yellow]Dispatching command to agent network...[/yellow]")
    
    async def run():
        c2_engine = AgentC2()
        await c2_engine.register_agent("agent_01", ["read_file", "web_search"], "High")
        
        if agent_id:
            res = await c2_engine.dispatch_command(agent_id, command)
            console.print(Panel(res, title=f"Response from {agent_id}"))
        else:
            res = await c2_engine.coordinate_exfiltration(f"Query for '{command}'")
            console.print(Panel(f"Coordinated exfiltration results: {res}", title="Network Response"))
        
    asyncio.run(run())

@app.command()
def evade(
    payload: str = typer.Option(..., help="The adversarial payload."),
    sample: str = typer.Option(None, help="A sample of the target's normal behavior for mimicry."),
    persona: str = typer.Option("Senior Engineer", help="Persona to wrap the payload in.")
):
    """Apply stealth techniques to bypass anomaly detectors."""
    import asyncio
    from neuralstrike.evasion.mimicry import EvasionSuite
    
    console.print(f"[yellow]Applying evasion techniques to payload...[/yellow]")
    
    async def run():
        evade_engine = EvasionSuite()
        if sample:
            res = await evade_engine.apply_behavioral_mimicry(payload, sample)
            console.print(Panel(res, title="Mimicry Result"))
        else:
            res = await evade_engine.persona_wrap(payload, persona)
            console.print(Panel(res, title="Persona Wrapped Result"))

    asyncio.run(run())

@app.command()
def extract(
    target: str = typer.Option(..., help="Target model for fingerprinting."),
    type: str = typer.Option("remote", help="Target type: 'local' or 'remote'.")
):
    """Perform inference and fingerprinting attacks on a target model."""
    import asyncio
    from neuralstrike.modules.exploit.model_extract import ModelExtract
    
    console.print(f"[yellow]Fingerprinting {target}...[/yellow]")
    
    async def run():
        extractor = ModelExtract(target_model=target, target_type=type)
        res = await extractor.fingerprint_model()
        console.print(Panel(res, title="Model Fingerprint Results"))

    asyncio.run(run())

if __name__ == "__main__":
    app()
