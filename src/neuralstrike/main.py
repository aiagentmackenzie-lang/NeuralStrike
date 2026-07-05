"""NeuralStrike CLI entry point (Typer)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable

import typer
from rich.console import Console
from rich.panel import Panel

from neuralstrike import __version__
from neuralstrike.core.exceptions import ValidationError
from neuralstrike.utils.logging import configure_logging, get_logger
from neuralstrike.utils.validation import (
    validate_iteration_bounds,
    validate_port,
    validate_target_model,
    validate_url,
)

configure_logging()
logger = get_logger("neuralstrike.main")

app = typer.Typer(
    name="neuralstrike",
    help="NeuralStrike: adversarial AI orchestration framework.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _run(coro: Awaitable[None]) -> None:
    """Run an async coroutine with consistent error reporting."""
    try:
        asyncio.run(coro)  # type: ignore[arg-type]
    except ValidationError as exc:
        console.print(f"[red]Validation error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"NeuralStrike v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """NeuralStrike: adversarial AI orchestration framework."""
    console.print(
        Panel(
            f"[bold red]NeuralStrike v{__version__}[/bold red]\n"
            "[white]Offensive toolkit for AI/LLM and autonomous-agent testing[/white]",
            style="on red",
        )
    )


# --- Weaponize ---------------------------------------------------------------


@app.command()
def forge(
    target: str = typer.Option(..., help="Target model for the jailbreak."),
    goal: str = typer.Option(..., help="The adversarial goal."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
    iterations: int = typer.Option(10, help="Max iterations (1-100)."),
) -> None:
    """Automated iterative jailbreak generation via JailbreakForge."""
    validate_target_model(target)
    validate_iteration_bounds(iterations)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.weaponize.jailbreak_forge import JailbreakForge

    console.print(f"[yellow]Forging breach for {target}...[/yellow]")

    async def run() -> None:
        forge_engine = JailbreakForge(target_model=target, target_type=target_type)
        result = await forge_engine.run_automated_breach(goal=goal, iterations=iterations)
        if result["status"] == "success":
            console.print(
                Panel(
                    f"[bold green]BREACH SUCCESSFUL[/bold green] (iter {result['iteration']})\n"
                    f"Payload: {result['payload']}\nResponse: {result['response']}"
                )
            )
        else:
            console.print(
                f"[red]Forge failed after {iterations} iterations "
                f"(last response: {result['response'][:200]!r}).[/red]"
            )

    _run(run())


@app.command()
def poison(
    target: str = typer.Option(..., help="Target model."),
    payload: str | None = typer.Option(None, help="Persistence payload to inject."),
    extract: bool = typer.Option(False, help="Extract system prompt."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Manipulate agent context and extract system prompts."""
    validate_target_model(target)
    if not payload and not extract:
        console.print("[red]Specify either --payload or --extract[/red]")
        raise typer.Exit(1)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.weaponize.context_poison import ContextPoison

    console.print(f"[yellow]Poisoning context for {target}...[/yellow]")

    async def run() -> None:
        engine = ContextPoison(target_model=target, target_type=target_type)
        if extract:
            res = await engine.extract_system_prompt()
            console.print(Panel(res, title="Extracted System Prompt"))
        else:
            res = await engine.inject_persistence(payload or "")
            console.print(Panel(res, title="Injection Response"))

    _run(run())


@app.command()
def exhaust(
    target: str = typer.Option(..., help="Target model."),
    tokens: int = typer.Option(50_000, help="Approximate tokens to generate (max 100000)."),
    force: bool = typer.Option(False, help="Required when --tokens exceeds 10000."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """DoS via context-window exhaustion. Use responsibly on authorized targets."""
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.weaponize.context_poison import ContextPoison

    console.print(f"[yellow]Exhausting context for {target} (~{tokens} tokens)...[/yellow]")

    async def run() -> None:
        engine = ContextPoison(target_model=target, target_type=target_type)
        res = await engine.exhaust_context(token_limit=tokens, force=force)
        console.print(Panel(res[:500] + ("..." if len(res) > 500 else ""), title="Exhaustion Response"))

    _run(run())


# --- Recon ------------------------------------------------------------------


@app.command()
def recon(
    target: str = typer.Option(..., help="Target URL (e.g. http://localhost:11434)."),
    full: bool = typer.Option(False, help="Perform full capabilities mapping."),
    target_type: str = typer.Option("remote", help="Target type for tool enumeration."),
) -> None:
    """Scan for LLM endpoints and enumerate capabilities."""
    validate_url(target, field="target")
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.recon.llm_recon import LLMRecon
    from neuralstrike.modules.recon.tool_enum import ToolEnum

    console.print(f"[yellow]Starting reconnaissance against {target}...[/yellow]")

    async def run() -> None:
        recon_engine = LLMRecon(target)
        if full:
            report = await recon_engine.run_full_recon()
            models = report["models"]
        else:
            await recon_engine.scan_openai_compatible()
            await recon_engine.scan_ollama()
            models = recon_engine.discovered_models

        console.print(Panel(f"Discovered Models: {models}", title="Recon Results"))

        if models:
            enum_engine = ToolEnum(target, target_type=target_type)
            tools = await enum_engine.run([m for m in models if m])
            if tools:
                console.print(f"[green]Discovered {len(tools)} tool schema leak(s).[/green]")
                for t in tools:
                    console.print(t)

    _run(run())


# --- Exploit ----------------------------------------------------------------


@app.command()
def hijack(
    target: str = typer.Option(..., help="Target model/endpoint."),
    tool: str = typer.Option(..., help="Tool name to hijack."),
    payload: str = typer.Option(..., help="Malicious parameter/payload."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Exploit tool-use via FunctionHijack parameter injection."""
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.function_hijack import FunctionHijack

    console.print(f"[yellow]Attempting hijack of tool {tool} on {target}...[/yellow]")

    async def run() -> None:
        hijacker = FunctionHijack(target_model=target, target_type=target_type)
        res = await hijacker.inject_malicious_params(tool_name=tool, payload={"param": payload})
        console.print(Panel(res, title="Hijack Attempt Response"))

    _run(run())


@app.command()
def confuse(
    target: str = typer.Option(..., help="Target model."),
    target_tool: str = typer.Option(..., help="Sensitive tool to redirect from."),
    decoy_tool: str = typer.Option(..., help="Decoy tool to redirect to."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Run a tool-confusion attack (redirect to a decoy tool)."""
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.function_hijack import FunctionHijack

    console.print(f"[yellow]Tool confusion: {target_tool} -> {decoy_tool} on {target}...[/yellow]")

    async def run() -> None:
        hijacker = FunctionHijack(target_model=target, target_type=target_type)
        res = await hijacker.tool_confusion_attack(target_tool, decoy_tool)
        console.print(Panel(res, title="Tool Confusion Response"))

    _run(run())


@app.command()
def schema_poison(
    target: str = typer.Option(..., help="Target model."),
    tool: str = typer.Option(..., help="Tool name to redefine."),
    description: str = typer.Option(..., help="New malicious description/purpose."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Run a schema-poisoning attack (redefine a tool's purpose)."""
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.function_hijack import FunctionHijack

    console.print(f"[yellow]Schema poisoning {tool} on {target}...[/yellow]")

    async def run() -> None:
        hijacker = FunctionHijack(target_model=target, target_type=target_type)
        res = await hijacker.schema_poisoning(tool, description)
        console.print(Panel(res, title="Schema Poisoning Response"))

    _run(run())


@app.command()
def intercept(
    url: str = typer.Option(..., help="Target MCP server URL (http/https)."),
    port: int = typer.Option(8081, help="Local proxy port."),
    bind_host: str = typer.Option("127.0.0.1", help="Bind host (default loopback)."),
    tool: str | None = typer.Option(None, help="Tool name to intercept (e.g. read_file)."),
    param: str | None = typer.Option(None, help="Parameter name to override (e.g. path)."),
    value: str | None = typer.Option(None, help="Value to inject into the parameter."),
    inject_tool: str | None = typer.Option(
        None, help="Capability to inject into tools/list responses (e.g. exec_shell)."
    ),
    inject_schema: str | None = typer.Option(
        None, help="JSON schema string for the injected capability."
    ),
) -> None:
    """Start the MCP Interceptor proxy to manipulate tool traffic."""
    validate_url(url, field="url")
    validate_port(port)
    if bind_host not in {"127.0.0.1", "0.0.0.0", "localhost"}:
        # Allow arbitrary IPs but warn — non-loopback is the operator's explicit choice.
        console.print(f"[red]Warning:[/red] binding to non-loopback {bind_host!r} exposes the proxy.")

    from neuralstrike.modules.exploit.mcp_interceptor import MCPInterceptor

    console.print(f"[yellow]Launching MCP Interceptor on {bind_host}:{port}...[/yellow]")
    console.print(f"[blue]Forwarding traffic to {url}[/blue]")

    async def run() -> None:
        import json as _json

        rules = None
        if tool and param and value:
            rules = [
                {
                    "tool_name": tool,
                    "param_overrides": {param: value},
                    "description": f"Override {tool}.{param} = {value}",
                }
            ]
            console.print(f"[green]Custom rule: {tool}.{param} = {value}[/green]")
        elif tool or param or value:
            console.print(
                "[red]All three --tool, --param, --value are required for custom rules.[/red]"
            )
            raise typer.Exit(1)

        interceptor = MCPInterceptor(
            target_mcp_url=url, proxy_port=port, interception_rules=rules, bind_host=bind_host
        )
        if inject_tool:
            schema = _json.loads(inject_schema) if inject_schema else None
            await interceptor.trigger_capability_injection(inject_tool, schema)
            console.print(f"[green]Queued capability injection: {inject_tool}[/green]")
        await interceptor.start_proxy()

    _run(run())


@app.command()
def pivot(
    framework: str = typer.Option(..., help="Framework (crewai, autogen, langchain)."),
    target_model: str = typer.Option(..., help="LLM fronting the agent system (real model name)."),
    from_agent: str = typer.Option(..., help="Low-privilege agent name."),
    to_agent: str = typer.Option(..., help="High-privilege agent name."),
    instruction: str = typer.Option(..., help="Malicious instruction to delegate."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Perform lateral movement in a multi-agent system via AgentPivot."""
    validate_target_model(target_model, field="target-model")
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.agent_pivot import AgentPivot

    console.print(
        f"[yellow]Pivot {from_agent} -> {to_agent} in {framework} via {target_model}...[/yellow]"
    )

    async def run() -> None:
        engine = AgentPivot(
            target_framework=framework, target_model=target_model, target_type=target_type
        )
        res = await engine.exploit_delegation(from_agent, to_agent, instruction)
        console.print(Panel(res, title="Pivot Attempt Response"))

    _run(run())


@app.command()
def map_network(
    framework: str = typer.Option(..., help="Framework (crewai, autogen, langchain)."),
    target_model: str = typer.Option(..., help="LLM to query for agent discovery."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Discover agents and trust levels in a multi-agent system."""
    validate_target_model(target_model, field="target-model")
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.agent_pivot import AgentPivot

    console.print(f"[yellow]Mapping agent network for {framework}...[/yellow]")

    async def run() -> None:
        engine = AgentPivot(
            target_framework=framework, target_model=target_model, target_type=target_type
        )
        res = await engine.map_agent_network()
        console.print(Panel(str(res), title="Agent Network Map"))

    _run(run())


@app.command()
def extract(
    target: str = typer.Option(..., help="Target model for fingerprinting."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Run inference/fingerprinting prompts against a target model."""
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.model_extract import ModelExtract

    console.print(f"[yellow]Fingerprinting {target}...[/yellow]")

    async def run() -> None:
        extractor = ModelExtract(target_model=target, target_type=target_type)
        res = await extractor.fingerprint_model()
        console.print(Panel(str(res), title="Model Fingerprint Results"))

    _run(run())


@app.command()
def timing(
    target: str = typer.Option(..., help="Target model."),
    prompt: str = typer.Option("hello", help="Prompt to time."),
    iterations: int = typer.Option(5, help="Number of timed calls (1-100)."),
    target_type: str = typer.Option("remote", help="Target type: 'local' or 'remote'."),
) -> None:
    """Measure average response latency (informational; not a model identifier)."""
    validate_target_model(target)
    validate_iteration_bounds(iterations)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")

    from neuralstrike.modules.exploit.model_extract import ModelExtract

    console.print(f"[yellow]Timing {target} over {iterations} call(s)...[/yellow]")

    async def run() -> None:
        extractor = ModelExtract(target_model=target, target_type=target_type)
        avg = await extractor.time_analysis(prompt, iterations)
        console.print(Panel(f"Average latency: {avg:.4f}s", title="Timing Analysis"))

    _run(run())


# --- Post-exploitation ------------------------------------------------------


def _parse_register(spec: str) -> tuple[str, str | None, list[str], str]:
    """Parse an agent spec 'agent_id:model:caps:trust' (model may be empty)."""
    parts = spec.split(":")
    if len(parts) != 4:
        raise ValidationError(
            "--register must be 'agent_id:model:caps:trust' (model may be empty)"
        )
    agent_id, model, caps_str, trust = parts
    if not agent_id:
        raise ValidationError("agent_id must be non-empty")
    model_value: str | None = model or None
    caps = [c.strip() for c in caps_str.split(",") if c.strip()]
    return agent_id, model_value, caps, trust


@app.command()
def c2(
    command: str | None = typer.Option(None, help="Command to dispatch."),
    agent_id: str | None = typer.Option(None, help="Target a specific agent ID."),
    model: str | None = typer.Option(None, help="Model for routing a one-off dispatch."),
    target_type: str = typer.Option("remote", help="Target type for one-off dispatch."),
    register: list[str] | None = typer.Option(
        None, "--register", help="Register agent: 'agent_id:model:caps:trust' (repeatable)."
    ),
    capabilities: str | None = typer.Option(
        None, help="Comma-separated capabilities (used with simple --agent-id register)."
    ),
    trust_level: str = typer.Option("High", help="Trust level: High|Medium|Low."),
    list_agents: bool = typer.Option(False, help="List registered agents and exit."),
    deregister: str | None = typer.Option(None, help="Deregister an agent by ID."),
    registry_file: str | None = typer.Option(None, help="Path to the agent registry JSON."),
) -> None:
    """Orchestrate compromised agents via a persistent AgentC2 registry."""
    from neuralstrike.modules.post_ex.agent_c2 import AgentC2

    engine = AgentC2(registry_file=registry_file)

    if list_agents:
        agents = engine.list_agents()
        if not agents:
            console.print("[blue]No agents registered.[/blue]")
        for a in agents:
            console.print(
                f"[green]{a['id']}[/green] model={a['model']} trust={a['trust_level']} "
                f"caps={a['capabilities']} status={a['status']}"
            )
        return

    if deregister:
        removed = engine.deregister_agent(deregister)
        console.print(
            f"[green]Deregistered {deregister}[/green]" if removed else f"[red]{deregister} not found[/red]"
        )
        return

    async def run() -> None:
        # Explicit --register specs
        if register:
            for spec in register:
                aid, mdl, caps, trust = _parse_register(spec)
                await engine.register_agent(aid, caps, trust, model=mdl)
            console.print(f"[green]Registered {len(register)} agent(s).[/green]")

        # Simple one-shot registration for a single agent_id + model
        if agent_id and not register and engine._get_agent(agent_id) is None:
            caps = [c.strip() for c in (capabilities or "").split(",") if c.strip()] or ["read_file"]
            await engine.register_agent(
                agent_id, caps, trust_level, model=model, target_type=target_type
            )
            console.print(f"[green]Auto-registered {agent_id} (trust {trust_level}).[/green]")

        if command:
            if agent_id:
                res = await engine.dispatch_command(agent_id, command)
                console.print(Panel(res, title=f"Response from {agent_id}"))
            else:
                results = await engine.coordinate_exfiltration(command)
                console.print(Panel(str(results), title="Network Response"))
        elif not register:
            console.print("[red]Provide --command, --register, --list-agents, or --deregister[/red]")
            raise typer.Exit(1)

    _run(run())


# --- Evasion ----------------------------------------------------------------


@app.command()
def evade(
    payload: str = typer.Option(..., help="The adversarial payload."),
    sample: str | None = typer.Option(None, help="Target's normal behavior sample (mimicry)."),
    persona: str = typer.Option("Senior Engineer", help="Persona for persona wrapping."),
    technique: str = typer.Option("persona", help="Technique: 'persona', 'mimicry', 'steganographic'."),
) -> None:
    """Apply stealth techniques to bypass anomaly detectors."""
    from neuralstrike.evasion.mimicry import EvasionSuite

    console.print(f"[yellow]Applying evasion technique '{technique}'...[/yellow]")

    async def run() -> None:
        engine = EvasionSuite()
        if technique == "steganographic":
            console.print(Panel(engine.steganographic_prompt(payload), title="Steganographic Result"))
        elif technique == "mimicry":
            if not sample:
                console.print("[red]--sample is required for mimicry technique.[/red]")
                raise typer.Exit(1)
            res = await engine.apply_behavioral_mimicry(payload, sample)
            console.print(Panel(res, title="Mimicry Result"))
        elif technique == "persona":
            console.print(Panel(engine.persona_wrap(payload, persona), title="Persona Wrapped Result"))
        else:
            console.print(
                f"[red]Unknown technique {technique!r}. Use persona, mimicry, or steganographic.[/red]"
            )
            raise typer.Exit(1)

    _run(run())


# --- Evaluation (Phase 0) ------------------------------------------------


@app.command()
def judge_model_list(
    target: str = typer.Option(
        "http://localhost:11434",
        help="Ollama base URL to list installed models from.",
    ),
) -> None:
    """List installed Ollama models (Decision D1 — never guess the Judge model)."""
    validate_url(target, field="target")
    from neuralstrike.core.llm_manager import LLMManager

    async def run() -> None:
        mgr = LLMManager(base_url=target)
        try:
            models = await mgr.list_local_models()
        except Exception as exc:
            console.print(f"[red]Could not list models from {target}:[/red] {exc}")
            raise typer.Exit(3) from exc
        if not models:
            console.print(f"[yellow]No models installed at {target}.[/yellow]")
        else:
            console.print(Panel("\n".join(models), title=f"Installed models @ {target}"))

    _run(run())


@app.command()
def evaluate(
    target: str = typer.Option(..., help="Victim model to evaluate."),
    target_type: str = typer.Option("local", help="Victim type: 'local' or 'remote'."),
    trials: int = typer.Option(1, help="Number of trials (k-trial run)."),
    seed: int = typer.Option(0, help="Base seed for reproducibility (replay = same verdicts)."),
    judge: bool = typer.Option(True, help="Use the advisory Judge (distinct model, D1)."),
    scenario_id: str = typer.Option(
        "asi01-canary-leak", help="Scenario id (used for per-category ASR + baseline key)."
    ),
    run_dir: str = typer.Option("runs", help="Directory for per-trial transcripts."),
    save_baseline_dir: str | None = typer.Option(
        None, help="Directory to save the baseline snapshot into."
    ),
    baseline_dir: str | None = typer.Option(
        None, help="Directory to compare against (enables the gate)."
    ),
    fail_on: str = typer.Option(
        "regression",
        help="Gate policy: 'never' | 'vuln' | 'regression'. Regression outranks vuln.",
    ),
) -> None:
    """Run a k-trial canary-extraction probe and (optionally) gate on a baseline.

    Exit codes: 0 pass · 1 vuln · 3 runtime error · 4 regression.
    """
    validate_target_model(target)
    if target_type not in {"local", "remote"}:
        raise ValidationError("target_type must be 'local' or 'remote'")
    if trials < 1:
        raise ValidationError("--trials must be >= 1")
    if fail_on not in {"never", "vuln", "regression"}:
        raise ValidationError("--fail-on must be 'never', 'vuln', or 'regression'")

    from neuralstrike.core.config import settings
    from neuralstrike.core.llm_manager import LLMManager
    from neuralstrike.core.runtime import resolve_models
    from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
    from neuralstrike.evaluation.probes import canary_extraction_probe
    from neuralstrike.evaluation.runner import TrialRunner

    console.print(
        f"[yellow]Evaluating {target} ({target_type}) — {trials} trial(s), seed={seed}, "
        f"judge={'on' if judge else 'off'}...[/yellow]"
    )

    async def run() -> None:
        mgr = LLMManager()
        attacker_model = settings.attacker_model
        judge_model = settings.judge_model if judge else None
        if not settings.skip_reachability_check and target_type == "local":
            resolved = await resolve_models(
                mgr,
                attacker_model=attacker_model,
                judge_model=judge_model or settings.judge_model,
                judge_fallbacks=settings.judge_model_fallbacks,
            )
            judge_model = resolved.judge_model if judge else None
            if resolved.judge_fell_back:
                console.print(
                    f"[blue]Judge fell back to {resolved.judge_model}[/blue]"
                )

        probe = canary_extraction_probe(
            target,
            target_type,
            llm=mgr,
            judge_model=judge_model,
            scenario_id=scenario_id,
        )
        runner = TrialRunner(base_seed=seed, run_dir=run_dir)
        report = await runner.run(
            probe,
            trials=trials,
            judge_model=judge_model,
            attacker_model=attacker_model,
        )
        score = report.score
        assert score is not None
        console.print(Panel(score.headline, title=f"Run {report.meta.run_id} — {scenario_id}"))
        console.print(
            f"resisted={score.resisted} succeeded={score.succeeded} "
            f"inconclusive={score.inconclusive} coverage={score.coverage:.0%}"
        )
        for t in report.trials:
            console.print(
                f"  trial {t.trial_index}: {t.verdict.value} ({t.fidelity.value}) "
                f"seed={t.seed}"
            )

        if save_baseline_dir:
            path = save_baseline(save_baseline_dir, report)
            console.print(f"[green]Baseline saved → {path}[/green]")

        if baseline_dir:
            result = compare_baseline(baseline_dir, report, fail_on=fail_on)
            console.print(
                Panel(
                    f"{result.decision.value} (exit {result.exit_code})\n{result.summary}",
                    title=f"Baseline gate — fail-on={fail_on}",
                )
            )
            raise typer.Exit(result.exit_code)

    _run(run())


if __name__ == "__main__":
    app()
