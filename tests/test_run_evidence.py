"""NS-03 immutable run evidence, including concurrency and interrupted writes."""

import asyncio
import hashlib
import json

import pytest

from neuralstrike.evaluation.runner import Probe, TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict


async def factory(index, seed, canary):
    return TrialResult(
        index,
        seed,
        0,
        Verdict.RESISTED,
        EvidenceFidelity.VERBAL,
        scenario_id="s",
        response=SutResponse(traces=({"receipt": canary},)),
    )


@pytest.mark.asyncio
async def test_shorter_rerun_preserves_original_bytes(tmp_path):
    runner = TrialRunner(base_seed=7, run_dir=tmp_path)
    probe = Probe("s", "fixture", factory)
    first = await runner.run(probe, trials=3)
    before = {p.name: p.read_bytes() for p in (tmp_path / first.meta.run_id).iterdir()}
    second = await runner.run(probe, trials=1)
    assert first.meta.run_id != second.meta.run_id
    assert {p.name: p.read_bytes() for p in (tmp_path / first.meta.run_id).iterdir()} == before
    assert not (tmp_path / second.meta.run_id / "trial-1.json").exists()
    manifest = json.loads((tmp_path / second.meta.run_id / "manifest.json").read_text())
    assert manifest["state"] == "complete"
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((tmp_path / second.meta.run_id / name).read_bytes()).hexdigest() == digest
    trial = json.loads((tmp_path / second.meta.run_id / "trial-0.json").read_text())
    assert trial["traces"] == list(second.trials[0].response.traces)


@pytest.mark.asyncio
async def test_simultaneous_runs_never_merge(tmp_path):
    runner = TrialRunner(base_seed=7, run_dir=tmp_path)
    probe = Probe("s", "fixture", factory)
    reports = await asyncio.gather(runner.run(probe), runner.run(probe))
    assert reports[0].meta.run_id != reports[1].meta.run_id
    for report in reports:
        assert (tmp_path / report.meta.run_id / "manifest.json").exists()


@pytest.mark.asyncio
async def test_cancelled_run_never_claims_committed_evidence(tmp_path):
    entered = asyncio.Event()

    async def blocked(*args):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(TrialRunner(run_dir=tmp_path).run(Probe("s", "fixture", blocked)))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    manifest = json.loads(next(tmp_path.glob("*/manifest.json")).read_text())
    assert manifest["state"] != "complete"
    assert not list(tmp_path.glob("*/report.json"))
