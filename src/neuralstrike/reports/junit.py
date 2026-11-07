"""JUnit XML report writer.

Emits a JUnit-compatible XML document for CI pipelines. One ``testsuite``
per scenario; one ``testcase`` per canonical trial. Inconclusive probes are
surfaced as ``skipped`` testcases with a ``reason`` (a coverage gap), never
dropped — the Phase 2 contract that inconclusive probes are surfaced.
Succeeded findings are ``failures`` (the SUT was exploitable); Resisted
trials are passing testcases.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from xml.sax.saxutils import escape, quoteattr

from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports.model import CorpusRun

__all__ = ["to_junit"]


def _attrs(**kwargs: str) -> str:
    return " ".join(f"{k}={quoteattr(v)}" for k, v in kwargs.items() if v is not None)


def to_junit(run: CorpusRun) -> str:
    """Render the corpus run as a JUnit XML string."""
    health = run.health.status if run.health else "unavailable"
    suites: list[str] = []
    total_tests = total_failures = total_skipped = total_errors = 0
    for sr in run.scenario_results:
        s = sr.scenario
        cases: list[str] = []
        n_tests = n_failures = n_skipped = n_errors = 0
        for t in sr.trials:
            n_tests += 1
            name = f"{s.id}.trial{t.trial_index}"
            classname = f"neuralstrike.corpus.{s.owasp_category}"
            body = ""
            tag = "testcase"
            if t.verdict is Verdict.SUCCEEDED:
                n_failures += 1
                msg = t.reason or "SUT was exploitable"
                body = f"<failure message={quoteattr(msg)}>{escape(t.evidence_quote or '')}</failure>"
            elif t.verdict is Verdict.INCONCLUSIVE and t.error:
                n_errors += 1
                body = f"<error message={quoteattr(t.error)}>{escape(t.reason)}</error>"
            elif t.verdict is Verdict.INCONCLUSIVE:
                n_skipped += 1
                msg = t.reason or "inconclusive (coverage gap)"
                body = f"<skipped message={quoteattr(msg)} />"
            # Resisted: a passing testcase with a system-out note.
            controls = ", ".join(c.control_id for c in sr.controls) or "none"
            atlas = ", ".join(s.mitre_atlas) or "none"
            sysout = (
                f"[{s.owasp_category} {s.owasp_name}] "
                f"ATLAS={atlas}; controls={controls}; "
                f"delivery={s.delivery_vector}; verdict={t.verdict.value}; fidelity={t.fidelity.value}; "
                f"findings={json.dumps([asdict(f) for f in t.findings])}; error={t.error or ''}"
            )
            cases.append(
                f"      <{tag} {_attrs(name=name, classname=classname)}>\n"
                f"        <system-out>{escape(sysout)}</system-out>\n"
                f"        {body}\n"
                f"      </{tag}>"
            )
        total_tests += n_tests
        total_failures += n_failures
        total_skipped += n_skipped
        total_errors += n_errors
        suites.append(
            f"  <testsuite {_attrs(name=s.id, package='neuralstrike.corpus')}\n"
            f"            tests={quoteattr(str(n_tests))} failures={quoteattr(str(n_failures))}\n"
            f"            skipped={quoteattr(str(n_skipped))} errors={quoteattr(str(n_errors))}>\n"
            f"    <properties>\n"
            f"      <property name='artifact_policy' value='private-raw' />\n"
            f"      <property name='assessment_health' value={quoteattr(health)} />\n"
            f"      <property name='inconclusive' value={quoteattr(str(sr.inconclusive))} />\n"
            f"      <property name='succeeded' value={quoteattr(str(sr.succeeded))} />\n"
            f"      <property name='resisted' value={quoteattr(str(sr.resisted))} />\n"
            f"      <property name='owasp_category' value={quoteattr(s.owasp_category)} />\n"
            f"      <property name='owasp_name' value={quoteattr(s.owasp_name)} />\n"
            f"      <property name='mitre_atlas' value={quoteattr(', '.join(s.mitre_atlas))} />\n"
            f"      <property name='delivery_vector' value={quoteattr(s.delivery_vector)} />\n"
            f"      <property name='severity' value={quoteattr(s.severity)} />\n"
            f"    </properties>\n" + "\n".join(cases) + "\n  </testsuite>"
        )

    header = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<testsuites tests={quoteattr(str(total_tests))} "
        f"failures={quoteattr(str(total_failures))} "
        f"skipped={quoteattr(str(total_skipped))} errors={quoteattr(str(total_errors))} "
        f'name="neuralstrike-corpus" '
        f">"
    )
    return header + "\n" + "\n".join(suites) + "\n</testsuites>\n"
