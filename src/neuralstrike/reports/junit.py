"""JUnit XML report writer.

Emits a JUnit-compatible XML document for CI pipelines. One ``testsuite``
per scenario; one ``testcase`` per trial-finding. Inconclusive probes are
surfaced as ``skipped`` testcases with a ``reason`` (a coverage gap), never
dropped — the Phase 2 contract that inconclusive probes are surfaced.
Succeeded findings are ``failures`` (the SUT was exploitable); Resisted
trials are passing testcases.
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports.model import CorpusRun

__all__ = ["to_junit"]


def _attrs(**kwargs: str) -> str:
    return " ".join(f'{k}={quoteattr(v)}' for k, v in kwargs.items() if v is not None)


def to_junit(run: CorpusRun) -> str:
    """Render the corpus run as a JUnit XML string."""
    suites: list[str] = []
    total_tests = total_failures = total_skipped = 0
    for sr in run.scenario_results:
        s = sr.scenario
        cases: list[str] = []
        n_tests = n_failures = n_skipped = 0
        for t in sr.trials:
            n_tests += 1
            name = f"{s.id}.trial{t.trial_index}.{t.oracle_id}"
            classname = f"neuralstrike.corpus.{s.owasp_category}"
            body = ""
            tag = "testcase"
            if t.verdict is Verdict.SUCCEEDED:
                n_failures += 1
                msg = t.reason or "SUT was exploitable"
                body = f"<failure message={quoteattr(msg)}>{escape(t.evidence_quote or '')}</failure>"
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
                f"delivery={s.delivery_vector}; fidelity={t.fidelity.value}"
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
        suites.append(
            f"  <testsuite {_attrs(name=s.id, package='neuralstrike.corpus')}\n"
            f"            tests={quoteattr(str(n_tests))} failures={quoteattr(str(n_failures))}\n"
            f"            skipped={quoteattr(str(n_skipped))}>\n"
            f"    <properties>\n"
            f"      <property name='owasp_category' value={quoteattr(s.owasp_category)} />\n"
            f"      <property name='owasp_name' value={quoteattr(s.owasp_name)} />\n"
            f"      <property name='mitre_atlas' value={quoteattr(', '.join(s.mitre_atlas))} />\n"
            f"      <property name='delivery_vector' value={quoteattr(s.delivery_vector)} />\n"
            f"      <property name='severity' value={quoteattr(s.severity)} />\n"
            f"    </properties>\n"
            + "\n".join(cases)
            + "\n  </testsuite>"
        )

    header = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites tests={quoteattr(str(total_tests))} '
        f'failures={quoteattr(str(total_failures))} '
        f'skipped={quoteattr(str(total_skipped))} '
        f'name="neuralstrike-corpus" '
        f'>'
    )
    return header + "\n" + "\n".join(suites) + "\n</testsuites>\n"
