"""Where a rendered report is written when the operator supplies `--out`.

One rule, one place. `--out report` gains the format's extension; `--out report.json` does not
gain a second one. The extension is appended **only when the path has none**, and a suffix the
operator typed is never replaced — a path is a thing they named, not a suggestion.

Before this module the extension was appended unconditionally at two call sites, so
`--out report.json` wrote `report.json.json`. That is a small bug with a large lesson: nobody
noticed because the documented example omits the extension.
"""

from __future__ import annotations

from pathlib import Path

#: The canonical extension per report format. `junit` is XML and `markdown` is `.md`, which is
#: exactly why the mapping is a table rather than `"." + format`.
FORMAT_EXTENSIONS: dict[str, str] = {
    "json": ".json",
    "sarif": ".sarif",
    "junit": ".xml",
    "markdown": ".md",
    "pdf": ".pdf",
}


def report_destination(out: str | Path, format: str) -> Path:
    """Return the path a report of ``format`` should be written to.

    - no suffix: append the format's canonical extension;
    - the format's own suffix: use the path verbatim;
    - any other suffix: use the path verbatim (the operator named that file).
    """
    try:
        extension = FORMAT_EXTENSIONS[format]
    except KeyError as exc:
        raise ValueError(f"unsupported report format: {format!r}") from exc
    path = Path(out)
    if path.suffix:
        return path
    return path.with_name(path.name + extension)
