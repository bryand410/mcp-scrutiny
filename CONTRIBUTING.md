# Contributing

Thanks for looking. This is a security tool, so the bar for a change is "does this make the
scanner more correct, or less noisy" — and the second one counts as much as the first.

## Setup

```bash
git clone https://github.com/bryand410/mcp-scrutiny
cd mcp-scrutiny
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
```

There is no build step, no service to start, and no network call in the test suite. If a test needs
the network, that is a bug in the test.

## The rules that matter here

**1. Never tune to the test set.** The semantic model is evaluated by 5-fold cross-validation and
by 20 held-out examples in `mcp_scrutiny/corpus.py` that are never used for fitting. If you add a
held-out example to the training half to make a number go up, you have made the reported metric
meaningless. Change the features instead.

**2. A false positive is a bug.** The corpus's benign half is deliberately hostile to the model: it
contains the exact phrases that make keyword scanners fire ("You MUST call this function first").
If your change makes one of those flag, the change is wrong, even if it catches more attacks.
Precision and recall are both in the README for a reason.

**3. Report the number you measured.** If a change moves cross-validation F1, say so in the pull
request, with the before and after. Training accuracy is not a number worth quoting and will be
asked about.

**4. Every finding needs a remediation a human can act on.** A finding that says "this is
suspicious" and stops is not finished. Look at the existing detectors for the register: what is
wrong, why it is exploitable, and the specific next step.

## Adding a detector

1. Create `mcp_scrutiny/detectors/yourname.py` with a class exposing `name: str` and
   `run(result: ScanResult, ctx: ScanContext) -> list[Finding]`.
2. Register it in `mcp_scrutiny/detectors/__init__.py` in `ALL_DETECTORS`, in the order it should
   appear in a report.
3. Add it to `_detector_description()` in `mcp_scrutiny/report.py` so SARIF and `--help` explain it.
4. Write tests in `tests/test_detectors.py`: one for the attack it catches, and at least one
   asserting it stays quiet on a benign configuration.
5. Document it in the README's detector table.

Detectors must be pure: no network, no filesystem writes, no state between calls. Two scans of the
same input must produce byte-identical reports.

## Adding a corpus example

Add the description to `MALICIOUS` or `BENIGN` in `mcp_scrutiny/corpus.py`, with a comment saying
where it comes from if it is a real attack. Then run:

```bash
mcp-scrutiny train
```

and paste the before/after cross-validation numbers into the pull request.

Adding an example that only makes the model pass a test it was failing is the wrong move — the fix
belongs in `mcp_scrutiny/features.py` as a named feature, so the model learns a *property* rather
than a sentence.

## Reporting a security issue

Not here — see [SECURITY.md](SECURITY.md). Do not open a public issue for a detector bypass.

## Style

- Python 3.11+, standard library only. A pull request that adds a runtime dependency will be
  declined: the zero-dependency property is checked in CI and is the reason this tool can run in an
  air-gapped pipeline.
- `ruff check .` must pass.
- Comments explain *why*, not *what*. The interesting comments in this codebase are the ones saying
  why a check exists and what it is compensating for.
- Commit messages: imperative mood, and say what the change fixes rather than what file it touches.
