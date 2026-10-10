# Security policy

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/bryand410/mcp-scrutiny/security/advisories/new).
Please do not open a public issue for a security problem.

Include, where you can: the version (`mcp-scrutiny --version`), the tool definition or config that
triggers it, and what you expected to happen. A minimal reproduction is worth more than a long
description.

**Response times.** Acknowledgement within 72 hours, an assessment within 7 days, a fix or a
public write-up within 30 days. If a fix needs longer, you will get the reasoning, not silence.

## What counts as a vulnerability

This is a detector, so its failure modes are not the usual ones. All of the following are in scope:

| Class | Example |
|---|---|
| **Detector bypass** | A tool description that instructs the model but scores below the semantic threshold |
| **Evasion** | A payload that survives the decode-and-rescore pass, or invisible Unicode that is not counted |
| **Drift bypass** | A change to a tool definition that does not alter any stored fingerprint |
| **False negative in toxic flow** | A capability combination that forms an exfiltration path and is not flagged |
| **Crash on hostile input** | A config or tool definition that makes the scanner raise instead of reporting |
| **Supply chain** | Anything that makes the scanner itself a risk to run: an unexpected dependency, a network call, code execution from a config value |

**False positives are also welcome as reports**, though they are bugs rather than vulnerabilities.
A scanner that cries wolf gets switched off, which makes a false positive a security problem in
practice. Open a normal issue for those, with the description that triggered it.

## What does not count

- The scanner is static. It does not execute tools, so it cannot detect attacks that only appear at
  runtime. That is a documented limitation, not a vulnerability.
- A malicious MCP server doing malicious things. Report that to the server's maintainers; this tool
  exists to find it, not to be it.
- Findings you disagree with the severity of. Open an issue and make the argument — the severity
  bands are a policy choice and policy choices are arguable.

## Supported versions

The latest released version on PyPI. Fixes are not backported.

## A note on the model

The semantic detector is a logistic regression trained on a small, hand-built corpus. It is
reported honestly: 5-fold cross-validation F1 is 0.88, not 1.00, and the README's Limitations
section lists what is known and unresolved. If you find a bypass, that is a useful result and not
an embarrassment — it is how the corpus grows.

Two bypasses are known today and both are worth your time: **non-English prompt injection is
invisible** (the steering patterns in `features.py` match English only), and a description that
names secret-looking keys while describing a security control can still cross the threshold.

If you report a bypass, the fix will be a new feature or a new labelled example, and the example
will be added to `mcp_scrutiny/corpus.py` with a regression test. You will be credited unless you
ask otherwise.
