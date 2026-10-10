# The state of MCP security in Francophone African mobile money

**October 2026** · Bryand Tamouffe Teyo · [`mcp-scrutiny`](https://github.com/bryand410/mcp-scrutiny)

---

## Why this report exists

Every MCP security audit published this year has looked at the same thing: the code. [AgentAudit](https://agentaudit.dev/) scanned 194 packages and reported 118 findings — `child_process.exec` without sanitisation, environment variable leakage, over-broad filesystem access, dependency chains. [`agent-audit-kit`](https://github.com/sattyamjjain/agent-audit-kit) statically scanned 2,303 server configurations. [`mcp-audit`](https://github.com/marcoslozina/mcp-audit) is an open-source scanner with a rule set of the same shape.

None of them looked at the layer the model actually reads, and none of them looked at Africa.

This report does both. It covers the MCP servers that move money across Francophone West and Central Africa — a region where mobile money is not a convenience but the payment system, where Orange Money and MTN MoMo settle a large share of ordinary commerce, and where the servers now being connected to LLM agents have never been reviewed by anyone.

**Scope.** Seven servers. Two scanned with tool definitions extracted from the published artefacts; five assessed from source, package metadata and repository state. No API was called. Nothing was tested against a live payment endpoint.

---

## The servers

| Server | Reach | Tools | State on 10 Oct 2026 |
|---|---|---|---|
| [`@theyahia/orange-money-mcp`](https://www.npmjs.com/package/@theyahia/orange-money-mcp) | Orange Money WebPay, ~12 countries incl. **Cameroon (XAF)** | 8 | v1.1.0, published 2026-05-03. Scanned. |
| [`Tahsine/momo-mcp`](https://github.com/Tahsine/momo-mcp) | MTN MoMo, Francophone West Africa | 4 | **1 commit, 2026-07-05, 18:33 → 18:38.** Scanned. |
| [`jmndao/deggo-mcp`](https://github.com/jmndao/deggo-mcp) | Senegalese mobile money | — | MCP SDK pinned at **0.5.0**; Dependabot bumps to 1.20.2 unmerged since Nov 2025 |
| [`cinetpay/cinetpay-mcp`](https://github.com/cinetpay/cinetpay-mcp) | 10 Francophone countries | — | **0 stars.** No description. |
| [`Bigabou007-dev/warimcp`](https://github.com/Bigabou007-dev/warimcp) | CinetPay + Wave + Hub2/Ecobank + PAPSS | — | **0 stars** |
| [`senorMk/zambia-fintech-mcp`](https://github.com/senorMk/zambia-fintech-mcp) | Zambia | 9 | **0 stars** |
| MoMo MCP Server (via [Wycord](https://wycord.com/)) | MTN MoMo incl. Cameroon | — | Docs **broken**; ships spend limits, idempotency, audit log, kill switch |

The last row is the important one, and it is good news: **the safe pattern is already established in this ecosystem.** A community MTN MoMo server documents approval gates, spend limits, an audit log and a kill switch. The problem is not that nobody knows how. It is that the pattern has not spread.

---

## Findings

Graded honestly. Nothing here is a vulnerability in the sense of an exploitable bug in someone's code. Every item is a property of the surface an LLM is given, and every one is fixable.

### H1 — An unpinned install command on a server that holds a merchant key

`servers/orange-money/README.md` recommends this in three separate client configurations:

```json
"command": "npx",
"args": ["-y", "@theyahia/orange-money-mcp"],
"env": {
  "ORANGE_MONEY_CLIENT_SECRET": "your_client_secret",
  "ORANGE_MONEY_MERCHANT_KEY": "your_merchant_key",
  "ORANGE_MONEY_COUNTRY": "sn"
}
```

With no version, `npx` resolves the dist-tag at every start. A future publish to that package name executes with the user's client secret and merchant key already in the environment, and can call `cashout` and `transfer`.

This is the `postmark-mcp` path from September 2025, which reached roughly 300 organisations. The difference is what is on the other end: there the payload was a hidden BCC, here it is a merchant key on a live payment rail.

**Fix:** `"args": ["@theyahia/orange-money-mcp@1.1.0"]`, drop `-y`, and document that the version moves when a human decides it does. *Disclosed as [theYahia/WWmcp#73](https://github.com/theYahia/WWmcp/issues/73).*

### H2 — A partner PIN passed as a tool parameter

On `cashin`, `cashout` and `transfer` in the same server:

```js
pin: z.string().optional().describe("Partner PIN if required")
```

A partner PIN authorises the movement of funds. As a tool parameter it arrives in the model's context window, where it can be read, echoed into a response, or captured by an injected instruction. It is a key, not an argument — it belongs in the server's own configuration beside `ORANGE_MONEY_MERCHANT_KEY`.

### H3 — Outbound money movement with no ceiling and no approval gate

`disburse_payment` in `momo-mcp` sends money with no spend limit, no beneficiary allow-list and no human-in-the-loop step. Its description states this explicitly:

> *« Contrairement à request_payment, aucune confirmation PIN n'est nécessaire côté bénéficiaire — l'argent est envoyé directement. »*
>
> ("Unlike request_payment, no PIN confirmation is needed on the beneficiary side — the money is sent directly.")

The description is accurate about how payouts work. The problem is the combination: an outbound fund primitive, unbounded, exposed to a model, whose own documentation tells the model that no further friction applies. An agent whose context has been poisoned — by a web page, a ticket, a file it read — can call it repeatedly.

**Fix:** remove that sentence from the description; add `annotations: {"destructiveHint": true}` so MCP clients prompt; add a per-call and per-day ceiling read from configuration. *Disclosed as [Tahsine/momo-mcp#1](https://github.com/Tahsine/momo-mcp/issues/1).*

### H4 — The model writes the message the victim reads

`request_payment` accepts `payer_message: str = ""` — free text displayed on the payer's phone, with no template, no length limit and no rate limiting.

This is the most direct phishing channel I have found in an MCP server. The model composes the message a person reads before entering their PIN. *"MTN: confirm this deduction to avoid your line being suspended"* passes through unchanged. A set of predefined messages selected by the caller would close it without removing the capability.

This finding is invisible from outside the region. In Europe there is no single dominant payment channel that displays free text on a human's handset. In Douala, there is.

### H5 — Lower-bound-only dependencies

`mcp>=1.28.0`, `httpx>=0.28.0`, `pydantic>=2.13.0`. Any future release installs silently, including a breaking major or a compromised publish. For a project that touches payments, an upper bound or a lockfile is worth the maintenance.

---

## What the scanner could not see, and one thing it got wrong

Findings H1 was produced by [`mcp-scrutiny`](https://github.com/bryand410/mcp-scrutiny). H2–H5 were not: no scanner finds them, because they are not patterns in text. They require knowing what a merchant PIN is, what a payout primitive does, and what a phone notification means to the person holding it.

The scan itself reported 3 HIGH findings across 2 servers and 12 tools. Only one was real. The other two were toxic-flow pairings of low practical value — `list_supported_countries` reads the process environment, `cashin` sends data outbound, so the detector paired them. Technically true, practically noise. Reporting them as HIGH would have made this report look stronger and be worth less.

**And the scanner produced a false positive that mattered more than any finding in it.**

Scanning `momo-mcp`'s `request_payment` scored **p=0.84** — "description reads as instructions to the model". It is an ordinary, well-written, procedural description of a payment tool. The cause was not the wording:

- the training corpus capped out at **228 characters**;
- it contained **no text in any language other than English**;
- so `log_len` sat **6.7 standard deviations** outside the training distribution, and the model had learned that *long means malicious*.

Every properly documented tool — which is every tool in a mature server — would have been flagged. And a detector that has never seen French is unusable for 300 million people.

This was fixed the same day, before publication: the corpus now carries long, `Args:`-blocked descriptions in English and French alongside long malicious ones, cross-validation F1 moved from 0.87 to 0.88, and four regression tests pin it. The `request_payment` case now scores **0.008**.

**It is in this report because it is the most useful thing the exercise produced.** A security tool that oversells itself is a liability, and the same applies to a security report.

The fix exposed the sharpest remaining limit, which is also disclosed: **the steering patterns in `features.py` are still English-only.** A French description saying *"ignorez les instructions précédentes"* scores 0.19 against a threshold of 0.5 — missed. Tracked as [`mcp-scrutiny#5`](https://github.com/bryand410/mcp-scrutiny/issues/5).

---

## Disclosure

All findings were reported to the maintainers **before** publication, and this report cites their repositories rather than characterising their work.

| Finding | Where | Status |
|---|---|---|
| H1, H2, H4 | [theYahia/WWmcp#73](https://github.com/theYahia/WWmcp/issues/73) | open, awaiting response |
| H3, H4, H5 | [Tahsine/momo-mcp#1](https://github.com/Tahsine/momo-mcp/issues/1) | open, awaiting response |

Both projects are early and neither is malicious. The correct reading of this report is not that these servers are dangerous — it is that **a real payment surface has been connected to LLM agents across a dozen countries with no review layer at all**, and that the first review took two days.

---

## Recommendations

**For maintainers of payment MCP servers:**

1. Pin every version in every install instruction. Never ship `-y` with no version next to a credential.
2. Keep secrets out of tool parameters. A PIN, a key, a token — configuration, never an argument.
3. Put a ceiling and an approval gate on every outbound money tool, and set `destructiveHint`.
4. Never let the model author text that a human will read on a payment surface. Use templates.
5. Ask what your description tells the model. Descriptions are not documentation — they are delivered as trusted context.

**For teams deploying them:** run `mcp-scrutiny baseline` once, commit the snapshot, and diff on every later scan. The single most effective MCP control is the diff, and it needs a baseline to diff against.

**For the wider field:** the audits that exist are excellent and they are looking at code. The description layer, and the non-English world, are unclaimed.

---

## Reproduce this

```bash
pip install mcp-scrutiny
mcp-scrutiny scan --tools-json docs/afrmcp-dump.json
```

The tool definitions used here are reconstructed from the published sources in `mcp_scrutiny/corpus.py` and the servers' own repositories. Corrections are welcome as issues, and a correction to a finding is worth more to me than a confirmation of one.

---

*Bryand Tamouffe Teyo — DevSecOps, Douala, Cameroon. Building `mcp-scrutiny`, an offline scanner for MCP tool definitions. [github.com/bryand410](https://github.com/bryand410)*
