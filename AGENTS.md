# AGENTS.md

RSP is a protocol. `SPEC.md` is the deliverable; the code is evidence that it
works. Decisions (D1–D9) and open questions (Q1–Q8) are in the
[wiki](https://github.com/PCBZ/rsp/wiki) — cite them by number, don't re-argue them.

## Layout

Each layer knows strictly less than the one above it, and the imports go one way.

- `rsp/process.py` — start a plugin, feed it, drain it, reap it. Knows no JSON.
- `rsp/codec.py` — a request in, a parsed response out. Knows no plugin identity.
- `rsp/handshake.py` — who a plugin says it is.
- `rsp/spans.py` — byte offsets and redaction. Knows no verdicts.
- `rsp/runtime.py` — the deciding layer: dispatch, compose, fail closed.
- `rsp/guards.py` — LlamaIndex adapter. Knows no transport.
- `rsp/config.py` — plugins from a file. Not in the spec; a host may ignore it.
- `rsp/ingest.py` — a directory through the LlamaIndex pipeline, for the demo.
- `rsp/cli.py` — `rsp validate` and `rsp ingest`.
- `plugins/*` — untrusted third-party code. Detection lives only here.

A change that makes a lower layer import a higher one is a design change, not a
convenience.

## Commands

```bash
uv sync
uv run ruff check rsp/ tests/ plugins/ conformance/
uv run ruff format --check rsp/ tests/ plugins/ conformance/
uv run pytest
```

## Rules

- Every error path ends in `BLOCK` unless that plugin's `on_error` says otherwise (D3).
- Validate a plugin's span before slicing with it: in range, `start <= end`, on a UTF-8 boundary (D6).
- Findings never reach an embedding or the LLM — both `excluded_*_metadata_keys` (Q8).
- Never log, embed, or echo matched content. Demo secrets are fabricated.
- No detection logic in `rsp/`. No dependencies in the core; `llama-index-core` is an extra.
- Ignore unknown protocol fields (D8).
- Cache key is `hash(content + plugin_version + plugin_config)`; never cache a plugin that didn't declare determinism (D4).
- Timeout every read and wait, then kill and reap. Plugin commands are argv lists, never `shell=True`.
- Strictest verdict wins, `BLOCK` short-circuits (D9).
- `guards.py` and each plugin adapter contain no detection logic and stay
  small: under 80 lines of code, counting neither docstrings nor comments nor
  blank lines. A language that puts a closing brace on its own line pays a
  fixed tax that is not growth — `examples/gitleaks-go/gitleaks.go` is 94
  lines, of which 54 do work and 34 are braces and struct tags. Judge the
  work, and say which it is when the number goes over.

## Conventions

- Work top-down: write the call site first, then the code it calls. A file may import a module that does not exist yet — don't stub it, make it run, or test it. This is about the order you write in, not the order things sit in a file.
- Every MUST in `SPEC.md` gets a conformance fixture the same day. Fixtures assert protocol behaviour, not implementation.
- Comments cite decisions by number: `# span application is the runtime's job (D6)`.
- Never an issue number. `D6` and `S1` resolve inside a clone; `#13` resolves
  only against a live tracker, and only until that issue is renumbered. Say the
  reason or cite the clause — a test enforces this.
- `ruff` owns formatting and annotation style.
- One issue per PR, titled `#N Short summary`. Out-of-scope findings become issues, not scope creep.

## Style

Written down so that a style finding cites a rule rather than a preference.
`ruff` enforces what it can (`pyproject.toml`); the rest is for reviewers.

- A comment says why, never what. If the code already says it, delete the comment.
- One line where one will do. Cite the clause instead of restating it: `(D6)`,
  `(S3, V3)`, `§4`.
- A reason lives in one place. Protocol rationale belongs to `SPEC.md`; code
  cites the clause. The same reason is not written in two files.
- No history. Not what the code used to do, not the bug that prompted a check —
  `git log` keeps that. Keep the reason that still holds.
- Docstrings: a one-line summary. A body only for what the caller cannot learn
  from the signature, after a blank line, with the closing `"""` on its own line.
  A test's name says what holds; its docstring, if any, says why.
- In `rsp/`, a name used only inside its module starts with `_`: no underscore
  means public API. A caught exception is `exc`.
- Constants come straight after the imports. A helper sits above its first
  caller; `main` comes last.
- Every parameter and return in `rsp/` is annotated.

## Reviewers

Skip formatting, non-running files, missing tests for call sites, spawn-per-call
performance (Q6), and matters of taste. One sentence per finding, naming the
failure. Nothing to say is a valid review.
