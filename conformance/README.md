# The conformance kit

Cases, a runner, and a plugin that misbehaves on request. Copy this directory
and `plugins/` next to your plugin and run it — there is nothing to install,
and nothing here imports the reference runtime. You are checking your plugin
against the protocol, not against our implementation of it.

```console
$ python conformance/run.py -- node my-wrapper.js

== echo
FAIL  verdict-block (utf-8): expected {...}, got {'verdict': 'ALLOW'}
...
== gitleaks
pass  gitleaks/aws-key
...
2/10 cases for echo
7/7 cases for gitleaks
clauses settled: H2, S1, V2, V3
```

A plugin conforms to a **role** rather than in general, so asked without one
the kit tries each and you read off which you are. Failures against a role you
never claimed are information, not a verdict: the exit code is 0 when some
role passed in full.

```console
$ python conformance/run.py --list-roles
echo      10 cases
gitleaks  7 cases
$ python conformance/run.py --role gitleaks -- node my-wrapper.js
```

Exit 1 if no role passed, 2 if the arguments are wrong. Every case runs twice,
once with raw UTF-8 in the request and once with `\uXXXX` escapes: JSON permits
both, and a plugin that decodes surrogate pairs wrong reports offsets that are
wrong by two — invisibly, until content leaves the BMP.

`echo` is the marker-driven reference plugin; `gitleaks` is any adapter over
that binary. See `cases/README.md` for what a role is and why a case names
one.

## Host cases

`host/` holds the other kind: a plugin's answer, or its refusal to give one,
and the behaviour a **host** must have in return. They are not run by
`run.py`, because a host is a library rather than a process and cannot be
spawned — the runner for those belongs to whoever wrote the host.
`tests/test_host_conformance.py` in this repository is one, and it is short
on purpose.

## What is here

| | |
|---|---|
| `cases/` | plugin cases: a request, and the response required |
| `host/` | host cases: a plugin's behaviour, and the host's required response to it |
| `harness.py` | what passing a case means. The repository's own suite calls this too, so there is one definition rather than two that drift |
| `run.py` | the command above |
