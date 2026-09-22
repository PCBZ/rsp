/**
 * Which verdict a report becomes.
 *
 * Driven through a stand-in binary that emits a report the test chose, because
 * the interesting case cannot be provoked from real gitleaks on demand: a
 * finding whose position the adapter cannot confirm. Whatever is wrong with
 * such a report — an off-by-one in the columns, a line that is not there — the
 * answer must not be a redaction of everything else.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import path from "node:path";

import { REPLACEMENT, respond } from "../src/protocol.ts";

const FAKE = path.join(import.meta.dirname, "fixtures", "fake-gitleaks.sh");
const SAVED = { ...process.env };
const KEY = "AKIALALEMEL33243OLIB";

afterEach(() => {
  process.env = { ...SAVED };
});

/** Point the adapter at a gitleaks that reports exactly this. */
function reporting(findings: unknown[]): void {
  process.env.RSP_GITLEAKS = FAKE;
  process.env.FAKE_GITLEAKS_REPORT = JSON.stringify(findings);
  process.env.FAKE_GITLEAKS_EXIT = findings.length > 0 ? "2" : "0";
}

describe("respond", () => {
  it("allows a chunk nothing was found in", () => {
    reporting([]);
    assert.deepEqual(respond({ hook: "on_chunk", content: "nothing here" }), {
      verdict: "ALLOW",
    });
  });

  it("redacts the spans of findings it could place", () => {
    reporting([
      {
        RuleID: "aws-access-token",
        StartLine: 1,
        EndLine: 1,
        StartColumn: 13,
        EndColumn: 32,
        Match: KEY,
      },
    ]);
    assert.deepEqual(respond({ hook: "on_chunk", content: `deploy with ${KEY} today` }), {
      verdict: "REDACT",
      spans: [{ start: 12, end: 32, type: "aws-access-token" }],
      replacement: REPLACEMENT,
      severity: "critical",
    });
  });

  it("blocks when a finding cannot be placed rather than redacting the others", () => {
    // Two findings, one of them mislocated. Reporting only the good span would
    // publish the other secret; an ALLOW would publish both.
    reporting([
      {
        RuleID: "aws-access-token",
        StartLine: 1,
        EndLine: 1,
        StartColumn: 13,
        EndColumn: 32,
        Match: KEY,
      },
      {
        RuleID: "aws-access-token",
        StartLine: 1,
        EndLine: 1,
        StartColumn: 99,
        EndColumn: 118,
        Match: KEY,
      },
    ]);
    const response = respond({ hook: "on_chunk", content: `deploy with ${KEY} today` });
    assert.equal("verdict" in response && response.verdict, "BLOCK");
    assert.ok("reason" in response && response.reason.length > 0, "BLOCK should say why");
  });

  it("blocks on a finding with no position rather than allowing the chunk", () => {
    // A report item missing its position fields cannot become a span. It is
    // still gitleaks saying it found something, so the chunk is blocked — the
    // same path a mislocated finding takes, for the same reason.
    reporting([{ RuleID: "aws-access-token", Match: KEY }]);
    const response = respond({ hook: "on_chunk", content: `deploy with ${KEY} today` });
    assert.equal("verdict" in response && response.verdict, "BLOCK");
  });

  it("refuses to answer at all when the report is not a report", () => {
    // Nothing sensible can be said about unparseable output, so the plugin
    // dies without a response and the host's error path decides (E1, D3).
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "not json";
    process.env.FAKE_GITLEAKS_EXIT = "2";
    assert.throws(() => respond({ hook: "on_chunk", content: "anything" }));
  });

  it("declares itself with the wrapped tool's version in its own", () => {
    // D4: a cache keyed on the adapter's version alone would keep serving
    // verdicts from a ruleset that has since changed.
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "8.30.1";
    const declaration = respond({ hook: "handshake" });
    assert.equal("version" in declaration && declaration.version, "0.1.0+8.30.1");
  });
});
