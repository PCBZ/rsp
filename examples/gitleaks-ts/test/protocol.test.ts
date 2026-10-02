/**
 * Which report becomes which verdict, through a stand-in binary so the
 * interesting case can be provoked: a finding that cannot be placed.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import path from "node:path";

import { REPLACEMENT, respond } from "../src/protocol.ts";

const FAKE = path.join(import.meta.dirname, "..", "..", "testdata", "fake-gitleaks.sh");
const SAVED = { ...process.env };
const KEY = "AKIALALEMEL33243OLIB";

afterEach(() => {
  process.env = { ...SAVED };
});

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
    // The second finding is mislocated.
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
    reporting([{ RuleID: "aws-access-token", Match: KEY }]);
    const response = respond({ hook: "on_chunk", content: `deploy with ${KEY} today` });
    assert.equal("verdict" in response && response.verdict, "BLOCK");
  });

  it("refuses to answer at all when the report is not a report", () => {
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "not json";
    process.env.FAKE_GITLEAKS_EXIT = "2";
    assert.throws(() => respond({ hook: "on_chunk", content: "anything" }));
  });

  it("refuses a missing report when gitleaks says it found something", () => {
    // Exit 2 is gitleaks saying it found something; nothing written is then a
    // report that went missing, and no findings publishes the chunk (E1, D3).
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "";
    process.env.FAKE_GITLEAKS_EXIT = "2";
    assert.throws(() => respond({ hook: "on_chunk", content: "anything" }));
  });

  it("reads an empty report with a clean exit as a clean chunk", () => {
    // The reading that has to survive the test above.
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "";
    process.env.FAKE_GITLEAKS_EXIT = "0";
    const response = respond({ hook: "on_chunk", content: "anything" });
    assert.equal("verdict" in response && response.verdict, "ALLOW");
  });

  it("refuses a report that is not a list of findings", () => {
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = '{"RuleID":"aws-access-token"}';
    process.env.FAKE_GITLEAKS_EXIT = "2";
    // The message, not just a throw: without the check an object still fails
    // somewhere further on, and any throw would pass for the wrong reason.
    assert.throws(
      () => respond({ hook: "on_chunk", content: "anything" }),
      /not a list of findings/,
    );
  });

  it("declares itself with the wrapped tool's version in its own", () => {
    process.env.RSP_GITLEAKS = FAKE;
    process.env.FAKE_GITLEAKS_REPORT = "8.30.1";
    const declaration = respond({ hook: "handshake" });
    assert.equal("version" in declaration && declaration.version, "0.1.0+8.30.1");
  });
});
