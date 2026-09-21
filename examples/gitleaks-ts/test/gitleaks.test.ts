/**
 * The conversion from gitleaks' line-and-column positions to the byte offsets
 * SPEC.md S1 requires.
 *
 * This is the only part of the adapter with logic, and it needs no binary: the
 * input is a report, which is data. What the binary actually emits is checked
 * once, in CI, by the cross-process cases — the two are different questions,
 * and only the second needs gitleaks installed.
 *
 * Positions here follow gitleaks: StartColumn is 1-based, EndColumn inclusive,
 * and both count bytes, because they come from Go regexp indices into a byte
 * slice.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toSpans, type Finding } from "../src/gitleaks.ts";

const KEY = "AKIALALEMEL33243OLIB";

function finding(line: number, startColumn: number, match = KEY): Finding {
  return {
    RuleID: "aws-access-token",
    StartLine: line,
    StartColumn: startColumn,
    EndColumn: startColumn + match.length - 1,
    Match: match,
  };
}

describe("toSpans", () => {
  it("returns nothing for an empty report", () => {
    assert.deepEqual(toSpans([], "anything"), []);
  });

  it("converts a position on the first line", () => {
    const content = `deploy with ${KEY} today`;
    const [span] = toSpans([finding(1, 13)], content);
    assert.deepEqual(span, { start: 12, end: 32, type: "aws-access-token" });
  });

  it("produces offsets that slice the key back out", () => {
    // The only test that matters: an offset is useful exactly when it indexes
    // the bytes the host is holding.
    const content = `deploy with ${KEY} today`;
    const [span] = toSpans([finding(1, 13)], content);
    const bytes = Buffer.from(content, "utf8");
    assert.equal(bytes.subarray(span?.start, span?.end).toString("utf8"), KEY);
  });

  it("counts bytes, not characters, when an earlier line is multi-byte", () => {
    // 密钥在这里 is five characters and fifteen bytes; the newline is one more.
    const content = `密钥在这里\n${KEY}`;
    const [span] = toSpans([finding(2, 1)], content);
    assert.equal(span?.start, 16);
    const bytes = Buffer.from(content, "utf8");
    assert.equal(bytes.subarray(span?.start, span?.end).toString("utf8"), KEY);
  });

  it("counts bytes within a line that starts with multi-byte text", () => {
    const content = `密钥 ${KEY}`;
    // gitleaks would report column 8: 密钥 is seven bytes, then a space.
    const [span] = toSpans([finding(1, 8)], content);
    assert.equal(span?.start, 7);
  });

  it("handles several findings on different lines", () => {
    const content = `${KEY}\nfiller\n${KEY}`;
    const spans = toSpans([finding(1, 1), finding(3, 1)], content);
    assert.deepEqual(
      spans.map((span) => span.start),
      [0, 28],
    );
  });

  it("carries the rule id through as the finding type", () => {
    const [span] = toSpans([{ ...finding(1, 1), RuleID: "private-key" }], KEY);
    assert.equal(span?.type, "private-key");
  });

  it("drops a finding on a line the content does not have", () => {
    // Defensive: the host validates spans anyway (S3), but a span it rejects
    // blocks the chunk, so an adapter should not manufacture one.
    assert.deepEqual(toSpans([finding(99, 1)], "one line"), []);
  });
});
