/**
 * The conversion from gitleaks' line-and-column positions to the byte offsets
 * SPEC.md S1 requires.
 *
 * This is the only part of the adapter with logic, and it needs no binary: the
 * input is a report, which is data. Every report below is transcribed from what
 * gitleaks 8.30.1 actually emitted for that content — inventing the numbers is
 * how the end offset came to be wrong for anything spanning two lines, since a
 * fabricated report agrees with whatever the code assumes.
 *
 * What the binary emits for new content is a separate question, checked in CI
 * by the cross-process cases. Only that one needs gitleaks installed.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toSpans, type Finding } from "../src/gitleaks.ts";

const KEY = "AKIALALEMEL33243OLIB";

const PEM = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
  "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

/** The reported range, sliced out of the content the report describes. */
function sliced(finding: Finding, content: string): string {
  const [span] = toSpans([finding], content);
  assert.ok(span, "expected one span");
  return Buffer.from(content, "utf8").subarray(span.start, span.end).toString("utf8");
}

function key(
  StartLine: number,
  EndLine: number,
  StartColumn: number,
  EndColumn: number,
  Match = KEY,
): Finding {
  return { RuleID: "aws-access-token", StartLine, EndLine, StartColumn, EndColumn, Match };
}

describe("toSpans", () => {
  it("returns nothing for an empty report", () => {
    assert.deepEqual(toSpans([], "anything"), []);
  });

  it("converts a position on the first line", () => {
    const content = `deploy with ${KEY} today`;
    assert.deepEqual(toSpans([key(1, 1, 13, 32)], content), [
      { start: 12, end: 32, type: "aws-access-token" },
    ]);
  });

  it("counts bytes, not characters, when multi-byte text precedes the key", () => {
    // 密钥 is two characters and six bytes, so a character index would say 3.
    const content = `密钥 ${KEY} 在后面`;
    const [span] = toSpans([key(1, 1, 8, 27)], content);
    assert.equal(span?.start, 7);
    assert.equal(sliced(key(1, 1, 8, 27), content), KEY);
  });

  it("counts a later line's columns from the newline before it", () => {
    // gitleaks reports column 11 for a key at byte 16 of a line starting at 7:
    // its columns run from the newline byte, so they are one lower than a
    // line-relative column would be. Assuming otherwise puts the span one byte
    // early, which slices a leading character and drops the key's last.
    const content = `header\nexport K=${KEY}\n`;
    const [span] = toSpans([key(2, 2, 11, 30)], content);
    assert.equal(span?.start, 16);
    assert.equal(sliced(key(2, 2, 11, 30), content), KEY);
  });

  it("counts bytes across multi-byte lines above the finding", () => {
    const content = `密钥\n说明\nK=${KEY}\n`;
    assert.equal(sliced(key(3, 3, 4, 23), content), KEY);
  });

  it("spans a finding that ends on a different line than it starts on", () => {
    // A PEM block is the ordinary case for this, and the one that shows why
    // EndColumn belongs to EndLine: read against the start line it lands 141
    // bytes early, redacting the first line of the key and publishing the rest.
    const content = `cfg:\n${PEM}\ntrailing\n`;
    const finding: Finding = {
      RuleID: "private-key",
      StartLine: 2,
      EndLine: 5,
      StartColumn: 2,
      EndColumn: 30,
      Match: PEM,
    };
    assert.deepEqual(toSpans([finding], content), [
      { start: 5, end: 5 + Buffer.byteLength(PEM), type: "private-key" },
    ]);
  });

  it("reports every occurrence, each with its own line's origin", () => {
    const content = `${KEY}\nfiller\n${KEY}`;
    const spans = toSpans([key(1, 1, 1, 20), key(3, 3, 2, 21)], content);
    assert.deepEqual(
      spans.map((span) => span.start),
      [0, 28],
    );
  });

  it("carries the rule id through as the finding type", () => {
    const content = KEY;
    const [span] = toSpans([{ ...key(1, 1, 1, 20), RuleID: "private-key" }], content);
    assert.equal(span?.type, "private-key");
  });

  it("drops a finding on a line the content does not have", () => {
    // Defensive: the host validates spans anyway (S3), but a span it rejects
    // blocks the chunk, so an adapter should not manufacture one.
    assert.deepEqual(toSpans([key(99, 99, 1, 20)], "one line"), []);
  });

  it("drops a span the host would reject", () => {
    const content = `密钥 ${KEY}`;
    // subarray truncates rather than failing, so an end past the content can
    // still slice to Match; offsets inside 密 are not a character.
    const pastEnd = key(1, 1, 8, 400);
    const insideRune: Finding = { ...key(1, 1, 2, 2), Match: "\ufffd" };

    assert.deepEqual(toSpans([pastEnd], content), []);
    assert.deepEqual(toSpans([insideRune], content), []);
  });

  it("drops a finding with an empty match", () => {
    // Offsets inside a character, which the slice check alone would accept.
    const finding: Finding = {
      RuleID: "aws-access-token",
      StartLine: 1,
      EndLine: 1,
      StartColumn: 3,
      EndColumn: 2,
      Match: "",
    };
    assert.deepEqual(toSpans([finding], "密钥"), []);
  });

  it("drops a finding whose offsets do not slice the match back out", () => {
    // The check that makes the arithmetic self-auditing: gitleaks has had
    // off-by-one bugs in these columns, and a span nobody verified redacts the
    // wrong bytes. Dropping it is not letting it through — the caller blocks
    // the chunk when a finding produced no span.
    const content = `deploy with ${KEY} today`;
    assert.deepEqual(toSpans([key(1, 1, 14, 32)], content), []);
  });
});
