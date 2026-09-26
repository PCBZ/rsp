/**
 * The conversion from gitleaks' line-and-column positions to the byte offsets
 * SPEC.md S1 requires.
 *
 * The table is `examples/gitleaks-offsets.json`, shared with the Go and Rust
 * adapters, because the numbers in it are facts about gitleaks rather than
 * about any of the three. What stays here is what this language makes
 * possible and the others do not.
 *
 * None of it needs the binary: the input is a report, which is data. What the
 * binary emits for new content is a separate question, checked in CI by the
 * cross-process cases.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { toSpans, type Finding, type Span } from "../src/gitleaks.ts";

interface Case {
  tcId: number;
  comment: string;
  flags: string[];
  content: string;
  findings: Finding[];
  spans: Span[];
}

const table: { notes: Record<string, string>; tests: Case[] } = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "gitleaks-offsets.json"), "utf8"),
);

function why(test: Case): string {
  return [test.comment, ...test.flags.map((flag) => table.notes[flag])].join("\n");
}

describe("the shared offset table", () => {
  it("has not lost cases to a path that resolved to nothing", () => {
    assert.ok(table.tests.length >= 13, `${table.tests.length} cases`);
  });

  for (const test of table.tests) {
    it(`converts ${test.comment}`, () => {
      assert.deepEqual(toSpans(test.findings, test.content), test.spans, why(test));
    });
  }
});

describe("what only this language can get wrong", () => {
  it("drops a span inside a character", () => {
    // Offsets inside 密, with Match the bytes they actually cover — subarray
    // truncates rather than failing, and a lone continuation byte decodes to
    // U+FFFD, so the slice comparison passes and only the boundary check can
    // refuse them. Each adapter spells those bytes in its own way and none of
    // the spellings is valid UTF-8, which is why this case is not in the JSON.
    const KEY = "AKIALALEMEL33243OLIB";
    const inside: Finding = {
      RuleID: "private-key",
      StartLine: 1,
      EndLine: 1,
      StartColumn: 2,
      EndColumn: 2,
      Match: "�",
    };

    assert.deepEqual(toSpans([inside], `密钥 ${KEY}`), []);
  });
});
