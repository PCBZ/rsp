/**
 * Line-and-column to byte offsets (S1). No binary needed: a report is data.
 * Cases belong in the shared table; only what it cannot hold stays here.
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
    // Offsets inside 密, with Match what they cover, so only the boundary check
    // refuses them. The shared table cannot hold it: those bytes are not UTF-8.
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
