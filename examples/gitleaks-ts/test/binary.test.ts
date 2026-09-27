/** What the adapter does when gitleaks does not answer. A script stands in. */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import path from "node:path";

import { scan } from "../src/gitleaks.ts";

const FAKE = path.join(import.meta.dirname, "fixtures", "fake-gitleaks.sh");
const SAVED = { ...process.env };

afterEach(() => {
  process.env = { ...SAVED };
});

function fake(exit: number): void {
  process.env.RSP_GITLEAKS = FAKE;
  process.env.FAKE_GITLEAKS_EXIT = String(exit);
}

describe("scan", () => {
  it("reports a clean chunk when the binary ran and found nothing", () => {
    fake(0);
    assert.deepEqual(scan("nothing to see here"), []);
  });

  it("throws when the binary fails instead of reporting a clean chunk", () => {
    fake(1);
    assert.throws(() => scan("AKIALALEMEL33243OLIB"), /gitleaks exited 1/);
  });

  it("throws when the binary is not installed", () => {
    process.env.RSP_GITLEAKS = "/nonexistent/gitleaks";
    assert.throws(() => scan("anything"), /ENOENT/);
  });

  it("throws when the binary dies before reading the chunk", () => {
    // gitleaks' fatal errors come before it reads stdin, so failure can surface
    // as a broken pipe instead of a status. Both must end the same way.
    process.env.RSP_GITLEAKS = "false";
    assert.throws(() => scan("anything"), /EPIPE|gitleaks exited 1/);
  });
});
