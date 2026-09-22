/**
 * What the adapter does when gitleaks does not answer.
 *
 * A gitleaks that could not run prints nothing on stdout, and so does a
 * gitleaks that found nothing — one byte apart in the report, a world apart in
 * meaning. These tests prove the adapter tells them apart, and need no gitleaks
 * to do it: a shell script stands in, exiting with whichever status is under
 * test after draining the chunk the way a real scan would.
 */
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
    // Returning [] here would be a silent ALLOW for content nobody scanned.
    fake(1);
    assert.throws(() => scan("AKIALALEMEL33243OLIB"), /gitleaks exited 1/);
  });

  it("throws when the binary is not installed", () => {
    process.env.RSP_GITLEAKS = "/nonexistent/gitleaks";
    assert.throws(() => scan("anything"), /ENOENT/);
  });

  it("throws when the binary dies before reading the chunk", () => {
    // gitleaks' own fatal errors happen before it reads stdin — an unwritable
    // report path is one — so the failure can surface as a broken pipe on the
    // write instead of as a status. Both must end the same way.
    process.env.RSP_GITLEAKS = "false";
    assert.throws(() => scan("anything"), /EPIPE|gitleaks exited 1/);
  });
});
