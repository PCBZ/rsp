/**
 * What the adapter does when gitleaks does not answer.
 *
 * A gitleaks that cannot run prints nothing on stdout, and so does a gitleaks
 * that found nothing — the two are one byte apart in the report and a world
 * apart in meaning. These tests stand in a binary of their own to prove the
 * adapter tells them apart, and need no gitleaks to do it.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { scan } from "../src/gitleaks.ts";

const REAL = process.env.RSP_GITLEAKS;

afterEach(() => {
  if (REAL === undefined) delete process.env.RSP_GITLEAKS;
  else process.env.RSP_GITLEAKS = REAL;
});

describe("scan", () => {
  it("throws when the binary fails instead of reporting a clean chunk", () => {
    // `false` is the smallest available stand-in for a broken gitleaks: no
    // output, nonzero status. Returning [] here would be a silent ALLOW.
    process.env.RSP_GITLEAKS = "false";
    assert.throws(() => scan("AKIALALEMEL33243OLIB"), /gitleaks exited 1/);
  });

  it("throws when the binary is not installed", () => {
    process.env.RSP_GITLEAKS = "/nonexistent/gitleaks";
    assert.throws(() => scan("anything"), /ENOENT/);
  });

  it("reports a clean chunk when the binary succeeds and says nothing", () => {
    process.env.RSP_GITLEAKS = "true";
    assert.deepEqual(scan("anything"), []);
  });
});
