/**
 * One message, refusing what a lenient parser would take (T4).
 *
 * JSON.parse already refuses NaN, a leading zero and a byte order mark. What
 * it takes and T4 does not: a repeated key, an integer it silently rounds,
 * and a lone surrogate, which survives parsing and cannot be written back as
 * UTF-8.
 */

/** The largest a JavaScript number carries exactly. */
const SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/** Parses one message, or throws naming the leniency it relied on. */
export function parse(raw: string): unknown {
  refuseRepeatedKeys(raw);
  refuseBigIntegers(raw);
  const value: unknown = JSON.parse(raw);
  refuseUnsafe(value);
  return value;
}

/**
 * The reviver sees the last value for a repeated key and cannot know there
 * was another, so the text is what says.
 */
function refuseRepeatedKeys(raw: string): void {
  const seen: Array<Set<string>> = [];
  let at = 0;
  while (at < raw.length) {
    const character = raw[at];
    if (character === '"') {
      const [text, next] = readString(raw, at);
      at = next;
      if (seen.length > 0 && raw.slice(at).match(/^\s*:/)) {
        // Unescaped first: \u0063ontent and content are one key to every
        // parser, and two keys to anything comparing what was written.
        const name = JSON.parse(`"${text}"`) as string;
        const keys = seen[seen.length - 1]!;
        if (keys.has(name)) throw new Error(`repeated key ${JSON.stringify(name)}`);
        keys.add(name);
      }
      continue;
    }
    if (character === "{") seen.push(new Set());
    if (character === "}") seen.pop();
    at += 1;
  }
}

/** Where a string literal ends, skipping what a backslash protects. */
function readString(raw: string, start: number): [string, number] {
  let at = start + 1;
  while (at < raw.length && raw[at] !== '"') {
    at += raw[at] === "\\" ? 2 : 1;
  }
  return [raw.slice(start + 1, at), at + 1];
}

/** A lone surrogate parses and cannot be encoded, so it is not a message (M1). */
function refuseUnsafe(value: unknown): void {
  if (typeof value === "string") {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) {
      throw new Error("unpaired surrogate");
    }
  } else if (typeof value === "object" && value !== null) {
    Object.values(value).forEach(refuseUnsafe);
  }
}

/**
 * Read from the text, because by the time it is a number the digits are gone
 * — but only outside strings, or a chunk mentioning a long number is refused
 * for what it says rather than for how it is written.
 */
function refuseBigIntegers(raw: string): void {
  let at = 0;
  while (at < raw.length) {
    if (raw[at] === '"') {
      [, at] = readString(raw, at);
      continue;
    }
    const digits = /^-?\d+/.exec(raw.slice(at));
    if (digits && (at === 0 || ":,[ \t\n\r".includes(raw[at - 1]!))) {
      const [whole] = digits;
      const after = raw[at + whole.length];
      if (after !== "." && after !== "e" && after !== "E"
          && Math.abs(Number(whole)) > SAFE_INTEGER) {
        throw new Error(`${whole} is outside ±(2^53 - 1)`);
      }
      at += whole.length;
      continue;
    }
    at += 1;
  }
}
