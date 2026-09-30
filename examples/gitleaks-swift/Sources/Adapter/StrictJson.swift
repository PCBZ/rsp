import Foundation

/// One message, refusing what a lenient parser would take (T4).
///
/// Measured rather than assumed: `JSONSerialization` already refuses NaN, a
/// leading zero, a lone surrogate and trailing characters. What it takes and
/// T4 does not is a repeated key, which it resolves to the first, an integer
/// above 2^53 − 1, and a byte order mark.
public enum StrictJson {
    /// The largest a JavaScript number carries exactly.
    public static let safeInteger = 9_007_199_254_740_991

    struct Refused: Error, CustomStringConvertible {
        let description: String
    }

    /// Decodes one message, or throws naming the leniency it relied on.
    ///
    /// Measured, not assumed, and the measurement is worse than a list of
    /// leniencies: `JSONDecoder` only validates the parts of the document it
    /// maps. `{"a":01}` is refused where `a` is declared and accepted where
    /// it is not, so how strict it is depends on the caller's struct — two
    /// Swift plugins reading one message can disagree. Everything T4 names is
    /// therefore read from the bytes here, including what the decoder would
    /// have caught on a field it happened to want.
    public static func decode<T: Decodable>(_ raw: [UInt8]) throws -> T {
        if raw.starts(with: [0xEF, 0xBB, 0xBF]) {
            throw Refused(description: "a byte order mark is not whitespace")
        }
        guard String(bytes: raw, encoding: .utf8) != nil else {
            throw Refused(description: "the request is not UTF-8")
        }
        try refuseRepeatedKeys(raw)
        try refuseNumberSyntax(raw)

        return try JSONDecoder().decode(T.self, from: Data(raw))
    }

    /// Read from the bytes, because the parser has resolved the repeat by the
    /// time anyone can ask. The delimiters are ASCII and a UTF-8 sequence
    /// cannot contain one, so no decoding is needed to find them — which is
    /// also why this does not go through UTF-16.
    ///
    /// Keys are unescaped before comparison: `\u0063ontent` and `content` are
    /// one key to every parser and two to anything comparing what was written.
    private static func refuseRepeatedKeys(_ raw: [UInt8]) throws {
        var seen: [Set<String>] = []
        var at = 0

        while at < raw.count {
            let byte = raw[at]
            if byte == quote {
                let (literal, next) = readString(raw, at)
                at = next
                var after = at
                while after < raw.count, isSpace(raw[after]) { after += 1 }
                if after < raw.count, raw[after] == colon, !seen.isEmpty {
                    let name = unescape(literal)
                    if seen[seen.count - 1].contains(name) {
                        throw Refused(description: "repeated key \"\(name)\"")
                    }
                    seen[seen.count - 1].insert(name)
                }
                continue
            }
            if byte == openBrace { seen.append([]) }
            if byte == closeBrace, !seen.isEmpty { seen.removeLast() }
            at += 1
        }
    }

    /// Outside strings only, or a chunk mentioning a long number is refused
    /// for what it says rather than for how the message is written.
    private static func refuseNumberSyntax(_ raw: [UInt8]) throws {
        var at = 0
        while at < raw.count {
            if raw[at] == quote {
                at = readString(raw, at).1
                continue
            }
            let starts = isDigit(raw[at]) || raw[at] == minus
            if starts, at == 0 || isBoundary(raw[at - 1]) {
                var end = raw[at] == minus ? at + 1 : at
                let first = end
                while end < raw.count, isDigit(raw[end]) { end += 1 }
                if end > first {
                    let digits = String(decoding: raw[first..<end], as: UTF8.self)
                    if digits.count > 1, digits.hasPrefix("0") {
                        throw Refused(description: "a number may not have a leading zero")
                    }
                    if end == raw.count || !isFractional(raw[end]) {
                        let whole = String(decoding: raw[at..<end], as: UTF8.self)
                        guard let value = Int(whole), abs(value) <= safeInteger else {
                            throw Refused(description: "\(whole) is outside ±(2^53 - 1)")
                        }
                    }
                    at = end
                    continue
                }
            }
            at += 1
        }
    }

    /// Where a string literal ends, skipping what a backslash protects.
    private static func readString(_ raw: [UInt8], _ start: Int) -> (String, Int) {
        var at = start + 1
        while at < raw.count, raw[at] != quote {
            at += raw[at] == backslash ? 2 : 1
        }
        let literal = String(decoding: raw[(start + 1)..<min(at, raw.count)], as: UTF8.self)
        return (literal, min(at + 1, raw.count))
    }

    private static func unescape(_ literal: String) -> String {
        let quoted = Data("\"\(literal)\"".utf8)
        if let value = try? JSONSerialization.jsonObject(
            with: quoted, options: [.fragmentsAllowed]) as? String {
            return value
        }
        return literal
    }

    private static let quote = UInt8(ascii: "\"")
    private static let colon = UInt8(ascii: ":")
    private static let comma = UInt8(ascii: ",")
    private static let openBrace = UInt8(ascii: "{")
    private static let closeBrace = UInt8(ascii: "}")
    private static let openBracket = UInt8(ascii: "[")
    private static let backslash = UInt8(ascii: "\\")
    private static let minus = UInt8(ascii: "-")

    private static func isSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
    }

    private static func isFractional(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: ".") || byte == UInt8(ascii: "e") || byte == UInt8(ascii: "E")
    }

    private static func isBoundary(_ byte: UInt8) -> Bool {
        isSpace(byte) || byte == colon || byte == comma || byte == openBracket
    }
}
