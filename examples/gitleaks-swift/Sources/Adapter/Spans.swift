import Foundation

/// Line-and-column positions from a gitleaks report, as byte offsets (S1).
///
/// Everything here takes `[UInt8]`. A Swift `String` cannot be indexed by an
/// integer at all — the compiler refuses it — so the mistake the other six
/// adapters keep by hand is not available to make. Reaching the bytes is
/// saying `content.utf8`, and that is the only way in.
public enum Spans {
    /// The spans for one report, or nil if any finding could not be placed.
    ///
    /// gitleaks counts a line's columns from the newline byte that ended the
    /// previous line, so only line one matches the 1-based column anyone
    /// assumes. EndColumn belongs to EndLine, which differs whenever a
    /// finding spans lines. Anything that does not slice Match back out is
    /// refused, and the caller turns that into a BLOCK.
    public static func of(_ findings: [Finding], _ content: [UInt8]) -> [Span]? {
        let starts = lineStarts(content)
        var spans: [Span] = []

        for finding in findings {
            guard let from = origin(starts, finding.startLine),
                  let to = origin(starts, finding.endLine)
            else { return nil }

            let start = from + finding.startColumn - 1
            let end = to + finding.endColumn
            let match = Array(finding.match.utf8)

            guard usable(start, end, content),
                  end - start == match.count,
                  Array(content[start..<end]) == match
            else { return nil }

            spans.append(Span(start: start, end: end, type: finding.ruleID))
        }
        return spans
    }

    /// In range, non-empty, and on a character boundary at both ends (S3).
    public static func usable(_ start: Int, _ end: Int, _ content: [UInt8]) -> Bool {
        guard start >= 0, end > start, end <= content.count else { return false }
        for at in [start, end] where at != 0 && at != content.count {
            // A continuation byte is 0b10xxxxxx; a boundary is anything else.
            if content[at] & 0xC0 == 0x80 { return false }
        }
        return true
    }

    /// The byte gitleaks counts this line's columns from.
    private static func origin(_ starts: [Int], _ line: Int) -> Int? {
        if line == 1 { return 0 }
        guard line > 1, line <= starts.count else { return nil }
        return starts[line - 1] - 1
    }

    private static func lineStarts(_ content: [UInt8]) -> [Int] {
        var starts = [0]
        for (at, byte) in content.enumerated() where byte == UInt8(ascii: "\n") {
            starts.append(at + 1)
        }
        return starts
    }
}
