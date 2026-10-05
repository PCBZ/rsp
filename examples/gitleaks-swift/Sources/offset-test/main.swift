import Adapter
import Foundation

/// Line-and-column to byte offsets. No binary needed: a report is data.
///
/// The table is examples/gitleaks-offsets.json, shared with the other six
/// adapters, because the numbers in it are facts about gitleaks rather than
/// about any of them. What stays here is what this language makes possible.
var failures = 0

func check(_ held: Bool, _ what: String) {
    if !held {
        FileHandle.standardError.write(Data("FAIL \(what)\n".utf8))
        failures += 1
    }
}

struct Case: Decodable {
    let comment: String
    let content: String
    let findings: [Finding]
    let spans: [Span]
}

struct Table: Decodable {
    let tests: [Case]
}

func theSharedTable() throws {
    let path = URL(fileURLWithPath: "../gitleaks-offsets.json")
    let table = try JSONDecoder().decode(Table.self, from: Data(contentsOf: path))
    // A path that resolved to nothing would leave this loop empty and green.
    check(table.tests.count >= 13, "the table did not lose cases")

    for test in table.tests {
        let content = Array(test.content.utf8)
        let produced = Spans.of(test.findings, content)
        if test.spans.isEmpty && !test.findings.isEmpty {
            check(produced == nil, test.comment)
        } else {
            let got = produced ?? []
            check(got == test.spans, test.comment)
        }
    }
}

func offsetsAreBytesAndOnlyBytes() {
    // 23 grapheme clusters, 27 bytes. The other six adapters each say in
    // their README that the content is encoded once; here the compiler says
    // it — `content[7..<27]` does not build, so `content.utf8` is the only
    // road to a byte. A fourth string model, and the one nobody can misuse.
    let content = "密钥 AKIALALEMEL33243OLIB"
    let bytes = Array(content.utf8)

    check(content.count == 23, "count is grapheme clusters")
    check(bytes.count == 27, "and the span is measured in bytes")
    check(Spans.usable(7, 27, bytes), "the key starts at byte seven")
    check(String(decoding: bytes[7..<27], as: UTF8.self) == "AKIALALEMEL33243OLIB",
          "and those bytes are it")
}

func spansTheHostWouldReject() {
    let content = Array("密钥 AKIALALEMEL33243OLIB".utf8)

    check(!Spans.usable(1, 3, content), "offsets inside a character are refused")
    check(!Spans.usable(0, 0, content), "an empty span is refused")
    check(!Spans.usable(-1, 5, content), "a negative start is refused")
    check(!Spans.usable(7, 400, content), "an end past the content is refused")
    check(Spans.usable(7, 27, content), "the key itself is usable")
}

do {
    try theSharedTable()
    offsetsAreBytesAndOnlyBytes()
    spansTheHostWouldReject()
} catch {
    FileHandle.standardError.write(Data("FAIL loading the table: \(error)\n".utf8))
    failures += 1
}

if failures > 0 {
    FileHandle.standardError.write(Data("\(failures) failed\n".utf8))
    exit(1)
}
print("ok")
