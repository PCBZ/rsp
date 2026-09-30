import Foundation

/// Wraps the gitleaks binary, through its `stdin` command and its report.
public enum Gitleaks {
    /// Separates "found something" from gitleaks failing, which shares 1.
    public static let found: Int32 = 2

    struct Failed: Error, CustomStringConvertible {
        let description: String
    }

    public static func binary() -> String {
        let override = ProcessInfo.processInfo.environment["RSP_GITLEAKS"] ?? ""
        return override.isEmpty ? "gitleaks" : override
    }

    /// Runs the binary once, returning what it wrote and how it exited.
    ///
    /// stdin is written on a queue of its own. Foundation's `Process` pumps
    /// nothing, so sending the chunk and then reading the report would
    /// deadlock against a tool that fills its stdout pipe before draining
    /// stdin. stderr is inherited: a pipe nobody reads stops the tool once it
    /// fills, and diagnostics are not the protocol's anyway (T2, E3).
    public static func run(_ arguments: [String], _ input: [UInt8]) throws -> (report: String, status: Int32) {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        child.arguments = [binary()] + arguments
        let toChild = Pipe()
        let fromChild = Pipe()
        child.standardInput = toChild
        child.standardOutput = fromChild
        try child.run()

        DispatchQueue.global().async {
            // A tool that exits early closes this; its status says why.
            try? toChild.fileHandleForWriting.write(contentsOf: Data(input))
            try? toChild.fileHandleForWriting.close()
        }
        let out = fromChild.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()

        let report = String(decoding: out, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (report, child.terminationStatus)
    }

    /// Carried in the declaration so a cache key includes it (D4).
    public static func version() throws -> String {
        try accepted(run(["version"], [])).report
    }

    /// 0 or `found` and nothing else: an unknown status is a run we cannot read.
    private static func accepted(_ outcome: (report: String, status: Int32)) throws
        -> (report: String, status: Int32) {
        guard outcome.status == 0 || outcome.status == found else {
            throw Failed(description: "gitleaks exited with \(outcome.status)")
        }
        return outcome
    }

    /// The findings for one chunk.
    public static func scan(_ content: [UInt8]) throws -> [Finding] {
        // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
        // writability pre-check. --no-banner keeps stdout to the report alone.
        let outcome = try accepted(run(
            ["stdin", "--no-banner", "--report-format", "json",
             "--report-path", "-", "--exit-code", "2"], content))

        // Exit 0 with nothing written is a clean chunk. Exit 2 is gitleaks
        // saying it found something, so nothing written is a report that went
        // missing, and no findings is the ALLOW E1 refuses.
        if outcome.report.isEmpty {
            if outcome.status == found {
                throw Failed(description: "gitleaks reported findings and wrote no report")
            }
            return []
        }
        do {
            return try JSONDecoder().decode([Finding].self, from: Data(outcome.report.utf8))
        } catch {
            throw Failed(description: "gitleaks wrote a report that is not a list of findings")
        }
    }
}
