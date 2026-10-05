import Foundation

/// The shape SPEC.md requires, in one file, for whoever ports this again.
///
/// Typed rather than a dictionary of `Any`: `Codable` is how Swift reads JSON,
/// the way struct tags are in Go and derive is in Rust.
public struct Request: Decodable {
    public let hook: String?
    public let content: String?

    /// `metadata` is absent on purpose. It is advisory and this plugin does
    /// not read it (M2), and `Codable` ignores an undeclared key without
    /// asking, which is D8. Declaring it would turn a field nobody reads into
    /// a shape the message must have: the host sends `source: null` and
    /// `score: 0.5`, and a `[String: String]` refuses both — so the request
    /// failed to decode, the plugin exited, and the host blocked a chunk over
    /// a field it had marked optional.
}

public struct Span: Codable, Equatable {
    public let start: Int
    public let end: Int
    public let type: String
}

/// One response for every verdict, so absent fields are absent rather than
/// empty: ALLOW carries nothing else (V2).
public struct Response: Encodable {
    public let verdict: String
    public var spans: [Span]?
    public var replacement: String?
    public var reason: String?
    public var severity: String?
}

/// What this plugin says it is (H2).
public struct Declaration: Encodable {
    public let rspVersion: String
    public let name: String
    public let version: String
    public let hooks: [String]
    public let deterministic: Bool

    enum CodingKeys: String, CodingKey {
        case rspVersion = "rsp_version"
        case name, version, hooks, deterministic
    }
}

public enum Answer: Encodable {
    case verdict(Response)
    case declaration(Declaration)

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .verdict(let response): try response.encode(to: encoder)
        case .declaration(let declaration): try declaration.encode(to: encoder)
        }
    }
}

public enum Handler {
    public static let replacement = "[REDACTED:secret]"

    public static func respond(_ request: Request) throws -> Answer {
        if request.hook == "handshake" {
            return .declaration(Declaration(
                rspVersion: "0.1",
                name: "rsp-gitleaks-swift",
                // The version carries the binary's: for a wrapper it is the
                // tool that decides verdicts, and the cache is keyed on it (D4).
                version: "0.1.0+\(try Gitleaks.version())",
                hooks: ["on_chunk", "on_retrieve"],
                deterministic: true))
        }
        // Encoded once, and the only way to a byte: an Int cannot index a
        // String, so the offsets below can only be offsets into these.
        let content = Array((request.content ?? "").utf8)

        let findings = try Gitleaks.scan(content)
        if findings.isEmpty {
            return .verdict(Response(verdict: "ALLOW"))
        }
        // A finding with no span is a secret we cannot point at; redacting
        // the rest would leave it in the chunk (V4).
        guard let spans = Spans.of(findings, content) else {
            return .verdict(Response(
                verdict: "BLOCK",
                reason: "gitleaks reported a finding whose position could not be confirmed",
                severity: "critical"))
        }
        return .verdict(Response(
            verdict: "REDACT",
            spans: spans,
            replacement: replacement,
            severity: "critical"))
    }
}
