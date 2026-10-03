import Foundation

/// The part of a gitleaks report a chunk can have.
///
/// Every field defaults, so a finding that arrives without a position is a
/// finding at line zero rather than a decode failure — the difference between
/// a BLOCK and a crash.
public struct Finding: Decodable {
    public var ruleID: String
    public var startLine: Int
    public var endLine: Int
    public var startColumn: Int
    public var endColumn: Int
    public var match: String

    enum CodingKeys: String, CodingKey {
        case ruleID = "RuleID"
        case startLine = "StartLine"
        case endLine = "EndLine"
        case startColumn = "StartColumn"
        case endColumn = "EndColumn"
        case match = "Match"
    }

    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        ruleID = try fields.decodeIfPresent(String.self, forKey: .ruleID) ?? ""
        startLine = try fields.decodeIfPresent(Int.self, forKey: .startLine) ?? 0
        endLine = try fields.decodeIfPresent(Int.self, forKey: .endLine) ?? 0
        startColumn = try fields.decodeIfPresent(Int.self, forKey: .startColumn) ?? 0
        endColumn = try fields.decodeIfPresent(Int.self, forKey: .endColumn) ?? 0
        match = try fields.decodeIfPresent(String.self, forKey: .match) ?? ""
    }
}
