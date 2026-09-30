import Adapter
import Foundation

/// One JSON object in, one out, then exit (T1).
///
/// Diagnostics go to stderr: a stray line on stdout is indistinguishable from
/// a response (T2). Any failure exits non-zero having written nothing to
/// stdout, which is how a plugin says it could not judge the chunk (E1, D3).
func answer() throws {
    let raw = Array(FileHandle.standardInput.readDataToEndOfFile())
    let request: Request = try StrictJson.decode(raw)

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let out = try encoder.encode(try Handler.respond(request))

    FileHandle.standardOutput.write(out)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

do {
    try answer()
} catch {
    FileHandle.standardError.write(Data("rsp-gitleaks-swift: \(error)\n".utf8))
    exit(1)
}
