// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "rsp-gitleaks-swift",
    // Said here rather than inherited from whoever builds: without it SwiftPM
    // picks an older default, and the build succeeded on a laptop whose
    // toolchain defaulted higher while failing on the runner. v11 rather than
    // v10_15 because write(contentsOf:) arrived in 10.15.4 and this list has
    // no patch numbers.
    platforms: [.macOS(.v11)],
    targets: [
        // A library so the offset test can reach Spans and Finding without
        // the entry point coming with them.
        .target(name: "Adapter", path: "Sources/Adapter"),
        .executableTarget(name: "rsp-gitleaks-swift", dependencies: ["Adapter"],
                          path: "Sources/rsp-gitleaks-swift"),
        .executableTarget(name: "offset-test", dependencies: ["Adapter"],
                          path: "Sources/offset-test"),
    ]
)
