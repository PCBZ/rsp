// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "rsp-gitleaks-swift",
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
