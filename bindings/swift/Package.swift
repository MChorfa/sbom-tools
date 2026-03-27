// swift-tools-version: 5.10

import PackageDescription
import Foundation

private let packageRootURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

private func existingSearchPaths() -> [String] {
    let candidates = [
        "../../target/aarch64-apple-darwin/release",
        "../../target/x86_64-apple-darwin/release",
        "../../target/aarch64-unknown-linux-gnu/release",
        "../../target/x86_64-unknown-linux-gnu/release",
        "../../target/release",
        "../../target/aarch64-apple-darwin/debug",
        "../../target/x86_64-apple-darwin/debug",
        "../../target/aarch64-unknown-linux-gnu/debug",
        "../../target/x86_64-unknown-linux-gnu/debug",
        "../../target/debug",
    ]

    let fileManager = FileManager.default
    return candidates.compactMap { relativePath in
        let absolute = packageRootURL.appendingPathComponent(relativePath).standardizedFileURL.path
        return fileManager.fileExists(atPath: absolute) ? absolute : nil
    }
}

private func linkerSettings() -> [LinkerSetting] {
    let searchPathFlags = existingSearchPaths().flatMap { ["-L", $0] }
    var settings: [LinkerSetting] = []
    if !searchPathFlags.isEmpty {
        settings.append(.unsafeFlags(searchPathFlags))
    }
    settings.append(.linkedLibrary("sbom_tools_ffi"))
    return settings
}

let package = Package(
    name: "SbomTools",
    products: [
        .library(name: "SbomTools", targets: ["SbomTools"]),
    ],
    targets: [
        .systemLibrary(
            name: "CSbomTools",
            path: "Sources/CSbomTools"
        ),
        .target(
            name: "SbomTools",
            dependencies: ["CSbomTools"],
            linkerSettings: linkerSettings()
        ),
        .testTarget(
            name: "SbomToolsTests",
            dependencies: ["SbomTools"]
        ),
    ]
)