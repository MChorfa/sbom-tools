import Foundation
import Testing
@testable import SbomTools

private func fixtureURL(_ name: String) -> URL {
    let fileURL = URL(fileURLWithPath: #filePath)
    let repoRoot = fileURL
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    return repoRoot.appending(path: "tests/fixtures/\(name)")
}

@Test func versionAndFormatDetectionWork() throws {
    let version = try SbomTools.version()
    #expect(!version.abiVersion.isEmpty)
    #expect(!version.crateVersion.isEmpty)

    let content = try String(contentsOf: fixtureURL("cyclonedx/minimal.cdx.json"), encoding: .utf8)
    let detected = try SbomTools.detectFormat(content)
    #expect(detected?.formatName == "CycloneDX")
}

@Test func parseDiffAndScoreWork() throws {
    let oldJSON = try SbomTools.parsePathJSON(fixtureURL("demo-old.cdx.json").path())
    let newJSON = try SbomTools.parsePathJSON(fixtureURL("demo-new.cdx.json").path())

    let diffJSON = try SbomTools.diffJSON(old: oldJSON, new: newJSON)
    let diffObject = try JSONSerialization.jsonObject(with: Data(diffJSON.utf8)) as? [String: Any]
    let summary = diffObject?["summary"] as? [String: Any]
    let totalChanges = summary?["total_changes"] as? Double
    #expect((totalChanges ?? 0) > 0)

    let scoreJSON = try SbomTools.scoreJSON(newJSON)
    let scoreObject = try JSONSerialization.jsonObject(with: Data(scoreJSON.utf8)) as? [String: Any]
    let overallScore = scoreObject?["overall_score"] as? Double
    #expect((overallScore ?? 0) > 0)
}

@Test func typedHelpersWork() throws {
    let oldPayload = try SbomTools.parsePath(fixtureURL("demo-old.cdx.json").path())
    let newPayload = try SbomTools.parsePath(fixtureURL("demo-new.cdx.json").path())

    let diff = try SbomTools.diff(old: oldPayload, new: newPayload)
    #expect(diff.summary.totalChanges > 0)

    let quality = try SbomTools.score(newPayload)
    #expect(quality.overallScore > 0)
}

@Test func invalidDiffInputFails() throws {
    do {
        _ = try SbomTools.diffJSON(old: "{not-json}", new: "{not-json}")
        Issue.record("Expected invalid normalized JSON to fail")
    } catch let error as SbomToolsError {
        #expect(error.code == 3)
        #expect(error.message.contains("invalid normalized SBOM JSON"))
    }
}

@Test func deduplicateInPlaceLastWins() throws {
    var payload = makeDedupFixturePayload()
    let originalComponentCount = payload.components.count
    let originalEdgeCount = payload.edges.count

    let removed = payload.deduplicateInPlace()

    #expect(removed.componentsRemoved == 1)
    #expect(removed.edgesRemoved == 1)
    #expect(payload.components.count == originalComponentCount - removed.componentsRemoved)
    #expect(payload.edges.count == originalEdgeCount - removed.edgesRemoved)
}

@Test func deduplicatedDoesNotMutateOriginal() throws {
    let payload = makeDedupFixturePayload()

    let originalComponentCount = payload.components.count
    let originalEdgeCount = payload.edges.count

    let result = payload.deduplicated()

    #expect(payload.components.count == originalComponentCount)
    #expect(payload.edges.count == originalEdgeCount)
    #expect(result.componentsRemoved == 1)
    #expect(result.edgesRemoved == 1)
    #expect(result.payload.components.count == originalComponentCount - 1)
    #expect(result.payload.edges.count == originalEdgeCount - 1)
}

@Test func dedupAwareDiffAndScoreHelpersWork() throws {
    var payload = try SbomTools.parsePath(fixtureURL("demo-old.cdx.json").path())
    #expect(!payload.components.isEmpty)

    payload.components.append(payload.components[0])

    if !payload.edges.isEmpty {
        payload.edges.append(payload.edges[0])
    } else {
        let edge: [String: JSONValue] = [
            "from": .object(payload.components[0].canonicalID),
            "to": .object(payload.components[0].canonicalID),
            "relationship": .string("DependsOn"),
            "scope": .null,
        ]
        payload.edges.append(edge)
        payload.edges.append(edge)
    }

    let diffResult = try SbomTools.diffDeduplicated(old: payload, new: payload)
    #expect(diffResult.result.summary.totalChanges == 0)
    #expect(diffResult.oldStats.componentsRemoved >= 1)
    #expect(diffResult.oldStats.edgesRemoved >= 1)
    #expect(diffResult.newStats.componentsRemoved >= 1)
    #expect(diffResult.newStats.edgesRemoved >= 1)

    let scoreResult = try SbomTools.scoreDeduplicated(payload)
    #expect(scoreResult.result.overallScore >= 0)
    #expect(scoreResult.stats.componentsRemoved >= 1)
    #expect(scoreResult.stats.edgesRemoved >= 1)
}

private func makeDedupFixturePayload() -> NormalizedSbomPayload {
    let duplicateCanonicalID: [String: JSONValue] = [
        "value": .string("pkg:npm/left-pad@1.3.0"),
        "source": .string("Purl"),
        "stable": .bool(true),
    ]
    let uniqueCanonicalID: [String: JSONValue] = [
        "value": .string("pkg:npm/unique-lib@2.0.0"),
        "source": .string("Purl"),
        "stable": .bool(true),
    ]

    let componentA = NormalizedSbomComponentEntry(
        canonicalID: duplicateCanonicalID,
        component: [
            "canonical_id": .object(duplicateCanonicalID),
            "name": .string("left-pad"),
        ]
    )
    let componentB = NormalizedSbomComponentEntry(
        canonicalID: duplicateCanonicalID,
        component: [
            "canonical_id": .object(duplicateCanonicalID),
            "name": .string("left-pad-new"),
        ]
    )
    let componentC = NormalizedSbomComponentEntry(
        canonicalID: uniqueCanonicalID,
        component: [
            "canonical_id": .object(uniqueCanonicalID),
            "name": .string("unique-lib"),
        ]
    )

    let duplicateEdge: [String: JSONValue] = [
        "from": .object(duplicateCanonicalID),
        "to": .object(uniqueCanonicalID),
        "relationship": .string("DependsOn"),
        "scope": .null,
    ]
    let uniqueEdge: [String: JSONValue] = [
        "from": .object(uniqueCanonicalID),
        "to": .object(duplicateCanonicalID),
        "relationship": .string("DependsOn"),
        "scope": .null,
    ]

    return NormalizedSbomPayload(
        document: [
            "format": .string("CycloneDx"),
            "format_version": .string("1.6"),
            "spec_version": .string("1.6"),
            "serial_number": .null,
            "created": .string("2026-01-01T00:00:00Z"),
            "creators": .array([]),
            "name": .null,
            "security_contact": .null,
            "vulnerability_disclosure_url": .null,
            "support_end_date": .null,
            "lifecycle_phase": .null,
            "completeness_declaration": .string("Unknown"),
            "signature": .null,
            "distribution_classification": .null,
            "citations_count": .unsignedInteger(0),
            "version": .string("1.6"),
        ],
        components: [componentA, componentB, componentC],
        edges: [duplicateEdge, duplicateEdge, uniqueEdge],
        extensions: [:],
        contentHash: 0,
        primaryComponentID: duplicateCanonicalID,
        collisionCount: 0
    )
}