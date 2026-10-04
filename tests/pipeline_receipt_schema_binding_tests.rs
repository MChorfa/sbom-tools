//! Bind the published JSON Schemas to the Rust validators.
//!
//! The schemas under schemas/ are the versioned public contract; the serde
//! structs and hand-rolled validators are the enforcement. Nothing else keeps
//! them aligned, so these tests fail on any one-sided edit: a schema pattern
//! the code does not enforce, a field the code requires but the schema
//! doesn't (or vice versa), or a fixture that drifts from both.

use regex::Regex;
use sbom_tools::verification::*;
use serde_json::Value;
use std::collections::BTreeMap;

fn schema_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::new(format!(
        "sha256:{}",
        char::from(byte).to_string().repeat(64)
    ))
    .unwrap()
}

fn receipt() -> PipelineShardReceipt {
    PipelineShardReceipt {
        schema: PIPELINE_SHARD_RECEIPT_SCHEMA.into(),
        repository: "org/repo".into(),
        workflow: "ci".into(),
        run_id: None,
        commit_sha: "a".repeat(40),
        source_fingerprint: digest(b'a'),
        trust_context: TrustContext::ProtectedMain,
        promotable: false,
        target: TargetIdentity {
            verification_scope: "unit".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            toolchain: "stable".into(),
            profile: "release".into(),
            features: vec![],
            binding_runtime: None,
        },
        lock_digest: digest(b'b'),
        versions: BTreeMap::new(),
        checks: vec![VerificationCheck {
            name: "build".into(),
            outcome: CheckOutcome::Passed,
            passed: 1,
            failed: 0,
            ignored: 0,
        }],
        artifacts: vec![],
        dagger_trace: None,
        started_at: "2026-01-01T00:00:00Z".into(),
        completed_at: "2026-01-01T00:01:00Z".into(),
        failure_classification: None,
    }
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

fn schema_string_list(value: &Value) -> Vec<String> {
    let mut list: Vec<String> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    list.sort();
    list
}

#[test]
fn verification_scope_validator_agrees_with_schema_pattern() {
    let schema = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let pattern = schema["$defs"]["target"]["properties"]["verification_scope"]["pattern"]
        .as_str()
        .unwrap();
    let regex = Regex::new(pattern).unwrap();
    // Corpus covering both sides of every historical divergence: dot-only,
    // leading-punctuation, and structural (slash/empty/traversal) cases.
    let corpus = [
        "ok",
        "a/b",
        "A1/b.c-d_e",
        "rust-lint",
        "x.y",
        "9start",
        "x.",
        "a/b/c",
        "...",
        "-x",
        ".hidden",
        "_x",
        "ok/.hidden",
        "a//b",
        "/a",
        "a/",
        "a b",
        "a\\b",
        "a/./b",
        "a/../b",
        ".",
        "..",
        "",
        "é",
        "a/é",
    ];
    for scope in corpus {
        let schema_accepts = regex.is_match(scope);
        let mut r = receipt();
        r.target.verification_scope = scope.into();
        let code_accepts = validate_receipt(&r).is_ok();
        assert_eq!(
            schema_accepts, code_accepts,
            "scope {scope:?}: schema={schema_accepts} code={code_accepts}"
        );
    }
}

#[test]
fn receipt_fields_match_schema_properties_and_required() {
    let schema = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let serialized = serde_json::to_value(receipt()).unwrap();
    // Every serialized field is a schema property, and vice versa.
    assert_eq!(keys(&serialized), keys(&schema["properties"]));
    // The receipt schema requires every property, nullable ones included.
    assert_eq!(
        schema_string_list(&schema["required"]),
        keys(&schema["properties"])
    );
    // Nullable-but-required semantics: deleting any key must fail
    // deserialization, null for the nullable ones must succeed.
    for key in keys(&serialized) {
        let mut pruned = serialized.clone();
        pruned.as_object_mut().unwrap().remove(&key);
        assert!(
            serde_json::from_value::<PipelineShardReceipt>(pruned).is_err(),
            "receipt deserialized without required key {key}"
        );
    }
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/pipeline-shard-receipt-v1.json")).unwrap();
    assert_eq!(keys(&fixture), keys(&schema["properties"]));
}

#[test]
fn generator_input_required_list_matches_struct_strictness() {
    let schema = schema_json("schemas/pipeline-shard-receipt/input-v1.schema.json");
    // The input schema also requires its nullable keys; the struct enforces
    // presence via require_nullable, so removing any required key must fail.
    let descriptor = serde_json::json!({
        "schema": PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA,
        "repository": "org/repo",
        "workflow": "ci",
        "commit_sha": "a".repeat(40),
        "source_root": "src-root",
        "lock_paths": ["Cargo.lock"],
        "artifact_root": "artifact-root",
        "artifacts": [],
        "target": serde_json::to_value(receipt().target).unwrap(),
        "versions": {},
        "checks": serde_json::to_value(receipt().checks).unwrap(),
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:01:00Z",
        "run_id": null,
        "dagger_trace": null,
        "failure_classification": null,
        "hosted": null,
        "local": true,
    });
    assert!(serde_json::from_value::<ReceiptGenerationInput>(descriptor.clone()).is_ok());
    assert_eq!(keys(&descriptor), keys(&schema["properties"]));
    for key in schema_string_list(&schema["required"]) {
        let mut pruned = descriptor.clone();
        pruned.as_object_mut().unwrap().remove(&key);
        assert!(
            serde_json::from_value::<ReceiptGenerationInput>(pruned).is_err(),
            "generator input deserialized without required key {key}"
        );
    }
}

#[test]
fn aggregate_policy_matches_published_schema() {
    let schema = schema_json("schemas/aggregate-policy/v1.schema.json");
    let policy = AggregatePolicy {
        schema: AGGREGATE_POLICY_SCHEMA.into(),
        expected_targets: vec![receipt().target],
        context: ExpectedContext {
            repository: "org/repo".into(),
            workflow: "ci".into(),
            commit_sha: "a".repeat(40),
            trust_context: TrustContext::ProtectedMain,
            promotable: false,
            source_fingerprint: digest(b'a'),
            lock_digest: digest(b'b'),
        },
        required_checks: vec!["build".into()],
        artifacts: vec![],
    };
    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(keys(&serialized), keys(&schema["properties"]));
    assert_eq!(
        schema_string_list(&schema["required"]),
        keys(&schema["properties"])
    );
    assert_eq!(
        keys(&serialized["context"]),
        keys(&schema["$defs"]["context"]["properties"])
    );
    // A policy asserting a different schema id is a gate verdict.
    let mut wrong = policy;
    wrong.schema = "aggregate-policy/v0".into();
    assert!(
        aggregate_receipts(&[], &wrong).is_err(),
        "policy with wrong schema id accepted"
    );
}

#[test]
fn target_schema_is_shared_across_all_public_documents() {
    let receipt = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    for path in [
        "schemas/pipeline-shard-receipt/input-v1.schema.json",
        "schemas/aggregate-policy/v1.schema.json",
    ] {
        assert_eq!(
            receipt["$defs"]["target"],
            schema_json(path)["$defs"]["target"],
            "{path}"
        );
    }
    assert_eq!(
        receipt["$defs"]["target"]["properties"]["features"]["uniqueItems"],
        true
    );
    assert_eq!(
        receipt["$defs"]["target"]["properties"]["features"]["items"]["minLength"],
        1
    );
}

// ---------------------------------------------------------------------------
// Recursive binding: every object, constraint, and enum in each schema.
//
// The walker resolves `$ref`s and visits every object node reachable from the
// schema root alongside the matching node of a fully populated sample
// document. For each node it requires the sample's keys to equal the schema's
// properties, every property to be required, and `additionalProperties:
// false`; then it mutates the sample at that pointer and requires the Rust
// side to reject each mutation: an unknown key, each missing key, an empty
// `minLength` string, an empty `minItems` array, a negative integer, a
// violated `const`, and an unlisted `enum` value. A one-sided edit to either
// the schema or the structs/validators fails here.
// ---------------------------------------------------------------------------

fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    match node.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let pointer = reference.strip_prefix('#').expect("local $ref");
            resolve(root, root.pointer(pointer).expect("dangling $ref"))
        }
        None => node,
    }
}

fn has_type(node: &Value, wanted: &str) -> bool {
    match &node["type"] {
        Value::String(t) => t == wanted,
        Value::Array(types) => types.iter().any(|t| t == wanted),
        _ => false,
    }
}

fn mutated(top: &Value, pointer: &str, edit: impl FnOnce(&mut Value)) -> Value {
    let mut copy = top.clone();
    edit(copy.pointer_mut(pointer).expect("sample pointer"));
    copy
}

struct Binding<'a> {
    schema: &'a Value,
    top: &'a Value,
    accepts: &'a dyn Fn(Value) -> bool,
    objects: Vec<String>,
}

impl Binding<'_> {
    fn reject(&self, pointer: &str, what: &str, document: Value) {
        assert!(
            !(self.accepts)(document),
            "{pointer}: Rust accepted a document the schema rejects ({what})"
        );
    }

    fn walk(&mut self, node: &Value, pointer: &str) {
        let node = resolve(self.schema, node);
        let sample = self.top.pointer(pointer).expect("sample pointer").clone();
        if let Some(constant) = node.get("const") {
            assert_eq!(&sample, constant, "{pointer}: sample violates const");
            let other = match constant {
                Value::Bool(b) => Value::Bool(!b),
                _ => Value::String("not-the-const".into()),
            };
            self.reject(pointer, "const", mutated(self.top, pointer, |v| *v = other));
        }
        if let Some(choices) = node.get("enum").and_then(Value::as_array) {
            assert!(choices.contains(&sample), "{pointer}: sample not in enum");
            self.reject(
                pointer,
                "enum",
                mutated(self.top, pointer, |v| *v = "not-an-enum-value".into()),
            );
        }
        if sample.is_string() && node["minLength"] == 1 {
            self.reject(
                pointer,
                "minLength",
                mutated(self.top, pointer, |v| *v = "".into()),
            );
        }
        if sample.is_u64() && node["minimum"] == 0 {
            self.reject(
                pointer,
                "minimum",
                mutated(self.top, pointer, |v| *v = (-1).into()),
            );
        }
        if let Some(items) = sample.as_array() {
            if node["minItems"] == 1 {
                self.reject(
                    pointer,
                    "minItems",
                    mutated(self.top, pointer, |v| *v = Value::Array(vec![])),
                );
            }
            if let Some(item_schema) = node.get("items") {
                if resolve(self.schema, item_schema)
                    .get("properties")
                    .is_some()
                {
                    assert!(
                        !items.is_empty(),
                        "{pointer}: populate the sample array to bind its items"
                    );
                }
                if !items.is_empty() {
                    self.walk(item_schema, &format!("{pointer}/0"));
                }
            }
        }
        if let (Some(properties), Some(object)) = (node.get("properties"), sample.as_object()) {
            assert!(
                has_type(node, "object"),
                "{pointer}: properties on a non-object"
            );
            self.objects.push(pointer.to_string());
            let mut sample_keys: Vec<_> = object.keys().cloned().collect();
            sample_keys.sort();
            assert_eq!(
                sample_keys,
                keys(properties),
                "{pointer}: sample keys vs schema properties"
            );
            assert_eq!(
                schema_string_list(&node["required"]),
                keys(properties),
                "{pointer}: every property must be required"
            );
            assert_eq!(
                node["additionalProperties"], false,
                "{pointer}: additionalProperties"
            );
            self.reject(
                pointer,
                "additionalProperties",
                mutated(self.top, pointer, |v| {
                    v.as_object_mut()
                        .unwrap()
                        .insert("unbound_extra".into(), Value::Bool(true));
                }),
            );
            for key in &sample_keys {
                self.reject(
                    pointer,
                    &format!("required {key}"),
                    mutated(self.top, pointer, |v| {
                        v.as_object_mut().unwrap().remove(key);
                    }),
                );
                self.walk(&properties[key], &format!("{pointer}/{key}"));
            }
        }
    }
}

fn bind(schema_path: &str, top: &Value, accepts: &dyn Fn(Value) -> bool) -> Vec<String> {
    let schema = schema_json(schema_path);
    assert!(
        accepts(top.clone()),
        "{schema_path}: baseline sample must be accepted"
    );
    let mut binding = Binding {
        schema: &schema,
        top,
        accepts,
        objects: Vec::new(),
    };
    binding.walk(&schema, "");
    binding.objects.sort();
    binding.objects
}

fn populated_receipt() -> PipelineShardReceipt {
    let mut r = receipt();
    r.target.features = vec!["ffi".into()];
    r.target.binding_runtime = Some("python-3.12".into());
    r.versions = BTreeMap::from([("rust".into(), "1.88".into())]);
    r.artifacts = vec![ReceiptArtifact {
        name: "report".into(),
        path: "out/report.json".into(),
        size: 6,
        sha256: digest(b'c'),
    }];
    r
}

#[test]
fn receipt_schema_binds_every_nested_object_and_constraint() {
    let top = serde_json::to_value(populated_receipt()).unwrap();
    let accepts = |v: Value| {
        serde_json::from_value::<PipelineShardReceipt>(v)
            .is_ok_and(|r| validate_receipt(&r).is_ok())
    };
    let objects = bind(
        "schemas/pipeline-shard-receipt/v1.schema.json",
        &top,
        &accepts,
    );
    assert_eq!(objects, ["", "/artifacts/0", "/checks/0", "/target"]);
}

#[test]
fn aggregate_policy_schema_binds_every_nested_object_and_constraint() {
    let receipt = populated_receipt();
    let policy = AggregatePolicy {
        schema: AGGREGATE_POLICY_SCHEMA.into(),
        expected_targets: vec![receipt.target.clone()],
        context: ExpectedContext {
            repository: receipt.repository.clone(),
            workflow: receipt.workflow.clone(),
            commit_sha: receipt.commit_sha.clone(),
            trust_context: receipt.trust_context,
            promotable: false,
            source_fingerprint: receipt.source_fingerprint.clone(),
            lock_digest: receipt.lock_digest.clone(),
        },
        required_checks: vec!["build".into()],
        artifacts: receipt
            .artifacts
            .iter()
            .map(|a| TrustedArtifact {
                name: a.name.clone(),
                path: a.path.clone(),
                size: a.size,
                sha256: a.sha256.clone(),
            })
            .collect(),
    };
    let top = serde_json::to_value(&policy).unwrap();
    let accepts = |v: Value| {
        serde_json::from_value::<AggregatePolicy>(v)
            .is_ok_and(|p| aggregate_receipts(std::slice::from_ref(&receipt), &p).is_ok())
    };
    let objects = bind("schemas/aggregate-policy/v1.schema.json", &top, &accepts);
    assert_eq!(
        objects,
        ["", "/artifacts/0", "/context", "/expected_targets/0"]
    );
}

#[test]
fn generator_input_schema_binds_every_nested_object_and_constraint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Cargo.lock"), b"lock").unwrap();
    std::fs::create_dir(dir.path().join("artifacts")).unwrap();
    std::fs::write(dir.path().join("artifacts/report.json"), b"report").unwrap();
    let sha = "a".repeat(40);
    let top = serde_json::json!({
        "schema": PIPELINE_SHARD_RECEIPT_INPUT_SCHEMA,
        "repository": "org/repo",
        "workflow": "ci",
        "commit_sha": sha,
        "source_root": dir.path(),
        "lock_paths": ["Cargo.lock"],
        "artifact_root": dir.path().join("artifacts"),
        "artifacts": [{"name": "report", "path": "report.json"}],
        "target": serde_json::to_value(populated_receipt().target).unwrap(),
        "versions": {"rust": "1.88"},
        "checks": serde_json::to_value(receipt().checks).unwrap(),
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:01:00Z",
        "run_id": "123",
        "dagger_trace": null,
        "failure_classification": null,
        "hosted": {
            "event_name": "push",
            "ref_name": "refs/heads/main",
            "repository": "org/repo",
            "default_branch": "main",
            "sha": sha,
            "head_repository": null,
        },
        "local": false,
    });
    let accepts = |v: Value| {
        serde_json::from_value::<ReceiptGenerationInput>(v)
            .is_ok_and(|d| generate_receipt_from_descriptor(d).is_ok())
    };
    let objects = bind(
        "schemas/pipeline-shard-receipt/input-v1.schema.json",
        &top,
        &accepts,
    );
    assert_eq!(
        objects,
        ["", "/artifacts/0", "/checks/0", "/hosted", "/target"]
    );
}

/// Exhaustive lists: adding a variant breaks the match until it is listed,
/// and the schema enum assertions then force the schemas to follow.
fn all_trust_contexts() -> Vec<TrustContext> {
    let all = [
        TrustContext::PullRequest,
        TrustContext::ProtectedMain,
        TrustContext::Release,
        TrustContext::Local,
    ];
    for context in all {
        match context {
            TrustContext::PullRequest
            | TrustContext::ProtectedMain
            | TrustContext::Release
            | TrustContext::Local => {}
        }
    }
    all.to_vec()
}

fn all_check_outcomes() -> Vec<CheckOutcome> {
    let all = [
        CheckOutcome::Passed,
        CheckOutcome::Failed,
        CheckOutcome::Cancelled,
        CheckOutcome::Skipped,
    ];
    for outcome in all {
        match outcome {
            CheckOutcome::Passed
            | CheckOutcome::Failed
            | CheckOutcome::Cancelled
            | CheckOutcome::Skipped => {}
        }
    }
    all.to_vec()
}

fn serialized_names<T: serde::Serialize>(values: &[T]) -> Vec<String> {
    let mut names: Vec<String> = values
        .iter()
        .map(|v| {
            serde_json::to_value(v)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn schema_enums_match_serde_variant_names() {
    let receipt = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let input = schema_json("schemas/pipeline-shard-receipt/input-v1.schema.json");
    let policy = schema_json("schemas/aggregate-policy/v1.schema.json");
    let trust = serialized_names(&all_trust_contexts());
    for node in [
        &receipt["properties"]["trust_context"],
        &policy["$defs"]["context"]["properties"]["trust_context"],
    ] {
        assert_eq!(schema_string_list(&node["enum"]), trust);
    }
    let outcomes = serialized_names(&all_check_outcomes());
    for node in [
        &receipt["$defs"]["check"]["properties"]["outcome"],
        &input["$defs"]["check"]["properties"]["outcome"],
    ] {
        assert_eq!(schema_string_list(&node["enum"]), outcomes);
    }
    for name in &trust {
        assert!(serde_json::from_value::<TrustContext>(Value::String(name.clone())).is_ok());
    }
    for name in &outcomes {
        assert!(serde_json::from_value::<CheckOutcome>(Value::String(name.clone())).is_ok());
    }
}

#[test]
fn shared_definitions_are_identical_across_schemas() {
    let receipt = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    let input = schema_json("schemas/pipeline-shard-receipt/input-v1.schema.json");
    let policy = schema_json("schemas/aggregate-policy/v1.schema.json");
    assert_eq!(receipt["$defs"]["digest"], policy["$defs"]["digest"]);
    assert_eq!(receipt["$defs"]["artifact"], policy["$defs"]["artifact"]);
    assert_eq!(receipt["$defs"]["check"], input["$defs"]["check"]);
    for schema in [&input, &policy] {
        assert_eq!(
            receipt["$defs"]["relative_path"],
            schema["$defs"]["relative_path"]
        );
    }
    let commit = &receipt["properties"]["commit_sha"];
    assert_eq!(commit, &input["properties"]["commit_sha"]);
    assert_eq!(commit, &input["properties"]["hosted"]["properties"]["sha"]);
    assert_eq!(
        commit,
        &policy["$defs"]["context"]["properties"]["commit_sha"]
    );
}

fn schema_regex(pointer: &str) -> Regex {
    let schema = schema_json("schemas/pipeline-shard-receipt/v1.schema.json");
    Regex::new(schema.pointer(pointer).unwrap().as_str().unwrap()).unwrap()
}

#[test]
fn digest_validator_agrees_with_schema_pattern() {
    let regex = schema_regex("/$defs/digest/pattern");
    let hex = "0123456789abcdef".repeat(4);
    for value in [
        format!("sha256:{hex}"),
        format!("sha256:{}", hex.to_uppercase()),
        format!("sha256:{}", &hex[1..]),
        format!("sha256:{hex}0"),
        format!("sha512:{hex}"),
        hex.clone(),
        format!("sha256:{}g", &hex[1..]),
        format!(" sha256:{hex}"),
        String::new(),
    ] {
        assert_eq!(
            regex.is_match(&value),
            Sha256Digest::new(&value).is_ok(),
            "digest {value:?}"
        );
    }
}

#[test]
fn commit_validator_agrees_with_schema_pattern() {
    let regex = schema_regex("/properties/commit_sha/pattern");
    for value in [
        "a".repeat(40),
        "0".repeat(64),
        "a".repeat(39),
        "a".repeat(65),
        "A".repeat(40),
        format!("{}g", "a".repeat(39)),
        format!("{} ", "a".repeat(40)),
        String::new(),
    ] {
        let mut r = receipt();
        r.commit_sha = value.clone();
        assert_eq!(
            regex.is_match(&value),
            validate_receipt(&r).is_ok(),
            "commit {value:?}"
        );
    }
}

#[test]
fn relative_path_validator_agrees_with_schema_pattern() {
    let regex = schema_regex("/$defs/relative_path/pattern");
    let corpus = [
        "report.json",
        "out/report.json",
        "a/b/c",
        ".hidden",
        "dir/.hidden",
        "...",
        "..x",
        "x..",
        "a b/c",
        "é/ü",
        "",
        ".",
        "..",
        "./a",
        "a/.",
        "a/./b",
        "../a",
        "a/..",
        "a/../b",
        "/abs",
        "a/",
        "a//b",
        "//server/share",
        "a\\b",
        "C:/x",
        "C:x",
        "a:b",
        "a\tb",
        "a\nb",
        "nul\u{0}",
    ];
    for path in corpus {
        let mut r = receipt();
        r.artifacts = vec![ReceiptArtifact {
            name: "artifact".into(),
            path: path.into(),
            size: 1,
            sha256: digest(b'c'),
        }];
        assert_eq!(
            regex.is_match(path),
            validate_receipt(&r).is_ok(),
            "path {path:?}"
        );
    }
}
