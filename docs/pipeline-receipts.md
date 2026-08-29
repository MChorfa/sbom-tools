# Pipeline shard receipts

`PipelineShardReceipt` is the unsigned, target-scoped evidence contract used by CI
verification jobs. Its schema identifier is `pipeline-shard-receipt/v1`.
Receipts bind a repository commit and deterministic source and lock fingerprints
to an OS, architecture, toolchain, profile, feature set, and binding runtime.

Validate one locally with:

```text
sbom-tools verify receipt path/to/receipt.json
sbom-tools verify receipt-aggregate receipts/ --policy aggregate-policy.json
```

Receipts are unsigned and are non-promotion evidence; this slice rejects
`promotable: true`. Slice 5 must introduce signed promotion authority.
`source_fingerprint(root)` includes path-qualified file names and contents while
excluding `.git`, `target`, and `receipts` directories. `lock_fingerprint(root)`
uses the applicable Cargo, toolchain, binding, and Dagger lock inputs. Both
functions sort paths before hashing, so the result is reproducible across
filesystems.

Receipts created from a local working tree must use `trust_context: "local"` and
`promotable: false`. Local receipts are useful for reproduction but cannot pass
a promotion gate. CI aggregation rejects missing or duplicate targets, source or
lock mismatches, failed/cancelled/skipped required checks, missing or digest-
invalid artifacts, and duplicate artifact identities.

The receipt is an action result, not a dependency cache. Cache keys must remain
separate from receipt and artifact identities; cache contents are never accepted
as verification evidence. Workflow wiring and cryptographic signatures are
explicitly deferred until later slices. Workflow integrations should eventually
emit receipts with `if: always()` while preserving native OS execution and
existing status guards.

Fingerprinting reads ordinary filesystem paths and has a documented local
mutation race: a file changed between directory enumeration and reading can
produce a fingerprint that does not describe one atomic filesystem snapshot.
The generator is deliberately local/non-promotable; aggregation trusts only
the externally supplied expected digests (they are policy inputs, not
recomputed by the aggregate command).

The aggregate policy is JSON with exactly `expected_targets`, `context`,
`required_checks`, and `artifacts` fields; each field uses the corresponding
receipt contract shape. Unknown fields are rejected. I/O and malformed JSON are
operational errors; a readable receipt or policy that violates the contract is
a gate verdict and exits 1. Aggregate success, including an explicitly expected
`trust_context: "local"`, is verification only and never a promotion decision
in v1.
