use super::pipeline_receipt::{AggregatePolicy, ReceiptError};
use std::collections::BTreeSet;

pub(crate) fn validate_policy(policy: &AggregatePolicy) -> Result<(), ReceiptError> {
    let context = &policy.context;
    if policy.expected_targets.is_empty() || policy.required_checks.is_empty() {
        return Err(ReceiptError::Contract(
            "aggregate policy targets and required checks must be nonempty".into(),
        ));
    }
    if context.promotable {
        return Err(ReceiptError::Contract(
            "unsigned receipt policies cannot be promotable".into(),
        ));
    }
    if context.repository.is_empty() || context.workflow.is_empty() {
        return Err(ReceiptError::Contract(
            "expected context identity is empty".into(),
        ));
    }
    if !(40..=64).contains(&context.commit_sha.len())
        || !context.commit_sha.bytes().all(|b| b.is_ascii_hexdigit())
        || context.commit_sha != context.commit_sha.to_ascii_lowercase()
    {
        return Err(ReceiptError::Contract(
            "expected commit_sha is invalid".into(),
        ));
    }
    let mut checks = BTreeSet::new();
    if policy
        .required_checks
        .iter()
        .any(|name| name.is_empty() || !checks.insert(name))
    {
        return Err(ReceiptError::Contract(
            "required check names must be unique and nonempty".into(),
        ));
    }
    for target in &policy.expected_targets {
        let mut features = BTreeSet::new();
        if target
            .features
            .iter()
            .any(|feature| feature.is_empty() || !features.insert(feature))
        {
            return Err(ReceiptError::Contract(
                "target feature names must be unique and nonempty".into(),
            ));
        }
    }
    if policy
        .artifacts
        .iter()
        .any(|artifact| artifact.name.is_empty())
    {
        return Err(ReceiptError::Contract(
            "trusted artifact name must be nonempty".into(),
        ));
    }
    Ok(())
}
