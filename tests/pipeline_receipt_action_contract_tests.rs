use std::fs;

#[test]
fn receipt_action_uses_canonical_archive_configuration() {
    let action = fs::read_to_string(".github/actions/emit-receipt/action.yml")
        .expect("receipt action must be present");

    assert!(
        action.contains(
            "git -c core.autocrlf=false -c core.eol=lf archive \"$RECEIPT_SHA\" | tar -x -C \"$target\""
        ),
        "receipt source snapshot must be independent of runner autocrlf settings"
    );
    assert!(
        !action.contains("\ngit archive \"$RECEIPT_SHA\"")
            && !action.contains("\n        git archive \"$RECEIPT_SHA\""),
        "receipt action must not regress to an environment-dependent archive"
    );
}
