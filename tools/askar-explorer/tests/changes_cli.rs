use std::process::{Command, Output};

use askar_explorer::{
    changes::{self, ProposalRequest, ProposalStore},
    source::Source,
};
use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::json;

fn explorer(proposals: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_WRITE_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .arg("changes")
        .arg("--proposals")
        .arg(proposals)
        .args(args)
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn the_cli_lists_shows_and_refuses_to_commit_without_a_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.db");
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    let mut session = backend.session(None, false).unwrap();
    let value = SecretBytes::from(
        json!({"state": "stuck", "note": "OLD-SECRET"})
            .to_string()
            .into_bytes(),
    );
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "people",
            "alice",
            Some(&value),
            Some(&[]),
            None,
        )
        .await
        .unwrap();
    session.close(true).await.unwrap();
    backend.close().await.unwrap();
    let uri = format!("sqlite://{}", path.display());

    let proposals = directory.path().join("proposals");
    let store = ProposalStore::new(&proposals);
    assert!(text(&explorer(&proposals, &["list"])).contains("No proposals"));

    let mut source = Source::open(&uri, None).await.unwrap();
    let profile = source.select_profiles(None).unwrap().remove(0);
    let id = source
        .scan(&profile, &Default::default(), 0, 10)
        .await
        .unwrap()[0]
        .id;
    let request: ProposalRequest = serde_json::from_value(json!({
        "title": "Unstick alice",
        "ops": [{"op": "set_json", "profile": "main", "id": id, "pointer": "/state", "value": "active"}]
    }))
    .unwrap();
    let proposal = changes::propose(&mut source, &store, request)
        .await
        .unwrap();
    drop(source);

    let listed = text(&explorer(&proposals, &["list"]));
    assert!(
        listed.contains(&proposal.id)
            && listed.contains("pending")
            && listed.contains("Unstick alice")
    );

    let shown = explorer(&proposals, &["show", &proposal.id, "--uri", &uri]);
    assert!(shown.status.success(), "{}", text(&shown));
    let shown = text(&shown);
    assert!(
        shown.contains("-  \"state\": \"stuck\"") && shown.contains("+  \"state\": \"active\""),
        "{shown}"
    );

    // A dry run writes nothing, and a script cannot answer the confirmation.
    let dry = explorer(
        &proposals,
        &["apply", &proposal.id, "--uri", &uri, "--write-uri", &uri],
    );
    assert!(
        dry.status.success() && text(&dry).contains("Dry run"),
        "{}",
        text(&dry)
    );
    let scripted = explorer(
        &proposals,
        &[
            "apply",
            &proposal.id,
            "--uri",
            &uri,
            "--write-uri",
            &uri,
            "--commit",
            "--confirm-backup",
        ],
    );
    assert!(!scripted.status.success());
    assert!(
        text(&scripted).contains("interactive terminal"),
        "{}",
        text(&scripted)
    );
    let still = {
        let mut source = Source::open(&uri, None).await.unwrap();
        let profile = source.select_profiles(None).unwrap().remove(0);
        let item = source
            .scan(&profile, &Default::default(), 0, 10)
            .await
            .unwrap()
            .remove(0);
        String::from_utf8(item.value.unwrap().to_vec()).unwrap()
    };
    assert!(still.contains("stuck"), "nothing was written: {still}");
    let nowrite = explorer(
        &proposals,
        &[
            "apply",
            &proposal.id,
            "--uri",
            &uri,
            "--commit",
            "--confirm-backup",
        ],
    );
    assert!(
        text(&nowrite).contains("ASKAR_EXPLORER_WRITE_URI"),
        "{}",
        text(&nowrite)
    );

    // Rejecting is recorded, and bad ids are refused.
    let rejected = explorer(&proposals, &["reject", &proposal.id]);
    assert!(rejected.status.success(), "{}", text(&rejected));
    assert!(text(&explorer(&proposals, &["list"])).contains("rejected"));
    assert!(text(&explorer(&proposals, &["reject", &proposal.id])).contains("already"));
    assert!(
        !explorer(&proposals, &["show", "../../etc/passwd", "--uri", &uri])
            .status
            .success()
    );
    let log = std::fs::read_to_string(proposals.join("changes.log")).unwrap();
    assert!(log.contains(&format!("rejected {}", proposal.id)) && !log.contains("OLD-SECRET"));
}
