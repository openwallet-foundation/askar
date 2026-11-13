//! Create a small demo store with mediator-like records, for trying the explorer.
//!
//! The store is created without a pass key, so it is only suitable for fake data:
//!
//! ```sh
//! cargo run -p askar-explorer --example seed_demo -- sqlite:///tmp/demo.db
//! ```

use anyhow::{bail, Result};
use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::json;

const STATES: [&str; 3] = ["active", "completed", "abandoned"];

#[tokio::main]
async fn main() -> Result<()> {
    let Some(uri) = std::env::args().nth(1) else {
        bail!("Usage: seed_demo <sqlite:// or postgres:// URI>");
    };
    let backend = uri
        .as_str()
        .provision_backend(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("mediator".into()),
            false,
        )
        .await?;
    let mut session = backend.session(None, false)?;
    let insert = |category: &str,
                  name: String,
                  value: serde_json::Value,
                  tags: Vec<EntryTag>,
                  expiry: Option<i64>| {
        let value = SecretBytes::from(value.to_string().into_bytes());
        (category.to_owned(), name, value, tags, expiry)
    };
    let mut rows = Vec::new();
    for index in 0..40 {
        let state = STATES[index % STATES.len()];
        rows.push(insert(
            "connections",
            format!("conn-{index:03}"),
            json!({
                "state": state,
                "role": if index % 7 == 0 { "mediator" } else { "recipient" },
                "their_label": format!("Demo Person {index}"),
                "their_did": format!("did:peer:2.Ez6LSdemo{index:04}abcdefghijklmnopqrstuvwxyz"),
                "created_at": 1_700_000_000 + index as i64 * 3600,
                "invitation_key": format!("DemoInvitationKey{index:04}Zq9XkL2mN8pR5tV7wY"),
            }),
            vec![
                EntryTag::Plaintext("state".into(), state.into()),
                EntryTag::Encrypted("their_did".into(), format!("did:peer:2.demo{index}")),
            ],
            None,
        ));
    }
    for index in 0..12 {
        rows.push(insert(
            "mediation_requests",
            format!("req-{index:03}"),
            json!({"status": if index % 4 == 0 { "denied" } else { "granted" }, "endpoint": format!("https://demo{index}.example.com/")}),
            vec![EntryTag::Plaintext("status".into(), if index % 4 == 0 { "denied" } else { "granted" }.into())],
            None,
        ));
    }
    for index in 0..8 {
        rows.push(insert(
            "queued_messages",
            format!("msg-{index:03}"),
            json!({"recipient_key": format!("DemoRecipientKey{index:04}Hs3Bd6Fg9Jk2Lm5Pq8Rt"), "payload_size": 2048 + index}),
            vec![],
            Some(if index < 3 { -60_000 } else { 86_400_000 }),
        ));
    }
    for (category, name, value, tags, expiry) in rows {
        session
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                &category,
                &name,
                Some(&value),
                Some(&tags),
                expiry,
            )
            .await?;
    }
    session.close(true).await?;
    backend.close().await?;
    println!("Created demo profile \"mediator\" in {uri}");
    Ok(())
}
