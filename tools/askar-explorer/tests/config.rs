use std::{fs, process::Command};

use askar_storage::{
    generate_raw_store_key, sqlite::SqliteStoreOptions, Backend, ManageBackend, StoreKeyMethod,
};

#[tokio::test]
async fn dotenv_and_cli_precedence_export_a_raw_key_store() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.db");
    let pass_key = generate_raw_store_key(None).unwrap();
    let store = SqliteStoreOptions::new(source.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::RawKey,
            pass_key.as_ref(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    store.close().await.unwrap();

    let uri = format!("sqlite://{}", source.display());
    fs::write(
        directory.path().join(".env"),
        format!(
            "ASKAR_EXPLORER_URI='{uri}'\nASKAR_EXPLORER_OUT='from-file.db'\nASKAR_EXPLORER_PASS_KEY='{}'\n",
            &*pass_key
        ),
    )
    .unwrap();

    let run = |args: &[&str], env_uri: Option<&str>, expected: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_askar-explorer"));
        command
            .current_dir(directory.path())
            .env_remove("ASKAR_EXPLORER_URI")
            .env_remove("ASKAR_EXPLORER_OUT")
            .env_remove("ASKAR_EXPLORER_PASS_KEY")
            .args(args);
        if let Some(uri) = env_uri {
            command.env("ASKAR_EXPLORER_URI", uri);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(directory.path().join(expected).exists());
    };
    run(&["export"], None, "from-file.db");

    fs::write(
        directory.path().join(".env"),
        format!(
            "ASKAR_EXPLORER_URI='sqlite:///missing.db'\nASKAR_EXPLORER_OUT='from-file-2.db'\nASKAR_EXPLORER_PASS_KEY='{}'\n",
            &*pass_key
        ),
    )
    .unwrap();
    run(
        &["export", "--out", "from-flag.db"],
        Some(&uri),
        "from-flag.db",
    );
    run(
        &["export", "--uri", &uri, "--out", "explicit.db"],
        Some("sqlite:///missing.db"),
        "explicit.db",
    );
}
