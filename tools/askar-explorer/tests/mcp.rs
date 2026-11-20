use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::{json, Value};

type SeedRow<'a> = (EntryKind, &'a str, &'a str, Vec<u8>, Vec<EntryTag>);

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    let person =
        json!({"token": "TOKEN-MARKER-1", "status": "ok", "age": 4242424242u64}).to_string();
    let rows: Vec<SeedRow<'_>> = vec![
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-alice",
            person.clone().into_bytes(),
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                EntryTag::Encrypted("owner".into(), "OWNER-MARKER".into()),
            ],
        ),
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-carol",
            person.into_bytes(),
            vec![],
        ),
        (
            EntryKind::Kms,
            "keys",
            "k",
            b"KEY-MATERIAL-MARKER".to_vec(),
            vec![],
        ),
    ];
    for (kind, category, name, value, tags) in rows {
        let value = SecretBytes::from(value);
        session
            .update(
                kind,
                EntryOperation::Insert,
                category,
                name,
                Some(&value),
                Some(&tags),
                None,
            )
            .await
            .unwrap();
    }
    session.close(true).await.unwrap();
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn explorer() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_askar-explorer"));
    command
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .env_remove("ASKAR_EXPLORER_POLICY")
        .env_remove("ASKAR_EXPLORER_PROPOSALS")
        .env_remove("ASKAR_EXPLORER_REVIEW_COMMAND")
        .env_remove("ASKAR_EXPLORER_AGENT_URL")
        .env_remove("ASKAR_EXPLORER_TOKEN_FILE");
    command
}

fn start_server(uri: &str, directory: &Path) -> (Process, String, PathBuf) {
    let policy = directory.join("policy.toml");
    std::fs::write(
        &policy,
        "show_tags = [\"state\"]\nshow_paths = [\"status\"]\n",
    )
    .unwrap();
    let token_file = directory.join("agent.token");
    let mut child = explorer()
        .args([
            "serve",
            "--uri",
            uri,
            "--agent-listen",
            "127.0.0.1:0",
            "--policy",
        ])
        .arg(&policy)
        .arg("--token-file")
        .arg(&token_file)
        .arg("--proposals")
        .arg(directory.join("proposals"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let line = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .next()
        .unwrap()
        .unwrap();
    let address = line
        .strip_prefix("Agent API listening on ")
        .unwrap()
        .to_owned();
    (Process(child), format!("http://{address}"), token_file)
}

struct Client {
    _child: Process,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    transcript: String,
}

impl Client {
    fn start(base: &str, token_file: &Path) -> Self {
        let mut child = explorer()
            .args(["mcp", "--agent-url", base, "--token-file"])
            .arg(token_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            _child: Process(child),
            stdin,
            stdout,
            next_id: 0,
            transcript: String::new(),
        }
    }

    fn send_raw(&mut self, text: &str) {
        writeln!(self.stdin, "{text}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        self.transcript.push_str(&line);
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let message =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        self.send_raw(&message.to_string());
        let reply = self.read();
        assert_eq!(reply["id"], self.next_id, "{reply}");
        reply
    }

    fn call(&mut self, name: &str, arguments: Value) -> (bool, String) {
        let reply = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &reply["result"];
        assert!(result.is_object(), "{reply}");
        (
            result["isError"].as_bool().unwrap(),
            result["content"][0]["text"].as_str().unwrap().to_owned(),
        )
    }

    fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (is_error, text) = self.call(name, arguments);
        assert!(!is_error, "{name}: {text}");
        serde_json::from_str(&text).unwrap()
    }
}

#[tokio::test]
async fn mcp_forwards_to_the_agent_api_without_leaking_or_writing() {
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
    seed(&backend).await;
    backend.close().await.unwrap();
    let (server, base, token_file) =
        start_server(&format!("sqlite://{}", path.display()), directory.path());
    let mut client = Client::start(&base, &token_file);

    // Handshake.
    let init = client.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
    );
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init["result"]["serverInfo"]["name"], "askar-explorer");
    assert!(init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("redacted"));
    let newer = client.request("initialize", json!({"protocolVersion": "9999-01-01"}));
    assert_eq!(
        newer["result"]["protocolVersion"], "2025-06-18",
        "unknown versions get the newest we speak"
    );
    client.send_raw(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(
        client.request("ping", json!({}))["result"],
        json!({}),
        "notifications get no reply"
    );

    // The tools read, or leave proposals that only a person can apply.
    let tools = client.request("tools/list", json!({}))["result"]["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_profiles",
            "category_stats",
            "describe_category",
            "query",
            "list_entries",
            "get_entry",
            "propose_change",
            "list_proposals"
        ]
    );
    for tool in tools.as_array().unwrap() {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["description"].as_str().unwrap().len() > 20);
        for forbidden in [
            "write", "update", "delete", "apply", "reveal", "insert", "remove",
        ] {
            assert!(!tool["name"].as_str().unwrap().contains(forbidden));
        }
    }

    // Tools work and return structured results.
    assert_eq!(client.ok("list_profiles", json!({}))["rows"][0][1], "main");
    let stats = client.ok("category_stats", json!({}));
    assert_eq!(stats["columns"][2], "category");
    let described = client.ok("describe_category", json!({"category": "people"}));
    assert!(described["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row[1] == "status" && row[7] == json!(["ok (2)"])));
    let queried = client.ok(
        "query",
        json!({"sql": "SELECT json_extract(value, '$.status') AS s, count(*) AS n FROM items WHERE category = 'people' GROUP BY 1"}),
    );
    assert_eq!(queried["rows"], json!([["ok", 2]]));
    let listed = client.ok(
        "list_entries",
        json!({"category": "people", "plaintext_tags": ["state=active"]}),
    );
    assert_eq!(listed["rows"].as_array().unwrap().len(), 1);
    let id = listed["rows"][0][1].as_i64().unwrap();
    let entry = client.ok("get_entry", json!({"id": id}));
    assert_eq!(entry["value"]["token"], "<string:14>");

    // Proposing saves a request for a person and changes nothing.
    let proposed = client.ok(
        "propose_change",
        json!({
            "title": "Fix the status",
            "rationale": "It is wrong",
            "ops": [{"op": "set_json", "profile": "main", "id": id, "pointer": "/status", "value": "fixed"}]
        }),
    );
    assert_eq!(proposed["status"], "pending");
    let proposal_id = proposed["id"].as_str().unwrap();
    assert!(proposed["review_command"]
        .as_str()
        .unwrap()
        .ends_with(&format!("changes show {proposal_id}")));
    let proposals = client.ok("list_proposals", json!({}));
    assert_eq!(proposals["proposals"][0]["id"], proposal_id);
    assert_eq!(proposals["proposals"][0]["status"], "pending");
    assert_eq!(
        client.ok("get_entry", json!({"id": id}))["value"]["status"],
        "ok",
        "proposing does not change the store"
    );

    // Nothing sensitive crossed the wire.
    for secret in ["MARKER", "4242424242", "alice", "carol"] {
        assert!(
            !client.transcript.contains(secret),
            "{secret} leaked:\n{}",
            client.transcript
        );
    }

    // Problems are reported as tool errors the agent can read, not as crashes.
    for (name, arguments) in [
        ("query", json!({"sql": "DROP TABLE items"})),
        (
            "query",
            json!({"sql": "SELECT * FROM items WHERE name = 'x'"}),
        ),
        ("query", json!({"sql": "SELECT 1", "view": "reveal"})),
        ("list_entries", json!({"tags": ["owner=OWNER-MARKER"]})),
        ("get_entry", json!({"id": 99999})),
        (
            "propose_change",
            json!({"title": "x", "ops": [{"op": "apply", "id": 1}]}),
        ),
        ("propose_change", json!({"title": " ", "ops": []})),
    ] {
        let (is_error, text) = client.call(name, arguments.clone());
        assert!(is_error, "{name} {arguments} should fail");
        assert!(!text.is_empty() && !text.contains("MARKER"));
    }
    let unknown = client.request(
        "tools/call",
        json!({"name": "reveal_value", "arguments": {}}),
    );
    assert_eq!(unknown["error"]["code"], -32602);
    let not_object = client.request(
        "tools/call",
        json!({"name": "query", "arguments": "SELECT 1"}),
    );
    assert_eq!(not_object["error"]["code"], -32602);
    assert_eq!(
        client.request("resources/list", json!({}))["error"]["code"],
        -32601
    );
    client.send_raw("{not json");
    assert_eq!(client.read()["error"]["code"], -32700);
    assert_eq!(
        client.request("ping", json!({}))["result"],
        json!({}),
        "the server keeps running"
    );

    // A wrong token is refused, and the proxy rereads the file so a new token works at once.
    let good = std::fs::read_to_string(&token_file).unwrap();
    std::fs::write(&token_file, "stale-token\n").unwrap();
    let (is_error, text) = client.call("list_profiles", json!({}));
    assert!(is_error && text.contains("token"), "{text}");
    std::fs::write(&token_file, good).unwrap();
    client.ok("list_profiles", json!({}));

    // With the server gone the agent is told so.
    drop(server);
    let (is_error, text) = client.call("list_profiles", json!({}));
    assert!(is_error && text.contains("Cannot reach"), "{text}");
}
