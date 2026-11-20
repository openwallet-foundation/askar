use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    generate_raw_store_key, Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde_json::json;

const XSS: &str = "<script>alert(1)</script>";

type SeedRow = (EntryKind, &'static str, String, Vec<u8>, Vec<EntryTag>);

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    let rows: Vec<SeedRow> = vec![
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-alice".into(),
            json!({"token": "TOKEN-MARKER-1", "status": "ok"})
                .to_string()
                .into_bytes(),
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                EntryTag::Encrypted("owner".into(), "OWNER-MARKER".into()),
            ],
        ),
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-carol".into(),
            json!({"token": "TOKEN-MARKER-2", "status": "ok"})
                .to_string()
                .into_bytes(),
            vec![],
        ),
        (
            EntryKind::Item,
            "hostile",
            format!("name {XSS}"),
            json!({"note": XSS}).to_string().into_bytes(),
            vec![EntryTag::Plaintext("t".into(), XSS.into())],
        ),
        (
            EntryKind::Item,
            "large",
            "large-record".into(),
            json!({"description": format!("{}FULL-VALUE-END", "x".repeat(240))})
                .to_string()
                .into_bytes(),
            vec![],
        ),
        (
            EntryKind::Kms,
            "keys",
            "k".into(),
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
                &name,
                Some(&value),
                Some(&tags),
                None,
            )
            .await
            .unwrap();
    }
    session.close(true).await.unwrap();
}

struct Ui {
    child: Child,
    base: String,
    port: u16,
    code: Option<String>,
}

impl Drop for Ui {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(uri: &str, extra: &[&str], expect_code: bool) -> Ui {
    let mut child = Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .env_remove("ASKAR_EXPLORER_PASS_KEY_FILE")
        .env_remove("ASKAR_EXPLORER_UI_HOSTS")
        .env_remove("ASKAR_EXPLORER_UI_IDLE_SECONDS")
        .args(["ui", "--uri", uri, "--listen", "127.0.0.1:0"])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = lines.next().expect("the server printed nothing").unwrap();
    let address = line
        .strip_prefix("Web UI listening on http://")
        .unwrap_or_else(|| panic!("unexpected output: {line}"))
        .to_owned();
    let code = expect_code.then(|| {
        lines
            .next()
            .unwrap()
            .unwrap()
            .strip_prefix("Login code: ")
            .unwrap()
            .to_owned()
    });
    Ui {
        child,
        base: format!("http://{address}"),
        port: address.rsplit(':').next().unwrap().parse().unwrap(),
        code,
    }
}

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

async fn login(ui: &Ui, secret: &str) -> Response {
    let token = login_csrf(ui).await;
    client()
        .post(format!("{}/login", ui.base))
        .form(&[("secret", secret), ("login_csrf", token.as_str())])
        .send()
        .await
        .unwrap()
}

async fn login_csrf(ui: &Ui) -> String {
    let (_, page) = get(ui, "/", None).await;
    page.split("name=\"login_csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

fn session_cookie(response: &Response) -> String {
    let cookie = response
        .headers()
        .get("set-cookie")
        .expect("a session cookie")
        .to_str()
        .unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    cookie.split(';').next().unwrap().to_owned()
}

async fn get(ui: &Ui, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut request = client().get(format!("{}{path}", ui.base));
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.text().await.unwrap())
}

async fn raw_store(directory: &std::path::Path, key: Option<&str>) -> String {
    let path = directory.join("store.db");
    let (method, pass_key) = match key {
        Some(key) => (StoreKeyMethod::RawKey, PassKey::from(key.to_owned())),
        None => (StoreKeyMethod::Unprotected, PassKey::empty()),
    };
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(method, pass_key, Some("main".into()), false)
        .await
        .unwrap();
    seed(&backend).await;
    backend.close().await.unwrap();
    format!("sqlite://{}", path.display())
}

#[tokio::test]
async fn nothing_is_shown_without_the_pass_key_and_the_page_is_hardened() {
    let directory = tempfile::tempdir().unwrap();
    let key = generate_raw_store_key(None).unwrap();
    let uri = raw_store(directory.path(), Some(&key)).await;
    let ui = start(&uri, &[], false);

    // The front page is a login form with security headers, and no data.
    let response = client().get(&ui.base).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    for (name, wanted) in [
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
    ] {
        assert_eq!(headers[name], wanted, "{name}");
    }
    let policy = headers["content-security-policy"].to_str().unwrap();
    assert!(policy.contains("default-src 'none'") && policy.contains("frame-ancestors 'none'"));
    let page = response.text().await.unwrap();
    assert!(page.contains("Unlock") && page.contains("type=\"password\""));
    assert!(!page.contains("MARKER") && !page.contains("<script"));

    // Every other page redirects to the login form, with or without a bogus cookie.
    for path in [
        "/entries",
        "/entries?category=people",
        "/entry?profile=main&id=1",
    ] {
        for cookie in [None, Some("askar_session=not-a-session")] {
            let mut request = client().get(format!("{}{path}", ui.base));
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
            assert_eq!(response.headers()["location"], "/");
        }
    }
    let (_, front) = get(&ui, "/", Some("askar_session=not-a-session")).await;
    assert!(front.contains("Unlock") && !front.contains("Profiles") && !front.contains("people"));

    // Unexpected hosts (DNS rebinding) and cross-origin posts are refused.
    let rebound = client()
        .get(format!("{}/", ui.base))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::MISDIRECTED_REQUEST);
    let login_csrf = login_csrf(&ui).await;
    let forged = client()
        .post(format!("{}/login", ui.base))
        .header("origin", "http://evil.example")
        .form(&[("secret", &*key), ("login_csrf", login_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    assert!(forged.headers().get("set-cookie").is_none());
    assert_eq!(
        client()
            .post(format!("{}/login", ui.base))
            .header("origin", format!("http://127.0.0.1:{}", ui.port))
            .form(&[("secret", "wrong"), ("login_csrf", login_csrf.as_str())])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "the page's own origin is accepted"
    );
    // Repeated wrong pass keys lock logins out, even for the right one.
    for _ in 0..4 {
        let wrong = login(&ui, "not the pass key").await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert!(wrong.headers().get("set-cookie").is_none());
        assert!(!wrong.text().await.unwrap().contains("MARKER"));
    }
    let blocked = login(&ui, &key).await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().get("set-cookie").is_none());
}

#[tokio::test]
async fn opaque_origin_login_requires_the_form_token() {
    let directory = tempfile::tempdir().unwrap();
    let key = generate_raw_store_key(None).unwrap();
    let uri = raw_store(directory.path(), Some(&key)).await;
    let ui = start(&uri, &[], false);
    let token = login_csrf(&ui).await;

    let invalid = client()
        .post(format!("{}/login", ui.base))
        .header("origin", "null")
        .form(&[("secret", &*key), ("login_csrf", "invalid")])
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);

    let valid = client()
        .post(format!("{}/login", ui.base))
        .header("origin", "null")
        .form(&[("secret", &*key), ("login_csrf", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn a_signed_in_person_browses_real_data_safely() {
    let directory = tempfile::tempdir().unwrap();
    let key = generate_raw_store_key(None).unwrap();
    let uri = raw_store(directory.path(), Some(&key)).await;
    let ui = start(&uri, &[], false);

    let response = login(&ui, &key).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = session_cookie(&response);
    let first = cookie.clone();

    let (status, front) = get(&ui, "/", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        front.contains("people") && front.contains("main"),
        "{front}"
    );

    // Real values and names are shown, and filters work.
    let (_, people) = get(
        &ui,
        "/entries?profile=main&category=people&kind=item",
        Some(&cookie),
    )
    .await;
    for shown in ["NAME-MARKER-alice", "NAME-MARKER-carol", "TOKEN-MARKER-1"] {
        assert!(people.contains(shown), "{shown} missing:\n{people}");
    }
    let (_, active) = get(
        &ui,
        "/entries?profile=main&category=people&ptag=state%3Dactive",
        Some(&cookie),
    )
    .await;
    assert!(active.contains("NAME-MARKER-alice") && !active.contains("NAME-MARKER-carol"));
    let (_, large) = get(&ui, "/entries?profile=main&category=large", Some(&cookie)).await;
    assert!(large.contains("<details>") && large.contains("<pre>"));
    assert!(
        large.contains("FULL-VALUE-END"),
        "full value was truncated: {large}"
    );
    let (_, owned) = get(
        &ui,
        "/entries?profile=main&category=people&tag=owner%3DOWNER-MARKER",
        Some(&cookie),
    )
    .await;
    assert!(owned.contains("NAME-MARKER-alice") && !owned.contains("NAME-MARKER-carol"));
    let (_, none) = get(
        &ui,
        "/entries?profile=main&category=people&tag=owner%3Dnobody",
        Some(&cookie),
    )
    .await;
    assert!(none.contains("No entries match"));

    // One entry in full.
    let id = people
        .split("/entry?profile=main&amp;id=")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (status, detail) = get(&ui, &format!("/entry?profile=main&id={id}"), Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail.contains("TOKEN-MARKER-1") && detail.contains("owner"));
    let (status, missing) = get(&ui, "/entry?profile=main&id=99999", Some(&cookie)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!missing.contains("MARKER"));

    // Hostile data is escaped everywhere it is shown.
    let (_, hostile) = get(&ui, "/entries?profile=main&category=hostile", Some(&cookie)).await;
    let (_, hostile_entry) = {
        let id = hostile
            .split("/entry?profile=main&amp;id=")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        get(&ui, &format!("/entry?profile=main&id={id}"), Some(&cookie)).await
    };
    for page in [&hostile, &hostile_entry] {
        assert!(page.contains("&lt;script&gt;"), "{page}");
        assert!(!page.contains("<script"), "unescaped markup:\n{page}");
    }

    // Key material is never shown.
    let (_, keys) = get(&ui, "/entries?profile=main&kind=kms", Some(&cookie)).await;
    assert!(keys.contains("<tr>") && !keys.contains("KEY-MATERIAL"));
    let (_, any) = get(&ui, "/entries?profile=main&kind=any", Some(&cookie)).await;
    assert!(!any.contains("KEY-MATERIAL"));

    // Locking needs the form token, then ends the session.
    let csrf = front
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let no_token = client()
        .post(format!("{}/logout", ui.base))
        .header("cookie", &cookie)
        .form(&[("csrf", "guess")])
        .send()
        .await
        .unwrap();
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN);
    assert_eq!(get(&ui, "/entries", Some(&cookie)).await.0, StatusCode::OK);
    let locked = client()
        .post(format!("{}/logout", ui.base))
        .header("cookie", &cookie)
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(locked.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        get(&ui, "/entries", Some(&cookie)).await.0,
        StatusCode::SEE_OTHER
    );

    // A new login replaces the old session, and a stolen old cookie stops working.
    let again = session_cookie(&login(&ui, &key).await);
    let newest = session_cookie(&login(&ui, &key).await);
    assert_ne!(again, newest);
    assert_ne!(first, newest);
    assert_eq!(
        get(&ui, "/entries", Some(&again)).await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(get(&ui, "/entries", Some(&newest)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn sessions_lock_themselves_when_idle() {
    let directory = tempfile::tempdir().unwrap();
    let key = generate_raw_store_key(None).unwrap();
    let uri = raw_store(directory.path(), Some(&key)).await;
    let ui = start(&uri, &["--idle-seconds", "1"], false);
    let cookie = session_cookie(&login(&ui, &key).await);
    assert_eq!(get(&ui, "/entries", Some(&cookie)).await.0, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert_eq!(
        get(&ui, "/entries", Some(&cookie)).await.0,
        StatusCode::SEE_OTHER
    );
    let (_, front) = get(&ui, "/", Some(&cookie)).await;
    assert!(front.contains("Unlock"));
}

#[tokio::test]
async fn a_store_without_a_pass_key_needs_the_login_code() {
    let directory = tempfile::tempdir().unwrap();
    let uri = raw_store(directory.path(), None).await;
    let ui = start(&uri, &[], true);
    let code = ui.code.clone().unwrap();
    assert_eq!(code.len(), 16);

    // An empty or guessed secret is not enough, since nothing else protects the page.
    for guess in ["", "0000000000000000", "main"] {
        let response = login(&ui, guess).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{guess:?}");
        assert!(response.headers().get("set-cookie").is_none());
    }
    let response = login(&ui, &code).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = session_cookie(&response);
    let (_, entries) = get(&ui, "/entries?profile=main&category=people", Some(&cookie)).await;
    assert!(entries.contains("NAME-MARKER-alice"));
}

#[tokio::test]
async fn lockouts_get_longer_and_a_successful_login_clears_them() {
    let directory = tempfile::tempdir().unwrap();
    let key = generate_raw_store_key(None).unwrap();
    let uri = raw_store(directory.path(), Some(&key)).await;
    let ui = start(&uri, &["--lockout-seconds", "1"], false);
    for _ in 0..5 {
        assert_eq!(login(&ui, "wrong").await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        login(&ui, "wrong").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    // The first lockout (1s) is over; five more failures earn a longer one (2s).
    for _ in 0..5 {
        assert_eq!(login(&ui, "wrong").await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        login(&ui, "wrong").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    assert_eq!(
        login(&ui, &key).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "still locked out after the length of the first lockout"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(login(&ui, &key).await.status(), StatusCode::SEE_OTHER);

    // Success starts over: the next lockout is short again.
    for _ in 0..5 {
        assert_eq!(login(&ui, "wrong").await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        login(&ui, "wrong").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    assert_eq!(login(&ui, &key).await.status(), StatusCode::SEE_OTHER);
}
