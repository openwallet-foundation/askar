//! Check that closing a transaction session does not hang when the Postgres
//! connection has silently died (no FIN/RST), using a TCP proxy that can be
//! switched to swallow all traffic.

#![cfg(feature = "pg_test")]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use askar_storage::{
    entry::{EntryKind, EntryOperation},
    future::{block_on, timeout},
    generate_raw_store_key, Backend, BackendSession, ManageBackend, StoreKeyMethod,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    spawn,
};

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    blackhole: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // swallow the data without closing either socket
                if !blackhole.load(Ordering::SeqCst) && to.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn start_proxy(upstream: String, blackhole: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    spawn(async move {
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(&upstream).await.unwrap();
            let (cr, cw) = client.into_split();
            let (sr, sw) = server.into_split();
            spawn(pump(cr, sw, blackhole.clone()));
            spawn(pump(sr, cw, blackhole.clone()));
        }
    });
    port
}

async fn setup(query: &str) -> (askar_storage::any::AnyBackend, Arc<AtomicBool>) {
    let pg_url = std::env::var("POSTGRES_URL").expect("'POSTGRES_URL' must be defined");
    let parsed = url::Url::parse(&pg_url).unwrap();
    let upstream = format!(
        "{}:{}",
        parsed.host_str().unwrap(),
        parsed.port().unwrap_or(5432)
    );
    let key = generate_raw_store_key(None).unwrap();
    let blackhole = Arc::new(AtomicBool::new(false));
    let port = start_proxy(upstream, blackhole.clone()).await;
    let proxy_url = format!(
        "postgres://{}:{}@127.0.0.1:{}/test-dead-conn?{}",
        parsed.username(),
        parsed.password().unwrap_or(""),
        port,
        query
    );
    let db = proxy_url
        .as_str()
        .provision_backend(StoreKeyMethod::RawKey, key.as_ref(), None, true)
        .await
        .expect("Error provisioning store");
    (db, blackhole)
}

#[test]
fn close_transaction_on_dead_connection() {
    block_on(async move {
        let (db, blackhole) = setup("max_connections=2&connect_timeout=5").await;

        let mut sess = db.session(None, true).unwrap();
        sess.ping().await.expect("Error starting transaction");

        // connection now dies without notifying either end
        blackhole.store(true, Ordering::SeqCst);

        let start = Instant::now();
        let res = timeout(Duration::from_secs(60), sess.close(false))
            .await
            .expect("session close hung");
        let elapsed = start.elapsed();
        println!("close returned in {elapsed:?}: {res:?}");
        assert!(res.is_err(), "expected close to fail on a dead connection");
        assert!(elapsed < Duration::from_secs(20));

        // the dead connection must not be reused or keep occupying the pool
        blackhole.store(false, Ordering::SeqCst);
        let mut sess = db.session(None, false).unwrap();
        timeout(Duration::from_secs(15), sess.ping())
            .await
            .expect("acquire hung after dead connection")
            .expect("ping failed after recovery");
        sess.close(false).await.unwrap();
        timeout(Duration::from_secs(30), db.close())
            .await
            .expect("pool close hung")
            .unwrap();
    });
}

async fn drop_on_dead_connection(transaction: bool, mid_operation: bool) {
    // a single connection, so the next session must wait for the dropped one
    let (db, blackhole) = setup("max_connections=1&connect_timeout=30").await;

    let mut sess = db.session(None, transaction).unwrap();
    sess.ping().await.expect("Error starting session");
    blackhole.store(true, Ordering::SeqCst);
    if mid_operation {
        // an operation which hangs and is cancelled part way through, which for a
        // session outside a transaction means dropping a transaction it started
        let res = timeout(
            Duration::from_secs(2),
            sess.update(
                EntryKind::Item,
                EntryOperation::Insert,
                "category",
                "name",
                Some(b"value"),
                None,
                None,
            ),
        )
        .await;
        assert!(
            res.is_none(),
            "expected update to hang on a dead connection"
        );
    }
    drop(sess);

    // stay dead for longer than the release timeout, so the pool has to give up
    // on the connection, then allow new ones
    askar_storage::future::sleep(Duration::from_secs(8)).await;
    blackhole.store(false, Ordering::SeqCst);
    let start = Instant::now();
    let mut sess = db.session(None, false).unwrap();
    let res = timeout(Duration::from_secs(20), sess.ping())
        .await
        .expect("acquire hung after dropping session on dead connection");
    println!("acquire returned in {:?}: {res:?}", start.elapsed());
    res.expect("ping failed after recovery");
    sess.close(false).await.unwrap();
    timeout(Duration::from_secs(30), db.close())
        .await
        .expect("pool close hung")
        .unwrap();
}

#[test]
fn drop_transaction_on_dead_connection() {
    block_on(drop_on_dead_connection(true, false));
}

#[test]
fn drop_session_on_dead_connection() {
    block_on(drop_on_dead_connection(false, false));
}

#[test]
fn drop_transaction_mid_operation_on_dead_connection() {
    block_on(drop_on_dead_connection(true, true));
}

#[test]
fn drop_session_mid_operation_on_dead_connection() {
    block_on(drop_on_dead_connection(false, true));
}
