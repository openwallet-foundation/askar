use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock},
    thread,
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use tokio::runtime::Runtime;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

static RUNTIME: LazyLock<ArcSwapOption<Runtime>> = LazyLock::new(|| {
    ArcSwapOption::new(Some(Arc::new(
        Runtime::new().expect("Error creating tokio runtime"),
    )))
});

/// Block the current thread on an async task, when not running inside the scheduler.
pub fn block_on<R>(f: impl Future<Output = R>) -> R {
    if let Some(rt) = RUNTIME.load().clone() {
        rt.block_on(f)
    } else {
        panic!("Runtime has been shut down");
    }
}

/// Run a blocking task without interrupting the async scheduler.
#[inline]
pub async fn unblock<F, T>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if let Some(rt) = RUNTIME.load().clone() {
        rt.spawn_blocking(f)
            .await
            .expect("Error running blocking task")
    } else {
        panic!("Runtime has been shut down");
    }
}

/// Spawn an async task into the runtime.
#[inline]
pub fn spawn_ok(fut: impl Future<Output = ()> + Send + 'static) {
    if let Some(rt) = RUNTIME.load().clone() {
        rt.spawn(fut);
    }
}

/// Wait until a specific duration has passed (used in tests).
/// This method must be called within `block_on` or a spawned task in order to have
/// access to the async runtime.
#[doc(hidden)]
pub async fn sleep(dur: Duration) {
    tokio::time::sleep(dur).await
}

/// Cancel an async task if it does not complete after a timeout (used in tests).
/// This method must be called within `block_on` or a spawned task in order to have
/// access to the async runtime.
#[doc(hidden)]
pub async fn timeout<R>(dur: Duration, f: impl Future<Output = R>) -> Option<R> {
    tokio::time::timeout(dur, f).await.ok()
}

/// Shut down the async runtime.
#[doc(hidden)]
pub fn shutdown(max_dur: Duration) {
    let start = Instant::now();
    if let Some(rt_swap) = LazyLock::get(&RUNTIME) {
        if let Some(mut rt) = rt_swap.swap(None) {
            loop {
                match Arc::try_unwrap(rt) {
                    Ok(rt) => {
                        rt.shutdown_timeout(max_dur.saturating_sub(start.elapsed()));
                        break;
                    }
                    Err(new_rt) => {
                        rt = new_rt;
                        if start.elapsed() >= max_dur {
                            break;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }
}
