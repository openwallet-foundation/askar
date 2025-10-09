use std::marker::PhantomData;
use std::os::raw::c_char;
use std::time::Duration;

use ffi_support::rust_string_to_c;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

#[macro_use]
mod handle;
use self::handle::ResourceHandle;

#[macro_use]
mod macros;

mod error;
mod kdf;
mod key;
mod log;
pub(crate) mod result_list;
mod secret;
mod store;
mod tags;

#[cfg(all(feature = "migration", feature = "sqlite"))]
mod migration;

use self::error::ErrorCode;
use crate::error::Error;

pub type CallbackId = i64;

ffi_support::define_string_destructor!(askar_string_free);

pub struct EnsureCallback<T, F: Fn(Result<T, Error>)> {
    f: F,
    resolved: bool,
    _pd: PhantomData<T>,
}

impl<T, F: Fn(Result<T, Error>)> EnsureCallback<T, F> {
    pub fn new(f: F) -> Self {
        Self {
            f,
            resolved: false,
            _pd: PhantomData,
        }
    }

    pub fn resolve(mut self, value: Result<T, Error>) {
        self.resolved = true;
        (self.f)(value);
    }
}

impl<T, F: Fn(Result<T, Error>)> Drop for EnsureCallback<T, F> {
    fn drop(&mut self) {
        // if std::thread::panicking()  - capture trace?
        if !self.resolved {
            (self.f)(Err(err_msg!(Unexpected)));
        }
    }
}

#[no_mangle]
pub extern "C" fn askar_terminate() {
    crate::future::shutdown(Duration::from_secs(5));
}

#[no_mangle]
pub extern "C" fn askar_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
