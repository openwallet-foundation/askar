use crate::error::{Error, ErrorKind};

use std::os::raw::c_char;
use std::sync::{LazyLock, RwLock};

use ffi_support::rust_string_to_c;

static LAST_ERROR: LazyLock<RwLock<Option<Error>>> = LazyLock::new(|| RwLock::new(None));

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize)]
#[repr(i64)]
pub enum ErrorCode {
    Success = 0,
    Backend = 1,
    Busy = 2,
    Duplicate = 3,
    Encryption = 4,
    Input = 5,
    NotFound = 6,
    Unexpected = 7,
    Unsupported = 8,
    Custom = 100,
}

impl From<ErrorKind> for ErrorCode {
    fn from(kind: ErrorKind) -> ErrorCode {
        match kind {
            ErrorKind::Backend => ErrorCode::Backend,
            ErrorKind::Busy => ErrorCode::Busy,
            ErrorKind::Custom => ErrorCode::Custom,
            ErrorKind::Duplicate => ErrorCode::Duplicate,
            ErrorKind::Encryption => ErrorCode::Encryption,
            ErrorKind::Input => ErrorCode::Input,
            ErrorKind::NotFound => ErrorCode::NotFound,
            ErrorKind::Unexpected => ErrorCode::Unexpected,
            ErrorKind::Unsupported => ErrorCode::Unsupported,
        }
    }
}

impl<T> From<Result<T, Error>> for ErrorCode {
    fn from(result: Result<T, Error>) -> ErrorCode {
        match result {
            Ok(_) => ErrorCode::Success,
            Err(err) => ErrorCode::from(err.kind()),
        }
    }
}

#[no_mangle]
pub extern "C" fn askar_get_current_error(error_json_p: *mut *const c_char) -> ErrorCode {
    trace!("askar_get_current_error");

    let error = rust_string_to_c(get_current_error_json());
    unsafe { *error_json_p = error };

    ErrorCode::Success
}

pub fn get_current_error_json() -> String {
    #[derive(Serialize)]
    struct ErrorJson {
        code: usize,
        message: String,
    }

    if let Some(err) = Option::take(&mut *LAST_ERROR.write().unwrap()) {
        let message = err.to_string();
        let code = ErrorCode::from(err.kind()) as usize;
        serde_json::json!(&ErrorJson { code, message }).to_string()
    } else {
        r#"{"code":0,"message":null}"#.to_owned()
    }
}

pub fn set_last_error(error: Option<Error>) -> ErrorCode {
    trace!("askar_set_last_error");
    let code = match error.as_ref() {
        Some(err) => err.kind.into(),
        None => ErrorCode::Success,
    };
    *LAST_ERROR.write().unwrap() = error;
    code
}
