"""Library instance and allocated buffer handling."""

import asyncio
import functools
import itertools
import logging
import os
import sys
import threading
import time
from copy import deepcopy

try:
    import orjson as json
except ImportError:
    import json

from ctypes import (
    Array,
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    addressof,
    byref,
    cast,
    c_char,
    c_char_p,
    c_int8,
    c_int32,
    c_int64,
    c_ubyte,
    c_void_p,
)
from ctypes.util import find_library
from typing import Callable, Optional, Tuple, Union
from weakref import finalize, ref

from ..error import AskarError, AskarErrorCode


LOGGER = logging.getLogger(__name__)
MODULE_NAME = __name__.split(".")[0]

LOG_LEVELS = {
    1: logging.ERROR,
    2: logging.WARNING,
    3: logging.INFO,
    4: logging.DEBUG,
}


def entry_cache(fn):
    """Cache results for properties of individual entries."""

    @functools.wraps(fn)
    def wrapper(self, index: int):
        if not hasattr(self, "_ecache"):
            setattr(self, "_ecache", {})
        cache = self._ecache
        ckey = (fn, index)
        if ckey in cache:
            res = cache[ckey]
        else:
            res = fn(self, index)
            cache[ckey] = res
        if isinstance(res, dict):
            # make sure the cached copy is not mutated
            res = deepcopy(res)
        return res

    return wrapper


def _convert_log_level(level: Union[str, int, None]):
    if level is None or level == "-1":
        return -1
    else:
        if isinstance(level, str):
            level = level.upper()
        name = logging.getLevelName(level)
        for k, v in LOG_LEVELS.items():
            if logging.getLevelName(v) == name:
                return k
    return 0


def _load_method_arguments(name, argtypes, args):
    """Preload argument values to avoid freeing any intermediate data."""
    if not argtypes:
        return args
    if len(args) != len(argtypes):
        raise ValueError(f"{name}: Arguments length does not match argtypes length")
    return [
        arg if hasattr(argtype, "_type_") else argtype.from_param(arg)
        for (arg, argtype) in zip(args, argtypes)
    ]


def _struct_dtor(ctype: type, address: int, dtor: Callable):
    value = ctype.from_address(address)
    if value:
        dtor(value)


def finalize_struct(instance, ctype):
    """Attach a struct destructor."""
    finalize(
        instance, _struct_dtor, ctype, addressof(instance), instance.__class__._cleanup
    )


def keepalive(instance, *depend):
    """Ensure that dependencies are kept alive as long as the instance."""
    finalize(instance, lambda *_args: None, *depend)


class LibLoad:
    def __init__(self, lib_name: str):
        """Load the CDLL library.

        The python module directory is searched first, followed by the usual
        library resolution for the current system.
        """
        self._cdll = None
        self._callbacks = {}
        self._cb_id = itertools.count(0)
        self._cfuncs = {}
        self._lib_name = lib_name
        self._log_cb = None
        self._log_enabled_cb = None
        self._methods = {}

        self._load_library()
        self._init_logger()

    def _load_library(self):
        lib_name = self._lib_name
        lib_prefix_mapping = {"win32": ""}
        lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
        try:
            os_name = sys.platform
            lib_prefix = lib_prefix_mapping.get(os_name, "lib")
            lib_suffix = lib_suffix_mapping.get(os_name, ".so")
            lib_path = os.path.join(
                os.path.dirname(__file__), "..", f"{lib_prefix}{lib_name}{lib_suffix}"
            )
            self._cdll = CDLL(lib_path)
            return
        except KeyError:
            LOGGER.debug("Unknown platform for shared library")
        except OSError:
            LOGGER.warning("Library not loaded from python package")

        lib_path = find_library(lib_name)
        if not lib_path:
            raise AskarError(
                AskarErrorCode.WRAPPER, f"Library not found in path: {lib_name}"
            )
        try:
            self._cdll = CDLL(lib_path)
        except OSError as e:
            raise AskarError(
                AskarErrorCode.WRAPPER, f"Error loading library: {lib_path}"
            ) from e

    def _init_logger(self):
        if self._log_cb:
            return

        logger = logging.getLogger(MODULE_NAME)
        if logging.getLevelName("TRACE") == "Level TRACE":
            # avoid redefining TRACE if another library has added it
            logging.addLevelName(5, "TRACE")

        self._log_cb_t = CFUNCTYPE(
            None, c_void_p, c_int32, c_char_p, c_char_p, c_char_p, c_char_p, c_int32
        )

        def _log_cb(
            _context,
            level: int,
            target: c_char_p,
            message: c_char_p,
            _module_path: c_char_p,
            file_name: c_char_p,
            line: int,
        ):
            logger.getChild("native." + target.decode().replace("::", ".")).log(
                LOG_LEVELS.get(level, level),
                "\t%s:%d | %s",
                file_name.decode() if file_name else None,
                line,
                message.decode(),
            )

        self._log_cb = self._log_cb_t(_log_cb)

        self._log_enabled_cb_t = CFUNCTYPE(c_int8, c_void_p, c_int32)

        def _enabled_cb(_context, level: int) -> bool:
            return self._cdll and logger.isEnabledFor(LOG_LEVELS.get(level, level))

        self._log_enabled_cb = self._log_enabled_cb_t(_enabled_cb)

        if os.getenv("RUST_LOG"):
            # level from environment
            level = -1
        else:
            # inherit current level from logger
            level = _convert_log_level(logger.level or logger.parent.level)

        set_logger = self.method(
            "askar_set_custom_logger",
            (c_void_p, c_void_p, c_void_p, c_void_p, c_int32),
            restype=c_int64,
        )
        if set_logger(
            None,  # context
            self._log_cb,
            self._log_enabled_cb,
            None,  # flush
            level,
        ):
            raise self.get_current_error(True)

        try:
            finalize(self, self.method("askar_clear_custom_logger", None, restype=None))
        except AttributeError:
            # method is new as of 0.2.5
            pass

    def invoke(self, name, argtypes, *args):
        """Perform a synchronous library function call."""
        method = self.method(name, argtypes, restype=c_int64)
        if not method:
            raise ValueError(f"FFI method not found: {name}")
        args = _load_method_arguments(name, argtypes, args)
        result = method(*args)
        if result:
            raise self.get_current_error(True)

    def invoke_async(
        self, name: str, argtypes, *args, return_type=None
    ) -> asyncio.Future:
        """Perform an asynchronous library function call."""
        method = self.method(name, (*argtypes, c_void_p, c_int64), restype=c_int64)
        if not method:
            raise ValueError(f"FFI method not found: {name}")
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        cb_info = self._cfuncs.get(name)
        if cb_info:
            cb = cb_info[1]
        else:
            cb_args = [c_int64, c_int64]
            if return_type:
                cb_args.append(return_type)
            cb_type = CFUNCTYPE(None, *cb_args)
            cb = cb_type(self._handle_callback)
            # must maintain a reference to cb_type, otherwise
            # it may be freed, resulting in memory errors.
            self._cfuncs[name] = (cb_type, cb)
        args = _load_method_arguments(name, argtypes, args)
        cb_id = next(self._cb_id)
        self._callbacks[cb_id] = (loop, fut, name)
        result = method(*args, cb, cb_id)
        if result:
            # FFI must not execute the callback if an error is returned
            err = self.get_current_error(True)
            if self._callbacks.pop(cb_id, None):
                self._fulfill_future(fut, None, err)
        return fut

    def invoke_dtor(self, name: str, *values, argtypes=None, restype=None):
        method = self.method(name, argtypes, restype=restype)
        if method:
            method(*values)

    def _handle_callback(self, cb_id: int, err: int, result=None):
        exc = self.get_current_error(True) if err else None
        cb = self._callbacks.pop(cb_id, None)
        if not cb:
            LOGGER.info("Callback already fulfilled: %s", cb_id)
            return
        (loop, fut, _name) = cb
        loop.call_soon_threadsafe(self._fulfill_future, fut, result, exc)

    def _fulfill_future(self, fut: asyncio.Future, result, err: Exception = None):
        """Resolve a callback future given the result and exception, if any."""
        if fut.cancelled():
            LOGGER.debug("callback previously cancelled")
        elif err:
            fut.set_exception(err)
        else:
            fut.set_result(result)

    def get_current_error(self, expect: bool = False) -> Optional[AskarError]:
        """
        Get the error result from the previous failed API method.

        Args:
            expect: Return a default error message if none is found
        """
        err_json = StrBuffer()
        method = self.method(
            "askar_get_current_error", (POINTER(StrBuffer),), restype=c_int64
        )
        if not method(byref(err_json)):
            try:
                msg = json.loads(err_json.value)
            except json.JSONDecodeError:
                LOGGER.warning("JSON decode error for askar_get_current_error")
                msg = None
            if msg and "message" in msg and "code" in msg:
                return AskarError(
                    AskarErrorCode(msg["code"]), msg["message"], msg.get("extra")
                )
            if not expect:
                return None
        return AskarError(AskarErrorCode.WRAPPER, "Unknown error")

    def method(self, name, argtypes, *, restype=None):
        """Access a method of the library."""
        method = self._methods.get(name)
        if not method:
            method = getattr(self._cdll, name, None)
            if not method:
                return None
            if argtypes:
                method.argtypes = argtypes
            method.restype = restype
            self._methods[name] = method
        return method

    def _cleanup(self):
        """Destructor."""
        if self._callbacks:

            def _wait_callbacks(cb):
                while cb:
                    time.sleep(0.01)

            th = threading.Thread(target=_wait_callbacks, args=(self._callbacks,))
            th.start()
            th.join(timeout=1.0)
            if th.is_alive():
                LOGGER.error(
                    "%s: Timed out waiting for callbacks to complete",
                    self._lib_name,
                )

        self.method("askar_terminate", None, restype=None)()


class Lib:
    """The loaded library instance."""

    INSTANCE = None
    LIB_NAME = "aries_askar"

    def __new__(cls, *args):
        """Class initializer."""
        inst = cls.INSTANCE and cls.INSTANCE()
        if inst is None:
            inst = super().__new__(cls, *args)
            inst._initlock = threading.Lock()
            inst._lib = None
            inst._objs = []
            # Keep a weak reference to the instance. This assumes that
            # at least one instance is assigned to a persistent variable.
            cls.INSTANCE = ref(inst)
            # Register finalizer to be called later than any derived objects.
            finalize(inst, cls._cleanup, inst._objs)
        return inst

    @property
    def loaded(self) -> LibLoad:
        """Access the loaded library instance, initializing it if necessary."""
        if not self._lib:
            with self._initlock:
                if not self._lib:
                    self._lib = LibLoad(self.__class__.LIB_NAME)
                    self._objs.append(self._lib)
        return self._lib

    def invoke(self, name, argtypes, *args):
        """Perform a synchronous library function call."""
        self.loaded.invoke(name, argtypes, *args)

    async def invoke_async(self, name: str, argtypes, *args, return_type=None):
        """Perform an asynchronous library function call."""
        return await self.loaded.invoke_async(
            name, argtypes, *args, return_type=return_type
        )

    def invoke_dtor(self, name: str, *args, argtypes=None, restype=None):
        """Call a destructor method."""
        if self._lib:
            self._lib.invoke_dtor(name, *args, argtypes=argtypes, restype=restype)

    def set_max_log_level(self, level: Union[str, int, None]):
        """Set the maximum log level for the library."""
        set_level = _convert_log_level(level)
        self.invoke("askar_set_max_log_level", (c_int32,), set_level)

    def version(self) -> str:
        """Get the version of the installed library."""
        return str(
            self.loaded.method(
                "askar_version",
                None,
                restype=StrBuffer,
            )()
        )

    def __repr__(self) -> str:
        loaded = self._lib is not None
        return f"<Lib('{self.__class__.LIB_NAME}', loaded={loaded})>"

    @classmethod
    def _cleanup(cls, objs):
        for obj in objs:
            obj._cleanup()


class RawBuffer(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("len", c_int64),
        ("data", POINTER(c_ubyte)),
    ]

    def __bool__(self) -> bool:
        return bool(self.data)

    def __bytes__(self) -> bytes:
        if not self.len:
            return b""
        return bytes(self.array)

    def __len__(self) -> int:
        return self.len.value

    @property
    def array(self) -> Array:
        return cast(self.data, POINTER(c_ubyte * self.len)).contents

    def __repr__(self) -> str:
        return f"<RawBuffer(len={self.len})>"


class FfiByteBuffer:
    """A byte buffer allocated by Python."""

    def __init__(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")

        if value is None:
            dlen = 0
            data = c_char_p()
        elif isinstance(value, memoryview):
            dlen = value.nbytes
            data = c_char_p(value.tobytes())
        elif isinstance(value, bytes):
            dlen = len(value)
            data = c_char_p(value)
        else:
            raise TypeError(f"Expected str or bytes value, got {type(value)}")
        self._dlen = dlen
        self._data = data

    def __bytes__(self) -> bytes:
        if not self._data:
            return b""
        return self._data.value

    def __len__(self) -> int:
        return self._dlen

    @property
    def _as_parameter_(self) -> RawBuffer:
        buf = RawBuffer(len=self._dlen, data=cast(self._data, POINTER(c_ubyte)))
        return buf

    @classmethod
    def from_param(cls, value):
        if isinstance(value, (ByteBuffer, FfiByteBuffer)):
            return value
        return cls(value)


class ByteBuffer(Structure):
    """A managed byte buffer allocated by the library."""

    _fields_ = [("buffer", RawBuffer)]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        finalize_struct(self, RawBuffer)

    @property
    def _as_parameter_(self):
        return self.buffer

    @property
    def array(self) -> Array:
        return self.buffer.array

    @property
    def view(self) -> memoryview:
        m = memoryview(self.array)
        keepalive(m, self)
        return m

    def __bytes__(self) -> bytes:
        return bytes(self.buffer)

    def __len__(self) -> int:
        return len(self.buffer)

    def __getitem__(self, idx) -> bytes:
        return bytes(self.buffer.array[idx])

    def __repr__(self) -> str:
        """Format byte buffer as a string."""
        return f"{self.__class__.__name__}({bytes(self)})"

    @classmethod
    def _cleanup(cls, buffer: RawBuffer):
        """Call the byte buffer destructor when this instance is released."""
        Lib().invoke_dtor("askar_buffer_free", buffer)


class FfiStr:
    """A string value allocated by Python."""

    def __init__(self, value=None):
        if value is None:
            value = c_char_p()
        elif isinstance(value, c_char_p):
            pass
        else:
            if isinstance(value, str):
                value = value.encode("utf-8")
            if not isinstance(value, bytes):
                raise TypeError(f"Expected string value, got {type(value)}")
            value = c_char_p(value)
        self.value = value

    @classmethod
    def from_param(cls, value):
        if isinstance(value, cls):
            return value
        return cls(value)

    @property
    def _as_parameter_(self):
        return self.value

    def __repr__(self) -> str:
        """Format handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class FfiJson:
    @classmethod
    def from_param(cls, value):
        if isinstance(value, FfiStr):
            return value
        if isinstance(value, dict):
            value = json.dumps(value)
        return FfiStr(value)


class FfiTagsJson:
    @classmethod
    def from_param(cls, tags):
        if isinstance(tags, FfiStr):
            return tags
        if tags:
            tags = json.dumps(
                {
                    name: (list(value) if isinstance(value, set) else value)
                    for name, value in tags.items()
                }
            )
        else:
            tags = None
        return FfiStr(tags)


class StrBuffer(Structure):
    """A string allocated by the library."""

    _fields_ = [("buffer", POINTER(c_char))]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        finalize_struct(self, c_char_p)

    def is_none(self) -> bool:
        """Check if the returned string pointer is null."""
        return not self.buffer

    def opt_str(self) -> Optional[str]:
        """Convert to an optional string."""
        val = self.value
        return val.decode("utf-8") if val is not None else None

    def __bool__(self) -> bool:
        return bool(self.buffer)

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        bval = self.value
        return bval if bval is not None else bytes()

    def __str__(self):
        """Convert to a string."""
        # not allowed to return None
        val = self.opt_str()
        return val if val is not None else ""

    @property
    def value(self) -> bytes:
        return cast(self.buffer, c_char_p).value

    @classmethod
    def _cleanup(cls, buffer: c_char_p):
        """Call the string destructor when this instance is released."""
        Lib().invoke_dtor("askar_string_free", buffer)


class AeadParams(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("nonce_length", c_int32),
        ("tag_length", c_int32),
    ]

    def __repr__(self) -> str:
        """Format AEAD params as a string."""
        return (
            f"<AeadParams(nonce_length={self.nonce_length}, "
            f"tag_length={self.tag_length})>"
        )


class Encrypted(Structure):
    """The result of an AEAD encryption operation."""

    _fields_ = [
        ("buffer", RawBuffer),
        ("tag_pos", c_int64),
        ("nonce_pos", c_int64),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        finalize_struct(self, RawBuffer)

    def __getitem__(self, idx) -> bytes:
        return bytes(self.buffer.array[idx])

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        return self.ciphertext_tag

    @property
    def ciphertext_tag(self) -> bytes:
        """Accessor for the combined ciphertext and tag."""
        p = self.nonce_pos
        return self[:p]

    @property
    def ciphertext(self) -> bytes:
        """Accessor for the ciphertext."""
        p = self.tag_pos
        return self[:p]

    @property
    def nonce(self) -> bytes:
        """Accessor for the nonce."""
        p = self.nonce_pos
        return self[p:]

    @property
    def tag(self) -> bytes:
        """Accessor for the authentication tag."""
        p1 = self.tag_pos
        p2 = self.nonce_pos
        return self[p1:p2]

    @property
    def parts(self) -> Tuple[bytes, bytes, bytes]:
        """Accessor for the ciphertext, tag, and nonce."""
        p1 = self.tag_pos
        p2 = self.nonce_pos
        return self[:p1], self[p1:p2], self[p2:]

    def __repr__(self) -> str:
        """Format encrypted value as a string."""
        return (
            f"<Encrypted(ciphertext={self.ciphertext}, tag={self.tag},"
            f" nonce={self.nonce})>"
        )

    @classmethod
    def _cleanup(cls, buffer: RawBuffer):
        """Call the byte buffer destructor when this instance is released."""
        Lib().invoke_dtor("askar_buffer_free", buffer)
