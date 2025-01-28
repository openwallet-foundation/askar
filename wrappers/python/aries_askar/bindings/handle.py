"""Handles for allocated resources."""

import logging

try:
    import orjson as json
except ImportError:
    import json

from ctypes import (
    POINTER,
    Structure,
    byref,
    c_int8,
    c_int32,
    c_int64,
    c_size_t,
    c_void_p,
)

from .lib import ByteBuffer, Lib, StrBuffer, entry_cache, finalize_struct


LOGGER = logging.getLogger(__name__)


class ArcHandle(Structure):
    """Base class for handle instances."""

    _fields_ = [
        ("value", c_size_t),
    ]
    _dtor_: str = None

    def __init__(self, value=0):
        """Initializer."""
        if isinstance(value, c_size_t):
            value = value.value
        if not isinstance(value, int):
            raise ValueError("Invalid handle")
        super().__init__(value=value)
        finalize_struct(self, c_size_t)

    @classmethod
    def from_param(cls, param):
        """Create from an input to a library method invocation."""
        if isinstance(param, cls):
            return param
        return cls(param)

    def __bool__(self) -> bool:
        """Convert to a boolean value."""
        return bool(self.value)

    def __repr__(self) -> str:
        """Format handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    @classmethod
    def _cleanup(cls, value: c_size_t):
        """Destructor."""
        if cls._dtor_:
            Lib().invoke_dtor(cls._dtor_, value)


class StoreHandle(ArcHandle):
    """Handle for an active Store instance."""

    async def close(self):
        """Manually close the store, waiting for any active connections."""
        if self.value:
            await Lib().invoke_async("askar_store_close", (c_size_t,), self.value)
            self.value = 0

    @classmethod
    def _cleanup(cls, value: c_size_t):
        """Close the store when there are no more references to this object."""
        Lib().invoke_dtor(
            "askar_store_close",
            value,
            None,
            0,
            argtypes=(c_size_t, c_void_p, c_int64),
            restype=c_int64,
        )


class SessionHandle(ArcHandle):
    """Handle for an active Session/Transaction instance."""

    async def close(self, commit: bool = False):
        """Manually close the session."""
        if self.value:
            await Lib().invoke_async(
                "askar_session_close",
                (c_size_t, c_int8),
                self.value,
                commit,
            )
            self.value = 0

    @classmethod
    def _cleanup(cls, value: c_size_t):
        """Close the session when there are no more references to this object."""
        Lib().invoke_dtor(
            "askar_session_close",
            value,
            0,
            None,
            0,
            argtypes=(c_size_t, c_int8, c_void_p, c_int64),
            restype=c_int64,
        )


class ScanHandle(ArcHandle):
    """Handle for an active Store scan instance."""

    _dtor_ = "askar_scan_free"


class EntryListHandle(ArcHandle):
    """Handle for an active EntryList instance."""

    _dtor_ = "askar_entry_list_free"

    @entry_cache
    def get_category(self, index: int) -> str:
        """Get the entry category."""
        cat = StrBuffer()
        Lib().invoke(
            "askar_entry_list_get_category",
            (EntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(cat),
        )
        return str(cat)

    @entry_cache
    def get_name(self, index: int) -> str:
        """Get the entry name."""
        name = StrBuffer()
        Lib().invoke(
            "askar_entry_list_get_name",
            (EntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(name),
        )
        return str(name)

    @entry_cache
    def get_value(self, index: int) -> memoryview:
        """Get the entry value."""
        val = ByteBuffer()
        Lib().invoke(
            "askar_entry_list_get_value",
            (EntryListHandle, c_int32, POINTER(ByteBuffer)),
            self,
            index,
            byref(val),
        )
        return val.view

    @entry_cache
    def get_tags(self, index: int) -> dict:
        """Get the entry tags."""
        tags = StrBuffer()
        Lib().invoke(
            "askar_entry_list_get_tags",
            (EntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(tags),
        )
        if tags:
            tags = json.loads(tags.value)
            for t in tags:
                if isinstance(tags[t], list):
                    tags[t] = set(tags[t])
        else:
            tags = dict()
        return tags


class KeyEntryListHandle(ArcHandle):
    """Handle for an active KeyEntryList instance."""

    _dtor_ = "askar_key_entry_list_free"

    @entry_cache
    def get_algorithm(self, index: int) -> str:
        """Get the key algorithm."""
        name = StrBuffer()
        Lib().invoke(
            "askar_key_entry_list_get_algorithm",
            (KeyEntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(name),
        )
        return str(name)

    @entry_cache
    def get_name(self, index: int) -> str:
        """Get the key name."""
        name = StrBuffer()
        Lib().invoke(
            "askar_key_entry_list_get_name",
            (KeyEntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(name),
        )
        return str(name)

    @entry_cache
    def get_metadata(self, index: int) -> str:
        """Get for the key metadata."""
        metadata = StrBuffer()
        Lib().invoke(
            "askar_key_entry_list_get_metadata",
            (KeyEntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(metadata),
        )
        return str(metadata)

    @entry_cache
    def get_tags(self, index: int) -> dict:
        """Get the key tags."""
        tags = StrBuffer()
        Lib().invoke(
            "askar_key_entry_list_get_tags",
            (KeyEntryListHandle, c_int32, POINTER(StrBuffer)),
            self,
            index,
            byref(tags),
        )
        return json.loads(tags.value) if tags else None

    def load_key(self, index: int) -> "LocalKeyHandle":
        """Load the key instance."""
        handle = LocalKeyHandle()
        Lib().invoke(
            "askar_key_entry_list_load_local",
            (KeyEntryListHandle, c_int32, POINTER(LocalKeyHandle)),
            self,
            index,
            byref(handle),
        )
        return handle


class LocalKeyHandle(ArcHandle):
    """Handle for an active LocalKey instance."""

    _dtor_ = "askar_key_free"


class StringListHandle(ArcHandle):
    """Handle for an active string list instance."""

    _dtor_ = "askar_string_list_free"
