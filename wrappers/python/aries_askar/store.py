"""Handling of Store instances."""

try:
    import orjson as json
except ImportError:
    import json

from typing import Optional, Sequence, Union

from . import bindings
from .bindings import (
    EntryListHandle,
    KeyEntryListHandle,
    ScanHandle,
    SessionHandle,
    StoreHandle,
)
from .error import AskarError, AskarErrorCode
from .key import Key
from .types import EntryOperation, KeyAlg


class Entry:
    """A single result from a store query."""

    _KEYS = ("name", "category", "value", "tags")

    def __init__(self, lst: EntryListHandle, pos: int):
        """Initialize the EntryHandle."""
        self._list = lst
        self._pos = pos

    @property
    def category(self) -> str:
        """Accessor for the entry category."""
        return self._list.get_category(self._pos)

    @property
    def name(self) -> str:
        """Accessor for the entry name."""
        return self._list.get_name(self._pos)

    @property
    def value(self) -> bytes:
        """Accessor for the entry value."""
        return bytes(self.raw_value)

    @property
    def raw_value(self) -> memoryview:
        """Accessor for the entry raw value."""
        return self._list.get_value(self._pos)

    @property
    def value_json(self) -> dict:
        """Accessor for the entry value as JSON."""
        return json.loads(self.value)

    @property
    def tags(self) -> dict:
        """Accessor for the entry tags."""
        return self._list.get_tags(self._pos)

    def keys(self) -> Sequence[str]:
        """Accessor for the list of mapping keys."""
        return Entry._KEYS

    def __getitem__(self, key):
        """Accessor for mapping value."""
        if key in Entry._KEYS:
            return getattr(self, key)
        return KeyError

    def __hasitem__(self, key) -> bool:
        """Check if a key is defined."""
        return key in Entry._KEYS

    def __repr__(self) -> str:
        """Format entry handle as a string."""
        return (
            f"<Entry(category={repr(self.category)}, name={repr(self.name)}, "
            f"value={self.value}, tags={self.tags})>"
        )


class EntryList:
    """A list of query results."""

    def __init__(self, handle: EntryListHandle, len: int = None):
        """Initialize the EntryList instance."""
        self._handle = handle
        self._pos = 0
        if handle:
            self._len = bindings.entry_list_count(self._handle) if len is None else len
        else:
            self._len = 0

    @property
    def handle(self) -> EntryListHandle:
        """Accessor for the entry list handle."""
        return self._handle

    def __getitem__(self, index) -> Entry:
        """Fetch an entry by index."""
        if not isinstance(index, int) or index < 0 or index >= self._len:
            return IndexError()
        return Entry(self._handle, index)

    def __iter__(self):
        """Iterate the entry list."""
        return IterEntryList(self)

    def __len__(self) -> int:
        """Accessor for the length of the list."""
        return self._len

    def __repr__(self) -> str:
        """Format entry list as a string."""
        return f"<EntryList(handle={self._handle}, pos={self._pos}, len={self._len})>"


class IterEntryList:
    """Iterator for the records in an entry list."""

    def __init__(self, list: EntryList):
        """Create a new entry list iterator."""
        self._handle = list._handle
        self._len = list._len
        self._pos = 0

    def __next__(self):
        """Fetch the next entry from the iterator."""
        if self._pos < self._len:
            entry = Entry(self._handle, self._pos)
            self._pos += 1
            return entry
        else:
            raise StopIteration


class KeyEntry:
    """Pointer to one result of a KeyEntryList instance."""

    def __init__(self, lst: KeyEntryListHandle, pos: int):
        """Initialize the KeyEntryHandle."""
        self._list = lst
        self._pos = pos

    @property
    def algorithm(self) -> str:
        """Accessor for the key entry algorithm."""
        return self._list.get_algorithm(self._pos)

    @property
    def name(self) -> str:
        """Accessor for the key entry name."""
        return self._list.get_name(self._pos)

    @property
    def metadata(self) -> str:
        """Accessor for the key entry metadata."""
        return self._list.get_metadata(self._pos)

    @property
    def key(self) -> Key:
        """Accessor for the key instance."""
        return Key(self._list.load_key(self._pos))

    @property
    def tags(self) -> dict:
        """Accessor for the entry tags."""
        return self._list.get_tags(self._pos)

    def __repr__(self) -> str:
        """Format key entry handle as a string."""
        return (
            f"<KeyEntry(algorithm={repr(self.algorithm)}, name={repr(self.name)}, "
            f"metadata={repr(self.metadata)}, key={self.key}, tags={self.tags})>"
        )


class KeyEntryList:
    """A list of key query results."""

    def __init__(self, handle: KeyEntryListHandle, len: int = None):
        """Initialize the KeyEntryList instance."""
        self._handle = handle
        self._pos = 0
        if handle:
            self._len = (
                bindings.key_entry_list_count(self._handle) if len is None else len
            )
        else:
            self._len = 0

    @property
    def handle(self) -> KeyEntryListHandle:
        """Accessor for the key entry list handle."""
        return self._handle

    def __getitem__(self, index) -> KeyEntry:
        """Fetch the key entry at a specific index."""
        if not isinstance(index, int) or index < 0 or index >= self._len:
            return IndexError()
        return KeyEntry(self._handle, index)

    def __iter__(self):
        """Create an iterator over the key entry list."""
        return IterKeyEntryList(self)

    def __len__(self) -> int:
        """Accessor for the number of key entries."""
        return self._len

    def __repr__(self) -> str:
        """Format this key entry list as a string."""
        return (
            f"<KeyEntryList(handle={self._handle}, pos={self._pos}, len={self._len})>"
        )


class IterKeyEntryList:
    """Iterator for a list of key entries."""

    def __init__(self, list: KeyEntryList):
        """Create a new key entry iterator."""
        self._handle = list._handle
        self._len = list._len
        self._pos = 0

    def __next__(self):
        """Fetch the next key entry from the iterator."""
        if self._pos < self._len:
            entry = KeyEntry(self._handle, self._pos)
            self._pos += 1
            return entry
        else:
            raise StopIteration


class Scan:
    """A scan of the Store."""

    def __init__(
        self,
        store: "Store",
        profile: Optional[str],
        category: Optional[str],
        tag_filter: Union[str, dict] = None,
        offset: int = None,
        limit: int = None,
        order_by: Optional[str] = None,
        descending: bool = False,
    ):
        """Initialize the Scan instance."""
        self._params = (
            store,
            profile,
            category,
            tag_filter,
            offset,
            limit,
            order_by,
            descending,
        )
        self._handle: ScanHandle = None
        self._buffer: IterEntryList = None

    @property
    def handle(self) -> ScanHandle:
        """Accessor for the scan handle."""
        return self._handle

    def __aiter__(self):
        """Async iterator for the scan results."""
        return self

    async def __anext__(self):
        """Fetch the next scan result during async iteration."""
        if self._handle is None:
            (
                store,
                profile,
                category,
                tag_filter,
                offset,
                limit,
                order_by,
                descending,
            ) = self._params
            self._params = None
            if not store.handle:
                raise AskarError(
                    AskarErrorCode.WRAPPER, "Cannot scan from closed store"
                )
            self._handle = await bindings.scan_start(
                store.handle,
                profile,
                category,
                tag_filter,
                offset,
                limit,
                order_by,
                descending,
            )
            list_handle = await bindings.scan_next(self._handle)
            self._buffer = iter(EntryList(list_handle)) if list_handle else None
        while True:
            if not self._buffer:
                raise StopAsyncIteration
            row = next(self._buffer, None)
            if row:
                return row
            list_handle = await bindings.scan_next(self._handle)
            self._buffer = iter(EntryList(list_handle)) if list_handle else None

    async def fetch_all(self) -> Sequence[Entry]:
        """Fetch all remaining rows."""
        rows = []
        async for row in self:
            rows.append(row)
        return rows

    def __repr__(self) -> str:
        """Format the scan instance as a string."""
        return f"<Scan(handle={self._handle})>"


class Store:
    """An opened Store instance."""

    def __init__(self, handle: StoreHandle, uri: str):
        """Initialize the Store instance."""
        self._handle = handle
        self._opener: OpenSession = None
        self._uri = uri

    @classmethod
    def generate_raw_key(cls, seed: Union[str, bytes] = None) -> str:
        """Generate a new raw key for a Store."""
        return bindings.generate_raw_key(seed)

    @property
    def handle(self) -> StoreHandle:
        """Accessor for the store handle."""
        return self._handle

    @property
    def uri(self) -> str:
        """Accessor for the store URI."""
        return self._uri

    @classmethod
    async def provision(
        cls,
        uri: str,
        key_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
        recreate: bool = False,
    ) -> "Store":
        """Provision a new store."""
        return Store(
            await bindings.store_provision(
                uri, key_method, pass_key, profile, recreate
            ),
            uri,
        )

    @classmethod
    async def open(
        cls,
        uri: str,
        key_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
    ) -> "Store":
        """Open an existing store."""
        return Store(await bindings.store_open(uri, key_method, pass_key, profile), uri)

    @classmethod
    async def remove(cls, uri: str) -> bool:
        """Remove an existing store."""
        return await bindings.store_remove(uri)

    async def __aenter__(self) -> "Session":
        """Start a new session when used as an async context."""
        if not self._opener:
            self._opener = OpenSession(self._handle, None, False)
        return await self._opener.__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        """Async context termination."""
        opener = self._opener
        self._opener = None
        return await opener.__aexit__(exc_type, exc, tb)

    async def create_profile(self, name: str = None) -> str:
        """
        Create a new profile in the store.

        Returns the name of the profile, which is automatically
        generated if not provided.
        """
        return await bindings.store_create_profile(self._handle, name)

    async def get_profile_name(self) -> str:
        """Accessor for the currently selected profile name."""
        return await bindings.store_get_profile_name(self._handle)

    async def get_default_profile(self) -> str:
        """Accessor for the default profile name when the store is opened."""
        return await bindings.store_get_default_profile(self._handle)

    async def set_default_profile(self, profile: str):
        """Setter for the default profile name when the store is opened."""
        await bindings.store_set_default_profile(self._handle, profile)

    async def remove_profile(self, name: str) -> bool:
        """Remove a profile from the store."""
        return await bindings.store_remove_profile(self._handle, name)

    async def list_profiles(self) -> Sequence[str]:
        """List the profile identifiers present in the store."""
        return await bindings.store_list_profiles(self._handle)

    async def rename_profile(self, from_name: str, to_name: str):
        """Remove a profile from the store."""
        if not await bindings.store_rename_profile(self._handle, from_name, to_name):
            raise AskarError(AskarErrorCode.WRAPPER, "Profile renaming failed")

    async def rekey(
        self,
        key_method: str = None,
        pass_key: str = None,
    ):
        """Update the master encryption key of the store."""
        await bindings.store_rekey(self._handle, key_method, pass_key)

    async def copy_to(
        self,
        target_uri: str,
        key_method: str = None,
        pass_key: str = None,
        *,
        recreate: bool = False,
    ) -> "Store":
        """Copy the store contents to a new location."""
        return Store(
            await bindings.store_copy(
                self._handle, target_uri, key_method, pass_key, recreate
            ),
            target_uri,
        )

    async def copy_profile_to(
        self,
        to_store: "Store",
        from_profile: str,
        to_profile: Optional[str] = None,
    ):
        """Copy a profile from this Store instance to another Store."""
        await bindings.store_copy_profile(
            self._handle, to_store._handle, from_profile, to_profile
        )

    def scan(
        self,
        category: str = None,
        tag_filter: Union[str, dict] = None,
        offset: int = None,
        limit: int = None,
        profile: str = None,
        order_by: Optional[str] = None,
        descending: bool = False,
    ) -> Scan:
        """Start a new record scan."""
        return Scan(
            self, profile, category, tag_filter, offset, limit, order_by, descending
        )

    def session(self, profile: str = None) -> "OpenSession":
        """Open a new session on the store without starting a transaction."""
        return OpenSession(self._handle, profile, False)

    def transaction(self, profile: str = None, *, autocommit=None) -> "OpenSession":
        """Open a new transactional session on the store."""
        return OpenSession(self._handle, profile, True, autocommit)

    async def close(self, *, remove: bool = False) -> bool:
        """Close and free the pool instance."""
        self._opener = None
        if self._handle:
            await self._handle.close()
            self._handle = None
        if remove:
            return await Store.remove(self._uri)
        else:
            return False

    def __repr__(self) -> str:
        """Format the store instance as a string."""
        return f"<Store(handle={self._handle})>"


class Session:
    """An opened Session instance."""

    def __init__(
        self,
        store: StoreHandle,
        handle: SessionHandle,
        is_txn: bool = False,
        autocommit: Optional[bool] = None,
    ):
        """Initialize the Session instance."""
        self._store = store
        self._handle = handle
        self._is_txn = is_txn
        self._autocommit = autocommit or False

    @property
    def autocommit(self) -> bool:
        """Determine if autocommit is enabled for a transaction."""
        return self._autocommit

    @autocommit.setter
    def autocommit(self, val: bool):
        """Set the autocommit flag for a transaction."""
        self._autocommit = val or False

    @property
    def is_transaction(self) -> bool:
        """Determine if the session is a transaction."""
        return self._is_txn

    @property
    def handle(self) -> SessionHandle:
        """Accessor for the SessionHandle instance."""
        return self._handle

    async def count(
        self, category: str = None, tag_filter: Union[str, dict] = None
    ) -> int:
        """Count the records matching a category and tag filter."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot count from closed session")
        return await bindings.session_count(self._handle, category, tag_filter)

    async def fetch(
        self, category: str, name: str, *, for_update: bool = False
    ) -> Optional[Entry]:
        """Fetch a record from the store by category and name."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot fetch from closed session")
        result_handle = await bindings.session_fetch(
            self._handle, category, name, for_update
        )
        return next(iter(EntryList(result_handle, 1)), None) if result_handle else None

    async def fetch_all(
        self,
        category: str = None,
        tag_filter: Union[str, dict] = None,
        limit: int = None,
        *,
        order_by: Optional[str] = None,
        descending: bool = False,
        for_update: bool = False,
    ) -> EntryList:
        """Fetch all records matching a category and tag filter."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot fetch from closed session")
        return EntryList(
            await bindings.session_fetch_all(
                self._handle,
                category,
                tag_filter,
                limit,
                order_by,
                descending,
                for_update,
            )
        )

    async def insert(
        self,
        category: str,
        name: str,
        value: Union[str, bytes] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        """Insert a new record into the store."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self._handle, EntryOperation.INSERT, category, name, value, tags, expiry_ms
        )

    async def replace(
        self,
        category: str,
        name: str,
        value: Union[str, bytes] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        """Replace a record in the store matching a category and name."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self._handle, EntryOperation.REPLACE, category, name, value, tags, expiry_ms
        )

    async def remove(
        self,
        category: str,
        name: str,
    ):
        """Remove a record by category and name."""
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        await bindings.session_update(
            self._handle, EntryOperation.REMOVE, category, name
        )

    async def remove_all(
        self,
        category: str = None,
        tag_filter: Union[str, dict] = None,
    ) -> int:
        """Remove all records matching a category and tag filter."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot remove all for closed session"
            )
        return await bindings.session_remove_all(self._handle, category, tag_filter)

    async def insert_key(
        self,
        name: str,
        key: Key,
        *,
        metadata: str = None,
        tags: dict = None,
        expiry_ms: int = None,
    ) -> str:
        """Insert a new key into the store."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot insert key with closed session"
            )
        return str(
            await bindings.session_insert_key(
                self._handle, key._handle, name, metadata, tags, expiry_ms
            )
        )

    async def fetch_key(
        self, name: str, *, for_update: bool = False
    ) -> Optional[KeyEntry]:
        """Fetch a key in the store by name."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot fetch key from closed session"
            )
        result_handle = await bindings.session_fetch_key(self._handle, name, for_update)
        return (
            next(iter(KeyEntryList(result_handle, 1)), None) if result_handle else None
        )

    async def fetch_all_keys(
        self,
        *,
        alg: Union[str, KeyAlg] = None,
        thumbprint: str = None,
        tag_filter: Union[str, dict] = None,
        limit: int = None,
        for_update: bool = False,
    ) -> KeyEntryList:
        """Fetch a set of keys in the store.."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot fetch key from closed session"
            )
        result_handle = await bindings.session_fetch_all_keys(
            self._handle, alg, thumbprint, tag_filter, limit, for_update
        )
        return KeyEntryList(result_handle)

    async def update_key(
        self,
        name: str,
        *,
        metadata: str = None,
        tags: dict = None,
        expiry_ms: int = None,
    ):
        """Update details of a key in the store."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot update key with closed session"
            )
        await bindings.session_update_key(self._handle, name, metadata, tags, expiry_ms)

    async def remove_key(self, name: str):
        """Remove a key from the store."""
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot remove key with closed session"
            )
        await bindings.session_remove_key(self._handle, name)

    async def commit(self):
        """Commit the current transaction and close the session."""
        if not self._is_txn:
            raise AskarError(AskarErrorCode.WRAPPER, "Session is not a transaction")
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot commit closed transaction")
        await self._handle.close(commit=True)
        self._handle = None

    async def rollback(self):
        """Roll back the current transaction and close the session."""
        if not self._is_txn:
            raise AskarError(AskarErrorCode.WRAPPER, "Session is not a transaction")
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot rollback closed transaction"
            )
        await self._handle.close(commit=False)
        self._handle = None

    async def close(self):
        """Close the session without specifying the commit behaviour."""
        if self._handle:
            await self._handle.close(commit=self._autocommit)
            self._handle = None

    def __repr__(self) -> str:
        """Format a string representation of the session."""
        return (
            f"<Session(handle={self._handle}, "
            f"is_transaction={self._is_txn}, "
            f"autocommit={self._autocommit})>"
        )


class OpenSession:
    """A pending session instance."""

    def __init__(
        self,
        store: StoreHandle,
        profile: Optional[str],
        is_txn: bool,
        autocommit: Optional[bool] = None,
    ):
        """Initialize the OpenSession instance."""
        self._store = store
        self._profile = profile
        self._is_txn = is_txn
        self._autocommit = autocommit
        self._session: Session = None

    @property
    def is_transaction(self) -> bool:
        """Determine if this instance would begin a transaction."""
        return self._is_txn

    async def _open(self) -> Session:
        """Open this pending session."""
        if not self._store:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot start session from closed store"
            )
        if self._session:
            raise AskarError(AskarErrorCode.WRAPPER, "Session already opened")
        return Session(
            self._store,
            await bindings.session_start(self._store, self._profile, self._is_txn),
            self._is_txn,
            self._autocommit,
        )

    def __await__(self) -> Session:
        """Open this pending session."""
        return self._open().__await__()

    async def __aenter__(self) -> Session:
        """Use this pending session as an async context manager, opening the session."""
        self._session = await self._open()
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        """Terminate the async context and close the session."""
        session = self._session
        self._session = None
        if exc:
            session.autocommit = False
        await session.close()
