"""Low-level interaction with the Askar library."""

import asyncio
import logging

try:
    import orjson as json
except ImportError:
    import json

from ctypes import POINTER, byref, c_int8, c_int32, c_int64
from typing import Optional, Sequence, Union

from ..types import EntryOperation, KeyAlg, KeyBackend, SeedMethod

from .lib import (
    AeadParams,
    ByteBuffer,
    Encrypted,
    FfiByteBuffer,
    FfiJson,
    FfiStr,
    FfiTagsJson,
    Lib,
    StrBuffer,
)
from .handle import (
    EntryListHandle,
    KeyEntryListHandle,
    LocalKeyHandle,
    ScanHandle,
    SessionHandle,
    StoreHandle,
    StringListHandle,
)


LIB = Lib()
LOGGER = logging.getLogger(__name__)
MODULE_NAME = __name__.split(".")[0]


def get_library(init: bool = True) -> Lib:
    """Return the library instance, loading it if necessary."""
    global LIB
    if LIB and init:
        # preload library - required to create handle instances
        LIB.loaded
    return LIB


def set_max_log_level(level: Union[str, int, None]):
    """Set the maximum logging level."""
    get_library().set_max_log_level(level)


def invoke(name, argtypes, *args):
    """Perform a synchronous library function call."""
    get_library().invoke(name, argtypes, *args)


def invoke_async(name: str, argtypes, *args, return_type=None) -> asyncio.Future:
    """Perform an asynchronous library function call."""
    return get_library().invoke_async(name, argtypes, *args, return_type=return_type)


def generate_raw_key(seed: Union[str, bytes] = None) -> str:
    """Generate a new raw store wrapping key."""
    key = StrBuffer()
    invoke(
        "askar_store_generate_raw_key",
        (FfiByteBuffer, POINTER(StrBuffer)),
        seed,
        byref(key),
    )
    return str(key)


def version() -> str:
    """Get the version of the installed library."""
    return get_library().version()


async def store_open(
    uri: str,
    key_method: Optional[str] = None,
    pass_key: Optional[str] = None,
    profile: Optional[str] = None,
) -> StoreHandle:
    """Open an existing Store and return the open handle."""
    return await invoke_async(
        "askar_store_open",
        (FfiStr, FfiStr, FfiStr, FfiStr),
        uri,
        key_method and key_method.lower(),
        pass_key,
        profile,
        return_type=StoreHandle,
    )


async def store_provision(
    uri: str,
    key_method: Optional[str] = None,
    pass_key: Optional[str] = None,
    profile: Optional[str] = None,
    recreate: bool = False,
) -> StoreHandle:
    """Provision a new Store and return the open handle."""
    return await invoke_async(
        "askar_store_provision",
        (FfiStr, FfiStr, FfiStr, FfiStr, c_int8),
        uri,
        key_method and key_method.lower(),
        pass_key,
        profile,
        recreate,
        return_type=StoreHandle,
    )


async def store_create_profile(handle: StoreHandle, name: Optional[str] = None) -> str:
    """Create a new profile in a Store."""
    return str(
        await invoke_async(
            "askar_store_create_profile",
            (StoreHandle, FfiStr),
            handle,
            name,
            return_type=StrBuffer,
        )
    )


async def store_get_profile_name(handle: StoreHandle) -> str:
    """Get the name of the selected Store instance profile."""
    return str(
        await invoke_async(
            "askar_store_get_profile_name",
            (StoreHandle,),
            handle,
            return_type=StrBuffer,
        )
    )


async def store_get_default_profile(handle: StoreHandle) -> str:
    """Get the name of the default Store instance profile."""
    return str(
        await invoke_async(
            "askar_store_get_default_profile",
            (StoreHandle,),
            handle,
            return_type=StrBuffer,
        )
    )


async def store_set_default_profile(handle: StoreHandle, profile: str):
    """Set the name of the default Store instance profile."""
    await invoke_async(
        "askar_store_set_default_profile",
        (StoreHandle, FfiStr),
        handle,
        profile,
    )


async def store_remove_profile(handle: StoreHandle, name: str) -> bool:
    """Remove an existing profile from a Store."""
    return (
        await invoke_async(
            "askar_store_remove_profile",
            (StoreHandle, FfiStr),
            handle,
            name,
            return_type=c_int8,
        )
        != 0
    )


async def store_rename_profile(
    handle: StoreHandle, from_name: str, to_name: str
) -> bool:
    """Change the name of an existing profile in a Store."""
    return (
        await invoke_async(
            "askar_store_rename_profile",
            (StoreHandle, FfiStr, FfiStr),
            handle,
            from_name,
            to_name,
            return_type=c_int8,
        )
        == 1
    )


async def store_list_profiles(handle: StoreHandle) -> Sequence[str]:
    """List the profile identifiers present in a Store."""
    handle = await invoke_async(
        "askar_store_list_profiles",
        (StoreHandle,),
        handle,
        return_type=StringListHandle,
    )
    count = c_int32()
    invoke(
        "askar_string_list_count",
        (StringListHandle, POINTER(c_int32)),
        handle,
        byref(count),
    )
    ret = []
    for idx in range(count.value):
        buf = StrBuffer()
        invoke(
            "askar_string_list_get_item",
            (StringListHandle, c_int32, POINTER(StrBuffer)),
            handle,
            idx,
            byref(buf),
        )
        ret.append(str(buf))

    return ret


async def store_rekey(
    handle: StoreHandle,
    key_method: Optional[str] = None,
    pass_key: Optional[str] = None,
) -> StoreHandle:
    """Replace the store key on a Store."""
    return await invoke_async(
        "askar_store_rekey",
        (StoreHandle, FfiStr, FfiStr),
        handle,
        key_method and key_method.lower(),
        pass_key,
        return_type=c_int8,
    )


async def store_copy(
    handle: StoreHandle,
    target_uri: str,
    key_method: Optional[str] = None,
    pass_key: Optional[str] = None,
    recreate: bool = False,
) -> StoreHandle:
    """Copy the Store contents to a new location."""
    return await invoke_async(
        "askar_store_copy",
        (StoreHandle, FfiStr, FfiStr, FfiStr, c_int8),
        handle,
        target_uri,
        key_method and key_method.lower(),
        pass_key,
        recreate,
        return_type=StoreHandle,
    )


async def store_copy_profile(
    from_handle: StoreHandle,
    to_handle: StoreHandle,
    from_profile: str,
    to_profile: Optional[str] = None,
):
    """Copy a profile from one Store instance to another."""
    await invoke_async(
        "askar_store_copy_profile",
        (StoreHandle, StoreHandle, FfiStr, FfiStr),
        from_handle,
        to_handle,
        from_profile,
        to_profile,
    )


async def store_remove(uri: str) -> bool:
    """Remove an existing Store, if any."""
    return (
        await invoke_async(
            "askar_store_remove",
            (FfiStr,),
            uri,
            return_type=c_int8,
        )
        != 0
    )


async def session_start(
    handle: StoreHandle, profile: Optional[str] = None, as_transaction: bool = False
) -> SessionHandle:
    """Start a new session with an open Store."""
    handle = await invoke_async(
        "askar_session_start",
        (StoreHandle, FfiStr, c_int8),
        handle,
        profile,
        as_transaction,
        return_type=SessionHandle,
    )
    return handle


async def session_count(
    handle: SessionHandle,
    category: Optional[str] = None,
    tag_filter: Optional[Union[str, dict]] = None,
) -> int:
    """Count rows in the Store."""
    return int(
        await invoke_async(
            "askar_session_count",
            (SessionHandle, FfiStr, FfiJson),
            handle,
            category,
            tag_filter,
            return_type=c_int64,
        )
    )


async def session_fetch(
    handle: SessionHandle, category: str, name: str, for_update: bool = False
) -> EntryListHandle:
    """Fetch a row from the Store."""
    return await invoke_async(
        "askar_session_fetch",
        (SessionHandle, FfiStr, FfiStr, c_int8),
        handle,
        category,
        name,
        for_update,
        return_type=EntryListHandle,
    )


async def session_fetch_all(
    handle: SessionHandle,
    category: Optional[str] = None,
    tag_filter: Optional[Union[str, dict]] = None,
    limit: Optional[int] = None,
    order_by: Optional[str] = None,
    descending: bool = False,
    for_update: bool = False,
) -> EntryListHandle:
    """Fetch all matching rows in the Store."""
    return await invoke_async(
        "askar_session_fetch_all",
        (SessionHandle, FfiStr, FfiJson, c_int64, FfiStr, c_int8, c_int8),
        handle,
        category,
        tag_filter,
        limit if limit is not None else -1,
        order_by,
        descending,
        for_update,
        return_type=EntryListHandle,
    )


async def session_remove_all(
    handle: SessionHandle,
    category: Optional[str] = None,
    tag_filter: Optional[Union[str, dict]] = None,
) -> int:
    """Remove all matching rows in the Store."""
    return int(
        await invoke_async(
            "askar_session_remove_all",
            (SessionHandle, FfiStr, FfiJson),
            handle,
            category,
            tag_filter,
            return_type=c_int64,
        )
    )


async def session_update(
    handle: SessionHandle,
    operation: EntryOperation,
    category: str,
    name: str,
    value: Optional[Union[str, bytes]] = None,
    tags: Optional[dict] = None,
    expiry_ms: Optional[int] = None,
):
    """Update a Store by inserting, updating, or removing a record."""
    return await invoke_async(
        "askar_session_update",
        (SessionHandle, c_int8, FfiStr, FfiStr, FfiByteBuffer, FfiTagsJson, c_int64),
        handle,
        operation.value,
        category,
        name,
        value,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_insert_key(
    handle: SessionHandle,
    key_handle: LocalKeyHandle,
    name: str,
    metadata: Optional[str] = None,
    tags: Optional[dict] = None,
    expiry_ms: Optional[int] = None,
):
    return await invoke_async(
        "askar_session_insert_key",
        (SessionHandle, LocalKeyHandle, FfiStr, FfiStr, FfiTagsJson, c_int64),
        handle,
        key_handle,
        name,
        metadata,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_fetch_key(
    handle: SessionHandle, name: str, for_update: bool = False
) -> KeyEntryListHandle:
    return await invoke_async(
        "askar_session_fetch_key",
        (SessionHandle, FfiStr, c_int8),
        handle,
        name,
        for_update,
        return_type=KeyEntryListHandle,
    )


async def session_fetch_all_keys(
    handle: SessionHandle,
    alg: Optional[Union[str, KeyAlg]] = None,
    thumbprint: Optional[str] = None,
    tag_filter: Optional[Union[str, dict]] = None,
    limit: Optional[int] = None,
    for_update: bool = False,
) -> KeyEntryListHandle:
    """Fetch all matching keys in the Store."""
    if isinstance(alg, KeyAlg):
        alg = alg.value
    return await invoke_async(
        "askar_session_fetch_all_keys",
        (SessionHandle, FfiStr, FfiStr, FfiJson, c_int64, c_int8),
        handle,
        alg,
        thumbprint,
        tag_filter,
        limit if limit is not None else -1,
        for_update,
        return_type=KeyEntryListHandle,
    )


async def session_update_key(
    handle: SessionHandle,
    name: str,
    metadata: Optional[str] = None,
    tags: Optional[dict] = None,
    expiry_ms: Optional[int] = None,
):
    await invoke_async(
        "askar_session_update_key",
        (SessionHandle, FfiStr, FfiStr, FfiTagsJson, c_int64),
        handle,
        name,
        metadata,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_remove_key(handle: SessionHandle, name: str):
    await invoke_async(
        "askar_session_remove_key",
        (SessionHandle, FfiStr),
        handle,
        name,
    )


async def scan_start(
    handle: StoreHandle,
    profile: Optional[str],
    category: Optional[str] = None,
    tag_filter: Optional[Union[str, dict]] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    order_by: Optional[str] = None,
    descending: bool = False,
) -> ScanHandle:
    """Create a new Scan against the Store."""
    return await invoke_async(
        "askar_scan_start",
        (StoreHandle, FfiStr, FfiStr, FfiJson, c_int64, c_int64, FfiStr, c_int8),
        handle,
        profile,
        category,
        tag_filter,
        offset or 0,
        limit if limit is not None else -1,
        order_by,
        descending,
        return_type=ScanHandle,
    )


async def scan_next(handle: ScanHandle) -> EntryListHandle:
    return await invoke_async(
        "askar_scan_next", (ScanHandle,), handle, return_type=EntryListHandle
    )


def entry_list_count(handle: EntryListHandle) -> int:
    len = c_int32()
    invoke(
        "askar_entry_list_count",
        (EntryListHandle, POINTER(c_int32)),
        handle,
        byref(len),
    )
    return len.value


def key_entry_list_count(handle: KeyEntryListHandle) -> int:
    len = c_int32()
    invoke(
        "askar_key_entry_list_count",
        (KeyEntryListHandle, POINTER(c_int32)),
        handle,
        byref(len),
    )
    return len.value


def key_generate(
    alg: Union[str, KeyAlg],
    backend: Optional[Union[KeyBackend, str]] = None,
    ephemeral: bool = False,
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(backend, KeyBackend):
        backend = backend.value
    invoke(
        "askar_key_generate",
        (FfiStr, FfiStr, c_int8, POINTER(LocalKeyHandle)),
        alg,
        backend,
        ephemeral,
        byref(handle),
    )
    return handle


def key_from_seed(
    alg: Union[str, KeyAlg],
    seed: Union[str, bytes, ByteBuffer],
    method: Optional[Union[str, SeedMethod]] = None,
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(method, SeedMethod):
        method = method.value
    invoke(
        "askar_key_from_seed",
        (FfiStr, FfiByteBuffer, FfiStr, POINTER(LocalKeyHandle)),
        alg,
        seed,
        method,
        byref(handle),
    )
    return handle


def key_from_public_bytes(
    alg: Union[str, KeyAlg], public: Union[bytes, ByteBuffer]
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_public_bytes",
        (FfiStr, FfiByteBuffer, POINTER(LocalKeyHandle)),
        alg,
        public,
        byref(handle),
    )
    return handle


def key_get_public_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_get_public_bytes",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(buf),
    )
    return buf


def key_from_secret_bytes(
    alg: Union[str, KeyAlg], secret: Union[bytes, ByteBuffer]
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_secret_bytes",
        (FfiStr, FfiByteBuffer, POINTER(LocalKeyHandle)),
        alg,
        secret,
        byref(handle),
    )
    return handle


def key_get_secret_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_get_secret_bytes",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(buf),
    )
    return buf


def key_from_jwk(jwk: Union[dict, str, bytes]) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(jwk, dict):
        jwk = json.dumps(jwk)
    invoke(
        "askar_key_from_jwk",
        (FfiByteBuffer, POINTER(LocalKeyHandle)),
        jwk,
        byref(handle),
    )
    return handle


def key_convert(handle: LocalKeyHandle, alg: Union[str, KeyAlg]) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_convert",
        (LocalKeyHandle, FfiStr, POINTER(LocalKeyHandle)),
        handle,
        alg,
        byref(key),
    )
    return key


def key_exchange(
    alg: Union[str, KeyAlg], sk_handle: LocalKeyHandle, pk_handle: LocalKeyHandle
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_key_exchange",
        (FfiStr, LocalKeyHandle, LocalKeyHandle, POINTER(LocalKeyHandle)),
        alg,
        sk_handle,
        pk_handle,
        byref(key),
    )
    return key


def key_get_algorithm(handle: LocalKeyHandle) -> str:
    alg = StrBuffer()
    invoke(
        "askar_key_get_algorithm",
        (LocalKeyHandle, POINTER(StrBuffer)),
        handle,
        byref(alg),
    )
    return str(alg)


def key_get_ephemeral(handle: LocalKeyHandle) -> bool:
    eph = c_int8()
    invoke(
        "askar_key_get_ephemeral",
        (LocalKeyHandle, POINTER(c_int8)),
        handle,
        byref(eph),
    )
    return eph.value != 0


def key_get_jwk_public(
    handle: LocalKeyHandle, alg: Optional[Union[str, KeyAlg]] = None
) -> str:
    jwk = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_get_jwk_public",
        (LocalKeyHandle, FfiStr, POINTER(StrBuffer)),
        handle,
        alg,
        byref(jwk),
    )
    return str(jwk)


def key_get_jwk_secret(handle: LocalKeyHandle) -> ByteBuffer:
    sec = ByteBuffer()
    invoke(
        "askar_key_get_jwk_secret",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(sec),
    )
    return sec


def key_get_jwk_thumbprint(
    handle: LocalKeyHandle, alg: Optional[Union[str, KeyAlg]] = None
) -> str:
    thumb = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_get_jwk_thumbprint",
        (LocalKeyHandle, FfiStr, POINTER(StrBuffer)),
        handle,
        alg,
        byref(thumb),
    )
    return str(thumb)


def key_aead_get_params(handle: LocalKeyHandle) -> AeadParams:
    params = AeadParams()
    invoke(
        "askar_key_aead_get_params",
        (LocalKeyHandle, POINTER(AeadParams)),
        handle,
        byref(params),
    )
    return params


def key_aead_random_nonce(handle: LocalKeyHandle) -> ByteBuffer:
    nonce = ByteBuffer()
    invoke(
        "askar_key_aead_random_nonce",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(nonce),
    )
    return nonce


def key_aead_encrypt(
    handle: LocalKeyHandle,
    input: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
    aad: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    enc = Encrypted()
    invoke(
        "askar_key_aead_encrypt",
        (
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(Encrypted),
        ),
        handle,
        input,
        nonce,
        aad,
        byref(enc),
    )
    return enc


def key_aead_decrypt(
    handle: LocalKeyHandle,
    ciphertext: Union[bytes, ByteBuffer, Encrypted],
    nonce: Union[bytes, ByteBuffer],
    tag: Optional[Union[bytes, ByteBuffer]],
    aad: Optional[Union[bytes, ByteBuffer]],
) -> ByteBuffer:
    dec = ByteBuffer()
    if isinstance(ciphertext, Encrypted):
        nonce = ciphertext.nonce
        ciphertext = ciphertext.ciphertext_tag
    invoke(
        "askar_key_aead_decrypt",
        (
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        handle,
        ciphertext,
        nonce,
        tag,
        aad,
        byref(dec),
    )
    return dec


def key_sign_message(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    sig_type: Optional[str],
) -> ByteBuffer:
    sig = ByteBuffer()
    invoke(
        "askar_key_sign_message",
        (LocalKeyHandle, FfiByteBuffer, FfiStr, POINTER(ByteBuffer)),
        handle,
        message,
        sig_type,
        byref(sig),
    )
    return sig


def key_verify_signature(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    signature: Union[bytes, ByteBuffer],
    sig_type: Optional[str],
) -> bool:
    verify = c_int8()
    invoke(
        "askar_key_verify_signature",
        (LocalKeyHandle, FfiByteBuffer, FfiByteBuffer, FfiStr, POINTER(c_int8)),
        handle,
        message,
        signature,
        sig_type,
        byref(verify),
    )
    return verify.value != 0


def key_wrap_key(
    handle: LocalKeyHandle,
    other: LocalKeyHandle,
    nonce: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    wrapped = Encrypted()
    invoke(
        "askar_key_wrap_key",
        (LocalKeyHandle, LocalKeyHandle, FfiByteBuffer, POINTER(Encrypted)),
        handle,
        other,
        nonce,
        byref(wrapped),
    )
    return wrapped


def key_unwrap_key(
    handle: LocalKeyHandle,
    alg: Union[str, KeyAlg],
    ciphertext: Union[bytes, ByteBuffer, Encrypted],
    nonce: Union[bytes, ByteBuffer],
    tag: Optional[Union[bytes, ByteBuffer]],
) -> LocalKeyHandle:
    result = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(ciphertext, Encrypted):
        ciphertext = ciphertext.ciphertext_tag
    invoke(
        "askar_key_unwrap_key",
        (
            LocalKeyHandle,
            FfiStr,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(LocalKeyHandle),
        ),
        handle,
        alg,
        ciphertext,
        nonce,
        tag,
        byref(result),
    )
    return result


def key_get_supported_backends() -> Sequence[str]:
    handle = StringListHandle()
    invoke(
        "askar_key_get_supported_backends", (POINTER(StringListHandle),), byref(handle)
    )
    count = c_int32()
    invoke(
        "askar_string_list_count",
        (StringListHandle, POINTER(c_int32)),
        handle,
        byref(count),
    )
    ret = []
    for idx in range(count.value):
        buf = StrBuffer()
        invoke(
            "askar_string_list_get_item",
            (StringListHandle, c_int32, POINTER(StrBuffer)),
            handle,
            idx,
            byref(buf),
        )
        ret.append(str(buf))

    return ret


def key_crypto_box_random_nonce() -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_random_nonce",
        (POINTER(ByteBuffer),),
        byref(buf),
    )
    return buf


def key_crypto_box(
    recip_handle: LocalKeyHandle,
    sender_handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box",
        (
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        recip_handle,
        sender_handle,
        message,
        nonce,
        byref(buf),
    )
    return buf


def key_crypto_box_open(
    recip_handle: LocalKeyHandle,
    sender_handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_open",
        (
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        recip_handle,
        sender_handle,
        message,
        nonce,
        byref(buf),
    )
    return buf


def key_crypto_box_seal(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_seal",
        (LocalKeyHandle, FfiByteBuffer, POINTER(ByteBuffer)),
        handle,
        message,
        byref(buf),
    )
    return buf


def key_crypto_box_seal_open(
    handle: LocalKeyHandle,
    ciphertext: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_seal_open",
        (LocalKeyHandle, FfiByteBuffer, POINTER(ByteBuffer)),
        handle,
        ciphertext,
        byref(buf),
    )
    return buf


def key_derive_ecdh_es(
    key_alg: Union[str, KeyAlg],
    ephem_key: LocalKeyHandle,
    receiver_key: LocalKeyHandle,
    alg_id: Union[bytes, str, ByteBuffer],
    apu: Union[bytes, str, ByteBuffer],
    apv: Union[bytes, str, ByteBuffer],
    receive: bool,
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(key_alg, KeyAlg):
        key_alg = key_alg.value
    invoke(
        "askar_key_derive_ecdh_es",
        (
            FfiStr,
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            c_int8,
            POINTER(LocalKeyHandle),
        ),
        key_alg,
        ephem_key,
        receiver_key,
        alg_id,
        apu,
        apv,
        receive,
        byref(key),
    )
    return key


def key_derive_ecdh_1pu(
    key_alg: Union[str, KeyAlg],
    ephem_key: LocalKeyHandle,
    sender_key: LocalKeyHandle,
    receiver_key: LocalKeyHandle,
    alg_id: Union[bytes, str, ByteBuffer],
    apu: Union[bytes, str, ByteBuffer],
    apv: Union[bytes, str, ByteBuffer],
    cc_tag: Optional[Union[bytes, ByteBuffer]],
    receive: bool,
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(key_alg, KeyAlg):
        key_alg = key_alg.value
    invoke(
        "askar_key_derive_ecdh_1pu",
        (
            FfiStr,
            LocalKeyHandle,
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            c_int8,
            POINTER(LocalKeyHandle),
        ),
        key_alg,
        ephem_key,
        sender_key,
        receiver_key,
        alg_id,
        apu,
        apv,
        cc_tag,
        receive,
        byref(key),
    )
    return key
