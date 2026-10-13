import asyncio
from ctypes import c_size_t
from unittest import mock

from pytest import raises

from aries_askar import AskarError, bindings
from aries_askar.bindings.handle import ScanHandle, SessionHandle
from aries_askar.store import Scan, Session


async def hang(*_args, **_kwargs):
    await asyncio.Event().wait()


async def test_cancel_session_operation_aborts_session():
    handle = mock.MagicMock()
    session = Session(None, handle)

    with mock.patch.object(bindings, "session_count", hang):
        with raises(asyncio.TimeoutError):
            await asyncio.wait_for(session.count(), 0.05)

    # the library is told to interrupt the operation by closing the session
    handle.abort.assert_called_once_with()
    assert session.handle is None
    with raises(AskarError):
        await session.count()


async def test_completed_session_operation_not_aborted():
    handle = mock.MagicMock()
    session = Session(None, handle)

    async def count(*_args, **_kwargs):
        return 3

    with mock.patch.object(bindings, "session_count", count):
        assert await session.count() == 3

    handle.abort.assert_not_called()
    assert session.handle is handle


async def test_cancel_scan_aborts_scan():
    scan = Scan(None, None, None)
    scan._handle = mock.MagicMock()
    scan._params = None
    scan._buffer = iter(())  # exhausted, so the next fetch goes to the library
    handle = scan._handle

    with mock.patch.object(bindings, "scan_next", hang):
        with raises(asyncio.TimeoutError):
            await asyncio.wait_for(scan.__anext__(), 0.05)

    handle.abort.assert_called_once_with()
    with raises(AskarError):
        await scan.__anext__()


def test_handle_abort_cleans_up_once():
    for cls in (SessionHandle, ScanHandle):
        logged = []
        with mock.patch.object(
            cls, "_cleanup", classmethod(lambda c, v: logged.append(v))
        ):
            h = cls()
            h.abort()
            assert not logged  # nothing to close

            h = cls()
            h.value = 99
            h.abort()
            assert not h.value
            assert [v.value for v in logged] == [99]

            # the finalizer must not close the handle again
            del h
            assert [v.value for v in logged] == [99]
            assert isinstance(logged[0], c_size_t)
