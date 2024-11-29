import asyncio
import os

from pytest import mark, raises
import pytest_asyncio

from aries_askar import (
    AskarError,
    KeyAlg,
    Key,
    Store,
)


TEST_STORE_URI = os.getenv("TEST_STORE_URI", "sqlite://:memory:")
TEST_ENTRY = {
    "category": "test category",
    "name": "test name",
    "value": b"test_value",
    "tags": {"~plaintag": "a", "enctag": {"b", "c"}},
}


def raw_key() -> str:
    return Store.generate_raw_key(b"00000000000000000000000000000My1")


@pytest_asyncio.fixture
@mark.asyncio
async def store() -> Store:
    key = raw_key()
    store = await Store.provision(TEST_STORE_URI, "raw", key, recreate=True)
    yield store
    await store.close(remove=True)


@mark.asyncio
async def test_insert_update(store: Store):
    async with store as session:
        # Insert a new entry
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

        # Count rows by category and (optional) tag filter
        assert (
            await session.count(
                TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
            )
        ) == 1

        # Fetch an entry by category and name
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert dict(found) == TEST_ENTRY

        # Fetch entries by category and tag filter
        found = await session.fetch_all(
            TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
        )
        assert len(found) == 1 and dict(found[0]) == TEST_ENTRY

        # Update an entry (outside of a transaction)
        upd_entry = TEST_ENTRY.copy()
        upd_entry["value"] = b"new_value"
        upd_entry["tags"] = {"upd": "tagval"}
        await session.replace(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            upd_entry["value"],
            upd_entry["tags"],
        )
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert dict(found) == upd_entry

        # Remove entry
        await session.remove(TEST_ENTRY["category"], TEST_ENTRY["name"])
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert found is None


@mark.asyncio
async def test_remove_all(store: Store):
    async with store as session:
        # Insert a new entry
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

        # Remove using remove_all
        await session.remove_all(
            TEST_ENTRY["category"],
            # note: this query syntax is optional
            {"~plaintag": "a", "$and": [{"enctag": "b"}, {"enctag": "c"}]},
        ),

        # Check removed
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert found is None


@mark.asyncio
async def test_scan(store: Store):
    async with store as session:
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

    # Scan entries by category and (optional) tag filter)
    rows = await store.scan(
        TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
    ).fetch_all()
    assert len(rows) == 1 and dict(rows[0]) == TEST_ENTRY

    # Scan entries with non-matching category
    rows = await store.scan("not the category").fetch_all()
    assert len(rows) == 0

    # Scan entries with non-matching tag filter
    rows = await store.scan(TEST_ENTRY["category"], {"~plaintag": "X"}).fetch_all()
    assert len(rows) == 0

    # Scan entries with no category filter
    rows = await store.scan(None, {"~plaintag": "a", "enctag": "b"}).fetch_all()
    assert len(rows) == 1 and dict(rows[0]) == TEST_ENTRY


@mark.asyncio
async def test_txn_basic(store: Store):
    async with store.transaction() as txn:
        # Insert a new entry
        await txn.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

        # Count rows by category and (optional) tag filter
        assert (
            await txn.count(TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"})
        ) == 1

        # Fetch an entry by category and name
        found = await txn.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert dict(found) == TEST_ENTRY

        # Fetch entries by category and tag filter
        found = await txn.fetch_all(
            TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
        )
        assert len(found) == 1 and dict(found[0]) == TEST_ENTRY

        await txn.commit()

    # Check the transaction was committed
    async with store.session() as session:
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert dict(found) == TEST_ENTRY


@mark.asyncio
async def test_txn_autocommit(store: Store):
    with raises(Exception):
        async with store.transaction(autocommit=True) as txn:
            # Insert a new entry
            await txn.insert(
                TEST_ENTRY["category"],
                TEST_ENTRY["name"],
                TEST_ENTRY["value"],
                TEST_ENTRY["tags"],
            )

            found = await txn.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
            assert dict(found) == TEST_ENTRY

            raise Exception()

    # Row should not have been inserted
    async with store as session:
        assert (await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])) is None

    async with store.transaction(autocommit=True) as txn:
        # Insert a new entry
        await txn.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

    # Transaction should have been committed
    async with store as session:
        found = await session.fetch(TEST_ENTRY["category"], TEST_ENTRY["name"])
        assert dict(found) == TEST_ENTRY


@mark.asyncio
async def test_txn_contention(store: Store):
    async with store.transaction() as txn:
        await txn.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            "0",
        )
        await txn.commit()

    INC_COUNT = 1000
    TASKS = 10

    async def inc():
        for _ in range(INC_COUNT):
            async with store.transaction() as txn:
                row = await txn.fetch(
                    TEST_ENTRY["category"], TEST_ENTRY["name"], for_update=True
                )
                if not row:
                    raise Exception("Row not found")
                new_value = str(int(row.value) + 1)
                await txn.replace(TEST_ENTRY["category"], TEST_ENTRY["name"], new_value)
                await txn.commit()

    tasks = [asyncio.create_task(inc()) for _ in range(TASKS)]
    await asyncio.gather(*tasks)

    # Check all the updates completed
    async with store.session() as session:
        result = await session.fetch(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
        )
        assert int(result.value) == INC_COUNT * TASKS


@mark.asyncio
async def test_key_store_ed25519(store: Store):
    # test key operations in a new session
    async with store as session:
        # Create a new keypair
        keypair = Key.generate(KeyAlg.ED25519)

        # Store keypair
        key_name = "testkey"
        await session.insert_key(
            key_name, keypair, metadata="metadata", tags={"a": "b"}
        )

        # Fetch keypair
        fetch_key = await session.fetch_key(key_name)
        assert fetch_key and fetch_key.name == key_name and fetch_key.tags == {"a": "b"}

        # Update keypair
        await session.update_key(key_name, metadata="updated metadata", tags={"a": "c"})

        # Fetch keypair
        fetch_key = await session.fetch_key(key_name)
        assert fetch_key and fetch_key.name == key_name and fetch_key.tags == {"a": "c"}

        # Check key equality
        thumbprint = keypair.get_jwk_thumbprint()
        assert fetch_key.key.get_jwk_thumbprint() == thumbprint

        # Fetch with filters
        keys = await session.fetch_all_keys(
            alg=KeyAlg.ED25519, thumbprint=thumbprint, tag_filter={"a": "c"}, limit=1
        )
        assert len(keys) == 1 and keys[0].name == key_name

        # Remove
        await session.remove_key(key_name)
        assert await session.fetch_key(key_name) is None


@mark.asyncio
@mark.parametrize(
    "key_alg",
    [KeyAlg.A128CBC_HS256, KeyAlg.XC20P],
)
async def test_key_store_symmetric(store: Store, key_alg: KeyAlg):
    # test key operations in a new session
    async with store as session:
        # Create a new keypair
        symm = Key.generate(key_alg)

        # Store symmetric key
        key_name = "testkey"
        await session.insert_key(key_name, symm, metadata="metadata", tags={"a": "b"})

        # Fetch keypair
        fetch_key = await session.fetch_key(key_name)
        assert fetch_key and fetch_key.name == key_name and fetch_key.tags == {"a": "b"}

        # Update keypair
        await session.update_key(key_name, metadata="updated metadata", tags={"a": "c"})

        # Fetch keypair
        fetch_key = await session.fetch_key(key_name)
        assert fetch_key and fetch_key.name == key_name and fetch_key.tags == {"a": "c"}

        # Check key equality
        jwk_secret = symm.get_jwk_secret()
        assert fetch_key.key.get_jwk_secret() == jwk_secret

        # Fetch with filters
        keys = await session.fetch_all_keys(alg=key_alg, tag_filter={"a": "c"}, limit=1)
        assert len(keys) == 1 and keys[0].name == key_name

        # Remove
        await session.remove_key(key_name)
        assert await session.fetch_key(key_name) is None


@mark.asyncio
async def test_profile(store: Store):
    # New session in the default profile
    async with store as session:
        # Insert a new entry
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )

    profile = await store.create_profile()

    active_profile = await store.get_profile_name()
    assert (await store.get_default_profile()) == active_profile
    assert set(await store.list_profiles()) == {active_profile, profile}

    async with store.session(profile) as session:
        # Should not find previously stored record
        assert (
            await session.count(
                TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
            )
        ) == 0

        # Insert a new entry
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )
        assert (
            await session.count(
                TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
            )
        ) == 1

    if ":memory:" not in TEST_STORE_URI:
        # Test accessing profile after re-opening
        key = raw_key()
        store_2 = await Store.open(TEST_STORE_URI, "raw", key)
        async with store_2.session(profile) as session:
            # Should not find previously stored record
            assert (
                await session.count(
                    TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
                )
            ) == 1
        await store_2.close()

    with raises(AskarError, match="Duplicate"):
        _ = await store.create_profile(profile)

    # check profile is still usable
    async with store.session(profile) as session:
        assert (
            await session.count(
                TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
            )
        ) == 1

    await store.remove_profile(profile)

    assert set(await store.list_profiles()) == {active_profile}

    # opening removed profile should fail
    with raises(AskarError, match="removed"):
        async with store.session(profile) as session:
            pass

    # opening unknown profile should fail
    with raises(AskarError, match="not found"):
        async with store.session("unknown profile") as session:
            pass

    await store.create_profile(profile)

    async with store.session(profile) as session:
        assert (
            await session.count(
                TEST_ENTRY["category"], {"~plaintag": "a", "enctag": "b"}
            )
        ) == 0

    assert (await store.get_default_profile()) != profile
    await store.set_default_profile(profile)
    assert (await store.get_default_profile()) == profile


@mark.asyncio
async def test_copy(store: Store):
    async with store as session:
        # Insert a new entry
        await session.insert(
            TEST_ENTRY["category"],
            TEST_ENTRY["name"],
            TEST_ENTRY["value"],
            TEST_ENTRY["tags"],
        )
    profiles = await store.list_profiles()

    copied = await store.copy_to("sqlite://:memory:", "raw", raw_key())
    assert profiles == await copied.list_profiles()
    await copied.close(remove=True)

    async with store as session:
        entries = await session.fetch_all(TEST_ENTRY["category"])
        assert len(entries) == 1
        assert entries[0].name == TEST_ENTRY["name"]
