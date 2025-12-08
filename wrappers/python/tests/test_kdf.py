from aries_askar import (
    Argon2,
    Argon2Algorithm,
    Argon2Config,
    Argon2Parameters,
    Argon2Version,
)


def test_argon2_interactive():
    password = "my password"
    salt = "long enough salt"

    output = Argon2.derive_password(Argon2Parameters.INTERACTIVE, password, salt)

    assert output == bytes.fromhex(
        "9ef87bcf828c46c0136a0d1d9e391d713f75b327c6dc190455bd36c1bae33259"
    )


def test_argon2_custom():
    password = "my password"
    salt = "long enough salt"
    config = Argon2Config(
        algorithm=Argon2Algorithm.ARGON2ID,
        version=Argon2Version.VERSION_0x10,
        parallelism=2,
        mem_cost=32 * 1024,
        time_cost=2,
    )

    output = Argon2.derive_password(config, password, salt)

    assert output == bytes.fromhex(
        "5060385221f423e0d5947cffe16c206ce7dbc8ecd07ceeb1f1c2489e53ef8bc4"
    )
