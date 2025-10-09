from aries_askar import (
    Argon2,
    Argon2Parameters
)

def test_argon2():
    password = "my password"
    salt = "long enough salt"

    output = Argon2.derive_password(Argon2Parameters.INTERACTIVE, password, salt)

    assert output == bytes.fromhex("9ef87bcf828c46c0136a0d1d9e391d713f75b327c6dc190455bd36c1bae33259")
