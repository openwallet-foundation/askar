from enum import IntEnum
from typing import Union
from . import bindings

class Argon2Parameters(IntEnum):
    MODERATE = 0
    INTERACTIVE = 1

class Argon2:
    def derive_password(
            parameter: Argon2Parameters,
            password: Union[bytes, str],
            salt: Union[bytes, str]
    ):
        return bytes(bindings.argon2_derive_password(parameter, password, salt))

