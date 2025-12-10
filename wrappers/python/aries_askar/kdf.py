from enum import IntEnum
from typing import Union

from . import bindings
from .bindings.lib import Argon2Algorithm, Argon2Config, Argon2Version

__all__ = [
    "Argon2",
    "Argon2Algorithm",
    "Argon2Config",
    "Argon2Version",
    "Argon2Parameters",
]


class Argon2Parameters(IntEnum):
    MODERATE = 0
    INTERACTIVE = 1


class Argon2:
    def derive_password(
        parameter: Argon2Parameters | Argon2Config,
        password: Union[bytes, str],
        salt: Union[bytes, str],
    ):
        return bytes(bindings.argon2_derive_password(parameter, password, salt))
