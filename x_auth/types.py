from msgspec import Struct

from x_auth.enums import Role


class AuthUser(Struct):
    id: int
    blocked: bool
    role: Role
