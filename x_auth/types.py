from datetime import datetime
from typing import Literal

from msgspec import Struct

from x_auth.enums import Role


class AuthUser(Struct):
    id: int
    blocked: bool
    role: Role


class Proxy(Struct):
    id: str
    username: str
    password: str
    proxy_address: str
    port: int
    valid: bool
    last_verification: datetime
    country_code: str
    city_name: str
    created_at: datetime


class Replacement(Struct):
    id: int
    reason: Literal["auto_invalidated", "auto_out_of_rotation"]
    replaced_with: str
    replaced_with_port: int
    replaced_with_country_code: str
    proxy: str
    proxy_port: int
    proxy_country_code: str
    created_at: datetime
