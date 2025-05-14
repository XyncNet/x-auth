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


class ToReplace(Struct):
    type: Literal["ip_range",]
    ip_ranges: list[str]


class ReplaceWith(Struct):
    type: Literal["country",]
    country_code: str


class Replacement(Struct):
    id: int
    to_replace: ToReplace
    replace_with: list[ReplaceWith]
    dry_run: bool
    state: str
    proxies_removed: int
    proxies_added: int
    reason: str
    created_at: datetime
    error: str = None
    error_code: str = None
    dry_run_completed_at: datetime = None
    completed_at: datetime = None
