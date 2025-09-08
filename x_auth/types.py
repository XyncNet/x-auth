from datetime import datetime
from json import dumps
from typing import Literal, Self

from aiogram.utils.web_app import WebAppUser
from msgspec import Struct, to_builtins, convert

from x_auth.enums import Role


class Xs(Struct):
    @classmethod
    def dec_hook(cls, *args, **kwargs):
        pass

    def dump(self, nones: bool = False) -> dict:
        return {k: v for k, v in to_builtins(self).items() if nones or v is not None}

    def json(self, nones: bool = False) -> str:
        return dumps(self.dump())

    @classmethod
    def load(cls, obj, **kwargs) -> Self:
        dct = dict(obj)
        return convert({**dct, **kwargs}, cls, dec_hook=cls.dec_hook)  # , strict=False


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


class TgUser(Xs):
    id: int
    first_name: str
    auth_date: int
    hash: str
    username: str | None = None
    photo_url: str | None = None
    last_name: str | None = None


class XyncUser(WebAppUser):
    xid: int
    pub: bytes | None
