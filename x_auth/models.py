from datetime import datetime

from aiogram.types import User as TgUser
from aiogram.utils.web_app import WebAppUser
from aiohttp import ClientSession
from msgspec import convert
from tortoise.fields import (
    BigIntField,
    BooleanField,
    CharField,
    IntEnumField,
    ForeignKeyRelation,
    ForeignKeyField,
    IntField,
    BinaryField,
    OneToOneRelation,
    OneToOneField,
    SmallIntField,
    BackwardOneToOneRelation,
    BackwardFKRelation,
    ForeignKeyNullableRelation,
    JSONField,
)
from x_auth import types
from x_model.field import DatetimeSecField
from x_model.models import Model, TsTrait
from tortoise import Model as TortModel
from x_model.types import BaseUpd

from x_auth.enums import Lang, Role
from x_auth.types import AuthUser


class Username(TortModel):
    id: int = BigIntField(True, description="tg_id")
    username: str = CharField(127, null=True)

    user: BackwardOneToOneRelation["User"]
    peers: BackwardFKRelation["Peer"]
    sessions: BackwardFKRelation["Session"]


class User(Model):
    username: OneToOneRelation[Username] = OneToOneField("models.Username", "user")
    username_id: int
    first_name: str | None = CharField(63)
    last_name: str | None = CharField(31, null=True)
    blocked: bool = BooleanField(default=False)
    lang: Lang | None = IntEnumField(Lang, default=Lang.ru, null=True)
    role: Role = IntEnumField(Role, default=Role.READER)

    def get_auth(self) -> AuthUser:
        return AuthUser.model_validate(self, from_attributes=True)

    @classmethod
    async def tg2in(cls, u: TgUser | WebAppUser, blocked: bool = None) -> BaseUpd:
        user = cls.validate(
            {**u.model_dump(), "username": u.username or u.id, "lang": u.language_code and Lang[u.language_code]}
        )
        if blocked is not None:
            user.blocked = blocked
        return user

    @classmethod
    async def is_blocked(cls, sid: str) -> bool:
        return (await cls[int(sid)]).blocked

    class Meta:
        abstract = True


class Country(Model):
    id = SmallIntField(True)
    code: int | None = IntField(null=True)
    short: str | None = CharField(3, null=True)
    name: str | None = CharField(63, unique=True, null=True)

    proxies: BackwardFKRelation["Proxy"]


class Proxy(Model, TsTrait):
    id: int = CharField(63, primary_key=True)
    host: str = CharField(63)
    port: str = IntField()
    username: str = CharField(63)
    password: str = CharField(63)
    valid: bool = BooleanField(null=True)
    country: ForeignKeyRelation[Country] = ForeignKeyField("models.Country", "proxies", null=True)  # todo rm nullable

    class Meta:
        unique_together = (("host", "port"),)

    @staticmethod
    async def load(wst: str):
        async with ClientSession("https://proxy.webshare.io/api/v2/") as s:
            resp = await s.post("download_token/proxy_list/", headers={"Authorization": f"Token {wst}"})
            dtok = (await resp.json())["key"]
            resp = await s.get(f"proxy/list/download/{dtok}/-/any/username/direct/-/")
            res = (await resp.text()).split("\r\n")
            proxies = [
                Proxy(host=p[0], port=p[1], username=p[2], password=p[3], success=True)
                for r in res
                if r and (p := r.split(":"))
            ]
            await Proxy.bulk_create(proxies, 10, False, ["username", "password", "success"], ["host", "port"])
            return proxies

    @staticmethod
    async def get_list(wst: str) -> list[types.Proxy]:
        async with ClientSession("https://proxy.webshare.io/api/v2/") as s:
            resp = await s.get("proxy/list/?mode=direct", headers={"Authorization": f"Token {wst}"})
            lst = (await resp.json())["results"]
            proxies = [convert(p, types.Proxy) for p in lst]
            return proxies

    @classmethod
    async def load_list(cls, wst: str):
        prxs = await cls.get_list(wst)
        ccl = cls._meta.fields_map["country"].related_model
        cmap = dict(await ccl.filter(short__in=[p.country_code for p in prxs]).values_list("short", "id"))
        for r in prxs:
            df = dict(
                username=r.username,
                password=r.password,
                valid=r.valid,
                country_id=cmap[r.country_code],
                updated_at=r.last_verification,
            )
            if prx := await cls.get_or_none(host=r.proxy_address, port=r.port):
                await prx.update_from_dict({**df, "id": r.id}).save()
            elif prx := await cls.get_or_none(id=r.id):
                await prx.update_from_dict({**df, "host": r.proxy_address, "port": r.port}).save()
            else:
                await cls.create(**df, host=r.proxy_address, port=r.port, id=r.id)

    @staticmethod
    async def get_replaced(wst: str):
        async with ClientSession("https://proxy.webshare.io/api/v2/") as s:
            resp = await s.get("proxy/list/replaced/", headers={"Authorization": f"Token {wst}"})
            lst = (await resp.json())["results"]
            reps = [convert(r, types.Replacement) for r in lst]
            return reps


class Session(TortModel):
    id = CharField(127, primary_key=True)
    dc_id = IntField(null=True)
    api_id = IntField(null=True)
    test_mode = BooleanField(default=False)
    auth_key = BinaryField(null=True)
    date = IntField(null=True)  # todo: refact to datetime?
    user: ForeignKeyNullableRelation[Username] = ForeignKeyField("models.Username", "sessions", null=True)
    user_id: int
    is_bot = BooleanField(null=True)
    state: dict = JSONField(default={})
    proxy: ForeignKeyNullableRelation[Proxy] = ForeignKeyField("models.Proxy", "sessions", null=True)

    peers: BackwardFKRelation["Peer"]
    update_states: BackwardFKRelation["UpdateState"]

    class Meta:
        unique_together = (("user_id", "dc_id"),)


class Peer(TortModel):
    id: int = BigIntField(True, description="access_hash")
    username: ForeignKeyRelation[Username] = ForeignKeyField("models.Username", "peers")
    username_id: int
    session: ForeignKeyRelation[Session] = ForeignKeyField("models.Session", "peers")
    session_id: int
    type = CharField(127)
    phone_number = BigIntField(null=True)
    last_update_on: datetime | None = DatetimeSecField(auto_now=True)

    class Meta:
        unique_together = (("username_id", "session_id"),)


class UpdateState(TortModel):
    id = IntField(True)
    session: ForeignKeyRelation[Session] = ForeignKeyField("models.Session", "update_states")
    pts = IntField()
    qts = IntField()
    date = IntField()
    seq = IntField()


class Version(TortModel):
    number = SmallIntField(True)
