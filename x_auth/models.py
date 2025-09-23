from datetime import datetime

from aiogram.utils.web_app import WebAppUser
from aiohttp import ClientSession
from msgspec import convert
from pyrogram.enums.client_platform import ClientPlatform
from pyrogram.types import User as PyroUser
from aiogram.types import User as AioUser
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
    OneToOneNullableRelation,
    OneToOneField,
    BackwardOneToOneRelation,
    BackwardFKRelation,
    ForeignKeyNullableRelation,
    JSONField,
    CASCADE,
)
from tortoise.fields.data import CharEnumFieldInstance

from x_auth import types
from x_model.field import DatetimeSecField, UInt8Field, UniqBinaryField, UInt1Field, UInt2Field
from x_model.models import Model, TsTrait
from tortoise import Model as TortModel
from x_model.types import BaseUpd

from x_auth.enums import Lang, Role, PeerType


class Username(TortModel):
    id: int = BigIntField(True, description="tg_id")
    username: str = CharField(127, null=True)
    phone = UInt8Field(null=True)

    user: BackwardOneToOneRelation["User"]
    peers: BackwardFKRelation["Peer"]
    session: BackwardOneToOneRelation["Session"]


class User(Model):
    username: OneToOneRelation[Username] = OneToOneField("models.Username", "user", on_update=CASCADE)
    username_id: int
    first_name: str | None = CharField(63)
    pic: str | None = CharField(127, null=True)
    last_name: str | None = CharField(31, null=True)
    blocked: bool = BooleanField(null=True)
    lang: Lang | None = IntEnumField(Lang, default=Lang.ru, null=True)
    role: Role = IntEnumField(Role, default=Role.READER)
    prv = UniqBinaryField(unique=True, null=True)  # len=32
    pub = UniqBinaryField(unique=True, null=True)  # len=32

    app: BackwardOneToOneRelation["App"]

    @classmethod
    async def tg2in(cls, u: PyroUser | AioUser | WebAppUser, blocked: bool = None) -> BaseUpd:
        un, _ = await cls._meta.fields_map["username"].related_model.update_or_create({"username": u.username}, id=u.id)
        user = cls.validate(
            {
                "first_name": u.first_name,
                "last_name": u.last_name,
                "username_id": un.id,
                "lang": u.language_code and Lang[u.language_code],
                "pic": hasattr(u, "photo_url")
                and u.photo_url
                and u.photo_url.replace("https://t.me/i/userpic/320/", "")[:-4],
            }
        )
        if blocked is not None:
            user.blocked = blocked
        return user

    @classmethod
    async def is_blocked(cls, sid: str) -> bool:
        return (await cls[int(sid)]).blocked

    @classmethod
    async def tg_upsert(cls, u: PyroUser | AioUser, blocked: bool = None) -> tuple["User", bool]:
        user_in: cls.in_type() = await cls.tg2in(u, blocked)
        prms = user_in.df_unq()
        return await cls.update_or_create(**prms)

    # class Meta:
    #     abstract = True


class Country(Model):
    id = UInt1Field(True)
    code: int | None = UInt2Field(null=True)
    short: str | None = CharField(3, null=True)
    name: str | None = CharField(63, unique=True, null=True)

    proxies: BackwardFKRelation["Proxy"]


class Proxy(Model, TsTrait):
    id: int = CharField(63, primary_key=True)
    host: str = CharField(63)
    port: str = UInt2Field()
    username: str = CharField(63)
    password: str = CharField(63)
    valid: bool = BooleanField(null=True)
    country: ForeignKeyRelation[Country] = ForeignKeyField(
        "models.Country", "proxies", on_update=CASCADE, null=True
    )  # todo rm nullable

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

    def dict(self):
        return dict(scheme="socks5", hostname=self.host, port=self.port, username=self.username, password=self.password)

    def str(self):
        # noinspection HttpUrlsUsage
        return f"http://{self.username}:{self.password}@{self.host}:{self.port}"


class Dc(TortModel):
    id: int = UInt1Field(True)
    ip = CharField(15, unique=True)
    pub = CharField(495, null=True)

    apps: BackwardFKRelation["App"]
    sessions: BackwardFKRelation["App"]


class Fcm(TortModel):
    id: int = UInt1Field(True)
    json: dict = JSONField(default={})

    apps: BackwardFKRelation["App"]


class App(Model):
    id: int = IntField(True)
    hsh = CharField(32, unique=True)
    dc: ForeignKeyRelation[Dc] = ForeignKeyField("models.Dc", "apps", on_update=CASCADE, default=2)
    dc_id: int
    title = CharField(127)
    short = CharField(76)
    ver = CharField(18, default="0.0.1")
    fcm: ForeignKeyNullableRelation[Fcm] = ForeignKeyField("models.Fcm", "apps", on_update=CASCADE, null=True)
    fcm_id: int
    platform: ClientPlatform = CharEnumFieldInstance(ClientPlatform)
    owner: OneToOneNullableRelation["User"] = OneToOneField("models.User", "app", on_update=CASCADE, null=True)

    sessions: BackwardFKRelation["Session"]


class Session(TortModel):
    id = BigIntField(True)
    api: ForeignKeyRelation[App] = ForeignKeyField("models.App", "sessions", on_update=CASCADE)
    api_id: int
    dc: ForeignKeyRelation[Dc] = ForeignKeyField("models.Dc", "sessions", on_update=CASCADE, default=2)
    dc_id: int
    test_mode = BooleanField(default=False)
    auth_key = BinaryField(null=True)
    date = IntField(default=0)  # todo: refact to datetime?
    user: OneToOneNullableRelation[Username] = OneToOneField("models.Username", "session", on_update=CASCADE, null=True)
    user_id: int
    is_bot = CharField(42, null=True)
    state: dict = JSONField(default={})
    proxy: ForeignKeyNullableRelation[Proxy] = ForeignKeyField("models.Proxy", "sessions", on_update=CASCADE, null=True)

    peers: BackwardFKRelation["Peer"]
    update_states: BackwardFKRelation["UpdateState"]

    class Meta:
        unique_together = (("user_id", "api_id"),)


class Peer(TortModel):
    id: int = BigIntField(True, description="access_hash")
    username: ForeignKeyRelation[Username] = ForeignKeyField("models.Username", "peers", on_update=CASCADE)
    username_id: int
    session: ForeignKeyRelation[Session] = ForeignKeyField("models.Session", "peers", on_update=CASCADE)
    session_id: int
    type: PeerType = IntEnumField(PeerType)
    phone_number = UInt8Field(null=True)  # duplicated to Username.phone
    last_update_on: datetime | None = DatetimeSecField(auto_now=True)

    class Meta:
        unique_together = (("username_id", "session_id"),)


class UpdateState(TortModel):
    id = UInt2Field(True)
    session: ForeignKeyRelation[Session] = ForeignKeyField("models.Session", "update_states", on_update=CASCADE)
    pts = UInt2Field()
    qts = UInt2Field()
    date = UInt2Field()
    seq = UInt2Field()


class Version(TortModel):
    number = UInt2Field(True)
