from aiogram.types import User as TgUser
from aiogram.utils.web_app import WebAppUser
from tortoise.fields import BigIntField, BooleanField, CharField, IntEnumField
from x_model.models import Model
from x_model.types import Upd

from x_auth.enums import Lang, Role
from x_auth.types import AuthUser


class UserTg(Model):
    class Upd(Upd):
        id: int
        username: str
        first_name: str
        last_name: str | None
        lang: Lang | None
        pic: str | None = None
        blocked: bool = False

    _in_type = Upd

    id: int = BigIntField(True, description="tg id")
    username: str | None = CharField(63, unique=True, null=True)
    first_name: str | None = CharField(63)
    last_name: str | None = CharField(31, null=True)
    pic: str | None = CharField(95, null=True)
    blocked: bool = BooleanField(default=False)
    lang: Lang | None = IntEnumField(Lang, default=Lang.ru, null=True)
    role: Role = IntEnumField(Role, default=Role.READER)

    def get_auth(self) -> AuthUser:
        return AuthUser.model_validate(self, from_attributes=True)

    @classmethod
    async def tg2in(cls, u: TgUser | WebAppUser, blocked: bool = None) -> Upd:
        user = cls._in_type(
            **{**u.model_dump(), "username": u.username or u.id, "lang": u.language_code and Lang[u.language_code]}
        )
        user.pic = (
            (gpp := await u.get_profile_photos(0, 1)).photos and gpp.photos[0][-1].file_unique_id
            if type(u) is TgUser
            else u.photo_url
        )  # (u.photo_url[0] if u.photo_url else None)
        if blocked is not None:
            user.blocked = blocked
        return user

    @classmethod
    async def is_blocked(cls, sid: str) -> bool:
        return (await cls[int(sid)]).blocked

    class Meta:
        abstract = True
