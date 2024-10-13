from tortoise.fields import CharField
from x_model import User as BaseUser


class User(BaseUser):
    from pwdlib import PasswordHash

    __cc = PasswordHash.recommended()

    password: str | None = CharField(60, null=True)

    def pwd_vrf(self, pwd: str) -> bool:
        return self.__cc.verify(pwd, self.password)

    @classmethod
    async def create(cls, using_db=None, **kwargs) -> BaseUser:
        user: User = await super().create(using_db, **kwargs)
        if pwd := kwargs.get("password"):
            await user.set_pwd(pwd)
        return user

    async def set_pwd(self, pwd: str = password) -> None:
        self.password = self.__cc.hash(pwd)
        await self.save()
