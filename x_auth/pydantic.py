from pydantic import BaseModel, computed_field
from starlette.authentication import BaseUser

from x_auth.enums import UserStatus, Role


class UserReg(BaseModel):
    username: str
    status: UserStatus = UserStatus.WAIT
    role: Role = Role.READER
    email: str | None = None
    phone: int | None = None


class AuthUser(BaseModel, BaseUser):
    id: int
    username: str
    status: UserStatus
    role: Role

    @computed_field
    @property
    def is_authenticated(self) -> bool:
        return bool(self.status)

    @computed_field
    @property
    def display_name(self) -> str:
        return self.username

    @computed_field
    @property
    def identity(self) -> int:
        return self.id


class Token(BaseModel):
    access_token: str
    user: AuthUser
