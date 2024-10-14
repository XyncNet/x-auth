from pydantic import BaseModel, computed_field

from x_auth.enums import UserStatus, Role, Scope


class UserReg(BaseModel):
    username: str
    email: str | None = None
    phone: int | None = None


class UserUpdate(BaseModel):
    username: str
    status: UserStatus
    email: str | None
    phone: int | None
    role: Role


class UserAuth(UserUpdate):
    id: int
    username: str
    status: UserStatus
    role: Role
    # ref_id: int | None

    @computed_field
    @property
    def scopes(self) -> list[str]:
        return [scope.name for scope in Scope if self.role.value & scope.value]
