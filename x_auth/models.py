from tortoise import fields
from x_auth.pydantic import AuthUser
from x_model.models import Model as BaseModel, TsTrait

from x_auth.enums import UserStatus, Role, Scope


class Model(BaseModel):
    _allowed: int = 0  # allows access to read/write/all for all

    @classmethod
    def _req_intersects(cls, *scopes: Scope) -> set[Scope]:
        def allows(s):
            return s & cls._allowed

        reqs = {scope for scope in Scope if not allows(scope)}
        return {*scopes} & reqs


class User(Model, TsTrait):
    username: str | None = fields.CharField(95, unique=True, null=True)
    status: UserStatus = fields.IntEnumField(UserStatus, default=UserStatus.WAIT)
    email: str | None = fields.CharField(100, unique=True, null=True)
    phone: int | None = fields.BigIntField(null=True)
    role: Role = fields.IntEnumField(Role, default=Role.READER)

    _icon = "user"
    _name = {"username"}

    def _can(self, scope: Scope) -> bool:
        return bool(self.role.value & scope)

    def get_auth(self) -> AuthUser:
        return AuthUser.model_validate(self, from_attributes=True)

    class Meta:
        table_description = "Users"
