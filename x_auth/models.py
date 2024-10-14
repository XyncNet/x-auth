from tortoise import fields
from x_model.model import Model as BaseModel, TsTrait

from x_auth.enums import UserStatus, Role, Scope


class Model(BaseModel):
    _allowed: Role = None  # allows access to read/write/all for all


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

    class Meta:
        table_description = "Users"
