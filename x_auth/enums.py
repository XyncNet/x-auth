from enum import IntEnum


class Lang(IntEnum):
    ru = 1
    en = 2


class RoleScope(IntEnum):
    READ = 4  # read all
    WRITE = 2  # read and write own
    ALL = 1  # write: all


class Role(IntEnum):
    READER = RoleScope.READ  # 4 - only read all
    WRITER = RoleScope.WRITE  # 2 - only create and read/edit created own
    MANAGER = RoleScope.READ + RoleScope.WRITE  # 6 - create, edit own, and read all
    ADMIN = RoleScope.READ + RoleScope.WRITE + RoleScope.ALL  # 7 - create and read/edit/delete all

    def scopes(self) -> list[str]:
        return [scope.name for scope in RoleScope if self.value & scope.value]
