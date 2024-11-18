from enum import IntEnum


class UserStatus(IntEnum):
    BANNED = 0
    WAIT = 1  # waiting for approve
    TEST = 2  # trial
    ACTIVE = 3
    PREMIUM = 4


class Scope(IntEnum):
    READ = 4  # read all
    WRITE = 2  # read and write own
    ALL = 1  # write: all


class Role(IntEnum):
    READER = Scope.READ  # 4 - only read all
    WRITER = Scope.WRITE  # 2 - only create and read/edit created own
    MANAGER = Scope.READ + Scope.WRITE  # 6 - create, edit own, and read all
    ADMIN = Scope.READ + Scope.WRITE + Scope.ALL  # 7 - create and read/edit/delete all

    def scopes(self) -> list[str]:
        return [scope.name for scope in Scope if self.value & scope.value]


class AuthFailReason(IntEnum):
    no_token = 0
    username = 1
    password = 2
    signature = 3
    header = 4
    status = 5
    permission = 6
    scheme = 7
    expired = 8
