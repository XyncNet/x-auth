from enum import IntEnum


class UserStatus(IntEnum):
    BANNED = 0
    WAIT = 1  # waiting for approve
    TEST = 2  # trial
    ACTIVE = 3
    PREMIUM = 4


class Scope(IntEnum):
    READ = 4
    WRITE = 2
    ALL = 1  # not only my


class Role(IntEnum):
    READER = Scope.READ  # 4
    WRITER = Scope.WRITE  # 2
    MANAGER = Scope.READ + Scope.WRITE  # 6
    ADMIN = Scope.READ + Scope.WRITE + Scope.ALL  # 7
