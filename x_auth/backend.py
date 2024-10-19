from datetime import timedelta
from typing import Annotated

from fastapi import Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, SecurityScopes
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection
from tortoise.exceptions import IntegrityError, ConfigurationError

from x_auth.enums import FailReason, Scope, AuthFailReason, UserStatus
from x_auth import jwt_decode, jwt_encode, HTTPException, AuthException
from x_auth.model import User
from x_auth.pydantic import AuthUser, UserReg, Token


class AuthBackend(AuthenticationBackend):
    expires = timedelta(minutes=15)

    dep = HTTPBearer(bearerFormat="xFormat", scheme_name="xSchema", description="xAuth", auto_error=False)

    # For Depends
    @staticmethod
    def get_authenticated_user(conn: HTTPConnection, _: HTTPAuthorizationCredentials = Depends(dep)) -> AuthUser:
        if not conn.user.is_authenticated:
            raise AuthException(AuthFailReason.no_token)
        return conn.user

    @staticmethod
    async def get_user_from_db(auth_user: AuthUser = Depends(get_authenticated_user)) -> AuthUser:
        try:  # todo: pass concrete User model
            db_user: User = await User[auth_user.id]
            return AuthUser.model_validate(db_user, from_attributes=True)
        except ConfigurationError:
            raise AuthException(AuthFailReason.username, f"Not inicialized user model: {User})", 500)
        except Exception:
            raise AuthException(AuthFailReason.username, f"No user#{auth_user.id}({auth_user.username})", 404)

    @staticmethod
    def is_active(auth_user: AuthUser = Depends(get_authenticated_user)):
        if auth_user.status < UserStatus.TEST:
            raise AuthException(AuthFailReason.status, parent=f"{auth_user.status.name} status denied")

    @staticmethod
    def _get_scopes(conn: HTTPConnection, _=Depends(is_active)) -> list[str]:
        return conn.auth.scopes

    # For Secure
    @staticmethod
    async def check_scopes(security_scopes: SecurityScopes, scopes: Annotated[list[str], Depends(_get_scopes)]):
        if need := set(security_scopes.scopes) - set(scopes):
            raise AuthException(AuthFailReason.permission, parent=f"Not enough permissions. Need '{need}'")

    READ = Security(check_scopes, scopes=[Scope.READ.name])  # read all
    WRITE = Security(check_scopes, scopes=[Scope.WRITE.name])  # read and write own
    ALL = Security(check_scopes, scopes=[Scope.ALL.name])  # write: all
    AUTHENTICATED = Depends(get_authenticated_user)
    EXISTED = Depends(get_user_from_db)
    ACTIVE = Depends(is_active)

    def __init__(self, secret: str, db_user_model: type(User) = User):
        self.secret: str = secret
        self.db_user_model: User = db_user_model
        # todo: optimize auth routes forwarding
        self.routes: dict[str, tuple[callable, str]] = {
            "reg": (self.reg, "POST"),
            "refresh": (self.refresh, "GET"),
        }

    def _user2tok(self, user: AuthUser) -> Token:
        return Token(access_token=jwt_encode(user, self.secret, self.expires), token_type="bearer", user=user)

    # dependency
    async def authenticate(
        self, conn: HTTPConnection, brt: HTTPBearer = dep
    ) -> tuple[AuthCredentials, AuthUser] | None:
        try:
            # noinspection PyTypeChecker
            token: str = (await brt(conn)).credentials
        except AttributeError:
            return None
        user: AuthUser = jwt_decode(token, self.secret, conn.scope["path"] != "/refresh")
        return AuthCredentials(scopes=user.role.scopes()), user

    # API ENDOINTS
    # api reg endpoint
    async def reg(self, user_reg_input: UserReg) -> Token:
        data = user_reg_input.model_dump()
        try:
            db_user: User = await self.db_user_model.create(**data)
        except IntegrityError as e:
            raise HTTPException(FailReason.body, e)
        user: AuthUser = AuthUser.model_validate(db_user, from_attributes=True)
        return self._user2tok(user)

    # api refresh token
    async def refresh(self, user: AuthUser = EXISTED) -> Token:
        return self._user2tok(await user)
