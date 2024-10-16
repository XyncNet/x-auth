from datetime import timedelta
from typing import Annotated

from fastapi import Security, Depends, HTTPException
from fastapi.params import Depends as DependsClass
from fastapi.security import HTTPBearer, SecurityScopes
from jose import jwt
from jose.constants import ALGORITHMS
from starlette import status
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection, Request
from tortoise.timezone import now

from x_auth import AuthException, FailReason, jwt_decode
from x_auth.models import User
from x_auth.enums import UserStatus, Req, Scope
from x_auth.pydantic import AuthUser, UserReg, Token


async def get_scopes(conn: HTTPConnection) -> set[str]:
    return conn.auth.scopes


async def get_auth_user(conn: HTTPConnection) -> AuthUser:
    return conn.user


async def is_authenticated(auth_user=Depends(get_auth_user)):
    if not auth_user.is_authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def is_active(auth_user=Depends(is_authenticated)):
    if auth_user.status < UserStatus.TEST:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")


async def check_token(security_scopes: SecurityScopes, scopes: Annotated[set[str], get_scopes]):
    if need := set(security_scopes.scopes) - scopes:
        raise AuthException(FailReason.permission, parent=Exception(f"Not enough permissions. Need '{need}'"))


bearer = HTTPBearer(bearerFormat="xFormat", scheme_name="xSchema", description="xAuth", auto_error=False)


class AuthBackend(AuthenticationBackend):
    expires = timedelta(days=1)
    reqs: dict[Req, DependsClass] = {
        Req.AUTHENTICATED: Depends(is_authenticated),
        Req.ACTIVE: Depends(is_active),
        Req.READ.name: Security(check_token, scopes=[Scope.READ.name]),
        Req.WRITE.name: Security(check_token, scopes=[Scope.WRITE.name]),
        Req.ALL.name: Security(check_token, scopes=[Scope.ALL.name]),
    }

    def __init__(self, secret: str, db_user_model: type(User) = User):
        self.secret = secret
        self.db_user_model = db_user_model
        self.reqs.update({Req.EXISTED: Depends(self.has_user)})

    def jwt_decode(self, jwtoken: str) -> AuthUser:
        return jwt_decode(jwtoken, self.secret)

    def jwt_encode(self, data: AuthUser, expires_delta: timedelta = expires) -> str:
        return jwt.encode({"exp": now() + expires_delta, **data.model_dump()}, self.secret, ALGORITHMS.NONE)

    # dependency

    async def has_user(self, auth_user=Depends(get_auth_user)) -> User:
        try:
            return await self.db_user_model[auth_user.id]
        except Exception:
            raise AuthException(FailReason.username)

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthUser] | None:
        try:
            # noinspection PyTypeChecker
            token: str = (await bearer(conn)).credentials
        except AttributeError:
            return None
        user: AuthUser = jwt_decode(token, self.secret)
        # noinspection PyTypeChecker
        return AuthCredentials(scopes=user.role.scopes()), user

    # API ENDOINTS
    # api reg endpoint
    async def reg_user(self, user_reg_input: UserReg) -> Token:
        data = user_reg_input.model_dump()
        try:
            db_user: User = await self.db_user_model.create(**data)
        except Exception as e:
            raise HTTPException(status.HTTP_406_NOT_ACCEPTABLE, detail=e.__repr__())
        user = AuthUser.model_validate(db_user, from_attributes=True)
        tok = self.jwt_encode(user)
        return Token(access_token=tok, token_type="bearer", user=user)

    # api refresh token
    async def refresh_token(self, request: Request) -> Token:
        try:
            db_user: User = await self.db_user_model[request.user.id]
        except Exception as e:
            raise HTTPException(status.HTTP_406_NOT_ACCEPTABLE, detail=e.__repr__())
        user = AuthUser.model_validate(db_user, from_attributes=True)
        tok = self.jwt_encode(user)
        return Token(access_token=tok, token_type="bearer", user=user)
