import logging
from datetime import timedelta, datetime
from enum import IntEnum
from typing import Annotated
from fastapi import Depends, HTTPException, Security
from fastapi.security import SecurityScopes, HTTPBearer
from jose import jwt, JWTError
from pydantic import BaseModel, ValidationError
from starlette import status
from starlette.authentication import SimpleUser, AuthenticationError
from starlette.requests import HTTPConnection
from starlette.responses import Response

from x_auth.enums import Scope, UserStatus
from x_auth.models import User
from x_auth.pydantic import UserAuth


class FailReason(IntEnum):
    username = 1
    password = 2
    signature = 3
    expired = 4
    dep_not_installed = 5
    undefined = 6


class AuthException(AuthenticationError, HTTPException):
    detail: FailReason

    def __init__(self, detail: FailReason, clear_cookie: str | None = "access_token", parent: Exception = None) -> None:
        hdrs = (
            {"set-cookie": clear_cookie + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"} if clear_cookie else None
        )  # path=/;
        if parent:
            logging.error(repr(parent))
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail.name, headers=hdrs)


def on_error(_: HTTPConnection, exc: AuthException) -> Response:
    hdr = {}
    if exc.status_code == 303 and "/login" in (r.path for r in _.app.routes):
        hdr = {"Location": "/login"}
    resp = Response(str(exc), status_code=exc.status_code, headers=hdr)
    resp.delete_cookie("access_token")
    return resp


def jwt_decode(jwtoken: str, secret: str) -> UserAuth:
    payload = jwt.decode(jwtoken, secret, algorithms=["HS256"])
    return UserAuth(**payload)


class AuthUser(SimpleUser):
    id: int

    def __init__(self, uid: int, username: str) -> None:
        super().__init__(username)
        self.id = uid


class BaseAuth:
    expires = timedelta(days=7)
    auth_scheme = HTTPBearer()

    class Token(BaseModel):
        access_token: str
        token_type: str
        user: UserAuth

    def __init__(self, secret: str, db_user_model: type[User] = User):
        self.secret: str = secret
        self.db_user_model: type[User] = db_user_model

        self.read = Security(self.check_token, scopes=[Scope.READ.name])
        self.write = Security(self.check_token, scopes=[Scope.WRITE.name])
        self.my = Security(self.check_token, scopes=[Scope.ALL.name])
        self.active = Depends(self.check_token)

    def jwt_encode(self, data: UserAuth, expires_delta: timedelta = expires) -> str:
        return jwt.encode({"exp": datetime.now() + expires_delta, **data}, self.secret)

    def jwt_decode(self, jwtoken: str) -> UserAuth:
        return jwt_decode(jwtoken, self.secret)

    # dependency
    async def check_token(self, security_scopes: SecurityScopes, token: Annotated[str, Depends(auth_scheme)]):
        auth_val = "Bearer"
        if security_scopes.scopes:
            auth_val += f' scope="{security_scopes.scope_str}"'
        cred_exc = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": auth_val},
        )
        try:
            user: UserAuth = self.jwt_decode(token)
        except (JWTError, ValidationError) as e:
            cred_exc.detail += f": {e}"
            raise cred_exc
        if not user.username or not user.id:
            cred_exc.detail += "token"
            raise cred_exc
        # noinspection PyTypeChecker
        user_status: UserStatus | None = await self.db_user_model.get_or_none(username=user.username).values_list(
            "status", flat=True
        )
        if not user_status:
            cred_exc.detail = "User not found"
            raise cred_exc
        elif user_status < UserStatus.TEST:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
        for scope in security_scopes.scopes:
            if scope not in user.scopes:
                cred_exc.detail = f"Not enough permissions. Need '{scope}'"
                raise cred_exc
