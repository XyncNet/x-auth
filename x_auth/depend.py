from typing import Annotated

from fastapi import Depends, Security
from fastapi.security import SecurityScopes, HTTPBearer, HTTPAuthorizationCredentials
from starlette.requests import HTTPConnection

from x_auth import AuthException
from x_auth.enums import UserStatus, Scope, AuthFailReason
from x_auth.models import User
from x_auth.pydantic import AuthUser

bearer = HTTPBearer(bearerFormat="xFormat", scheme_name="xSchema", description="xAuth", auto_error=False)


# For Depends
async def get_authenticated_user(conn: HTTPConnection, _: HTTPAuthorizationCredentials = Depends(bearer)) -> AuthUser:
    if not conn.user.is_authenticated:
        raise AuthException(AuthFailReason.no_token)
    return conn.user


async def get_user_from_db(auth_user: AuthUser = Depends(get_authenticated_user)) -> AuthUser:
    try:  # todo: pass concrete User model
        db_user: User = await User[auth_user.id]
        return AuthUser.model_validate(db_user, from_attributes=True)
    except Exception:
        raise AuthException(AuthFailReason.username, f"No user#{auth_user.id}({auth_user.username})", 404)


async def is_active(auth_user: AuthUser = Depends(get_authenticated_user)):
    if auth_user.status < UserStatus.TEST:
        raise AuthException(AuthFailReason.status, parent=f"{auth_user.status.name} status denied")


async def _get_scopes(conn: HTTPConnection, _=Depends(is_active)) -> list[str]:
    return conn.auth.scopes


# For Secure
async def check_scopes(security_scopes: SecurityScopes, scopes: Annotated[list[str], Depends(_get_scopes)]):
    if need := set(security_scopes.scopes) - set(scopes):
        raise AuthException(AuthFailReason.permission, parent=f"Not enough permissions. Need '{need}'")


class Req:
    READ = Security(check_scopes, scopes=[Scope.READ.name])  # read all
    WRITE = Security(check_scopes, scopes=[Scope.WRITE.name])  # read and write own
    ALL = Security(check_scopes, scopes=[Scope.ALL.name])  # write: all
    AUTHENTICATED = Depends(get_authenticated_user)
    EXISTED = Depends(get_user_from_db)
    ACTIVE = Depends(is_active)
