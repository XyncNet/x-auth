from typing import Annotated

from fastapi import HTTPException, Depends, Security
from fastapi.params import Depends as DependsClass
from fastapi.security import SecurityScopes
from starlette import status
from starlette.requests import HTTPConnection

from x_auth import AuthException
from x_auth.enums import FailReason, UserStatus, Scope, Req
from x_auth.models import User
from x_auth.pydantic import AuthUser


async def _get_scopes(conn: HTTPConnection) -> set[str]:
    return conn.auth.scopes


# For Depends
async def get_authenticated_user(conn: HTTPConnection) -> AuthUser:
    if not conn.user.is_authenticated:
        # todo: replase all HTTPExceptions -> AuthException with unify reasons
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return conn.user


async def get_user_from_db(auth_user=Depends(get_authenticated_user), user_model=None) -> AuthUser:  # user_model: User
    user_model = user_model or User
    try:
        db_user: user_model = await user_model[auth_user.id]
        return AuthUser.model_validate(db_user, from_attributes=True)
    except Exception:
        raise AuthException(FailReason.username)


async def is_active(auth_user=Depends(get_authenticated_user)):
    if auth_user.status < UserStatus.TEST:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")


# For Secure
async def check_scopes(security_scopes: SecurityScopes, scopes: Annotated[set[str], _get_scopes]):
    if need := set(security_scopes.scopes) - scopes:
        raise AuthException(FailReason.permission, parent=Exception(f"Not enough permissions. Need '{need}'"))


reqs: dict[Req, DependsClass] = {
    Req.AUTHENTICATED: Depends(get_authenticated_user),
    Req.EXISTED: Depends(get_user_from_db),
    Req.ACTIVE: Depends(is_active),
    Req.READ: Security(check_scopes, scopes=[Scope.READ.name]),
    Req.WRITE: Security(check_scopes, scopes=[Scope.WRITE.name]),
    Req.ALL: Security(check_scopes, scopes=[Scope.ALL.name]),
}
