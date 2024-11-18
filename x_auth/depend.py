from typing import Annotated

from fastapi import Depends, Security
from fastapi.security import SecurityScopes
from starlette.requests import HTTPConnection

from x_auth.enums import AuthFailReason, Scope
from x_auth import AuthUser, AuthException, BearerSecurity


class Depend:
    def __init__(self, scheme: BearerSecurity):
        # For Depends
        def authenticated(conn: HTTPConnection, _: str | None = Depends(scheme)) -> AuthUser:
            if not conn.user.is_authenticated:
                raise AuthException(AuthFailReason.no_token)
            return conn.user

        self.AUTHENTICATED = Depends(authenticated)

        def active(auth_user: AuthUser = self.AUTHENTICATED) -> AuthUser:
            if auth_user.status < 2:
                raise AuthException(AuthFailReason.status, parent=f"{auth_user.status.name} status denied")
            return auth_user

        self.ACTIVE = Depends(active)

        def get_scopes(conn: HTTPConnection, _=self.ACTIVE) -> list[str]:
            return conn.auth.scopes

        # For Secure
        def check_scopes(security_scopes: SecurityScopes, scopes: Annotated[list[str], Depends(get_scopes)]):
            if need := set(security_scopes.scopes) - set(scopes):
                raise AuthException(AuthFailReason.permission, parent=f"Not enough permissions. Need '{need}'")

        self.READ = Security(check_scopes, scopes=[Scope.READ.name])  # read all
        self.WRITE = Security(check_scopes, scopes=[Scope.WRITE.name])  # read and write own
        self.ALL = Security(check_scopes, scopes=[Scope.ALL.name])  # write: all
