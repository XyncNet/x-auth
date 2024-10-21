from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection

from x_auth import jwt_decode, BearerSecurity
from x_auth.pydantic import AuthUser


class AuthBackend(AuthenticationBackend):
    def __init__(self, secret: str, auth_scheme: BearerSecurity):
        self.auth_scheme = auth_scheme
        self.secret = secret

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthUser]:
        if token := await self.auth_scheme(conn):
            verify_exp: bool = conn.scope["path"] != "/refresh"
            user: AuthUser = jwt_decode(token, self.secret, verify_exp)
            return AuthCredentials(scopes=user.role.scopes()), user
