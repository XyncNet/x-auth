from datetime import timedelta

from jose import ExpiredSignatureError
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection
from tortoise import ConfigurationError

from x_auth import jwt_decode, BearerSecurity, AuthException, jwt_encode
from x_auth.enums import AuthFailReason
from x_auth.models import User
from x_auth.pydantic import AuthUser


class AuthBackend(AuthenticationBackend):
    def __init__(
        self,
        secret: str,
        auth_scheme: BearerSecurity,
        db_user_model: type(User) = User,
        expires: timedelta = timedelta(minutes=15),
    ):
        self.auth_scheme = auth_scheme
        self.secret = secret
        self.db_user_model: type(User) = db_user_model
        self.expires: timedelta = expires
        # todo: refact! cause: secret, db_user_model, expieres - overforwarding

    async def refresh(self, auth_user: AuthUser) -> AuthUser:
        try:
            db_user: User = await self.db_user_model[auth_user.id]
            if db_user.status < 2:
                raise AuthException(AuthFailReason.status, f"Your status is still: {db_user.status.name})", 403)
            return db_user.get_auth()
        except ConfigurationError:
            raise AuthException(AuthFailReason.username, f"Not inicialized user model: {User})", 500)
        except Exception:
            raise AuthException(AuthFailReason.username, f"No user#{auth_user.id}({auth_user.username})", 404)

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthUser]:
        if token := await self.auth_scheme(conn):
            verify_exp: bool = conn.scope["path"] != "/refresh"  # manual refresh
            try:
                user: AuthUser = jwt_decode(token, self.secret, verify_exp)
            except ExpiredSignatureError:  # auto refresh
                user: AuthUser = jwt_decode(token, self.secret, False)
                user = await self.refresh(user)
                tok = jwt_encode(user, self.secret, self.expires)
                conn.scope["tok"] = tok
                # raise AuthException(AuthFailReason.expired, tok, 410)

            return AuthCredentials(scopes=user.role.scopes()), user
