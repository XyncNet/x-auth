from jose import JWTError
from pydantic import ValidationError
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection

from x_auth import AuthUser, AuthException, FailReason, jwt_decode
from x_auth.pydantic import UserAuth


class AuthBackend(AuthenticationBackend):
    def __init__(self, secret: str):
        self.secret = secret

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthUser] | None:
        # todo: refact with BearerSchema
        if not (auth := conn.headers.get("Authorization")):
            return

        scheme, credentials = auth.split()

        if scheme.lower() == "bearer":
            try:
                user: UserAuth = jwt_decode(credentials, self.secret)
                return AuthCredentials(user.scopes), AuthUser(**user.model_dump())
            except JWTError as e:
                raise AuthException(FailReason.expired, parent=e)
            except ValidationError as e:
                raise AuthException(FailReason.signature, parent=e)
