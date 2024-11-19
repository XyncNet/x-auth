from datetime import timedelta

from fastapi.openapi.models import HTTPBase, SecuritySchemeType
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from jose import jwt, JWTError, ExpiredSignatureError
from jose.constants import ALGORITHMS
from pydantic import ValidationError
from starlette import status
from starlette.authentication import AuthenticationError
from starlette.requests import HTTPConnection
from starlette.responses import Response
from tortoise.timezone import now
from x_model import HTTPException

from x_auth.enums import AuthFailReason
from x_auth.pydantic import AuthUser

cookie_name = "access_token"


class AuthException(HTTPException, AuthenticationError):
    def __init__(
        self,
        reason: AuthFailReason,
        parent: Exception | str = None,
        status_: status = status.HTTP_401_UNAUTHORIZED,
        cookie_name_: str | None = cookie_name,
    ) -> None:
        hdrs = (
            {
                "set-cookie": cookie_name_
                + "=; Domain=.xync.net; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            }
            if cookie_name_
            else None
        )
        super().__init__(reason=reason, parent=parent, status_=status_, hdrs=hdrs)


class BearerModel(HTTPBase):
    type_: SecuritySchemeType = SecuritySchemeType.http
    scheme: str = "bearer"


class BearerSecurity(SecurityBase):
    """HTTP Bearer token authentication"""

    def __init__(self, model_: BearerModel = BearerModel(), auto_error: bool = False, scheme_name: str = None):
        self.model = model_
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, conn: HTTPConnection) -> str | None:
        authorization = conn.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise AuthException(reason=AuthFailReason.header, parent="Not authenticated")
            else:
                return None
        if scheme.lower() != self.model.scheme:
            if self.auto_error:
                raise AuthException(reason=AuthFailReason.scheme, parent="Invaid scheme")
            else:
                return None
        return credentials


def on_error(_: HTTPConnection, exc: AuthException) -> Response:
    hdr = {}
    status_ = getattr(exc, "status_code", 401)
    if status_ == 303 and "/login" in (r.path for r in _.app.routes):
        hdr = {"Location": "/login"}
    resp = Response(exc.__repr__(), status_code=status_, headers=hdr)
    resp.delete_cookie(cookie_name, "/", ".xync.net", secure=True, samesite="none")
    return resp


def jwt_encode(data: AuthUser, secret: str, expires_delta: timedelta) -> str:
    return jwt.encode({"exp": now() + expires_delta, **data.model_dump()}, secret, ALGORITHMS.HS256)


def jwt_decode(jwtoken: str, secret: str, verify_exp: bool = True) -> AuthUser:
    try:
        payload = jwt.decode(jwtoken, secret, ALGORITHMS.HS256, {"verify_exp": verify_exp})
    except ExpiredSignatureError as e:
        raise e
    except (ValidationError, JWTError) as e:
        raise AuthException(AuthFailReason.signature, e)
    return AuthUser(**payload)
