import logging
from fastapi import HTTPException
from jose import jwt, JWTError
from jose.constants import ALGORITHMS
from pydantic import ValidationError
from starlette import status
from starlette.authentication import AuthenticationError
from starlette.requests import HTTPConnection
from starlette.responses import Response

from x_auth.enums import FailReason
from x_auth.pydantic import AuthUser


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


def jwt_decode(jwtoken: str, secret: str) -> AuthUser:
    try:
        payload = jwt.decode(jwtoken, secret, algorithms=[ALGORITHMS.NONE])
    except JWTError as e:
        raise AuthException(FailReason.expired, parent=e)
    try:
        return AuthUser(**payload)
    except ValidationError as e:
        raise AuthException(FailReason.signature, parent=e)
