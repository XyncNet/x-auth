import logging
from typing import Sequence, Any

from anyio.from_thread import start_blocking_portal
from jwt import ExpiredSignatureError
from msgspec import Struct
from litestar.security.jwt import Token
from litestar.security.jwt.token import JWTDecodeOptions
from x_auth.models import UserTg

from x_auth.enums import Role
from x_auth.exceptions import ExpiredSignature


class AuthUser(Struct):
    id: int
    blocked: bool
    role: Role


class Tok(Token):
    @classmethod
    def decode_payload(
        cls,
        encoded_token: str,
        secret: str,
        algorithms: list[str],
        issuer: list[str] | None = None,
        audience: str | Sequence[str] | None = None,
        options: JWTDecodeOptions | None = None,
    ) -> Any:
        try:
            return super().decode_payload(encoded_token, secret, algorithms, issuer, audience, options)
        except ExpiredSignatureError as e:
            logging.warning("JWToken expired")
            options["verify_exp"] = False
            payload = super().decode_payload(encoded_token, secret, algorithms, issuer, audience, options)
            with start_blocking_portal(backend="asyncio") as port:
                if port.call(UserTg.is_blocked, payload["sub"]):
                    logging.error(f"User#{payload['sub']} can't refresh. Blocked!")
                    raise e
            encoded_token = super().encode(secret, algorithms[0])  # check where from getting algorithms
            raise ExpiredSignature(encoded_token)
