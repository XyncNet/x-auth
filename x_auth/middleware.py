import logging
from typing import Sequence, Any

from anyio.from_thread import start_blocking_portal
from jwt import ExpiredSignatureError
from litestar.datastructures import MutableScopeHeaders
from litestar.types import Scope, Receive, Send, Message
from litestar.security.jwt import JWTCookieAuthenticationMiddleware, Token
from litestar.security.jwt.token import JWTDecodeOptions

from x_auth.exceptions import ExpiredSignature
from x_auth.models import UserTg


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


class JWTAuthMiddleware(JWTCookieAuthenticationMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        except ExpiredSignature as e:
            uet: str = e.args[0]  # updated encoded token

            async def send_wrapper(msg: Message) -> None:
                if msg["type"] == "http.response.start":
                    headers = MutableScopeHeaders.from_message(msg)
                    headers["Set-Cookie"] = f"access_token={uet}; Domain=.xync.net; Path=/; SameSite=none; Secure"
                await send(msg)

            await super().__call__(scope, receive, send_wrapper)
