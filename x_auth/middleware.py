import logging
from datetime import datetime, timezone
from typing import Sequence, Any

from jwt import ExpiredSignatureError
from litestar.datastructures import MutableScopeHeaders, Headers

# from litestar.exceptions import NotAuthorizedException
from litestar.types import Scope, Receive, Send, Message
from litestar.security.jwt import JWTCookieAuthenticationMiddleware, Token
from litestar.security.jwt.token import JWTDecodeOptions
from msgspec import convert

from x_auth.exceptions import ExpiredSignature


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
            payload.update(
                {
                    "exp": (now := int(datetime.now(timezone.utc).timestamp())) + (payload["exp"] - payload["iat"]),
                    "iat": now,
                }
            )
            tok = convert(payload, cls, strict=False)
            encoded_token = tok.encode(secret, algorithms[0])  # check where from getting algorithms
            raise ExpiredSignature(int(payload["sub"]), encoded_token, e)


class JWTAuthMiddleware(JWTCookieAuthenticationMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        except ExpiredSignature as e:
            uid, uet, _e = e.args  # uid, updated encoded token
            if await scope["app"].state.get("user_model").is_blocked(uid):
                logging.error(f"User#{uid} can't refresh. Blocked!")
                raise _e

            async def send_wrapper(msg: Message) -> None:
                if msg["type"] == "http.response.start":
                    headers = MutableScopeHeaders.from_message(msg)
                    headers["Set-Cookie"] = f"token=Bearer {uet}; Domain=.xync.net; Path=/; SameSite=none; Secure"
                await send(msg)

            # todo: refact dirty header update
            # noinspection PyUnresolvedReferences
            scope["state"]["_ls_connection_state"].headers = Headers({"authorization": "Bearer " + uet})
            await super().__call__(scope, receive, send_wrapper)
        # except NotAuthorizedException as e:
        #     if e.detail == "No JWT token found in request header or cookies" and e.status_code == 401:
        #         return e
