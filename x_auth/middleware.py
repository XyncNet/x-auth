from litestar.datastructures import MutableScopeHeaders
from litestar.security.jwt import JWTCookieAuthenticationMiddleware
from litestar.types import Scope, Receive, Send, Message

from x_auth.exceptions import ExpiredSignature


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
