from starlette.types import ASGIApp, Receive, Scope, Send, Message


class AuthRefreshMiddleware:
    def __init__(self, app: ASGIApp, domain: str = ".xync.net") -> None:
        self.app = app
        self.domain = domain

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(msg: Message) -> None:
            if msg["type"] == "http.response.start" and (tok := scope.get("tok")):
                ck = f"access_token={tok}; SameSite=None; Secure; Path=/; Domain={self.domain}"
                msg["headers"].append((b"set-cookie", ck.encode()))

            await send(msg)

        await self.app(scope, receive, send_wrapper)
