from datetime import timedelta

from aiogram.utils.web_app import WebAppInitData, safe_parse_webapp_init_data
from litestar import Response, post, Controller as BaseController
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.security.jwt import JWTCookieAuth

from x_auth.middleware import JWTAuthMiddleware
from x_auth.models import UserTg
from x_auth.types import AuthUser, Tok


class Auth(BaseController):
    path = "/auth"
    tags = ["Auth"]

    @staticmethod
    async def retrieve_user_handler(token: Tok, _cn: ASGIConnection) -> AuthUser:
        return AuthUser(id=token.sub, role=token.extras["role"], status=token.extras["status"])

    @staticmethod
    async def revoked_token_handler(token: Tok, _cn: ASGIConnection) -> bool:
        return not token.extras["blocked"]

    def __init__(self, sec: str):
        super().__init__()
        self.jwt = JWTCookieAuth[AuthUser, Tok](
            retrieve_user_handler=self.retrieve_user_handler,
            revoked_token_handler=self.revoked_token_handler,
            default_token_expiration=timedelta(minutes=1),
            authentication_middleware_class=JWTAuthMiddleware,
            token_secret=sec,
            token_cls=Tok,
            # endpoints excluded from authentication: (login and openAPI docs)
            exclude=["/login", "/schema", "/public/"],
        )

    @post("/tma")
    async def login_handler(self, init_data: str) -> Response[UserTg.pyd()]:
        try:
            twaid: WebAppInitData = safe_parse_webapp_init_data(token=self.jwt.token_secret, init_data=init_data)
        except ValueError:
            raise NotAuthorizedException(detail="Tg Initdata invalid")
        db_user: UserTg
        user_in = await UserTg.tg2in(twaid.user)
        db_user, cr = await UserTg.upsert(user_in)  # on login: update user in db from tg
        return self.jwt.login(
            identifier=str(db_user.id),
            token_extras={"role": db_user.role, "blocked": db_user.blocked},
            response_body=await db_user.one(),
        )
