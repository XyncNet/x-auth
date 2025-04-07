from datetime import timedelta

from aiogram.utils.web_app import WebAppInitData, safe_parse_webapp_init_data
from litestar import Response, post
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.security.jwt import JWTCookieAuth

from x_auth.middleware import JWTAuthMiddleware, Tok
from x_auth.models import UserTg
from x_auth.types import AuthUser


async def retrieve_user_handler(token: Tok, _cn: ASGIConnection) -> AuthUser:
    return AuthUser(id=int(token.sub), role=token.extras["role"], blocked=token.extras["blocked"])


async def revoked_token_handler(token: Tok, _cn: ASGIConnection) -> bool:
    return token.extras["blocked"]


class Auth:
    def __init__(self, sec: str, user_model: type[UserTg] = UserTg, exc_paths: list[str] = None):
        self.jwt = JWTCookieAuth(  # [AuthUser, Tok]
            retrieve_user_handler=retrieve_user_handler,
            revoked_token_handler=revoked_token_handler,
            default_token_expiration=timedelta(minutes=1),
            authentication_middleware_class=JWTAuthMiddleware,
            token_secret=sec,
            token_cls=Tok,
            domain=".xync.net",
            # endpoints excluded from authentication: (login and openAPI docs)
            exclude=["/schema", "/auth", "/public"] + (exc_paths or []),
        )

        @post("/auth/tma", tags=["Auth"], description="Gen JWToken from tg initData")
        async def tma(tid: str) -> Response[user_model.in_type(True)]:
            try:
                twaid: WebAppInitData = safe_parse_webapp_init_data(self.jwt.token_secret, tid)
            except ValueError:
                raise NotAuthorizedException(detail="Tg Initdata invalid")
            user_in = await user_model.tg2in(twaid.user)
            db_user, cr = await user_model.update_or_create(**user_in.df_unq())  # on login: update user in db from tg
            res = self.jwt.login(
                identifier=str(db_user.id),
                token_extras={"role": db_user.role, "blocked": db_user.blocked},
                response_body=user_model.validate(dict(db_user)),
            )
            res.cookies[0].httponly = False
            return res

        self.handler = tma
