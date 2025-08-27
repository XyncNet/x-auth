from datetime import timedelta

from aiogram.utils.auth_widget import check_signature
from aiogram.utils.web_app import WebAppInitData, safe_parse_webapp_init_data, WebAppUser
from litestar import Response, post
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.security.jwt import JWTCookieAuth

from x_auth.middleware import JWTAuthMiddleware, Tok
from x_auth.models import User
from x_auth.types import AuthUser, TgUser


async def retrieve_user_handler(token: Tok, _cn: ASGIConnection) -> AuthUser:
    return AuthUser(id=int(token.sub), role=token.extras["role"], blocked=token.extras["blocked"])


async def revoked_token_handler(token: Tok, _cn: ASGIConnection) -> bool:
    return token.extras["blocked"]


class Auth:
    def __init__(self, sec: str, user_model: type[User] = User, exc_paths: list[str] = None):
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

        async def user_proc(user: WebAppUser) -> Response[WebAppUser]:
            user_in = await user_model.tg2in(user)
            db_user, cr = await user_model.update_or_create(**user_in.df_unq())  # on login: update user in db from tg
            res = self.jwt.login(
                identifier=str(db_user.id),
                token_extras={"role": db_user.role, "blocked": db_user.blocked},
                response_body=user,
            )
            res.cookies[0].httponly = False
            return res

        # login for api endpoint
        @post("/auth/twa", tags=["Auth"], description="Gen JWToken from tg login widget")
        async def twa(data: TgUser) -> Response[WebAppUser]:  # widget
            dct = data.dump()
            if not check_signature(self.jwt.token_secret, dct.pop("hash"), **dct):
                raise NotAuthorizedException("Tg login widget data invalid")
            return await user_proc(WebAppUser(**dct))

        @post("/auth/tma", tags=["Auth"], description="Gen JWToken from tg initData")
        async def tma(tid: str) -> Response[WebAppUser]:
            try:
                twaid: WebAppInitData = safe_parse_webapp_init_data(self.jwt.token_secret, tid)
            except ValueError as e:
                raise NotAuthorizedException(detail=f"Tg Initdata invalid {e}")
            return await user_proc(twaid.user)

        self.tma_handler = tma
        self.twa_handler = twa
