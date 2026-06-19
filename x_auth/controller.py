import logging
from base64 import b64encode
from datetime import timedelta

from aiogram import Bot
from aiogram.exceptions import TelegramForbiddenError, TelegramBadRequest
from aiogram.utils.auth_widget import check_signature
from aiogram.utils.web_app import WebAppInitData, safe_parse_webapp_init_data, WebAppUser
from litestar import Response, post
from litestar.config.app import AppConfig
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.security.jwt import JWTCookieAuth

from x_auth.middleware import JWTAuthMiddleware, Tok
from x_auth.models import User
from x_auth.types import AuthUser, TgUser, XyncUser


async def retrieve_user_handler(token: Tok, _cn: ASGIConnection) -> AuthUser:
    return AuthUser(id=int(token.sub), role=token.extras["role"], blocked=token.extras["blocked"])


async def revoked_token_handler(token: Tok, _cn: ASGIConnection) -> bool:
    return False  # token.extras["blocked"]


class Auth:
    def __init__(self, sec: str, user_model: type[User] = User, exc_paths: list[str] = None, domain: str = ".xync.net"):
        self.jwt = JWTCookieAuth(  # [AuthUser, Tok]
            retrieve_user_handler=retrieve_user_handler,
            revoked_token_handler=revoked_token_handler,
            default_token_expiration=timedelta(minutes=1),
            authentication_middleware_class=JWTAuthMiddleware,
            token_secret=sec,
            token_cls=Tok,
            domain=domain,
            # endpoints excluded from authentication: (login and openAPI docs)
            exclude=["/schema", "/auth", "/public"] + (exc_paths or []),
        )
        self.user_model = user_model

        async def user_proc(user: WebAppUser) -> Response[XyncUser]:
            db_user, cr = await user_model.tg_upsert(user)  # on login: update user in db from tg
            if user.allows_write_to_pm is None:
                try:
                    await Bot(sec).send_chat_action(user.id, "typing")
                    db_user.blocked = False
                except (TelegramForbiddenError, TelegramBadRequest):
                    db_user.blocked = True
            else:
                db_user.blocked = not user.allows_write_to_pm
            await db_user.save()
            res = self.jwt.login(
                identifier=str(db_user.id),
                token_extras={"role": db_user.role, "blocked": db_user.blocked},
                response_body=XyncUser.model_validate(
                    {
                        **user.model_dump(),
                        "xid": db_user.id,
                        "pub": b64encode(db_user.pub),
                        "prv": db_user.prv and b64encode(db_user.prv),
                        "allows_write_to_pm": user.allows_write_to_pm or not db_user.blocked,
                    }
                ),
            )
            logging.warning({db_user.id: res.cookies[0]})
            res.cookies[0].httponly = False
            return res

        # login for api endpoint
        @post("/auth/twa", tags=["Auth"], description="Gen JWToken from tg login widget")
        async def twa(data: TgUser) -> Response[XyncUser]:  # widget
            dct = data.dump()
            if not check_signature(self.jwt.token_secret, dct.pop("hash"), **dct):
                raise NotAuthorizedException("Tg login widget data invalid")
            return await user_proc(WebAppUser(**dct))

        @post("/auth/tma", tags=["Auth"], description="Gen JWToken from tg initData")
        async def tma(tid: str) -> Response[XyncUser]:
            try:
                twaid: WebAppInitData = safe_parse_webapp_init_data(self.jwt.token_secret, tid)
            except ValueError as e:
                logging.error(e)
                raise NotAuthorizedException(detail=f"Tg Initdata invalid {e}")
            return await user_proc(twaid.user)

        self.tma_handler = tma
        self.twa_handler = twa

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        # JWTAuthMiddleware's silent-refresh path looks the user model up from app state
        # (`app.state["user_model"].permissions(uid)`); register it here so that contract
        # holds. Register on the app this Auth guards instead of leaving it to each caller.
        app_config.state["user_model"] = self.user_model
        return self.jwt.on_app_init(app_config)
