from datetime import timedelta

from starlette.responses import JSONResponse
from tortoise.exceptions import IntegrityError, ConfigurationError
from starlette.authentication import AuthenticationBackend
from fastapi.routing import APIRoute
from x_model import FailReason
from x_auth.backend import AuthBackend
from x_auth.depend import Depend
from x_auth.enums import AuthFailReason
from x_auth import jwt_encode, HTTPException, AuthException, BearerSecurity
from x_auth.models import User
from x_auth.pydantic import AuthUser, UserReg, Token


class AuthRouter:
    expires = timedelta(minutes=15)

    def __init__(
        self,
        secret: str,
        domain: str,
        db_user_model: type(User) = User,
        backend: AuthenticationBackend = None,
        scheme: BearerSecurity = BearerSecurity(),
    ):
        self.depend = Depend(scheme)
        self.secret = secret
        self.domain = domain
        self.db_user_model = db_user_model

        # api refresh token
        async def refresh(auth_user: AuthUser = self.depend.AUTHENTICATED) -> Token:
            try:
                db_user: User = await self.db_user_model[auth_user.id]
                auth_user: AuthUser = db_user.get_auth()
            except ConfigurationError:
                raise AuthException(AuthFailReason.username, f"Not inicialized user model: {User})", 500)
            except Exception:
                raise AuthException(AuthFailReason.username, f"No user#{auth_user.id}({auth_user.username})", 404)

            return self._user2tok(auth_user)

        self.routes: dict[str, tuple[callable, str]] = {
            "reg": (self.reg, "POST"),
            "refresh": (refresh, "GET"),
        }
        self.backend = backend or AuthBackend(secret, scheme)

    # API ENDOINTS
    def _user2tok(self, user: AuthUser, tokmod: type[Token] = Token) -> Token | JSONResponse:
        token = tokmod(access_token=jwt_encode(user, self.secret, self.expires), user=user)
        token_dict = token.model_dump()
        resp = JSONResponse(token_dict)
        resp.set_cookie("access_token", token.access_token, domain=f".{self.domain}", samesite="none", secure=True)
        return resp

    # api reg endpoint
    async def reg(self, user_reg_input: UserReg) -> Token:
        data = user_reg_input.model_dump()
        try:
            db_user: User = await self.db_user_model.create(**data)
        except IntegrityError as e:
            raise HTTPException(FailReason.body, e)
        return self._user2tok(db_user.get_auth())

    def get_routes(self) -> list[APIRoute]:
        return [
            APIRoute(
                "/" + path,
                func,
                tags=["Auth"],
                methods=[method],
                name=path.title(),
                operation_id=path,
            )
            for path, (func, method) in self.routes.items()
        ]
