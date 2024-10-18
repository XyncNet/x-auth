from datetime import timedelta

from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection
from tortoise.exceptions import IntegrityError

from x_auth.enums import FailReason

from x_auth import jwt_decode, jwt_encode, HTTPException
from x_auth.depend import bearer, Req
from x_auth.models import User
from x_auth.pydantic import AuthUser, UserReg, Token


class AuthBackend(AuthenticationBackend):
    expires = timedelta(minutes=15)

    def __init__(self, secret: str, db_user_model: type(User) = User):
        self.secret: str = secret
        self.db_user_model: User = db_user_model
        # todo: optimize auth routes forwarding
        self.routes: dict[str, tuple[callable, str]] = {
            "reg": (self.reg, "POST"),
            "refresh": (self.refresh, "GET"),
        }

    def _user2tok(self, user: AuthUser) -> Token:
        return Token(access_token=jwt_encode(user, self.secret, self.expires), token_type="bearer", user=user)

    # dependency
    async def authenticate(self, conn: HTTPConnection, brt=bearer) -> tuple[AuthCredentials, AuthUser] | None:
        try:
            token: str = (await brt(conn)).credentials
        except AttributeError:
            return None
        user: AuthUser = jwt_decode(token, self.secret, conn.scope["path"] != "/refresh")
        return AuthCredentials(scopes=user.role.scopes()), user

    # API ENDOINTS
    # api reg endpoint
    async def reg(self, user_reg_input: UserReg) -> Token:
        data = user_reg_input.model_dump()
        try:
            db_user: User = await self.db_user_model.create(**data)
        except IntegrityError as e:
            raise HTTPException(FailReason.body, e)
        user: AuthUser = AuthUser.model_validate(db_user, from_attributes=True)
        return self._user2tok(user)

    # api refresh token
    async def refresh(self, user: AuthUser = Req.EXISTED) -> Token:
        return self._user2tok(user)
