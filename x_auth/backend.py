from datetime import timedelta

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from starlette import status
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection

from x_auth import jwt_decode, jwt_encode
from x_auth.depend import get_user_from_db
from x_auth.models import User
from x_auth.pydantic import AuthUser, UserReg, Token

bearer = HTTPBearer(bearerFormat="xFormat", scheme_name="xSchema", description="xAuth", auto_error=False)


class AuthBackend(AuthenticationBackend):
    expires = timedelta(days=1)

    def __init__(self, secret: str, db_user_model: type(User) = User):
        self.secret = secret
        self.db_user_model = db_user_model

    def _user2tok(self, user: AuthUser) -> Token:
        return Token(access_token=jwt_encode(user, self.secret, self.expires), token_type="bearer", user=user)

    # dependency
    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, AuthUser] | None:
        try:
            # noinspection PyTypeChecker
            token: str = (await bearer(conn)).credentials
        except AttributeError:
            return None
        user: AuthUser = jwt_decode(token, self.secret)
        # noinspection PyTypeChecker
        return AuthCredentials(scopes=user.role.scopes()), user

    # API ENDOINTS
    # api reg endpoint
    async def reg_user(self, user_reg_input: UserReg) -> Token:
        data = user_reg_input.model_dump()
        try:
            db_user: User = await self.db_user_model.create(**data)
        except Exception as e:
            raise HTTPException(status.HTTP_406_NOT_ACCEPTABLE, detail=e.__repr__())
        user: AuthUser = AuthUser.model_validate(db_user, from_attributes=True)
        return self._user2tok(user)

    # api refresh token
    async def refresh_token(self, user=Depends(get_user_from_db)) -> Token:
        return self._user2tok(user)
