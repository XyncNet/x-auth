from datetime import timedelta
from tortoise.exceptions import IntegrityError, ConfigurationError
from x_auth.backend import AuthBackend

from x_auth.depend import Depend
from x_auth.enums import FailReason, AuthFailReason
from x_auth import jwt_encode, HTTPException, AuthException, BearerBase
from x_auth.model import User
from x_auth.pydantic import AuthUser, UserReg, Token


class AuthRouter:
    expires = timedelta(minutes=15)

    def __init__(self, secret: str, db_user_model: type(User) = User, scheme: BearerBase = BearerBase(False)):
        self.depend = Depend(scheme)

        # API ENDOINTS
        def _user2tok(user: AuthUser) -> Token:
            return Token(access_token=jwt_encode(user, secret, self.expires), user=user)

        # api reg endpoint
        async def reg(user_reg_input: UserReg) -> Token:
            data = user_reg_input.model_dump()
            try:
                db_user: User = await db_user_model.create(**data)
            except IntegrityError as e:
                raise HTTPException(FailReason.body, e)
            user: AuthUser = AuthUser.model_validate(db_user, from_attributes=True)
            return _user2tok(user)

        # api refresh token
        async def refresh(auth_user: AuthUser = self.depend.AUTHENTICATED) -> Token:
            try:
                db_user: User = await User[auth_user.id]
                auth_user = AuthUser.model_validate(db_user, from_attributes=True)
            except ConfigurationError:
                raise AuthException(AuthFailReason.username, f"Not inicialized user model: {User})", 500)
            except Exception:
                raise AuthException(AuthFailReason.username, f"No user#{auth_user.id}({auth_user.username})", 404)

            return _user2tok(auth_user)

        self.routes: dict[str, tuple[callable, str]] = {
            "reg": (reg, "POST"),
            "refresh": (refresh, "GET"),
        }
        self.backend = AuthBackend(secret, scheme)