import secrets
from datetime import UTC, datetime, timedelta

from werkzeug.wrappers import Response

from app.configs import config
from app.extensions.ext_redis import redis_client
from app.services.passport import PassportService

COOKIE_NAME_ACCESS_TOKEN = "access_token"
COOKIE_NAME_REFRESH_TOKEN = "refresh_token"
COOKIE_NAME_CSRF_TOKEN = "csrf_token"


class TokenService:
    @staticmethod
    def is_secure() -> bool:
        url = str(config.CONSOLE_WEB_URL)
        return url.startswith("https") if url else False

    @staticmethod
    def real_cookie_name(cookie_name: str) -> str:
        return "__Host-" + cookie_name if TokenService.is_secure() else cookie_name

    @staticmethod
    def generate_refresh_token() -> str:
        return secrets.token_hex(64)

    @staticmethod
    def generate_csrf_token(user_id: str) -> str:
        exp_dt = datetime.now(UTC) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "exp": int(exp_dt.timestamp()),
            "sub": user_id,
        }
        return PassportService().issue(payload)

    @staticmethod
    def store_refresh_token(refresh_token: str, account_id: str) -> None:
        refresh_token_key = f"{config.REFRESH_TOKEN_PREFIX}{refresh_token}"
        account_refresh_token_key = f"{config.ACCOUNT_REFRESH_TOKEN_PREFIX}{account_id}"
        refresh_token_expiry = timedelta(days=int(config.REFRESH_TOKEN_EXPIRE_DAYS))
        redis_client.setex(refresh_token_key, refresh_token_expiry, account_id)
        redis_client.setex(account_refresh_token_key, refresh_token_expiry, refresh_token)

    @staticmethod
    def _set_cookie_pair(
        response: Response,
        cookie_name: str,
        value: str,
        *,
        httponly: bool,
        secure: bool,
        samesite: str,
        max_age: int,
    ):
        # 普通 cookie，兼容仍读取 access_token / refresh_token / csrf_token 的接口
        response.set_cookie(
            cookie_name,
            value=value,
            httponly=httponly,
            secure=secure,
            samesite=samesite,
            max_age=max_age,
            path="/",
        )

        # https 下额外写 __Host- 前缀 cookie
        if TokenService.is_secure():
            response.set_cookie(
                f"__Host-{cookie_name}",
                value=value,
                httponly=httponly,
                secure=True,
                samesite=samesite,
                max_age=max_age,
                path="/",
            )

    @staticmethod
    def set_access_token_to_cookie(response: Response, token: str, samesite: str = "Lax"):
        TokenService._set_cookie_pair(
            response=response,
            cookie_name=COOKIE_NAME_ACCESS_TOKEN,
            value=token,
            httponly=True,
            secure=TokenService.is_secure(),
            samesite=samesite,
            max_age=int(config.ACCESS_TOKEN_EXPIRE_MINUTES * 60),
        )

    @staticmethod
    def set_refresh_token_to_cookie(response: Response, token: str):
        TokenService._set_cookie_pair(
            response=response,
            cookie_name=COOKIE_NAME_REFRESH_TOKEN,
            value=token,
            httponly=True,
            secure=TokenService.is_secure(),
            samesite="Lax",
            max_age=int(60 * 60 * 24 * config.REFRESH_TOKEN_EXPIRE_DAYS),
        )

    @staticmethod
    def set_csrf_token_to_cookie(response: Response, token: str):
        TokenService._set_cookie_pair(
            response=response,
            cookie_name=COOKIE_NAME_CSRF_TOKEN,
            value=token,
            httponly=False,
            secure=TokenService.is_secure(),
            samesite="Lax",
            max_age=int(config.ACCESS_TOKEN_EXPIRE_MINUTES * 60),
        )