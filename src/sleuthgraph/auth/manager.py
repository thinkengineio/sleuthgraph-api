"""UserManager: password policy + lifecycle callbacks.

Uses purpose-specific HKDF subkeys for reset/verification tokens (these
flows aren't wired in Phase 2 routes, but fastapi-users requires the
property to exist on UserManager).

Includes HIBP Pwned Passwords v3 (k-anonymity) check to reject breached
passwords at registration / password-change time.  The check is async and
graceful: if the HIBP API is unreachable the password is allowed through
so that an external service outage never blocks user registration.
"""

import hashlib
import logging
import uuid
from typing import Any

import httpx
from fastapi_users import BaseUserManager, UUIDIDMixin
from fastapi_users.exceptions import InvalidPasswordException

from sleuthgraph.auth.models import User
from sleuthgraph.crypto import password_reset_token_key, verification_token_key

log = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12


async def _is_password_pwned(password: str) -> bool:
    """Check the HIBP Pwned Passwords API using k-anonymity.

    Returns True if the password hash suffix appears in the HIBP response,
    meaning the password has been seen in a data breach.
    Returns False if the password is clean *or* if the API is unreachable
    (graceful degradation).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5.0,
            )
            resp.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException):
        log.warning("HIBP API unreachable; skipping breached-password check")
        return False

    for line in resp.text.splitlines():
        hash_suffix, _, _ = line.partition(":")
        if hash_suffix.strip() == suffix:
            return True
    return False


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    @property
    def reset_password_token_secret(self) -> str:
        return password_reset_token_key()

    @property
    def verification_token_secret(self) -> str:
        return verification_token_key()

    async def validate_password(self, password: str, user: Any) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                reason=f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            )

        if await _is_password_pwned(password):
            raise InvalidPasswordException(
                reason="This password has appeared in a data breach. Please choose a different password."
            )

    async def on_after_forgot_password(self, user, token, request=None):
        from sleuthgraph.auth.email import get_email_sender

        await get_email_sender().send_password_reset(user.email, token)

    async def on_after_request_verify(self, user, token, request=None):
        from sleuthgraph.auth.email import get_email_sender

        await get_email_sender().send_email_verify(user.email, token)
