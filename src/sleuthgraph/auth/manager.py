"""UserManager: password policy + lifecycle callbacks.

Uses purpose-specific HKDF subkeys for reset/verification tokens (these
flows aren't wired in Phase 2 routes, but fastapi-users requires the
property to exist on UserManager).
"""

import uuid
from typing import Any

from fastapi_users import BaseUserManager, UUIDIDMixin
from fastapi_users.exceptions import InvalidPasswordException

from sleuthgraph.auth.models import User
from sleuthgraph.crypto import password_reset_token_key, verification_token_key

MIN_PASSWORD_LENGTH = 8


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
