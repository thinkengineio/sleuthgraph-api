"""Pluggable email delivery for auth flows.

MVP ships ``ConsoleEmailSender`` — writes the reset/verify link to server
logs so a self-host operator can paste it during initial setup. SMTP/SES
delivery is a Phase 7+ follow-up.
"""

import logging
from typing import Protocol

from sleuthgraph.config import get_settings

log = logging.getLogger(__name__)


class EmailSender(Protocol):
    async def send_password_reset(self, to: str, token: str) -> None: ...
    async def send_email_verify(self, to: str, token: str) -> None: ...


class ConsoleEmailSender:
    async def send_password_reset(self, to: str, token: str) -> None:
        link = f"{get_settings().auth_frontend_base_url}/reset-password?token={token}"
        log.info("[email] to=%s subject='Reset your Sleuthgraph password' link=%s", to, link)

    async def send_email_verify(self, to: str, token: str) -> None:
        link = f"{get_settings().auth_frontend_base_url}/verify-email?token={token}"
        log.info("[email] to=%s subject='Verify your Sleuthgraph email' link=%s", to, link)


_sender: EmailSender = ConsoleEmailSender()


def get_email_sender() -> EmailSender:
    """DI point so tests can inject a FakeEmailSender."""
    return _sender
