"""Entity type enumeration.

These are the 8 MVP entity types. Stored as VARCHAR(32) on the Entity model
(app-layer validation via Pydantic + this enum). Adding types in Phase 5+ is
a string-value change — no migration.
"""

from enum import StrEnum


class EntityType(StrEnum):
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    URL = "URL"
    CRYPTO_ADDRESS = "CRYPTO_ADDRESS"
