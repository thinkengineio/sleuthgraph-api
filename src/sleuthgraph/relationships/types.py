"""Relationship type enumeration.

MVP set of typed edges. Stored as VARCHAR(32) on the model; extensible
without migration by adding values here.
"""

from enum import Enum


class RelationshipType(str, Enum):
    OWNS = "OWNS"
    EMPLOYED_BY = "EMPLOYED_BY"
    REGISTERED_BY = "REGISTERED_BY"
    HOSTED_ON = "HOSTED_ON"
    RESOLVES_TO = "RESOLVES_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    MENTIONS = "MENTIONS"
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
