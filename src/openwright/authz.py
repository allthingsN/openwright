"""Authorization for who may write evidence vs. generate reports (NFR-SEC-04).

A small capability model with segregation of duties: the party that *writes
evidence* need not be the party that *generates reports*, and neither need hold
the checkpoint signing key. Authorization is opt-in — pass a ``principal`` +
``Authorizer`` to the SDK / report builder to enforce it; omit them to run
unauthenticated (the default, e.g. for the demo). The collector supports
optional bearer-token authentication mapping tokens to principals.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Optional


class Capability(str, enum.Enum):
    WRITE_EVIDENCE = "write_evidence"
    GENERATE_REPORT = "generate_report"
    ADMIN = "admin"


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    id: str
    capabilities: frozenset = field(default_factory=frozenset)

    def has(self, cap: Capability) -> bool:
        return Capability.ADMIN in self.capabilities or cap in self.capabilities


class Authorizer:
    """Enforces capabilities. With no principal supplied, enforcement is off."""

    def require(self, principal: Optional[Principal], capability: Capability) -> None:
        if principal is None:
            return  # unauthenticated mode (opt-in auth)
        if not principal.has(capability):
            raise AuthorizationError(
                f"principal {principal.id!r} lacks capability {capability.value!r}"
            )


class TokenAuthority:
    """Maps opaque bearer tokens to principals for the collector (NFR-SEC-04)."""

    def __init__(self, tokens: Optional[Dict[str, Principal]] = None) -> None:
        self._tokens = dict(tokens or {})

    def add(self, token: str, principal: Principal) -> None:
        self._tokens[token] = principal

    def principal_for(self, token: Optional[str]) -> Optional[Principal]:
        if not token:
            return None
        return self._tokens.get(token)

    def authorize_bearer(self, authorization_header: Optional[str], capability: Capability) -> bool:
        token = None
        if authorization_header and authorization_header.lower().startswith("bearer "):
            token = authorization_header[7:].strip()
        principal = self.principal_for(token)
        return principal is not None and principal.has(capability)
