"""Concrete ``AuthorityProvider`` implementations.

Core defines the ``AuthorityProvider`` port and refuses to know anything
about a particular issuer. This package is where that knowledge is
allowed to live: one subpackage per external delegation format, each
translating its issuer's vocabulary into the neutral
``ResolvedAuthority`` the rest of the system consumes.

Nothing here is wired into a request path by importing it. A provider
becomes live only when a deployment constructs one and hands it to
``AuthorityEvaluationService``; an unconstructed provider changes no
decision anywhere.
"""

from __future__ import annotations

__all__: list[str] = []
