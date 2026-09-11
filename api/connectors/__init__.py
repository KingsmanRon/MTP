"""Vendor connectors.

Everything under this package is allowed to name a vendor, a scheme and
that vendor's own field types, because speaking an external protocol is
the whole job. The rule the boundary rests on runs the other way: nothing
a connector knows may travel inward. A connector's only outputs are the
vendor-neutral types in :mod:`api.core.authority` and the neutral scope
keys :mod:`api.domains.payment` understands.

A connector answers exactly one question: *is this delegation
cryptographically valid, intended for this principal, current,
sufficiently disclosed, and what scope does it delegate?* It never
answers whether the organisation permits the act. That is policy, it is
decided afterwards, and a valid external credential is never by itself an
Inntris ALLOW.
"""
