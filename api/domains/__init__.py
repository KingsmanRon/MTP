"""Domain modules.

Each domain owns the policy semantics that are specific to one class of
consequential action and implements the ``DomainPolicy`` port from
``api.core.authority``. The general policy engine keeps the concerns that
are not domain-specific — action-type registration, trust thresholds,
lifecycle checks — and dispatches into these modules.
"""
