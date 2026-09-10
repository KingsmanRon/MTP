"""Durable state for the core authority boundary.

The types in ``api.core.authority`` describe what execution authority *is*.
This package is where it lives between the decision and the execution, and
where the race-safety the boundary promises is actually enforced — by the
database, not by application ordering.
"""
