"""Internal services shared by the legacy and generic HTTP surfaces.

There is one evaluation path and one consumption path. Both HTTP surfaces
call into these; neither reimplements a decision.
"""
