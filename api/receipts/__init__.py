"""Public receipt schemas and their version-branched canonicalisation.

v1 and v2 live in ``api.legacy_main`` and are frozen: their field set,
their ``json.dumps(sort_keys=True)`` canonicalisation and their published
meaning are unchanged by anything here. v3 is a separate branch.
"""
