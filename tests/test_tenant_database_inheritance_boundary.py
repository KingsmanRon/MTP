"""Structural guard for TenantScopedDatabase inheritance safety.

TenantScopedDatabase deliberately reuses business methods from the legacy
Database class. That is safe only while inherited methods obtain connections
through acquisition methods overridden by the tenant facade, never by touching
Database._pool directly or reflectively.
"""


_RAW_CONNECTION_PRIMITIVES = frozenset(
    {"__init__", "create", "close", "acquire", "acquire_as_tenant"}
)
_RAW_POOL_METHODS = frozenset({"__init__", "close", "acquire", "acquire_as_tenant"})


def _code_references_raw_pool(code) -> bool:
    if "_pool" in code.co_names or "_pool" in code.co_consts:
        return True
    return any(
        hasattr(constant, "co_names") and _code_references_raw_pool(constant)
        for constant in code.co_consts
    )


def test_tenant_facade_overrides_every_raw_connection_primitive() -> None:
    """Inherited code cannot fall back to the privileged constructor/pool API."""
    adapter_module = __import__(
        "api.system_tenant_adapter", fromlist=["TenantScopedDatabase"]
    )
    tenant_scoped_database = adapter_module.TenantScopedDatabase

    missing = sorted(
        name
        for name in _RAW_CONNECTION_PRIMITIVES
        if name not in tenant_scoped_database.__dict__
    )
    assert missing == [], f"TenantScopedDatabase must override raw DB primitives: {missing}"


def test_inherited_database_business_methods_never_reference_raw_pool() -> None:
    """Any future raw-pool reference in an inheritable business method fails CI.

    Direct attribute access compiles ``_pool`` into ``co_names``; reflective
    access such as ``getattr(self, '_pool')`` places it in ``co_consts``. Nested
    code objects are checked recursively. The only permitted raw-pool references
    are the connection primitives that TenantScopedDatabase overrides.
    """
    database_module = __import__("api.database", fromlist=["Database"])
    database = database_module.Database
    violations: list[str] = []

    for name, member in database.__dict__.items():
        function = getattr(member, "__func__", member)
        code = getattr(function, "__code__", None)
        if code is None:
            continue
        if _code_references_raw_pool(code) and name not in _RAW_POOL_METHODS:
            violations.append(name)

    assert violations == [], (
        "Inherited Database methods bypass TenantScopedDatabase acquisition overrides: "
        f"{sorted(violations)}"
    )
