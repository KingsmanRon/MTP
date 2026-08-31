"""Static guard for TenantScopedDatabase inheritance safety.

TenantScopedDatabase deliberately reuses business methods from the legacy
Database class. That is safe only while inherited methods obtain connections
through acquisition methods overridden by the tenant facade, never by touching
Database._pool directly.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from api.database import Database
from api.system_tenant_adapter import TenantScopedDatabase


_RAW_CONNECTION_PRIMITIVES = frozenset(
    {"__init__", "create", "close", "acquire", "acquire_as_tenant"}
)
_SELF_POOL_METHODS = frozenset({"__init__", "close", "acquire", "acquire_as_tenant"})


def _database_class_ast() -> ast.ClassDef:
    source_path = Path(inspect.getsourcefile(Database))
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Database":
            return node
    raise AssertionError("Database class AST not found")


def _touches_self_pool(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Attribute)
        and child.attr == "_pool"
        and isinstance(child.value, ast.Name)
        and child.value.id == "self"
        for child in ast.walk(node)
    )


def test_tenant_facade_overrides_every_raw_connection_primitive() -> None:
    """Inherited code cannot fall back to the privileged constructor/pool API."""
    missing = sorted(
        name for name in _RAW_CONNECTION_PRIMITIVES if name not in TenantScopedDatabase.__dict__
    )
    assert missing == [], f"TenantScopedDatabase must override raw DB primitives: {missing}"


def test_inherited_database_business_methods_never_touch_raw_pool_directly() -> None:
    """Any future direct self._pool access in an inheritable method fails CI.

    The four methods allowed to touch ``self._pool`` are precisely the connection
    primitives that TenantScopedDatabase overrides. ``Database.create`` creates
    a local pool but never reads ``self._pool`` and is also overridden by the
    tenant facade. Every other inherited Database method must therefore reach a
    connection only through ``self.acquire()`` or ``self.acquire_as_tenant()``.
    """
    violations: list[str] = []
    database_class = _database_class_ast()
    for node in database_class.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _touches_self_pool(node) and node.name not in _SELF_POOL_METHODS:
            violations.append(node.name)

    assert violations == [], (
        "Inherited Database methods bypass TenantScopedDatabase acquisition overrides: "
        f"{sorted(violations)}"
    )
