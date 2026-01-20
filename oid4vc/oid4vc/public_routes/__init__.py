"""Public routes package.

This package is being incrementally built to replace the monolithic
public_routes.py module. For now, to avoid circular imports, exports from
the .py module are lazily loaded via __getattr__.
"""

import sys

# Cache the loaded module to avoid reloading it multiple times
_public_routes_py_module = None


def _get_public_routes_module():
    """Load the public_routes.py module once and cache it."""
    global _public_routes_py_module
    if _public_routes_py_module is None:
        import importlib.util
        from pathlib import Path

        _module_path = Path(__file__).parent.parent / "public_routes.py"
        _spec = importlib.util.spec_from_file_location(
            "oid4vc._public_routes_py", _module_path
        )
        _module = importlib.util.module_from_spec(_spec)
        # Set package so relative imports work
        _module.__package__ = "oid4vc"
        sys.modules["oid4vc._public_routes_py"] = _module
        _spec.loader.exec_module(_module)
        _public_routes_py_module = _module
    return _public_routes_py_module


def __getattr__(name):
    """Lazy import to avoid circular dependency.

    Re-export all public symbols from the parallel public_routes.py module.
    Cache them in this module's namespace so monkeypatching works.
    """
    module = _get_public_routes_module()
    if hasattr(module, name):
        attr = getattr(module, name)
        # Cache in this module's namespace so patches stick
        globals()[name] = attr
        return attr
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
