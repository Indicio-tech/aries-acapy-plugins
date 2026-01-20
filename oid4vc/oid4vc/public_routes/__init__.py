"""Public routes package.

This package is being incrementally built to replace the monolithic public_routes.py module.
For now, to avoid circular imports, the register function is imported using sys.modules manipulation.
"""

import sys

# The parallel public_routes.py module has the register function we need.
# To avoid circular import (since package and module have the same name),
# we access it via sys.modules after Python has already loaded it.

def __getattr__(name):
    """Lazy import to avoid circular dependency."""
    if name == "register":
        # At this point, oid4vc.public_routes refers to THIS package.
        # We need to get the .py module which Python loaded as part of oid4vc.
        # When Python imported oid4vc, it loaded public_routes.py first before this package.
        # But then it replaced sys.modules['oid4vc.public_routes'] with this package.
        # So we reload the .py file explicitly.
        import importlib.util
        from pathlib import Path
        _module_path = Path(__file__).parent.parent / "public_routes.py"
        _spec = importlib.util.spec_from_file_location("oid4vc._public_routes_py", _module_path)
        _module = importlib.util.module_from_spec(_spec)
        # Set as oid4vc parent so relative imports work
        _module.__package__ = "oid4vc"
        sys.modules["oid4vc._public_routes_py"] = _module
        _spec.loader.exec_module(_module)
        return _module.register
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
