"""Public routes package."""

# Re-export register function from the parallel public_routes.py module
# This allows imports like `from .public_routes import register` to work
# even though public_routes is now also a package (directory)
from ..public_routes import register

__all__ = ["register"]
