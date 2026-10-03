"""
longcat_sentinel.web
~~~~~~~~~~~~~~~~~~~~
Dashboard assets and the authenticated admin API.
"""

__all__ = ["admin_router"]


def __getattr__(name):
    # Imported lazily so importing this package never triggers a circular import
    # through longcat_sentinel.server.
    if name == "admin_router":
        from longcat_sentinel.web.admin_api import admin_router

        return admin_router
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
