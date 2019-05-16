# External
from importlib_metadata import version

# Project
from .ssl_context import create_client_ssl_context, create_server_ssl_context

try:
    __version__ = version("security")
except Exception:
    __version__ = "unknown"

__all__ = ("__version__", "create_client_ssl_context", "create_server_ssl_context")
