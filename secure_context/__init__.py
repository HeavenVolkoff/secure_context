# Internal
import sys

# Project
from .ssl_context import (
    SSLWarning,
    create_server_ssl_context,
    create_client_authentication_ssl_context,
)

if sys.version_info >= (3, 8):
    # Internal
    from importlib.metadata import metadata
else:
    # External
    from importlib_metadata import metadata  # type: ignore[import,reportMissingImports]

try:
    _metadata = metadata(__name__)
    __author__: str = _metadata["Author"]
    __version__: str = _metadata["Version"]
    __summary__: str = _metadata["Summary"]
except Exception:  # pragma: no cover
    # Internal
    import traceback
    from warnings import warn

    warn(
        f"Failed to gather package {__name__} metadata, due to:\n{traceback.format_exc()}",
        ImportWarning,
    )

    __author__ = "unknown"
    __version__ = "0.0a0"
    __summary__ = ""

__all__ = (
    "__author__",
    "__version__",
    "__summary__",
    "SSLWarning",
    "create_server_ssl_context",
    "create_client_authentication_ssl_context",
)
