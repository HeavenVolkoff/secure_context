# Internal
from ssl import SSLContext

def set_ecdh_curve(ctx: SSLContext, curve: str) -> None: ...
