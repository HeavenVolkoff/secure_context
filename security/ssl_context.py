"""SSL_Context -- Utilities for creation of security contexts.

Offers methods for creation of client and server secure contexts that improve upon NSA Suite B
(https://tools.ietf.org/html/rfc6460) policies.

Warning
-------
    LAST MODIFIED DATE: 15/05/2019
    All definitions here must be constantly reviewed and modified to ensure a capable secure system.

TODO
----
    Improve ECDH curves selection:
        https://bugs.python.org/issue32882
        https://bugs.python.org/issue32883

References
----------
    https://tools.ietf.org/html/rfc4492
    https://tools.ietf.org/html/rfc5246
    https://tools.ietf.org/html/rfc5289
    https://tools.ietf.org/html/rfc6460
    https://tools.ietf.org/html/rfc7301
    https://tools.ietf.org/html/rfc7905
    https://docs.python.org/3.6/library/ssl.html
    https://wiki.mozilla.org/Security/Server_Side_TLS
    https://github.com/trimstray/nginx-admins-handbook
    https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

Minimum requirements
--------------------
    Python: 3.6
    OpenSSL: 1.0.1 (With ECDH, SNI and ALPN)

"""

# Internal
import ssl
import sys
import typing as T
from os import environ
from sys import version_info
from pathlib import Path
from warnings import warn
from contextlib import suppress

# External
import importlib_resources

# Requirements checks
if version_info < (3, 6):
    raise RuntimeError("Minimum required Python version: 3.6")

if ssl.OPENSSL_VERSION_INFO < (1, 1, 0, 8):
    raise RuntimeError("Minimum required OpenSSL version: 1.1.0h")

if not getattr(ssl, "HAS_TLSv1_2", hasattr(ssl, "PROTOCOL_TLSv1_2")):
    raise RuntimeError("OpenSSL doesn't seem to support TLS 1.2")

# https://tools.ietf.org/html/rfc4492
if not ssl.HAS_ECDH:
    raise RuntimeError(
        "OpenSSL doesn't support Elliptic Curve-based Diffie-Hellman key" "exchange."
    )

# https://en.wikipedia.org/wiki/Server_Name_Indication
if not ssl.HAS_SNI:
    raise RuntimeError("OpenSSL doesn't support Server Name Indication TLS extension.")

# https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
if not ssl.HAS_ALPN:
    raise RuntimeError(
        "OpenSSL doesn't support Application Layer Protocol Negotiation TLS" "extension."
    )

# Define accepted cryptographic ciphers
# https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
# The current definition include ciphers specified in RFC7905.
#   Aimed at client with newer software/hardware support and need of future-proof security and/or
#   improved performance.
#   https://tools.ietf.org/html/rfc7905
# The current definition include ciphers specified in RFC6460.
#   Aimed at legacy clients, while still maintaining complete security for today scenery.
#   https://tools.ietf.org/html/rfc5289
# Raises SSLError for unavailable or invalid ciphers
_CYPHERS = ":".join(
    (
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-CHACHA20-POLY1305",
    )
)
_ECDH_CURVES = ("prime256v1", "secp521r1", "secp384r1", "X25519")
_CLIENT_OPTIONS = (
    # Prevent all connections with protocols < TLS 1.2
    # TLS is the successor of SSL, and the current recommended protocol for secure communication
    # over computer networks.
    # https://en.wikipedia.org/wiki/Transport_Layer_Security
    getattr(ssl, "OP_NO_SSLv2", 0)
    | getattr(ssl, "OP_NO_SSLv2", 0)
    | getattr(ssl, "OP_NO_SSLv3", 0)
    | getattr(ssl, "OP_NO_TLSv1", 0)
    | getattr(ssl, "OP_NO_TLSv1_1", 0)
    # Disable TLS compression due to possible security concerns.
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-4929
    | ssl.OP_NO_COMPRESSION
    # Disable all renegotiation in TLSv1.2
    # TLS renegotiation is complicated and has been removed from TLS 1.3.
    # Also it is not supported on the OS X and Windows native cryptography implementations.
    # https://jira.mongodb.org/browse/PYTHON-1726
    | getattr(ssl, "OP_NO_RENEGOTIATION", 0x40000000)
)
_SERVER_OPTIONS = (
    _CLIENT_OPTIONS
    # Prevents re-use of the same DH key for distinct SSL sessions
    # Improves forward secrecy
    | ssl.OP_SINGLE_DH_USE
    # Prevents re-use of the same ECDH key for distinct SSL sessions
    # Improves forward secrecy
    | ssl.OP_SINGLE_ECDH_USE
    # Enforce Server cryptographic cipher choice
    | ssl.OP_CIPHER_SERVER_PREFERENCE
)


class SSLWarning(RuntimeWarning):
    pass


def _str_or_none(obj: T.Any) -> T.Optional[str]:
    return obj if obj is None else str(obj)


def _setup_ca(
    ctx: ssl.SSLContext,
    ca_file: T.Optional[T.Union[str, Path]],
    ca_path: T.Optional[T.Union[str, Path]],
    ca_data: T.Optional[T.Union[bytes, str]],
    crl_file: T.Optional[T.Union[str, Path]],
    ca_load_default: bool,
) -> bool:
    # Disable workarounds for broken X509 certificates
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT

    if not any((ca_file, ca_path, ca_data, ca_load_default)):
        warn(
            "No Certificate Authority was provided to load into the SSLContext, "
            "disabling certificate verification",
            SSLWarning,
        )
        # No ca was passed, disable certificate validation
        ctx.verify_mode = ssl.CERT_NONE
        return False

    if ca_path and not Path(ca_path).is_dir():
        raise NotADirectoryError("ca_path must be a directory")

    if ca_file and not Path(ca_file).is_file():
        raise FileNotFoundError("ca_file must be a valid file")

    if crl_file and not Path(crl_file).is_file():
        raise FileNotFoundError("crl_file must be a valid file")

    # Enforce certificate validation
    ctx.verify_mode = ssl.CERT_REQUIRED

    if ca_load_default:
        # Load system default certificate authorities
        ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)

    if ca_path or ca_file or ca_data:
        # Load custom certificate authorities
        ctx.load_verify_locations(_str_or_none(ca_file), _str_or_none(ca_path), ca_data)

    if crl_file:
        # Enable verification of certificate revocation list
        ctx.load_verify_locations(_str_or_none(crl_file))

        # VERIFY_CRL_CHECK_CHAIN must come after loading CRL of it will fail
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

    return True


def _load_cert_key_protocols(
    ctx: ssl.SSLContext, cert_file: str, key_file: str, protocols: T.Optional[T.List[str]]
) -> None:
    # Load server certificate and private key
    # Raises FileNotFoundError if any given path is invalid
    ctx.load_cert_chain(str(cert_file), str(key_file))

    if protocols:
        try:
            # Define server accepted protocols as described in RFC7301
            # https://tools.ietf.org/html/rfc7301.html
            # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
            ctx.set_alpn_protocols(protocols)

            # NPN is not necessarily available
            with suppress(NotImplementedError):
                ctx.set_npn_protocols(protocols)
        except (MemoryError, TypeError) as exc:
            # Normalize errors
            raise ssl.SSLError("ALPN protocols must be a list of valid string names") from exc


def create_server_ssl_context(
    cert_file: T.Union[Path, str],
    key_file: T.Union[Path, str],
    *,
    ca_file: T.Optional[T.Union[Path, str]] = None,
    ca_path: T.Optional[T.Union[Path, str]] = None,
    ca_data: T.Optional[T.Union[bytes, str]] = None,
    crl_file: T.Optional[T.Union[Path, str]] = None,
    protocols: T.Optional[T.List[str]] = None,
    ca_load_default: bool = False,
) -> ssl.SSLContext:
    """Create SSL context for Antenna servers.

    Args:
        cert_file: Path to SSL certificate file
        key_file: Path to private key file
        ca_file: Path to a file of concatenated CA certificates in PEM format
        ca_path: Path to a directory containing CA certificates in PEM format, following an OpenSSL
            specific layout
        ca_data: ASCII string of one or more PEM-encoded certificates or a bytes-like object of
            DER-encoded certificates
        crl_file: Path to a certificate revocation list file.
        protocols: ALPN and NPN protocols accepted
        ca_load_default: Whether to load system defaults (default: {False})

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    # Check if path are a valid because `load_verify_locations` doesn't

    # Create SSLContext
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Configure OpenSSL for server use
    ctx.options |= _SERVER_OPTIONS

    # TODO: Think of a way to expose this option in a useful manner for validating clients
    #  certificates
    ctx.check_hostname = False

    _setup_ca(ctx, ca_file, ca_path, ca_data, crl_file, ca_load_default)

    # Set minimum supported TLS version to TLSv1_2 in Python >= 3.7
    if hasattr(ctx, "minimum_version"):
        ctx.minimum_version = getattr(getattr(ssl, "TLSVersion", 0), "TLSv1_2", 771)

    # Define cryptographic ciphers accepted by server contexts
    # Raises SSLError for unavailable or invalid ciphers
    ctx.set_ciphers(_CYPHERS)

    for curve in _ECDH_CURVES:
        with suppress(ValueError, ssl.SSLError):
            ctx.set_ecdh_curve(curve)
            break
    else:
        raise ssl.SSLError(
            f"Current OpenSSL does not support any of the ECDH curves in: {', '.join(_ECDH_CURVES)}"
        )

    with importlib_resources.path("security", "ffdhe4096") as dh_params_path:
        # Load Diffie-Hellman parameters
        ctx.load_dh_params(dh_params_path)

    _load_cert_key_protocols(ctx, str(cert_file), str(key_file), protocols)

    return ctx


def create_client_ssl_context(
    cert_file: T.Union[Path, str],
    key_file: T.Union[Path, str],
    *,
    ca_file: T.Optional[T.Union[Path, str]] = None,
    ca_path: T.Optional[T.Union[Path, str]] = None,
    ca_data: T.Optional[T.Union[bytes, str]] = None,
    crl_file: T.Optional[T.Union[Path, str]] = None,
    protocols: T.Optional[T.List[str]] = None,
    check_hostname: bool = True,
) -> ssl.SSLContext:
    """Create SSL context for Antenna clients.

    Args:
        cert_file: Path to SSL certificate file
        key_file: Path to private key file
        ca_file: Path to a file of concatenated CA certificates in PEM format
        ca_path: Path to a directory containing CA certificates in PEM format, following an OpenSSL
            specific layout
        ca_data: ASCII string of one or more PEM-encoded certificates or a bytes-like object of
            DER-encoded certificates
        crl_file: Path to a certificate revocation list file.
        protocols: ALPN and NPN protocols accepted
        check_hostname: Server hostname match (default: {False})

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    # Create SSLContext
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Disable check_hostname before setup ca to avoid errors
    ctx.check_hostname = False
    if _setup_ca(ctx, ca_file, ca_path, ca_data, crl_file, ca_load_default=False):
        # Configure server hostname match with server certificate's hostname
        # Only if _setup_ca was successful
        ctx.check_hostname = check_hostname

    # Configure OpenSSL for client use
    ctx.options |= _CLIENT_OPTIONS

    # Define cryptographic ciphers accepted by client contexts
    # Raises SSLError for unavailable or invalid ciphers
    ctx.set_ciphers(_CYPHERS)

    _load_cert_key_protocols(ctx, str(cert_file), str(key_file), protocols)

    return ctx
