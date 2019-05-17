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
import typing as T
from sys import version_info
from pathlib import Path
from contextlib import suppress

# External
import importlib_resources

# Requirements checks
if version_info < (3, 6):
    raise RuntimeError("Minimum required Python version: 3.7")

if ssl.OPENSSL_VERSION_INFO < (1, 0, 1):
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
    | getattr(ssl, "OP_NO_RENEGOTIATION", 0)
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


def create_server_ssl_context(
    cert_file: T.Union[Path, str],
    key_file: T.Union[Path, str],
    *,
    ca_file: T.Optional[T.Union[Path, str]] = None,
    ca_path: T.Optional[T.Union[Path, str]] = None,
    ca_data: T.Optional[T.Union[object, str]] = None,
    crl_path: T.Optional[T.Union[Path, str]] = None,
    protocols: T.Optional[T.List[str]] = None,
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
        crl_path: Path to a certificate revocation list file.
        protocols: ALPN and NPN protocols accepted

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    # Check if path are a valid because `load_verify_locations` doesn't
    if not (
        (ca_path is None or Path(ca_path).is_dir())
        and (ca_file is None or Path(ca_file).is_file())
        and (crl_path is None or Path(crl_path).is_file())
    ):
        raise FileNotFoundError("ca_path or ca_file or crl_path are not valid or don't exist")

    # Create SSLContext
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH, cafile=ca_file, capath=ca_path, cadata=ca_data
    )

    # Configure OpenSSL for server use
    ctx.options |= _SERVER_OPTIONS

    # Disable workarounds for broken X509 certificates
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT

    # Enforce client certificate validation
    if ca_path or ca_file or ca_data:
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Enable verification of certificate revocation list
        if crl_path:
            ctx.load_verify_locations(crl_path)
            # VERIFY_CRL_CHECK_CHAIN must come after loading CRL of it will fail
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

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

    # Load server certificate and private key
    # Raises FileNotFoundError if any given path is invalid
    ctx.load_cert_chain(cert_file, key_file)

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
            raise ssl.SSLError("ALPN protocols must be a List of valid string names") from exc

    return ctx


def create_client_ssl_context(
    cert_file: T.Union[Path, str],
    key_file: T.Union[Path, str],
    *,
    ca_file: T.Optional[T.Union[Path, str]] = None,
    ca_path: T.Optional[T.Union[Path, str]] = None,
    ca_data: T.Optional[T.Union[object, str]] = None,
    crl_path: T.Optional[T.Union[Path, str]] = None,
    protocols: T.Optional[T.List[str]] = None,
    check_hostname: bool = True,
    verify_server_cert: bool = True,
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
        crl_path: Path to a certificate revocation list file.
        protocols: ALPN and NPN protocols accepted
        check_hostname: Server hostname match (default: {False})
        verify_server_cert: Activate server cert check

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    # Check if path are a valid because `load_verify_locations` doesn't
    if not (
        (ca_path is None or Path(ca_path).is_dir())
        and (ca_file is None or Path(ca_file).is_file())
        and (crl_path is None or Path(crl_path).is_file())
    ):
        raise FileNotFoundError("ca_path or ca_file or crl_path are not valid or don't exist")

    # Create SSLContext
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_file, capath=ca_path, cadata=ca_data
    )

    # Configure OpenSSL for server use
    ctx.options |= _CLIENT_OPTIONS

    # Disable workarounds for broken X509 certificates
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT

    # Configure server hostname match with server certificate's hostname
    ctx.check_hostname = check_hostname

    # Configure verification of server certificate
    ctx.verify_mode = ssl.CERT_REQUIRED if verify_server_cert else ssl.CERT_NONE

    # Enable verification of certificate revocation list
    if crl_path:
        ctx.load_verify_locations(crl_path)
        # VERIFY_CRL_CHECK_CHAIN must come after loading CRL of it will fail
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

    # Define cryptographic ciphers accepted by client contexts
    # Raises SSLError for unavailable or invalid ciphers
    ctx.set_ciphers(_CYPHERS)

    # Load server certificate and private key
    # Raises FileNotFoundError if any path is invalid
    ctx.load_cert_chain(cert_file, key_file)

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
            raise ssl.SSLError("ALPN protocols must be a List of valid string names") from exc

    return ctx
