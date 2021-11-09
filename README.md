# Secure Context

Utilities for creation of SSL/TLS security contexts for servers and clients

> The purpose of this module is to expose, simple to use, secure definitions that follow current, community agreed,
> standards. As of now it offers methods for creation of client and server secure contexts.

It is __STRONGLY RECOMMENDED__ that you __READ__ the __CODE BEFORE__ considering __USING__ this library.
I am __NOT RESPONSIBLE__ if your product is hacked or cats become humans overlords due to usage of this code.

## Documentation

Currently, only two functions are exported:

```python
def create_server_ssl_context(
    cert_file: Union[Path, str],
    key_file: Union[Path, str],
    *,
    ca_file: Optional[Union[Path, str]] = None,
    ca_path: Optional[Union[Path, str]] = None,
    ca_data: Optional[Union[bytes, str]] = None,
    crl_file: Optional[Union[Path, str]] = None,
    protocols: Optional[List[str]] = None,
    ca_load_default: bool = False,
) -> ssl.SSLContext:
    """Create SSL context for TLS servers

    Args:
        cert_file: Path to SSL certificate file
        key_file: Path to private key file
        ca_file: Path to a file of concatenated CA certificates in PEM format
        ca_path: Path to a directory containing CA certificates in PEM format, following an OpenSSL specific layout
        ca_data: ASCII string of one or more PEM-encoded certificates or a bytes-like object of DER-encoded certificates
        crl_file: Path to a certificate revocation list file
        protocols: ALPN and NPN protocols accepted
        ca_load_default: Whether to load system defaults (default: {False})

    Note:
        If any of `ca_file`, `ca_path`, `ca_data` are defined client authentication will be enabled, which requires all
        clients to provide a accepted certificate to connect to the server.

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    ...
```

```python
def create_client_authentication_ssl_context(
    cert_file: Union[Path, str],
    key_file: Union[Path, str],
    *,
    ca_file: Optional[Union[Path, str]] = None,
    ca_path: Optional[Union[Path, str]] = None,
    ca_data: Optional[Union[bytes, str]] = None,
    crl_file: Optional[Union[Path, str]] = None,
    protocols: Optional[List[str]] = None,
    check_hostname: bool = True,
) -> ssl.SSLContext:
    """Create SSL context for clients that require TLS client authentication

    WARNING:
        For clients that DO NOT require client authentication,
        ssl.create_default_context should be used instead

    Args:
        cert_file: Path to SSL certificate file
        key_file: Path to private key file
        ca_file: Path to a file of concatenated CA certificates in PEM format
        ca_path: Path to a directory containing CA certificates in PEM format, following an OpenSSL specific layout
        ca_data: ASCII string of one or more PEM-encoded certificates or a bytes-like object of DER-encoded certificates
        crl_file: Path to a certificate revocation list file
        protocols: ALPN and NPN protocols accepted
        check_hostname: Server hostname match (default: {False})

    Raises:
        SSLError: Occurs if SSLContext creation fails
        FileNotFoundError: Occurs if a file path is invalid

    Returns:
        SSL context

    """
    ...
```

## License

Copyright © 2019-2021 Vítor Vasconcellos

[BSD-3-Clause](./LICENSE)
