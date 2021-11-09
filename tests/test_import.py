# Internal
import unittest
import warnings
import importlib
from os import environ

# External
import secure_context
import secure_context.ssl_context


class TestImport(unittest.TestCase):
    def tearDown(self) -> None:
        environ.pop("SECURE_CONTEXT_NO_EXTENSIONS", None)

    def test_export_types(self) -> None:
        self.assertTrue(
            issubclass(secure_context.SSLWarning, RuntimeWarning)  # type: ignore[reportUnnecessaryIsInstance]
        )
        self.assertTrue(callable(secure_context.create_server_ssl_context))
        self.assertTrue(callable(secure_context.create_client_authentication_ssl_context))

    def test_create_client_simple_ctx(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            importlib.reload(secure_context.ssl_context)
            importlib.reload(secure_context)

        with self.assertWarnsRegex(secure_context.SSLWarning, "No Certificate Authority"):
            secure_context.create_client_authentication_ssl_context("./cert.pem", "./cert.key")

    def test_create_server_simple_ctx(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            importlib.reload(secure_context.ssl_context)
            importlib.reload(secure_context)

        with self.assertWarnsRegex(secure_context.SSLWarning, "No Certificate Authority"):
            secure_context.create_server_ssl_context("./cert.pem", "./cert.key")

    def test_create_client_simple_ctx_no_module(self) -> None:
        environ["SECURE_CONTEXT_NO_EXTENSIONS"] = ""

        with self.assertWarnsRegex(
            RuntimeWarning, "Couldn't load native workaround implementation"
        ):
            importlib.reload(secure_context.ssl_context)
            importlib.reload(secure_context)

        with self.assertWarnsRegex(secure_context.SSLWarning, "No Certificate Authority"):
            secure_context.create_client_authentication_ssl_context("./cert.pem", "./cert.key")

    def test_create_server_simple_ctx_no_module(self) -> None:
        environ["SECURE_CONTEXT_NO_EXTENSIONS"] = ""

        with self.assertWarnsRegex(
            RuntimeWarning, "Couldn't load native workaround implementation"
        ):
            importlib.reload(secure_context.ssl_context)
            importlib.reload(secure_context)

        with self.assertWarnsRegex(secure_context.SSLWarning, "No Certificate Authority"):
            secure_context.create_server_ssl_context("./cert.pem", "./cert.key")


if __name__ == "__main__":
    unittest.main()
