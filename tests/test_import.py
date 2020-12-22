# Internal
import unittest


class TestImport(unittest.TestCase):
    def test_import(self) -> None:
        # External
        from antenna.security import create_client_ssl_context, create_server_ssl_context

        self.assertTrue(callable(create_client_ssl_context))
        self.assertTrue(callable(create_server_ssl_context))


if __name__ == "__main__":
    unittest.main()
