"""Public CI diagnostics must never contain a supplied secret or arbitrary stderr."""
import importlib.util
import json
import unittest

from dev import ROOT

spec = importlib.util.spec_from_file_location('boot_guest', ROOT/'deploy/bootstand/guest.py')
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class BootDiagnosticsTests(unittest.TestCase):
    def test_known_error_keeps_only_safe_category(self):
        error = guest.CommandFailure('surveyscanctl',5,15.12345,
            b'{"error":"NETWORK_OR_TLS_UNAVAILABLE","password":"canary-private","body":"sensitive-body"}')
        self.assertEqual(error.cli_error,'NETWORK_OR_TLS_UNAVAILABLE')
        self.assertEqual(error.elapsed,15.123)
        encoded = json.dumps(error.__dict__)+str(error)
        self.assertNotIn('canary-private',encoded)
        self.assertNotIn('sensitive-body',encoded)

    def test_arbitrary_error_not_exported(self):
        for value in ['canary-private','HTTP_999','TOKEN_PRIVATE','NETWORK_OR_TLS_UNAVAILABLE canary']:
            error = guest.CommandFailure('surveyscanctl',5,1,json.dumps({'error':value}).encode())
            self.assertIsNone(error.cli_error)
            self.assertNotIn(value,str(error.__dict__))

    def test_http_status_is_safe_and_precise(self):
        error = guest.CommandFailure('surveyscanctl',5,10.5,b'{"error":"HTTP_502"}')
        self.assertEqual(error.cli_error,'HTTP_502')
        self.assertEqual(error.code,5)

    def test_other_program_cannot_export_cli_body_or_private_path(self):
        error = guest.CommandFailure('/private/canary',1,2,b'{"error":"HTTP_503"}')
        self.assertEqual(error.program,'test_command')
        self.assertIsNone(error.cli_error)
        self.assertNotIn('canary',json.dumps(error.__dict__))

    def test_invalid_json_never_falls_back_to_raw_text(self):
        error = guest.CommandFailure('surveyscanctl',2,0.1,b'raw private-canary error')
        self.assertIsNone(error.cli_error)
        self.assertNotIn('private-canary',str(error.__dict__))


if __name__ == '__main__':unittest.main()
