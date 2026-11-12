"""Synthetic fixtures only: no real hosts, account tokens, or node passwords."""

import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT = Path(__file__).resolve().parents[1] / "proxy_dump.sh"
KEY = bytes.fromhex("a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef")
TOKEN = "0" * 32  # Deliberately synthetic, never accepted by any real service.


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "fixture.bin"

    def encrypt(self, plain, key=KEY):
        nonce = os.urandom(12)
        self.config.write_bytes(nonce + AESGCM(key).encrypt(nonce, plain, None))

    def run_tool(self, *args, env=None):
        return subprocess.run(
            ["/bin/sh", str(SCRIPT), *args, "--file", str(self.config)],
            capture_output=True,
            timeout=20,
            env=env,
        )

    def flat_config(self, **overrides):
        value = {"mother_ip": "127.0.0.1", "api_port": 4399, "api_token": TOKEN, "debug": False}
        value.update(overrides)
        return json.dumps(value, ensure_ascii=False).encode()

    def test_help_and_syntax(self):
        subprocess.run(["/bin/sh", "-n", str(SCRIPT)], check=True)
        result = subprocess.run(["/bin/sh", str(SCRIPT), "--help"], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"config|nodes", result.stdout)

    def test_decrypt_byte_boundaries_and_unicode(self):
        for size in (0, 1, 15, 16, 17, 255, 4096):
            with self.subTest(size=size):
                plain = os.urandom(size)
                self.encrypt(plain)
                result = self.run_tool("config")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stdout, plain + b"\n")
        plain = json.dumps({"note": "仅用于测试，不是真实配置"}, ensure_ascii=False).encode()
        self.encrypt(plain)
        self.assertEqual(self.run_tool().stdout, plain + b"\n")

    def test_largest_supported_ciphertext(self):
        plain = b"x" * (65536 - 28)
        self.encrypt(plain)
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, plain + b"\n")

    def test_nonce_ciphertext_and_tag_tampering_never_output_plaintext(self):
        self.encrypt(self.flat_config())
        original = self.config.read_bytes()
        for offset in (0, 12, len(original) - 1):
            with self.subTest(offset=offset):
                corrupt = bytearray(original)
                corrupt[offset] ^= 1
                self.config.write_bytes(corrupt)
                result = self.run_tool()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(TOKEN.encode(), result.stderr)

    def test_custom_key_and_wrong_key(self):
        custom = os.urandom(32)
        self.encrypt(self.flat_config(), custom)
        keyfile = self.root / "fixture.key"
        keyfile.write_text(custom.hex() + "\n")
        self.assertEqual(self.run_tool("--key-file", str(keyfile)).returncode, 0)
        self.assertNotEqual(self.run_tool().returncode, 0)
        keyfile.write_text("not a valid key")
        self.assertNotEqual(self.run_tool("--key-file", str(keyfile)).returncode, 0)

    def test_truncated_and_oversized_input(self):
        for data in (b"", b"too short", bytes(65537)):
            self.config.write_bytes(data)
            result = self.run_tool()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_source_unchanged_and_output_private(self):
        plain = self.flat_config()
        self.encrypt(plain)
        before = self.config.read_bytes()
        output = self.root / "output.json"
        result = self.run_tool("--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertEqual(output.read_bytes(), plain)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(self.config.read_bytes(), before)

    def test_existing_file_and_symlinks_not_overwritten(self):
        self.encrypt(self.flat_config())
        existing = self.root / "existing.json"
        existing.write_bytes(b"keep me")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(existing)
        dangling = self.root / "dangling.json"
        dangling.symlink_to(self.root / "absent")
        for output in (existing, symlink, dangling):
            result = self.run_tool("--output", str(output))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        self.assertEqual(existing.read_bytes(), b"keep me")
        self.assertFalse((self.root / "absent").exists())

    def test_no_python_or_jq_needed_at_runtime(self):
        tools = self.root / "bin"
        tools.mkdir()
        for name in ("openssl", "awk", "od", "dd", "tr", "wc", "mktemp", "cat", "rm"):
            path = shutil.which(name)
            self.assertIsNotNone(path)
            (tools / name).symlink_to(path)
        env = dict(os.environ, PATH=str(tools))
        self.encrypt(self.flat_config())
        result = self.run_tool(env=env)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)["api_token"], TOKEN)

    @contextlib.contextmanager
    def api(self, status=200, body=None):
        expected = {"listen_ip": "192.0.2.1", "nodes": [{"id": 1, "socks_pass": "test-only"}]}
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append((self.path, self.headers.get("Authorization"), self.headers.get("User-Agent")))
                self.send_response(status)
                if 300 <= status < 400:
                    self.send_header("Location", "/must-not-follow")
                self.end_headers()
                self.wfile.write(body if body is not None else json.dumps(expected).encode())

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, expected, received
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_nodes_auth_and_ignore_ambient_proxy(self):
        with self.api() as (port, expected, received):
            self.encrypt(self.flat_config(api_port=port))
            env = dict(os.environ, http_proxy="http://127.0.0.1:1", HTTP_PROXY="http://127.0.0.1:1")
            result = self.run_tool("nodes", env=env)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), expected)
            self.assertEqual(received, [("/guest/nodes", "Bearer " + TOKEN, "What-You-Wanna-Do")])

    def test_api_override(self):
        with self.api() as (port, expected, received):
            self.encrypt(self.flat_config())
            result = self.run_tool("nodes", "--api-url", "http://127.0.0.1:{}/guest/nodes".format(port))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), expected)
            self.assertEqual(len(received), 1)

    def test_redirect_and_http_error_never_publish_body(self):
        for status in (302, 401, 500):
            with self.subTest(status=status), self.api(status, b"SECRET_RESPONSE") as (port, _, received):
                self.encrypt(self.flat_config(api_port=port))
                result = self.run_tool("nodes")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"SECRET_RESPONSE", result.stderr)
                self.assertEqual(len(received), 1)

    def test_nodes_rejects_ambiguous_or_injectable_configuration(self):
        malformed = [
            b"[]",
            b'{"mother_ip":"127.0.0.1","api_port":4399,"api_token":"abc","api_token":"def"}',
            self.flat_config(mother_ip="127.0.0.1/other-path"),
            self.flat_config(api_port=0),
            self.flat_config(api_port=65536),
            self.flat_config(api_port="4399"),
            self.flat_config(api_token='bad"header'),
            self.flat_config(api_token="bad\nheader"),
            self.flat_config(extra={"nested": True}),
        ]
        for plain in malformed:
            with self.subTest(plain=plain):
                self.encrypt(plain)
                result = self.run_tool("nodes")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_invalid_cli(self):
        self.encrypt(self.flat_config())
        for args in (("--unknown",), ("config", "nodes"), ("--file",), ("--timeout", "NaN"), ("--timeout", "301"), ("--api-url", "http://127.0.0.1")):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_tool(*args).returncode, 0)


if __name__ == "__main__":
    unittest.main()
