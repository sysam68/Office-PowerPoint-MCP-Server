import json
import os
import tempfile
import unittest
import time
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

import ppt_mcp_server as server
from ppt_security import AUDIENCES, CLIENT_ID, READ, WRITE, READ_TOOLS, WRITE_TOOLS, OIDCVerifier, _paths

AUDIENCE = AUDIENCES[0]
INTERNAL_AUDIENCE = AUDIENCES[1]


class StubVerifier:
    async def verify_token(self, token):
        users = {"alice": ("alice", [READ, WRITE]), "alice-read": ("alice", [READ]),
                 "bob": ("bob", [READ, WRITE])}
        if token not in users:
            return None
        subject, scopes = users[token]
        return AccessToken(token=token, client_id=CLIENT_ID, subject=subject, scopes=scopes,
                           claims={"iss": "https://issuer.example"})


class SecurityTests(unittest.TestCase):
    def test_signed_tokens_are_verified_and_claims_are_required(self):
        import asyncio
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        issuer = "https://issuer.example"
        now = int(time.time())
        base = {"iss": issuer, "aud": AUDIENCE, "client_id": CLIENT_ID, "sub": "alice",
                "jti": "id", "iat": now, "exp": now + 300, "groups": ["users"], "scope": READ}

        def handler(request):
            if request.url.path.endswith("openid-configuration"):
                return httpx.Response(200, json={"issuer": issuer, "jwks_uri": issuer + "/jwks"})
            return httpx.Response(200, json={"keys": [jwk]})

        original_client = httpx.AsyncClient
        def client(*args, **kwargs):
            return original_client(transport=httpx.MockTransport(handler))

        async def verify(claims, signing_key=key):
            signed = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})
            return await OIDCVerifier(issuer).verify_token(signed)

        with patch("ppt_security.httpx.AsyncClient", client):
            self.assertIsNotNone(asyncio.run(verify(base)))
            self.assertIsNotNone(asyncio.run(verify({**base, "aud": [AUDIENCE, "https://secondary.example.test/resource"]})))
            self.assertIsNotNone(asyncio.run(verify({**base, "aud": INTERNAL_AUDIENCE})))
            self.assertIsNotNone(asyncio.run(verify({key: value for key, value in base.items() if key != "groups"})))
            self.assertIsNotNone(asyncio.run(verify({**base, "groups": ["guests"]})))
            self.assertIsNotNone(asyncio.run(verify({**base, "scope": [READ, WRITE]})))
            without_scope = {key: value for key, value in base.items() if key != "scope"}
            self.assertIsNotNone(asyncio.run(verify({**without_scope, "scp": READ})))
            self.assertIsNotNone(asyncio.run(verify({**without_scope, "scp": [READ, WRITE]})))
            self.assertIsNotNone(asyncio.run(verify({**base, "scp": [READ]})))
            for change in ({"aud": "wrong"}, {"aud": ["wrong", "also-wrong"]},
                           {"aud": [AUDIENCE, 1]}, {"client_id": "wrong"},
                           {"sub": ""}, {"jti": ""}, {"scope": "openid"}, {"exp": now - 1},
                           {"iss": "https://other.example"}, {"azp": "wrong"}):
                with self.subTest(change=change):
                    self.assertIsNone(asyncio.run(verify({**base, **change})))
            for invalid_claims in (
                without_scope,
                {**without_scope, "scope": [READ, 1]},
                {**without_scope, "scp": [READ, 1]},
                {**without_scope, "scp": []},
                {**base, "scp": [WRITE]},
            ):
                with self.subTest(invalid_claims=invalid_claims):
                    self.assertIsNone(asyncio.run(verify(invalid_claims)))
            other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.assertIsNone(asyncio.run(verify(base, other_key)))

    def test_configuration_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                server.configure_auth("http", "0.0.0.0")
        with patch.dict(os.environ, {"PPT_AUTH_MODE": "local"}, clear=True):
            with self.assertRaises(ValueError):
                server.configure_auth("http", "0.0.0.0")

    def test_paths_cannot_escape(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                _paths("open_presentation", {"file_path": "../outside.pptx"}, root / "user", root / "templates")
            with self.assertRaises(ValueError):
                _paths("manage_image", {"image_source": "/etc/passwd"}, root / "user", root / "templates")

    def test_catalog_has_complete_explicit_policy(self):
        import asyncio
        names = {tool.name for tool in asyncio.run(server.app.list_tools())}
        self.assertEqual(names, READ_TOOLS | WRITE_TOOLS)
        self.assertFalse(READ_TOOLS & WRITE_TOOLS)

    def test_http_session_isolation_and_scopes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "PPT_AUTH_MODE": "oidc", "PPT_OIDC_ISSUER": "https://issuer.example",
            "PPT_OIDC_AUDIENCES": ",".join(AUDIENCES), "PPT_RESOURCE_URL": AUDIENCE,
            "PPT_WORKSPACE_ROOT": directory, "PPT_TEMPLATE_PATH": directory,
        }, clear=True):
            server.configure_auth("http", "127.0.0.1")
            server.app._token_verifier = StubVerifier()
            with TestClient(server.build_http_app(json_response=True), base_url="http://127.0.0.1:8000") as client:
                metadata = client.get("/.well-known/oauth-protected-resource/powerpoint/api/mcp")
                self.assertEqual(metadata.json()["scopes_supported"], [READ, WRITE])
                self.assertEqual(client.post("/mcp").status_code, 401)
                headers = {"Authorization": "Bearer alice", "Accept": "application/json, text/event-stream"}
                init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}}
                response = client.post("/mcp", headers=headers, json=init)
                self.assertEqual(response.status_code, 200, response.text)
                headers["mcp-session-id"] = response.headers["mcp-session-id"]
                client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                listing = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 3,
                                      "method": "tools/list", "params": {}})
                self.assertIn("create_presentation", listing.text)
                def call(name, args=None, token="alice"):
                    return client.post("/mcp", headers={**headers, "Authorization": "Bearer " + token},
                                       json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                             "params": {"name": name, "arguments": args or {}}})
                created = call("create_presentation", {"id": "owned"})
                self.assertIn("owned", created.text)
                saved = call("save_presentation", {"file_path": "test.pptx", "presentation_id": "owned"})
                self.assertIn("Presentation saved", saved.text)
                denied = call("create_presentation", {"id": "denied"}, "alice-read")
                self.assertIn("Not authorized", denied.text)
                stolen = call("list_presentations", token="bob")
                self.assertIn(stolen.status_code, (401, 403, 404))
                self.assertNotIn("owned", stolen.text)
                own = call("list_presentations", token="alice-read")
                self.assertIn("owned", own.text)


if __name__ == "__main__":
    unittest.main()
