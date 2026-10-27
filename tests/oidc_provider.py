"""Synthetic signed OIDC issuer: verifies real code, PKCE and callback exchanges."""

import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlencode

import httpx2
from joserfc import jwt
from joserfc.jwk import RSAKey


class Provider:
    def __init__(self, issuer="https://identity.example.com"):
        self.issuer = issuer
        self.key = RSAKey.generate_key()
        self.key.ensure_kid()
        self.public = self.key.as_dict(private=False)
        self.public.update(use="sig", alg="RS256")
        self.codes, self.tamper, self.calls = {}, {}, []
        self.required_authorization = None

    def authorize(self, url, subject="subject-one", groups=None):
        params = parse_qs(url.split("?", 1)[1])
        assert params["code_challenge_method"] == ["S256"]
        code = secrets.token_urlsafe(24)
        self.codes[code] = (
            params,
            subject,
            ["example-users"] if groups is None else groups,
        )
        return (
            params["redirect_uri"][0]
            + "?"
            + urlencode({"code": code, "state": params["state"][0]})
        )

    def transport(self):
        def handle(request):
            assert str(request.url).startswith(self.issuer)
            self.calls.append(request.url.path)
            if request.url.path == "/.well-known/openid-configuration":
                return httpx2.Response(
                    200,
                    json={
                        "issuer": self.issuer,
                        "authorization_endpoint": self.issuer + "/authorize",
                        "token_endpoint": self.issuer + "/token",
                        "jwks_uri": self.issuer + "/jwks",
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "token_endpoint_auth_methods_supported": [
                            "none",
                            "client_secret_basic",
                        ],
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            if request.url.path == "/jwks":
                return httpx2.Response(200, json={"keys": [self.public]})
            assert request.url.path == "/token"
            if self.required_authorization:
                assert request.headers["authorization"] == self.required_authorization
            form = parse_qs(request.content.decode())
            params, subject, groups = self.codes.pop(form["code"][0])
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(form["code_verifier"][0].encode()).digest()
            )
            assert params["code_challenge"] == [challenge.rstrip(b"=").decode()]
            assert params["redirect_uri"] == form["redirect_uri"]
            claims = {
                "iss": self.issuer,
                "sub": subject,
                "aud": params["client_id"][0],
                "nonce": params["nonce"][0],
                "iat": int(time.time()),
                "exp": int(time.time()) + 900,
                "auth_time": int(time.time()),
                "name": "Example One",
                "groups": groups,
                "person_id": "first",
                "unselected": "private-provider-value",
                **self.tamper,
            }
            return httpx2.Response(
                200,
                json={
                    "access_token": "synthetic-access-token",
                    "refresh_token": "synthetic-refresh-token",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "id_token": jwt.encode(
                        {"alg": "RS256", "kid": self.key.kid}, claims, self.key
                    ),
                },
            )

        return httpx2.MockTransport(handle)
