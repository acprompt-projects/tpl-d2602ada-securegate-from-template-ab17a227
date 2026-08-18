===
import time
import pytest
import jwt

from jwt_auth import JWTAuthMiddleware, JWTConfig, RevocationStore, TokenError


@pytest.fixture
def auth():
    config = JWTConfig(secret_key="test-secret-key-that-is-long-enough", issuer="securegate")
    store = RevocationStore()
    return JWTAuthMiddleware(config, store)


class TestTokenIssuance:
    def test_issue_tokens_returns_both_tokens(self, auth):
        result = auth.issue_tokens("user-1", roles=["admin"])
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 900

    def test_access_token_contains_correct_claims(self, auth):
        result = auth.issue_tokens("user-1", roles=["admin", "viewer"])
        payload = jwt.decode(result["access_token"], auth.config.secret_key, algorithms=["HS256"])
        assert payload["sub"] == "user-1"
        assert payload["iss"] == "securegate"
        assert payload["type"] == "access"
        assert payload["roles"] == ["admin", "viewer"]
        assert "jti" in payload
        assert "exp" in payload

    def test_refresh_token_contains_family(self, auth):
        result = auth.issue_tokens("user-1")
        payload = jwt.decode(result["refresh_token"], auth.config.secret_key, algorithms=["HS256"])
        assert payload["type"] == "refresh"
        assert "family" in payload

    def test_custom_claims_included(self, auth):
        result = auth.issue_tokens("user-1", claims={"org": "acme"})
        payload = jwt.decode(result["access_token"], auth.config.secret_key, algorithms=["HS256"])
        assert payload["org"] == "acme"


class TestTokenValidation:
    def test_validate_valid_access_token(self, auth):
        result = auth.issue_tokens("user-1", roles=["viewer"])
        payload = auth.validate_token(result["access_token"])
        assert payload["sub"] == "user-1"
        assert payload["type"] == "access"

    def test_validate_valid_refresh_token(self, auth):
        result = auth.issue_tokens("user-1")
        payload = auth.validate_token(result["refresh_token"], expected_type="refresh")
        assert payload["type"] == "refresh"

    def test_validate_expired_token_raises(self, auth):
        now = int(time.time())
        expired = jwt.encode(
            {"sub": "u", "iss": "securegate", "iat": now, "exp": now - 10, "jti": "x", "type": "access"},
            auth.config.secret_key, algorithm="HS256",
        )
        with pytest.raises(TokenError, match="expired"):
            auth.validate_token(expired)

    def test_validate_wrong_type_raises(self, auth):
        result = auth.issue_tokens("user-1")
        with pytest.raises(TokenError, match="Expected access"):
            auth.validate_token(result["refresh_token"], expected_type="access")

    def test_validate_tampered_token_raises(self, auth):
        with pytest.raises(TokenError):
            auth.validate_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.bad")

    def test_validate_wrong_issuer_raises(self, auth):
        now = int(time.time())
        bad = jwt.encode(
            {"sub": "u", "iss": "wrong", "iat": now, "exp": now + 300, "jti": "x", "type": "access"},
            auth.config.secret_key, algorithm="HS256",
        )
        with pytest.raises(TokenError):
            auth.validate_token(bad)


class TestTokenRevocation:
    def test_revoked_access_token_fails_validation(self, auth):
        result = auth.issue_tokens("user-1")
        auth.revoke_token(result["access_token"])
        with pytest.raises(TokenError, match="revoked"):
            auth.validate_token(result["access_token"])

    def test_revoked_refresh_token_fails_validation(self, auth):
        result = auth.issue_tokens("user-1")
        auth.revoke_token(result["refresh_token"])
        with pytest.raises(TokenError, match="revoked"):
            auth.validate_token(result["refresh_token"], expected_type="refresh")


class TestRefreshRotation:
    def test_refresh_returns_new_token_pair(self, auth):
        result = auth.issue_tokens("user-1", roles=["viewer"])
        refreshed = auth.refresh_tokens(result["refresh_token"])
        assert "access_token" in refreshed
        assert "refresh_token" in refreshed
        assert refreshed["access_token"] != result["access_token"]

    def test_old_refresh_token_is_revoked_after_rotation(self, auth):
        result = auth.issue_tokens("user-1")
        auth.refresh_tokens(result["refresh_token"])
        with pytest.raises(TokenError, match="revoked"):
            auth.validate_token(result["refresh_token"], expected_type="refresh")

    def test_refresh_reuse_revokes_entire_family(self, auth):
        result = auth.issue_tokens("user-1")
        first_refresh = result["refresh_token"]
        # Rotate once
        auth.refresh_tokens(first_refresh)
        # Attempt reuse of old token — family gets revoked
        with pytest.raises(TokenError):
            auth.refresh_tokens(first_refresh)

    def test_new_refresh_token_works_after_rotation(self, auth):
        result = auth.issue_tokens("user-1")
        refreshed = auth.refresh_tokens(result["refresh_token"])
        payload = auth.validate_token(refreshed["refresh_token"], expected_type="refresh")
        assert payload["sub"] == "user-1"

    def test_roles_carried_through_rotation(self, auth):
        result = auth.issue_tokens("user-1", roles=["admin"])
        refreshed = auth.refresh_tokens(result["refresh_token"])
        payload = auth.validate_token(refreshed["access_token"])
        assert payload["roles"] == ["admin"]

    def test_roles_updated_during_rotation(self, auth):
        result = auth.issue_tokens("user-1", roles=["viewer"])
        refreshed = auth.refresh_tokens(result["refresh_token"], roles=["admin"])
        payload = auth.validate_token(refreshed["access_token"])
        assert payload["roles"] == ["admin"]
===