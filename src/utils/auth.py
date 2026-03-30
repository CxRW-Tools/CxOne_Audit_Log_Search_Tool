import sys
import time
import requests


class AuthManager:
    """CxOne IAM token via API key (refresh token grant)."""

    def __init__(self, base_url, tenant_name, api_key, iam_base_url=None, debug=False):
        self.base_url = base_url
        self.tenant_name = tenant_name
        self.api_key = api_key
        self.debug = debug
        self.auth_token = None
        self.token_expiration = 0
        self.iam_base_url = iam_base_url or self._default_iam_url()
        self.auth_url = f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

    def _default_iam_url(self):
        return self.base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")

    def ensure_authenticated(self):
        if time.time() >= self.token_expiration - 60:
            self._authenticate()
        return self.auth_token

    def _authenticate(self):
        if self.debug:
            print("Authenticating with API key...")

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.api_key,
        }

        try:
            response = requests.post(self.auth_url, headers=headers, data=data, timeout=60)
            response.raise_for_status()
            body = response.json()
            self.auth_token = body.get("access_token")
            if not self.auth_token:
                raise ValueError("No access token in response")
            expires_in = body.get("expires_in", 600)
            self.token_expiration = time.time() + expires_in
            if self.debug:
                print("Authentication successful")
        except (requests.exceptions.RequestException, ValueError) as e:
            print("Authentication error:", e)
            sys.exit(1)

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.ensure_authenticated()}",
            "Content-Type": "application/json",
        }

    def get_audit_headers(self):
        """Headers required by GET /api/audit-events/ (Accept version)."""
        return {
            "Authorization": f"Bearer {self.ensure_authenticated()}",
            "Accept": "application/json; version=1.0",
        }

    def get_iam_admin_headers(self):
        """Bearer token for Keycloak admin APIs (user/group/role resolution)."""
        return {
            "Authorization": f"Bearer {self.ensure_authenticated()}",
        }
