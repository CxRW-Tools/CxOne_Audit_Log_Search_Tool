"""Resolve UUIDs in audit event payloads via Keycloak admin APIs."""

import re

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)


def is_uuid(value) -> bool:
    if value is None:
        return False
    return bool(_UUID_RE.fullmatch(str(value)))


class UuidResolver:
    def __init__(self, auth_manager, api_client, tenant_name, debug=False):
        self.auth = auth_manager
        self.api = api_client
        self.tenant_name = tenant_name
        self.debug = debug
        self._cache = {}

    def _iam_base(self):
        return self.auth.iam_base_url

    def resolve_uuid(self, uid: str, uuid_type: str) -> str:
        if uid in self._cache:
            return self._cache[uid]

        if uuid_type in ("actionUserId", "userId"):
            resolved = self._resolve_user(uid)
        elif uuid_type in ("roleId", "assignedRoles", "unassignedRoles"):
            resolved = self._resolve_role(uid)
        elif uuid_type == "groupId":
            resolved = self._resolve_group(uid)
        else:
            resolved = uid

        self._cache[uid] = resolved
        return resolved

    def _resolve_user(self, uid: str) -> str:
        url = f"{self._iam_base()}/auth/admin/realms/{self.tenant_name}/users/{uid}"
        data = self.api.get_json_iam(url, self.auth.get_iam_admin_headers())
        if not data:
            return "Unresolved User ID"
        username = data.get("username", "N/A")
        first_name = data.get("firstName", "N/A")
        last_name = data.get("lastName", "N/A")
        return f"{first_name} {last_name} ({username})"

    def _resolve_role(self, uid: str) -> str:
        url = f"{self._iam_base()}/auth/admin/realms/{self.tenant_name}/roles-by-id/{uid}"
        data = self.api.get_json_iam(url, self.auth.get_iam_admin_headers())
        if not data:
            return "Unresolved Role ID"
        return data.get("name", "N/A")

    def _resolve_group(self, uid: str) -> str:
        url = f"{self._iam_base()}/auth/admin/realms/{self.tenant_name}/groups"
        data = self.api.get_json_iam(url, self.auth.get_iam_admin_headers())
        if not data:
            return "Unresolved Group ID"
        for group in data:
            gid = group.get("id")
            name = group.get("name", "N/A")
            if gid:
                self._cache[gid] = name
            if gid == uid:
                return name
        return "Unresolved Group ID"

    def resolve_in_event(self, obj):
        """Resolve UUID strings in nested dict/list structures (mutates in place)."""
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                value = obj[key]
                if isinstance(value, dict):
                    self.resolve_in_event(value)
                elif isinstance(value, list):
                    uuid_type = (
                        "roleId" if key in ("assignedRoles", "unassignedRoles") else key
                    )
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            self.resolve_in_event(item)
                        elif isinstance(item, list):
                            self.resolve_in_event(item)
                        elif is_uuid(item):
                            value[i] = self.resolve_uuid(str(item), uuid_type)
                elif isinstance(value, str) and is_uuid(value):
                    obj[key] = self.resolve_uuid(value, key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self.resolve_in_event(item)
                elif is_uuid(item):
                    obj[i] = self.resolve_uuid(str(item), "roleId")
