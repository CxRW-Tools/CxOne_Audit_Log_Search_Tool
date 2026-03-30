"""HTTP client for CxOne audit-events API with pagination and retries."""

import time
import requests


class APIClient:
    def __init__(self, base_url, auth_manager, config, debug=False, debug_logger=None):
        self.base_url = base_url.rstrip("/")
        self.auth = auth_manager
        self.config = config
        self.debug = debug
        self.logger = debug_logger

    def get_audit_events_all(self, params_base):
        """
        GET /api/audit-events/ with full pagination until all events are collected.
        params_base must include startDate and endDate (RFC3339).
        """
        endpoint = "/api/audit-events/"
        all_events = []
        offset = 0
        limit = min(1000, max(1, getattr(self.config, "page_size", 1000)))
        total_filtered = None

        while True:
            page_params = dict(params_base)
            page_params["limit"] = limit
            page_params["offset"] = offset

            if self.logger:
                self.logger.log(
                    f"API: GET {endpoint} offset={offset} limit={limit}"
                )

            data = self._get_json(endpoint, page_params, audit=True)
            if data is None:
                raise RuntimeError(
                    "Failed to fetch audit events from CxOne API after retries. "
                    "Check base URL, credentials, and that GET /api/audit-events/ is available for your tenant."
                )

            if total_filtered is None:
                total_filtered = data.get("totalFilteredCount")

            events = data.get("events") or []
            all_events.extend(events)

            if self.logger:
                self.logger.log(
                    f"API: page returned {len(events)} events (total so far: {len(all_events)}"
                    + (f", totalFilteredCount={total_filtered}" if total_filtered is not None else "")
                    + ")"
                )

            if not events:
                break

            if len(events) < limit:
                break

            if total_filtered is not None and len(all_events) >= total_filtered:
                break

            offset += limit

        return all_events

    def _get_json(self, endpoint, params=None, audit=False):
        url = f"{self.base_url}{endpoint}"
        headers = self.auth.get_audit_headers() if audit else self.auth.get_headers()

        for attempt in range(self.config.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    params=params or {},
                    timeout=self.config.request_timeout,
                )

                if response.status_code == 429:
                    wait_time = 30
                    if self.debug:
                        print(f"Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue

                response.raise_for_status()
                return response.json()

            except requests.exceptions.Timeout:
                if attempt < self.config.max_retries - 1:
                    wait_time = self.config.retry_delay * (2**attempt)
                    if self.logger:
                        self.logger.log(f"API: Timeout on {url}. Retrying in {wait_time}s...")
                    if self.debug:
                        print(f"Timeout. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    if self.logger:
                        self.logger.log(f"API: Request timed out after {self.config.max_retries} attempts: {url}")
                    return None

            except requests.exceptions.RequestException as e:
                if attempt < self.config.max_retries - 1:
                    wait_time = self.config.retry_delay * (2**attempt)
                    if self.logger:
                        self.logger.log(f"API: Error on {url}: {e}. Retrying in {wait_time}s...")
                    if self.debug:
                        print(f"Error: {e}. Retrying...")
                    time.sleep(wait_time)
                else:
                    if self.logger:
                        self.logger.log(f"API: Request failed after {self.config.max_retries} attempts: {url} - {e}")
                    return None

        return None

    def get_json_iam(self, url, headers):
        """GET for IAM admin URLs (no Accept version on AST)."""
        for attempt in range(self.config.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.config.request_timeout,
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2**attempt))
                else:
                    if self.debug:
                        print(f"IAM request failed: {url} - {e}")
                    return None
        return None
