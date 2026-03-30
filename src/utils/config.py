import os
from datetime import date, timedelta
from dotenv import load_dotenv


class Config:
    """Application configuration (env + CLI overrides)."""

    def __init__(self):
        self.base_url = None
        self.tenant_name = None
        self.api_key = None
        self.iam_base_url = None
        self.debug = False

        self.max_retries = 3
        self.retry_delay = 2.0
        self.request_timeout = 60
        self.page_size = 1000

        self.output_directory = "./output"
        self.temp_directory = "./temp"
        self.output_filename_template = "audit_events_{tenant}_{timestamp}.csv"

        self.temp_file_cleanup = True

        # Optional YYYY-MM-DD; can be set via CXONE_START_DATE / CXONE_END_DATE in .env
        self.start_date = None
        self.end_date = None

    @classmethod
    def from_env(cls, env_file=".env"):
        load_dotenv(env_file)
        config = cls()
        config.base_url = os.getenv("CXONE_BASE_URL")
        config.tenant_name = os.getenv("CXONE_TENANT")
        config.api_key = os.getenv("CXONE_API_KEY")
        config.iam_base_url = os.getenv("CXONE_IAM_BASE_URL")
        config.debug = os.getenv("CXONE_DEBUG", "").lower() == "true"
        config.start_date = os.getenv("CXONE_START_DATE")
        config.end_date = os.getenv("CXONE_END_DATE")
        if os.getenv("CXONE_OUTPUT_DIR"):
            config.output_directory = os.getenv("CXONE_OUTPUT_DIR")
        if os.getenv("CXONE_PAGE_SIZE"):
            config.page_size = min(1000, max(1, int(os.getenv("CXONE_PAGE_SIZE"))))
        return config

    def validate(self):
        if not self.base_url:
            return (
                False,
                "Base URL is required (set CXONE_BASE_URL in .env or use --base-url).",
            )
        if not self.tenant_name:
            return (
                False,
                "Tenant name is required (set CXONE_TENANT in .env or use --tenant-name).",
            )
        if not self.api_key:
            return (
                False,
                "API key is required (set CXONE_API_KEY in .env or use --api-key).",
            )
        return True, None

    @staticmethod
    def validate_date_range(start_date: date, end_date: date):
        today = date.today()
        if start_date > today:
            return False, "Start date cannot be in the future."
        if start_date > end_date:
            return False, "Start date is after end date."
        earliest = today - timedelta(days=365)
        if start_date < earliest:
            return (
                False,
                f"Audit events are only available for the previous 365 days. "
                f"Earliest allowed start date is {earliest.isoformat()}.",
            )
        return True, None
