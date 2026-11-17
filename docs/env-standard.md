# Adding `.env` support to a CxOne tool

This is how the Audit Log Search Tool handles configuration. Do the same in other tools, so the same env file works everywhere.

## How it works

- **Config file:** settings come from an env file, `.env` by default, or another file passed with `--env-file`.
- **Overrides:** CLI flags override the file. Real environment variables also beat the file, because python-dotenv doesn't overwrite variables that are already set.
- **Precedence:** CLI flag > environment variable > env file > built-in default.
- **In the repo:** `example.env` is committed as a template, and `.env` is gitignored.

## Steps

**1. Add the dependency** to `requirements.txt`:

```text
python-dotenv>=1.0.0
```

**2. Use the standard variable names.** Every CxOne tool uses these, so one env file works for all of them:

```dotenv
CXONE_BASE_URL=https://ast.checkmarx.net
CXONE_TENANT=my-tenant
CXONE_API_KEY=<your-api-key>
CXONE_DEBUG=false
# Optional
# CXONE_IAM_BASE_URL=https://iam.checkmarx.net
```

Tool-specific settings also start with `CXONE_` (for example `CXONE_OUTPUT_DIR`). Commit this as `example.env`, with placeholders only.

**3. Load the settings in a config class** (see [`src/utils/config.py`](../src/utils/config.py)):

```python
import os
from dotenv import load_dotenv


class Config:
    def __init__(self):
        self.base_url = None
        self.tenant_name = None
        self.api_key = None
        self.iam_base_url = None
        self.debug = False

    @classmethod
    def from_env(cls, env_file=".env"):
        load_dotenv(env_file)  # a missing file is fine; existing env vars are not overwritten
        config = cls()
        config.base_url = os.getenv("CXONE_BASE_URL")
        config.tenant_name = os.getenv("CXONE_TENANT")
        config.api_key = os.getenv("CXONE_API_KEY")
        config.iam_base_url = os.getenv("CXONE_IAM_BASE_URL")
        config.debug = os.getenv("CXONE_DEBUG", "").lower() == "true"
        return config

    def validate(self):
        if not self.base_url:
            return False, "Base URL is required (set CXONE_BASE_URL in .env or use --base-url)."
        if not self.tenant_name:
            return False, "Tenant name is required (set CXONE_TENANT in .env or use --tenant-name)."
        if not self.api_key:
            return False, "API key is required (set CXONE_API_KEY in .env or use --api-key)."
        return True, None
```

**4. Add `--env-file` and override flags, then validate** (see [`main.py`](../main.py)):

```python
p = argparse.ArgumentParser()
p.add_argument("--env-file", default=".env", help="Path to environment file (default: .env)")
p.add_argument("--base-url", help="Region base URL (e.g. https://ast.checkmarx.net)")
p.add_argument("--tenant-name", help="Tenant name")
p.add_argument("--api-key", help="API key")
args = p.parse_args()

config = Config.from_env(args.env_file)
if args.base_url:
    config.base_url = args.base_url
if args.tenant_name:
    config.tenant_name = args.tenant_name
if args.api_key:
    config.api_key = args.api_key

ok, err = config.validate()
if not ok:
    print("Configuration error:", err)
    sys.exit(1)
```

**5. Ignore real env files** in `.gitignore`:

```gitignore
.env
```

**6. Document it in the README:**
- a "Configuration" section listing each variable;
- "copy `example.env` to `.env`";
- "CLI flags override `.env` values".

## Using a shared tenant file

Point any tool at a tenant file in `CxTools/Environment Files/`:

```bash
python main.py --env-file "../Environment Files/rw_sandbox.env"
```

## Rules

- **Never commit a real `.env`.** `example.env` holds placeholders only, never a real or shortened key.
- **Never print the API key.** Printing the tenant and base URL on start-up is fine.
