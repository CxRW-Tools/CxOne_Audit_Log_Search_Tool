# CxOne Audit Log Search Tool Usage Guide

## Summary

The script is designed to search and fetch audit logs from the CxOne platform. It uses multi-threading to fetch detailed logs and offers various options for filtering and outputting the logs. The script also resolves UUIDs to human-readable strings for easier interpretation.

## Syntax and Arguments

Run the script using the following syntax:

```bash
python search_audit_logs.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --start_date START_DATE --end_date END_DATE [OPTIONS]
```

### Required Arguments

- `--base_url`: The base URL of the CxOne region.
- `--tenant_name`: The name of the tenant.
- `--api_key`: The API key used for authentication.
- `--start_date`: The start date for fetching logs, in YYYY-MM-DD format.
- `--end_date`: The end date for fetching logs, in YYYY-MM-DD format.

### Optional Arguments

- `--iam_base_url`: The IAM base URL of the CxOne region. If not provided, it will be generated based on the `base_url`.
- `--debug`: Enable debug output. (Flag, no value required)
- `--search_string`: A string to filter events. Only events containing this string will be included.
- `--raw`: Output raw logs. (Flag, no value required)
- `--human_readable`: Resolve UUIDs to human-readable strings. (Flag, no value required)

## Usage Examples

Fetch logs for a specific date range:

```bash
python search_audit_logs.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31
```

Fetch logs with debug output:

```bash
python search_audit_logs.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31 --debug
```

Fetch logs and filter them by a specific string:

```bash
python search_audit_logs.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31 --search_string "login"
```

Fetch logs with a specified IAM base URL:

```bash
python search_audit_logs.py --base_url https://example.com --iam_base_url https://iam.example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31
```

## Output

The script will output the fetched logs either in a human-readable format or as raw JSON, based on the options provided. It will also indicate if no logs were found for the specified date range.

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
