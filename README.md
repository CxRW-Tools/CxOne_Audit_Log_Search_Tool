# CxOne Audit Log Search Tool Usage Guide

## Summary

The script is designed to search and fetch audit logs from the CxOne platform. It uses multi-threading to fetch detailed logs and offers various options for filtering and outputting the logs. The script also resolves UUIDs to human-readable strings for easier interpretation.

## Requirements

- Python 3.x
- Install the required packages:
  ```
  pip install requests==2.31.0
  pip install tqdm==4.66.1
  ```

## Syntax and Arguments

Run the script using the following syntax:

```bash
python script_name.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --start_date START_DATE --end_date END_DATE [OPTIONS]
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
python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31
```

Fetch logs with debug output:

```bash
python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31 --debug
```

Fetch logs and filter them by a specific string:

```bash
python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31 --search_string "login"
```

Fetch logs with a specified IAM base URL:

```bash
python script_name.py --base_url https://example.com --iam_base_url https://iam.example.com --tenant_name my_tenant --api_key my_api_key --start_date 2022-01-01 --end_date 2022-01-31
```

## Output

The script will output the fetched logs either in a human-readable format or as raw JSON, based on the options provided. It will also indicate if no logs were found for the specified date range.
