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
python script_name.py --base_url [BASE_URL] [--iam_base_url IAM_BASE_URL] --tenant_name [TENANT_NAME] --api_key [API_KEY] --start_date [START_DATE] --end_date [END_DATE] [OPTIONS]
```

### Required Arguments:

- `--base_url`: The base URL of the CxOne region.
- `--tenant_name`: The name of the tenant.
- `--api_key`: The API key used for authentication.
- `--start_date`: The start date for fetching logs, in YYYY-MM-DD format.
- `--end_date`: The end date for fetching logs, in YYYY-MM-DD format.

### Optional Arguments:

- `--iam_base_url`: The IAM base URL of the CxOne region.
- `--debug`: Enable debug output.
- `--search_string`: Filter events containing specific strings.
- `--raw`: Output raw logs.
- `--human_readable`: Resolve UUIDs to human-readable strings.

## Usage Examples

1. Basic usage:

    ```bash
    python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key 12345 --start_date 2021-01-01 --end_date 2021-01-31
    ```

2. With debug output:

    ```bash
    python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key 12345 --start_date 2021-01-01 --end_date 2021-01-31 --debug
    ```

3. With a search string:

    ```bash
    python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key 12345 --start_date 2021-01-01 --end_date 2021-01-31 --search_string "login"
    ```

4. Output raw logs:

    ```bash
    python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key 12345 --start_date 2021-01-01 --end_date 2021-01-31 --raw
    ```

5. Resolve UUIDs to human-readable strings:

    ```bash
    python script_name.py --base_url https://example.com --tenant_name my_tenant --api_key 12345 --start_date 2021-01-01 --end_date 2021-01-31 --human_readable
    ```

## Output

The script will output the fetched logs either in a human-readable format or as raw JSON, based on the options provided. It will also indicate if no logs were found for the specified date range.
