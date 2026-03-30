#!/usr/bin/env python3
"""
CxOne Audit Log Search Tool — fetch audit events via GET /api/audit-events/,
filter, optional human-readable UUID resolution, console and/or CSV export.
"""

import argparse
import json
import os
import sys
import time
from datetime import date, datetime

from src.operations.audit_events_collector import AuditEventsCollector
from src.operations.uuid_resolver import UuidResolver
from src.utils.api_client import APIClient
from src.utils.audit_output import filter_events, print_formatted_events, sort_events
from src.utils.auth import AuthManager
from src.utils.config import Config
from src.utils.csv_export import write_audit_events_csv
from src.utils.debug_logger import DebugLogger
from src.utils.file_manager import FileManager
from src.utils.progress import StageTracker


def parse_args():
    p = argparse.ArgumentParser(
        description="Search and export Checkmarx One audit events (GET /api/audit-events/)"
    )
    p.add_argument("--env-file", default=".env", help="Path to environment file (default: .env)")
    p.add_argument("--base-url", help="Region base URL (e.g. https://ast.checkmarx.net)")
    p.add_argument("--iam-base-url", help="IAM base URL (default: derived from base URL)")
    p.add_argument("--tenant-name", help="Tenant name")
    p.add_argument("--api-key", help="API key (refresh token)")
    p.add_argument(
        "--start-date",
        help="Start date YYYY-MM-DD (inclusive). Overrides CXONE_START_DATE from .env.",
    )
    p.add_argument(
        "--end-date",
        help="End date YYYY-MM-DD (inclusive). Overrides CXONE_END_DATE from .env.",
    )
    p.add_argument("--debug", action="store_true", help="Verbose console + debug log file")
    p.add_argument("--search-string", help="Only include events whose JSON contains this string")
    p.add_argument("--raw", action="store_true", help="Print events as JSON to stdout (ignored when --csv is set without --print-events)")
    p.add_argument(
        "--human-readable",
        action="store_true",
        help="Resolve UUIDs via IAM admin APIs (users, groups, roles)",
    )
    p.add_argument("--csv", action="store_true", help="Write results to a UTF-8 CSV under output/")
    p.add_argument(
        "--csv-path",
        help="Explicit CSV file path (default: timestamped file under output directory)",
    )
    p.add_argument(
        "--print-events",
        action="store_true",
        help="With --csv, also print formatted or raw events to stdout (default: summary only)",
    )
    p.add_argument("--output-dir", help="Output directory for CSV and debug logs (default: ./output)")
    return p.parse_args()


def _print_missing_date_help(env_file: str):
    env_hint = ""
    if not os.path.isfile(env_file):
        env_hint = (
            f"\n  No file at {env_file!r}. Copy example.env to .env and edit it, "
            "or pass credentials and dates on the command line.\n"
        )
    print(
        "Error: Date range is required.\n\n"
        "  Provide either:\n"
        "    - Environment: CXONE_START_DATE and CXONE_END_DATE (YYYY-MM-DD) in your .env file, or\n"
        "    - Command line: --start-date YYYY-MM-DD --end-date YYYY-MM-DD\n\n"
        "  Credentials (same pattern): CXONE_BASE_URL, CXONE_TENANT, CXONE_API_KEY in .env "
        "or --base-url, --tenant-name, --api-key.\n"
        f"{env_hint}"
        f"  Default env file path: {os.path.abspath(env_file)}"
    )


def parse_dates(start_s: str, end_s: str):
    try:
        start_date = datetime.strptime(start_s, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_s, "%Y-%m-%d").date()
    except ValueError:
        print("Error: Invalid date format. Use YYYY-MM-DD.")
        sys.exit(1)
    today = date.today()
    if end_date > today:
        end_date = today
    ok, err = Config.validate_date_range(start_date, end_date)
    if not ok:
        print("Configuration error:", err)
        sys.exit(1)
    return start_date, end_date


def main():
    start_time = time.time()
    args = parse_args()

    config = Config.from_env(args.env_file)
    if args.base_url:
        config.base_url = args.base_url
    if args.tenant_name:
        config.tenant_name = args.tenant_name
    if args.api_key:
        config.api_key = args.api_key
    if args.iam_base_url:
        config.iam_base_url = args.iam_base_url
    if args.debug:
        config.debug = True
    if args.output_dir:
        config.output_directory = args.output_dir

    start_s = args.start_date or config.start_date
    end_s = args.end_date or config.end_date
    if not start_s or not end_s:
        _print_missing_date_help(args.env_file)
        sys.exit(1)

    start_date, end_date = parse_dates(start_s, end_s)

    ok, err = config.validate()
    if not ok:
        print("Configuration error:", err)
        sys.exit(1)

    print("=" * 120)
    print("CxOne Audit Log Search")
    print("=" * 120)
    print("Tenant:", config.tenant_name)
    print("Base URL:", config.base_url)
    print("Date range:", start_date.isoformat(), "to", end_date.isoformat())
    print("Output directory:", config.output_directory)
    print("=" * 120)

    auth_manager = AuthManager(
        base_url=config.base_url,
        tenant_name=config.tenant_name,
        api_key=config.api_key,
        iam_base_url=config.iam_base_url,
        debug=config.debug,
    )

    file_manager = FileManager(config, config.debug)
    file_manager.setup_directories()

    debug_logger = None
    dbg_path = None
    if config.debug:
        dbg_path = file_manager.get_standalone_debug_log_path()
        debug_logger = DebugLogger(dbg_path, console_debug=True)
        debug_logger.log("CxOne Audit Log Search — debug log")

    try:
        auth_manager.ensure_authenticated()
        if config.debug:
            print("\nAuthenticated with CxOne")

        api_client = APIClient(
            config.base_url,
            auth_manager,
            config,
            config.debug,
            debug_logger,
        )

        stages = StageTracker(config.debug)
        stages.start_stage("Stage 1: Fetch audit events")
        collector = AuditEventsCollector(
            config,
            auth_manager,
            api_client=api_client,
            progress=None,
            debug_logger=debug_logger,
        )
        events = collector.execute(start_date, end_date)
        stages.end_stage("Stage 1: Fetch audit events", events_fetched=len(events))

        events = filter_events(events, args.search_string)
        events = sort_events(events)

        if args.human_readable:
            stages.start_stage("Stage 2: Resolve UUIDs (human-readable)")
            resolver = UuidResolver(
                auth_manager,
                api_client,
                config.tenant_name,
                debug=config.debug,
            )
            for ev in events:
                resolver.resolve_in_event(ev)
            stages.end_stage("Stage 2: Resolve UUIDs (human-readable)", events=len(events))

        csv_path = None
        if args.csv:
            csv_path = args.csv_path or file_manager.get_output_csv_path()
            os.makedirs(os.path.dirname(os.path.abspath(csv_path)) or ".", exist_ok=True)
            n = write_audit_events_csv(csv_path, events)
            print("\nCSV export:", n, "rows written to", os.path.abspath(csv_path))

        suppress_detail = args.csv and not args.print_events

        if not suppress_detail:
            if not events:
                print("No logs found for the specified criteria.")
            elif args.raw:
                print(json.dumps(events, indent=2, ensure_ascii=False, default=str))
            else:
                print_formatted_events(events)
        elif args.csv and not events:
            print("No events matched; CSV written with header only.")

        if debug_logger:
            debug_logger.log("Events after filter: " + str(len(events)))
            debug_logger.close()
        if dbg_path:
            print("\nDebug log:", os.path.abspath(dbg_path))

        elapsed = time.time() - start_time
        print("\nDone in {:.1f}s".format(elapsed))

    except KeyboardInterrupt:
        print("\n\nCancelled.")
        if debug_logger:
            debug_logger.log("INTERRUPTED")
            debug_logger.close()
        sys.exit(1)
    except Exception as e:
        print("\nError:", e)
        if config.debug:
            import traceback

            traceback.print_exc()
        if debug_logger:
            debug_logger.log("FATAL: " + str(e))
            debug_logger.close()
        sys.exit(1)


if __name__ == "__main__":
    main()
