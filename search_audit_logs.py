# Install specific versions packages
# pip install requests==2.31.0
# pip install tqdm==4.66.1

import requests  # version 2.31.0
import json
import datetime
from datetime import date
from datetime import datetime
import argparse
import re
from dateutil.parser import parse
from tqdm import tqdm  # version 4.66.1
from concurrent.futures import ThreadPoolExecutor, as_completed



base_url = None
tenant_name = None
debug = False
auth_url = None
iam_base_url = None
auth_token = None
uuid_cache = {}


def generate_auth_url():
    global iam_base_url
    try:
        if debug:
            print("Generating authentication URL...")
        
        iam_base_url = base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")
        temp_auth_url = f"{iam_base_url}/auth/realms/{tenant_name}/protocol/openid-connect/token"
        
        if debug:
            print(f"Generated authentication URL: {temp_auth_url}")
            print(f"Generated IAM base URL: {iam_base_url}")
        
        return temp_auth_url
    except AttributeError:
        print("Error: Invalid base_url provided.")
        return None

def authenticate(api_key):
    if auth_url is None:
        return None
    
    if debug:
        print("Authenticating with API...")
        
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {api_key}'
    }
    data = {
        'grant_type': 'refresh_token',
        'client_id': 'ast-app',
        'refresh_token': api_key
    }
    
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        
        json_response = response.json()
        access_token = json_response.get('access_token')
        
        if not access_token:
            print("Error: Access token not found in the response.")
            return None
        
        if debug:
            print("Successfully authenticated.")
        
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during authentication: {e}")
        return None

def fetch_audit_logs(start_date, end_date):
    if auth_token is None:
        return None
    
    # Initialize tqdm object with unknown total if debug is False
    pbar = tqdm(total=(end_date - start_date).days, desc="Processing events") if not debug else None
    
    try:
        audit_url = f"{base_url}/api/audit/"
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {auth_token}'}
        response = requests.get(audit_url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        
        if debug:
            print("Fetched initial audit log links.")
        
        # Update tqdm object with the actual total
        if pbar:
            pbar.total = len(json_response.get('links', []))
            pbar.refresh()
        
        logs = {}
        found_links = False
        
        links = json_response.get('links', [])
        
        # Create a ThreadPoolExecutor
        with ThreadPoolExecutor() as executor:
            future_to_date = {}
            for link in links:
                event_date_str = link.get('eventDate')
                if event_date_str:
                    event_date = parse(event_date_str).date()
                    if start_date <= event_date <= end_date:
                        found_links = True
                        if debug:
                            print(f"Scheduling detailed logs fetching for {event_date}")
                        future = executor.submit(fetch_detailed_logs, link.get('url'))
                        future_to_date[future] = event_date

            for future in as_completed(future_to_date):
                event_date = future_to_date[future]
                try:
                    logs[event_date] = future.result()
                except Exception as e:
                    print(f"An error occurred during fetching detailed logs for {event_date}: {e}")

                # Update tqdm object
                if pbar:
                    pbar.update(1)

        # Close tqdm object
        if pbar:
            pbar.close()

        # Capture events for the current day if it's within the date range
        today = date.today()
        if start_date <= today <= end_date:
            current_day_events = json_response.get('events', [])
            if current_day_events:
                found_links = True
                if debug:
                    print(f"Capturing events for today: {today}")
                logs[today] = current_day_events
        
        if not found_links:
            print("No audit logs found for the specified date range.")
        
        return logs
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during fetching audit logs: {e}")
        return None

def fetch_detailed_logs(url):
    try:
        headers = {'Authorization': f'Bearer {auth_token}'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        
        if debug:
            print(f"Fetched detailed logs from {url}")
        
        return json_response
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during fetching detailed logs: {e}")
        return None

def apply_filters(logs, search_string=None):
    if debug:
        print("Applying filters to logs...")
        
    filtered_logs = {}
    
    for date, log_list in logs.items():
        filtered_list = []
        for log in log_list:
            if search_string and search_string not in json.dumps(log):
                continue
            filtered_list.append(log)
        
        if filtered_list:
            filtered_logs[date] = filtered_list
    
    if debug:
        print("Finished applying filters.")
        
    return filtered_logs
    
def is_uuid(value):
    if debug:
        print(f"Checking if {value} is a UUID...")
        
    uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    return bool(uuid_pattern.fullmatch(value))

def resolve_userid(uuid):
    if debug:
        print(f"Resolving UUID {uuid} as a userId")
        
    try:
        # Construct the URL for the GET request
        user_url = f"{iam_base_url}/auth/admin/realms/{tenant_name}/users/{uuid}"
        
        if debug:
            print(f"Constructed user URL: {user_url}")
        
        # Set the headers for the request
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        # Make the GET request
        response = requests.get(user_url, headers=headers)
        response.raise_for_status()
        
        if debug:
            print("GET request successful. Parsing response...")
        
        # Parse the JSON response
        user_data = response.json()
        
        # Extract the required fields
        username = user_data.get('username', 'N/A')
        first_name = user_data.get('firstName', 'N/A')
        last_name = user_data.get('lastName', 'N/A')
        
        if debug:
            print(f"Extracted user details: Username: {username}, First Name: {first_name}, Last Name: {last_name}")
        
        # Format the string
        resolved_string = f"{first_name} {last_name} ({username})"
        
        if debug:
            print(f"Formatted resolved string: {resolved_string}")
        
        # Store the resolved string in the cache
        uuid_cache[uuid] = resolved_string
        
        if debug:
            print(f"Stored {resolved_string} in cache for UUID {uuid}")
        
        return resolved_string
        
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"An error occurred while resolving user ID: {e}")
        return "Unresolved User ID"

    except Exception as e:
        if debug:
            print(f"An unexpected error occurred: {e}")
        return "Unresolved User ID"

def resolve_groupid(uuid):
    if debug:
        print(f"Resolving UUID {uuid} as a groupId")
        
    try:
        # Construct the URL for the GET request
        group_url = f"{iam_base_url}/auth/admin/realms/{tenant_name}/groups"

        if debug:
            print(f"Constructed group URL: {group_url}")

        # Set the headers for the request
        headers = {'Authorization': f'Bearer {auth_token}'}

        # Make the GET request
        response = requests.get(group_url, headers=headers)
        response.raise_for_status()

        if debug:
            print("GET request successful. Parsing response...")

        # Parse the JSON response
        group_data = response.json()

        # Initialize a variable to hold the group name for the given UUID
        group_name_for_uuid = "Unresolved Group ID"

        # Loop through all groups and cache them
        for group in group_data:
            group_id = group.get('id', 'N/A')
            group_name = group.get('name', 'N/A')

            # Cache the group name
            uuid_cache[group_id] = group_name
            
            if debug:
                print(f"Stored {group_name} in cache for UUID {group_id}")

            # Check if this is the group we are looking for
            if group_id == uuid:
                group_name_for_uuid = group_name

        if debug:
            print(f"Stored all group names in cache. Resolved name for UUID {uuid}: {group_name_for_uuid}")

        return group_name_for_uuid

    except requests.exceptions.RequestException as e:
        if debug:
            print(f"An error occurred while resolving group ID: {e}")
        return "Unresolved Group ID"

    except Exception as e:
        if debug:
            print(f"An unexpected error occurred: {e}")
        return "Unresolved Group ID"

def resolve_roleid(uuid):
    if debug:
        print(f"Resolving UUID {uuid} as a roleId")
    try:
        # Construct the URL for the GET request
        role_url = f"{iam_base_url}/auth/admin/realms/{tenant_name}/roles-by-id/{uuid}"
        
        if debug:
            print(f"Constructed role URL: {role_url}")
        
        # Set the headers for the request
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        # Make the GET request
        response = requests.get(role_url, headers=headers)
        response.raise_for_status()
        
        if debug:
            print("GET request successful. Parsing response...")
        
        # Parse the JSON response
        role_data = response.json()
        
        # Extract the required field
        rolename = role_data.get('name', 'N/A')
        
        if debug:
            print(f"Extracted role details: Role Name: {rolename}")

        # Store the resolved role name in the cache
        uuid_cache[uuid] = rolename
        
        if debug:
            print(f"Stored {rolename} in cache for UUID {uuid}")
        
        return rolename
        
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"An error occurred while resolving role ID: {e}")
        return "Unresolved Role ID"

    except Exception as e:
        if debug:
            print(f"An unexpected error occurred: {e}")
        return "Unresolved Role ID"

def resolve_uuid(uuid, uuid_type):
    if debug:
        print(f"Resolving UUID {uuid} of type {uuid_type}...")

    # Check if the UUID is already in the cache
    if uuid in uuid_cache:
        if debug:
            print(f"Cache hit for UUID {uuid}. Using cached value.")
        return uuid_cache[uuid]
    elif debug:
        print(f"UUID {uuid} is not in the cache")

    if uuid_type == 'actionUserId' or uuid_type == 'userId':
        return resolve_userid(uuid)
    elif uuid_type == 'roleId' or uuid_type == 'assignedRoles' or uuid_type == 'unassignedRoles':
        return resolve_roleid(uuid)
    elif uuid_type == 'groupId':
        return resolve_groupid(uuid)
    else:
        if debug:
            print(f"Unable to resolve UUID {uuid}")
        return uuid

def resolve_uuids_in_dict(d):
    if debug:
        print("Resolving UUIDs in dictionary...")
        
    for key, value in d.items():
        if isinstance(value, dict):
            resolve_uuids_in_dict(value)
        elif isinstance(value, list):
            uuid_type = 'roleId' if key in ['assignedRoles', 'unassignedRoles'] else key
            d[key] = [resolve_uuid(v, uuid_type) if is_uuid(str(v)) else v for v in value]
        elif isinstance(value, str):
            if value.startswith("[") and value.endswith("]"):
                try:
                    list_value = value[1:-1].split(", ")
                    list_value = [item.strip() for item in list_value]
                    d[key] = [resolve_uuid(v, key) if is_uuid(str(v)) else v for v in list_value]
                except Exception as e:
                    print(f"Exception while parsing list: {e}")
            elif is_uuid(value):
                d[key] = resolve_uuid(value, key)
                
    if debug:
        print("Finished resolving UUIDs.")

def output_logs(logs, raw=False, human_readable=False):
    if debug:
        print("Outputting events...")
    
    flat_logs = [event for sublist in logs.values() for event in sublist]
    flat_logs.sort(key=lambda x: x.get('eventDate'))

    if human_readable:
        for log in flat_logs:
            resolve_uuids_in_dict(log)

    if raw:
        print(json.dumps(flat_logs, indent=4))
        return
        
    print("-" * 40)
    for log in flat_logs:
        event_date = log.get('eventDate', 'N/A')
        event_type = log.get('eventType', 'N/A')
        action_user = log.get('actionUserId', 'N/A')

        print(f"Event Date: {event_date}")
        print(f"Event Type: {event_type}")
        print(f"Action User: {action_user}")

        data_fields = log.get('data', {})
        if data_fields:
            print("Data:")
            for key, value in data_fields.items():
                if isinstance(value, list):
                    value = ', '.join(map(str, value))
                print(f"  {key}: {value}")

        print("-" * 40)

    if debug:
        print("Finished outputting events.")

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token

    parser = argparse.ArgumentParser(description='Search CxOne Audit Logs')
    parser.add_argument('--base_url', required=True, help='Region Base URL')
    parser.add_argument('--tenant_name', required=True, help='Tenant name')
    parser.add_argument('--api_key', required=True, help='API key for authentication')
    parser.add_argument('--start_date', required=True, help='Start date in YYYY-MM-DD format')
    parser.add_argument('--end_date', required=True, help='End date in YYYY-MM-DD format')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--search-string', required=False, help='Filter events containing specific strings')
    parser.add_argument('--raw', action='store_true', help='Output raw logs')
    parser.add_argument('--human-readable', action='store_true', help='Resolve UUIDs to human-readable strings')

    args = parser.parse_args()
    
    try:
        start_date = datetime.strptime(args.start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(args.end_date, '%Y-%m-%d').date()
    except ValueError:
        print("Error: Invalid date format. Please use YYYY-MM-DD.")
        return

    if start_date > end_date:
        print("Error: Start date is after the end date. Please provide a valid date range.")
        return

    base_url = args.base_url
    tenant_name = args.tenant_name
    debug = args.debug
    
    if debug:
        print("Starting the script...")

    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)

    logs = fetch_audit_logs(start_date, end_date)

    filtered_logs = apply_filters(logs, search_string=args.search_string)

    output_logs(filtered_logs, raw=args.raw, human_readable=args.human_readable)
    
    if debug:
        print("Script execution completed.")

if __name__ == "__main__":
    main()