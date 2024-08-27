import requests
import json
import time
import os
import boto3

# Global Variables
BEARER_TOKEN = os.getenv('CLOUDFLARE_BEARER_TOKEN')
destination_account_id = os.getenv('CLOUDFLARE_DESTINATION_ACCOUNT_ID')
CLOUDFLARE_BOTO_ACCESS_KEY = os.getenv('CLOUDFLARE_BOTO_ACCESS_KEY')
CLOUDFLARE_BOTO_SECRET_ACCESS_KEY = os.getenv('CLOUDFLARE_BOTO_SECRET_ACCESS_KEY')
print(BEARER_TOKEN)
zone_id_source = ""
zone_id_destination = ""
domain_temp = False

##########################
def make_api_call(url, method, data=None):
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    response = requests.request(method, url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"API call failed with status code {response.status_code}: {response.text}")
        return None
    
##########################
def format_headers(headers):
    result = headers.get('result', {})
    formatted_headers = []
    for item in result.get('managed_request_headers', []):
        formatted_headers.append(f"{item['id']}: [{str(item['enabled']).lower()}]")
    for item in result.get('managed_response_headers', []):
        formatted_headers.append(f"{item['id']}: [{str(item['enabled']).lower()}]")
    return "\n".join(formatted_headers)

##########################
def verify_api_token():
    response = make_api_call("https://api.cloudflare.com/client/v4/user/tokens/verify", "GET")
    if not response.get("success"):
        print("Error: Authentication error. Please check your API token.")
        global BEARER_TOKEN
        BEARER_TOKEN = input("Enter a new valid API token: ")
        verify_api_token()

##########################
def get_primary_domain(zone_id):
    zone_info_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}", "GET")
    if zone_info_response and "result" in zone_info_response:
        return zone_info_response['result']['name']
    else:
        print("Error fetching zone details. Response:", zone_info_response)
        return None

##########################
def do_zone_dns_copy():
    # Retrieve and Delete Default DNS Records from new zone before copying existing ones
    print("\nDeleting default DNS records from target zone...")
    new_zone_dns_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/dns_records", "GET")
    record_ids = [record['id'] for record in new_zone_dns_results['result']]
    for record_id in record_ids:
        make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/dns_records/{record_id}", "DELETE")

    # Retrieve DNS Records from the Source Account
    dns_records = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_source}/dns_records", "GET")

    # Get the primary domain for the destination zone
    primary_domain = get_primary_domain(zone_id_destination)
    if not primary_domain:
        print("Failed to retrieve the primary domain. Exiting script.")
        exit(1)

    # Parse and Create DNS Records in the Destination Account/Zone
    print("\nCreating new DNS records:")
    dns_copy_errors = "successfully"

    for record in dns_records['result']:
        # Determine if the record type can be proxied
        can_be_proxied = record['type'] not in ['MX', 'NS', 'SRV', 'CAA', 'TXT']

        # Case 1: Handle primary A record
        if record['type'] == 'A' and record['name'] == primary_domain:
            create_record_data = {
                "type": "CNAME",
                "name": primary_domain,
                "content": "primesites.com.au",
                "ttl": record['ttl'],
                "proxied": True  # Explicitly enable proxying
            }
            print(f"Skipping primary A record and creating CNAME record instead: {create_record_data}")

        # Case 2: Handle CNAME record for www
        elif record['type'] == 'CNAME' and record['name'] == f"www.{primary_domain}":
            create_record_data = {
                "type": "CNAME",
                "name": record['name'],
                "content": "primesites.com.au",
                "ttl": record['ttl'],
                "proxied": True  # Explicitly enable proxying
            }
            print(f"Modifying CNAME www record to point to primesites.com.au: {create_record_data}")

        else:
            # Default behavior for other records
            create_record_data = {
                "name": record['name'],
                "type": record['type'],
                "ttl": record['ttl'],
                "proxied": record.get('proxied', False) if can_be_proxied else False  # Duplicate the proxy status
            }

            if record['type'] == 'SRV':
                # Ensure that all required fields are present
                priority = record.get('data', {}).get('priority')
                weight = record.get('data', {}).get('weight')
                port = record.get('data', {}).get('port')
                target = record.get('data', {}).get('target')

                if priority is None or weight is None or port is None or target is None:
                    dns_copy_errors = "WITH ERRORS!!!!!!"
                    print(f"Error: Missing required SRV field in record {record['name']}. Skipping this record.")
                    continue  # Skip to the next record

                # Populate the SRV record data
                create_record_data["data"] = {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target
                }
            else:
                # Include the 'content' and 'priority' fields for non-SRV records if they exist
                create_record_data['content'] = record['content']
                if 'priority' in record:
                    create_record_data['priority'] = record['priority']

        # Make the API call to create the DNS record
        create_record_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/dns_records", "POST", create_record_data)
        if create_record_response and "result" in create_record_response:
            created_record = create_record_response['result']
            print(f"Created DNS Record: Type: {created_record['type']}, Name: {created_record['name']}, Content: {created_record.get('content', '')}")
        else:
            print("Error creating DNS record. Response:", create_record_response)
            dns_copy_errors = "WITH ERRORS!!!!!!"

    print(f"\nDNS copy completed {dns_copy_errors}.")

##########################
def do_zone_create():
    global zone_id_source, zone_id_destination, domain_temp, destination_account_id

    # Domain prompt
    user_domain = input(f"\nThis script clones a zone to the CFA Cloudflare account. Domain to search for: ")
    if not user_domain:
        print("No domain entered. Bye.")
        return

    print(f"Searching for: {user_domain}")

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={user_domain}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count > 1:
        print(f"Error: More than one zone found for {user_domain}. Bye.")
        exit(0)
    if result_count < 1:
        print(f"Error: Zone not found for {user_domain}. Bye.")
        exit(0)

    # Extract Account ID
    source_zone_name = search_results['result'][0]['name']
    zone_id_source = search_results['result'][0]['id']
    source_zone_name_servers = search_results['result'][0]['name_servers']
    account_id = search_results['result'][0]['account']['id']
    account_name = search_results['result'][0]['account']['name']
    print(f"Found Zone {source_zone_name} (ID: {zone_id_source})\nNameservers: {source_zone_name_servers} \nAccount: {account_name} (ID: {account_id})")

    if domain_temp:
        epoch_seconds = int(time.time())
        user_domain = f"{epoch_seconds}-{user_domain}"

    # User Confirmation to Proceed
    user_confirmation = input(f"\nNew Zone name: {user_domain}. Proceed with transferring the zone? (Y/n) ")
    if user_confirmation.lower() != "y":
        print("Operation aborted by the user. Bye.")
        return

    # Create the new Zone under the destination account
    create_results = make_api_call("https://api.cloudflare.com/client/v4/zones", "POST", {
        "account": {"id": destination_account_id},
        "name": user_domain,
        "type": "full"
    })

    # Extract the new zone ID
    zone_id_destination = create_results['result']['id']
    print(f"Successfully created new zone with ID: {zone_id_destination}")

##########################
def transfer_managed_rules(zone_id_source, zone_id_destination):
    print("\nReading Source Managed Rules...")
    source_managed_headers = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_source}/managed_headers", "GET")

    # Parse Managed Headers for Update
    managed_request_headers = source_managed_headers['result'].get('managed_request_headers', [])
    managed_response_headers = source_managed_headers['result'].get('managed_response_headers', [])

    update_data = {
        "managed_request_headers": managed_request_headers,
        "managed_response_headers": managed_response_headers
    }

    print("Writing destination Managed Rules...")
    make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/managed_headers", "PATCH", update_data)

    # Verify the Update
    print("\nDestination Managed Rules:")
    new_managed_headers = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/managed_headers", "GET")
    formatted_new_headers = format_headers(new_managed_headers)
    print(formatted_new_headers)

    print("\nManaged Rules successfully copied")

##########################
def transfer_ruleset(phase, zone_id_source, zone_id_destination):
    print(f"\nStarting {phase} rules transfer process...")

    # Retrieve ruleset from the source account
    ruleset = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_source}/rulesets?phase={phase}", "GET")

    # Extract the ruleset ID
    ruleset_id = None
    for rs in ruleset['result']:
        if rs.get('phase') == phase:
            ruleset_id = rs.get('id')
            break

    if not ruleset_id:
        print(f"Error: Unable to retrieve {phase} ruleset details.")
        return

    # Get details of the ruleset
    ruleset_details = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_source}/rulesets/{ruleset_id}", "GET")

    # Retrieve ruleset ID from the new zone
    new_ruleset_id = None
    existing_rulesets = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/rulesets?phase={phase}", "GET")
    for rs in existing_rulesets['result']:
        if rs.get('phase') == phase:
            new_ruleset_id = rs.get('id')
            break

    # Create a new ruleset if not exist
    if not new_ruleset_id:
        new_ruleset_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/rulesets", "POST", {
            "kind": "zone",
            "phase": phase,
            "name": f"{phase} Ruleset",  # Ensure the name is provided
            "description": f"{phase} ruleset for {zone_id_destination}",
            "rules": []
        })

        # Check if the creation was successful
        if not new_ruleset_response.get("success"):
            errors = new_ruleset_response.get("errors", [])
            for error in errors:
                print(f"Error creating new ruleset: {error.get('message', 'Unknown error')}")
            return

        new_ruleset_id = new_ruleset_response['result']['id']
        print(f"Created new ruleset with ID: {new_ruleset_id}")

    # Prepare the rules data
    rules_data = [{
        "description": rule.get('description', ''),
        "expression": rule.get('expression', ''),
        "action": rule.get('action', ''),
        "enabled": rule.get('enabled', True),
        "action_parameters": rule.get('action_parameters', {})
    } for rule in ruleset_details['result']['rules']]

    # Update the ruleset in the destination account/zone
    update_ruleset_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/rulesets/{new_ruleset_id}", "PUT", {
        "description": f"{phase} ruleset for new zone",
        "name": f"{phase} Ruleset",  # Provide the name again
        "kind": "zone",
        "phase": phase,
        "rules": rules_data
    })

    if update_ruleset_response.get("success"):
        ruleset = update_ruleset_response.get("result", {})
        print(f"Updated Ruleset: ID: {ruleset.get('id')}, Name: {ruleset.get('name')}")
    else:
        errors = update_ruleset_response.get("errors", [])
        for error in errors:
            print(f"Error updating ruleset: {error.get('message', 'Unknown error')}")

    print(f"{phase} rules transfer process complete.")

##########################
def get_page_rules(zone_id):
    endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules"
    response = make_api_call(endpoint, "GET")
    if response and response.get("success"):
        return response.get("result", [])
    else:
        print(f"Error retrieving page rules: {response}")
        return []

##########################
def create_page_rule(zone_id, page_rule_data):
    endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules"
    response = make_api_call(endpoint, "POST", page_rule_data)
    if response and response.get("success"):
        print(f"Created Page Rule: {response.get('result')}")
    else:
        print(f"Error creating page rule: {response}")

##########################
def copy_page_rules(zone_id_source, zone_id_destination):
    print(f"\nCopying Page Rules from source zone {zone_id_source} to destination zone {zone_id_destination}...")

    page_rules = get_page_rules(zone_id_source)

    if not page_rules:
        print("No page rules found in the source zone.")
        return

    for rule in page_rules:
        # Update URL targets to reflect the new domain
        new_targets = []
        for target in rule.get('targets', []):
            if target['target'] == 'url':
                new_target_value = target['constraint']['value'].replace("source-domain.com", "destination-domain.com")
                new_targets.append({
                    "constraint": {
                        "operator": target['constraint'].get('operator'),
                        "value": new_target_value
                    },
                    "target": target.get('target')
                })

        # Define valid actions
        valid_actions = {
            "forwarding_url": "on",
            "browser_cache_ttl": 14400,  # Example TTL
            "cache_level": "aggressive",
            # Add more valid actions here if needed
        }

        # Prepare page rule data for creation
        page_rule_data = {
            "actions": [
                {"id": action.get("id"), "value": action.get("value")}
                for action in rule.get("actions", [])
                if action.get("id") in valid_actions
            ],
            "priority": rule.get("priority", 1),
            "status": rule.get("status", "active"),
            "targets": new_targets
        }

        # Ensure at least one action is included
        if not page_rule_data.get("actions"):
            print("Error: Page rule must include at least one valid action.")
            continue

        # Post the rule to the destination zone
        create_page_rule(zone_id_destination, page_rule_data)

    print("Page rules copy process complete.")

##########################
def list_page_rules(zone_id_source):
    page_rules = get_page_rules(zone_id_source)

    print("\nSource Zone Page Rules:")

    if not page_rules:
        print("No page rules found.")
        return
    
    needs_attention = "All page rules disabled."
    for rule in page_rules:
        status = rule.get("status", "Unknown")
        if status.lower() != "disabled":
            needs_attention = "NOTE: ZONE HAS NON-DISABLED PAGE RULES"
        url = ""
        for target in rule.get("targets", []):
            if target.get("target") == "url":
                url = target.get("constraint", {}).get("value", "Unknown URL")
                break

        print(f"> {status.capitalize()}: {url}")

    print(f"RESULT: {needs_attention}")

##########################
def activate_cloudflare_fonts(zone_id_destination):
    print("\nActivating Cloudflare Fonts in destination...")

    # Make API call to update the fonts setting
    update_response = make_api_call(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/settings/fonts",
        "PATCH",
        {"value": "on"}
    )

    # Check if the update was successful
    if update_response.get("success", False):
        print("Cloudflare Fonts set to: 'on'")
    else:
        print("Error: Unable to update Fonts Settings. Response:")
        print(update_response)

##########################
def activate_early_hints(zone_id_destination):
    print("\nActivating Early Hints in destination...")

    # Make API call to update the Early Hints setting
    update_response = make_api_call(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/settings/early_hints",
        "PATCH",
        {"value": "on"}
    )

    # Check if the update was successful
    if update_response.get("success", False):
        print("Early Hints set to: 'on'")
    else:
        print("Error: Unable to update Early Hints Settings. Response:")
        print(update_response)

##########################
def activate_crawler_hints(zone_id_destination):
    print("\nActivating Crawler Hints in destination...")

    # Define the endpoint and payload for enabling Crawler Hints
    endpoint = f"https://api.cloudflare.com/client/v4/zones/{zone_id_destination}/flags/products/cache/changes"
    payload = {"feature": "crawlhints_enabled", "value": True}

    # Make API call to update the Crawler Hints setting
    update_response = make_api_call(endpoint, "POST", payload)

    # Handle potential None response
    if update_response is None:
        print("Error: No response from API.")
        return

    # Check if the update was successful
    if update_response.get("success", False):
        print("Crawler Hints set to: 'on'")
    else:
        print("Error: Unable to update Crawler Hints Settings. Response:")
        print(update_response)

##########################
def get_zone_settings(zone_id):
    print(f"\nRetrieving settings for zone {zone_id}...")
    response = make_api_call(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings",
        "GET"
    )
    if response and response.get("success"):
        print("Settings retrieved successfully:")
        print(response)
    else:
        print("Error retrieving settings. Response:")
        print(response)

##########################
def activate_smart_tiered_cache(zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/cache/tiered_cache_smart_topology_enable"
    data = {
        "value": "on"
    }

    response = make_api_call(url, "PATCH", data)
    if response and response.get('success'):
        print(f"\nSmart Tiered Caching activated successfully for zone {zone_id}: {response.get('success')}")
    else:
        print(f"\nError activating Smart Tiered Caching for zone {zone_id}. Response:", response)

##########################
def check_smart_tiered_cache(zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/cache/tiered_cache_smart_topology_enable"

    response = make_api_call(url, "GET")
    if response and response.get('success') and response.get('result'):
        print(f"\nSmart Tiered Caching setting for zone {zone_id}: {response.get('result').get('value')}")
    else:
        print(f"\nError activating Smart Tiered Caching for zone {zone_id}. Response:", response)

##########################
def special_feature():
    global zone_id_source, zone_id_destination

    '''
    # Prompt for source and destination zone IDs
    zone_id_source = input("\nEnter Source Zone ID: ").strip()
    if not zone_id_source:
        print("No zone ID entered. Bye.")
        exit(0)
    '''
    zone_id_destination = input("\nEnter Destination Zone ID: ").strip()
    if not zone_id_destination:
        print("No zone ID entered. Bye.")
        exit(0)
    
    # set the function you'd like to call 
    # Activate Smart Tiered Caching
    check_smart_tiered_cache(zone_id_destination)

    print("\nSpecial Feature script complete.")

##########################
def get_bucket_info(account_id, bucket_name):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/r2/buckets/{bucket_name}"
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        bucket_info = response.json()
        if bucket_info.get('success'):
            return bucket_info.get('result')
        else:
            print(f"Error fetching bucket info: {bucket_info['errors']}")
            return None
    else:
        print(f"Error fetching bucket info: {response.status_code}, {response.text}")
        return None

##########################
def list_bucket_objects(bucket_name, bucket_region, access_key_id, secret_access_key):
    s3_client = boto3.client(
        's3',
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        endpoint_url=f"https://{bucket_region}.r2.cloudflarestorage.com",
        config=boto3.session.Config(signature_version='s3v4', retries={'max_attempts': 10}, ssl_verify=False)
    )
    
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            print(f"Objects in bucket '{bucket_name}':")
            for obj in response['Contents']:
                print(f"- {obj['Key']} (Last Modified: {obj['LastModified']}, Size: {obj['Size']} bytes)")
        else:
            print(f"No objects found in bucket '{bucket_name}'.")
    except Exception as e:
        print(f"Error listing objects in bucket '{bucket_name}': {e}")

##########################
def list_r2_buckets():
    bucket_account_id = input("\nEnter Account ID: ").strip()
    if not bucket_account_id:
        print("No zone ID entered. Bye.")
        exit(0)

    url = f"https://api.cloudflare.com/client/v4/accounts/{bucket_account_id}/r2/buckets"
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        
        # Access the correct part of the response structure
        if 'result' in data and 'buckets' in data['result']:
            buckets = data['result']['buckets']
            
            if not buckets:
                print("No R2 buckets found.")
            else:
                print("R2 Buckets:")
                for bucket in buckets:
                    name = bucket.get('name', 'Unknown')
                    print(f"- {name}")
        else:
            print("Unexpected response structure:", data)
    else:
        print(f"Error fetching R2 buckets: {response.status_code}, {response.text}")

    delete_bucket_question = input("\nList items for a bucket [Y/n]: ").strip()
    if delete_bucket_question.lower() != "y":
        print("Operation aborted by the user. Bye.")
        return
     
    delete_bucket_name = input("\nEnter name of bucket to list items: ").strip()
    if not delete_bucket_name:
        print("No bucket name entered. Bye.")
        exit(0)
    
    bucket_info = get_bucket_info(account_id=bucket_account_id, bucket_name=delete_bucket_name)
    if bucket_info:
        list_bucket_objects(
            bucket_name=bucket_info['name'],
            bucket_region=bucket_info['location'].lower(),
            access_key_id=CLOUDFLARE_BOTO_ACCESS_KEY,
            secret_access_key=CLOUDFLARE_BOTO_SECRET_ACCESS_KEY
        )
        
    '''
    # URL for deleting the specified bucket
    delete_url = f"https://api.cloudflare.com/client/v4/accounts/{bucket_account_id}/r2/buckets/{delete_bucket_name}"
    
    delete_response = requests.delete(delete_url, headers=headers)

    # Check the status code for success or failure
    if delete_response.status_code == 200:
        delete_data = delete_response.json()
        if delete_data.get("success"):
            print(f"Bucket '{delete_bucket_name}' deleted successfully.")
        else:
            print(f"Failed to delete bucket '{delete_bucket_name}'. Error: {delete_data.get('errors')}")
    else:
        print(f"Error deleting bucket '{delete_bucket_name}': {delete_response.status_code}, {delete_response.text}")
    '''
        
##########################
def copy_zone_content():

    # List Page Rules
    list_page_rules(zone_id_source)

    # Copy Managed Rules
    transfer_managed_rules(zone_id_source, zone_id_destination)

    # Copy rulesets (phase: http_request_cache_settings)
    transfer_ruleset("http_request_cache_settings", zone_id_source, zone_id_destination)

    # Copy rulesets (phase: http_request_transform)
    transfer_ruleset("http_request_transform", zone_id_source, zone_id_destination)

    # Copy rulesets (phase: http_request_firewall_custom)
    transfer_ruleset("http_request_firewall_custom", zone_id_source, zone_id_destination)

    # Copy rulesets (phase: http_response_headers_transform)
    transfer_ruleset("http_response_headers_transform", zone_id_source, zone_id_destination)

    # Copy Redirect Rules
    transfer_ruleset("http_request_dynamic_redirect", zone_id_source, zone_id_destination)

    # Activate Cloudflare fonts
    activate_cloudflare_fonts(zone_id_destination)

    # Activate Early Hints
    activate_early_hints(zone_id_destination)

    # Activate Crawler Hints
    activate_crawler_hints(zone_id_destination)

    # Activate Smart Tiered Caching
    activate_smart_tiered_cache(zone_id_destination)

##########################
def zone_clone():
    global domain_temp

    # Verify API token
    verify_api_token()

    # Prompt for temporary domain creation if domain_temp is not already set
    if domain_temp:
        print("Creating the new Zone using a temporary domain name.")

    # Execute the domain creation
    do_zone_create()

    # Copy DNS Records
    do_zone_dns_copy()

    # copy all the contents
    copy_zone_content()

##########################
def zone_copy():
    global zone_id_source, zone_id_destination, destination_account_id

    # Source Domain prompt
    source_domain = input(f"\nThis script copies settings from one Zone to another. \n\nEnter source domain: ")
    if not source_domain:
        print("No domain entered. Bye.")
        return

    print(f"Searching for: {source_domain}")

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={source_domain}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count > 1:
        print(f"Error: More than one zone found for {source_domain}. Bye.")
        exit(0)
    if result_count < 1:
        print(f"Error: Zone not found for {source_domain}. Bye.")
        exit(0)

    # Extract Account ID
    source_zone_name = search_results['result'][0]['name']
    zone_id_source = search_results['result'][0]['id']
    source_zone_name_servers = search_results['result'][0]['name_servers']
    account_id = search_results['result'][0]['account']['id']
    account_name = search_results['result'][0]['account']['name']
    print(f"Found Source Zone {source_zone_name} (ID: {zone_id_source})\nNameservers: {source_zone_name_servers} \nAccount: {account_name} (ID: {account_id})")

    # Destination Domain prompt
    destination_domain = input(f"\nEnter destination domain: ")
    if not destination_domain:
        print("No domain entered. Bye.")
        return

    print(f"Searching for: {destination_domain}")

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={destination_domain}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count > 1:
        print(f"Error: More than one zone found for {destination_domain}. Bye.")
        exit(0)
    if result_count < 1:
        print(f"Error: Zone not found for {destination_domain}. Bye.")
        exit(0)

    # Extract Account ID
    destination_zone_name = search_results['result'][0]['name']
    zone_id_destination = search_results['result'][0]['id']
    destination_zone_name_servers = search_results['result'][0]['name_servers']
    destination_account_id = search_results['result'][0]['account']['id']
    destination_account_name = search_results['result'][0]['account']['name']
    print(f"Found Destination Zone {destination_zone_name} (ID: {zone_id_destination})\nNameservers: {destination_zone_name_servers} \nAccount: {destination_account_name} (ID: {destination_account_id})")

    # User Confirmation to Proceed
    user_confirmation = input(f"\nPlease confirm copy of zone settings (excl. DNS): \nFrom: {source_domain} (ID: {zone_id_source}) \nTo: {destination_domain} (ID: {zone_id_destination}). \nProceed with transferring the zone? (Y/n) ")
    if user_confirmation.lower() != "y":
        print("Operation aborted by the user. Bye.")
        return

    # Copy the domain contents (excl. DNS records!)
    copy_zone_content()

##########################
def print_large_text(text):
    letters = {
        'P': ['████', '█  █', '████', '█   ', '█   '],
        'R': ['████', '█  █', '████', '█ █ ', '█  █'],
        'I': ['███', ' █ ', ' █ ', ' █ ', '███'],
        'M': ['█   █', '██ ██', '█ █ █', '█   █', '█   █'],
        'E': ['████', '█   ', '███ ', '█   ', '████'],
        'S': [' ███', '█   ', ' ██ ', '   █', '███ '],
        'T': ['█████', '  █  ', '  █  ', '  █  ', '  █  '],
    }
    
    for i in range(5):
        for char in text.upper():
            if char in letters:
                print(letters[char][i], end='  ')
            else:
                print('     ', end='  ')
        print()

##########################
def main_loop():
    global domain_temp

    #print_large_text("PrimeSites")
    print("\n#######################################")
    print("\n Cloudflare Zone Manager by PrimeSites ")
    print("\n#######################################")
    print("\nSelect an option:\n")

    print("1] Zone Clone:")
    print("   - Clone existing zone to a new zone of the same name in the CFA account")
    print("2] Zone Clone (Temporary):")
    print("   - Clone existing zone to a temporary zone of (almost) the same name in the CFA account")
    print("3] Zone Copy:")
    print("   - Copy settings (excl. DNS records) from one zone to another")
    print("4] List R2 Buckets")
    print("   - Output all existing R2 buckets")
    print("5] Special Feature")
    print("   - Testing ground for individual functions")
    print("6] Exit")

    user_input = input("\nEnter number & return: ")

    if user_input == "1":
        zone_clone()
    elif user_input == "2":
        domain_temp = True
        zone_clone()
    elif user_input == "3":
        zone_copy()
    elif user_input == "4":
        list_r2_buckets()
    elif user_input == "5":
        special_feature()
    elif user_input == "6":
        print("\nScript shutting down. Bye.\n")
        exit(0)
    else:
        print("\nNo valid option selected. Bye.\n")
        exit(0)

    print("\nScript completed successfully.\n")

if __name__ == "__main__":
    main_loop()
