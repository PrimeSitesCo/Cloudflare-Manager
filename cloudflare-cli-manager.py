import sys
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

zone_id_source = ""
zone_id_destination = ""
domain_temp = False

##########################
def make_api_call(url, method, data=None, retries=3, delay=5):
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    for attempt in range(retries):
        response = requests.request(method, url, headers=headers, json=data)
        if response.status_code in [200, 201]:
            return response.json()
        elif response.status_code in [502, 503, 504]:
            print(f"API call failed with status code {response.status_code}. Retrying in {delay} seconds...")
            time.sleep(delay)
        else:
            print(f"API call failed with status code {response.status_code}: {response.text}")
            return None
    print(f"API call failed after {retries} attempts.")
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
def add_port_firewall_rule_to_zone():

    if len(sys.argv) > 2:
        domain_name = sys.argv[2]
    else:
        domain_name = input("Enter Zone Domain Name: ").strip()

    if not domain_name:
        print("No domain name entered. Bye.")
        return

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={domain_name}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count != 1:
        print(f"Error: Zone not found or multiple zones found for {domain_name}. Bye.")
        return

    zone_id = search_results['result'][0]['id']

    # Retrieve existing WAF rules to determine the highest priority
    existing_rules_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "GET")
    if not existing_rules_response or not existing_rules_response.get("success"):
        print(f"Error retrieving existing WAF rules for {domain_name}. Response: {existing_rules_response}")
        return

    existing_rules = existing_rules_response.get("result", [])
    highest_priority = max([rule.get("priority", 0) for rule in existing_rules if "priority" in rule], default=0)

    # Define the new WAF rule with a priority higher than the highest existing priority
    waf_rule_data = {
        "description": "80 443",
        "filter": {
            "expression": "not (cf.edge.server_port in {80 443})",
            "paused": False
        },
        "action": "block",
        "priority": highest_priority + 1,  # Set a priority value higher than the highest existing priority
        "paused": False
    }

    # Add the new WAF rule
    response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "POST", [waf_rule_data])

    if response and response.get("success"):
        print(f"Successfully added WAF rule to block requests if port is not in [80, 443] for domain {domain_name}.")
        
        # Retrieve all rules again to reorder them
        all_rules_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "GET")
        if not all_rules_response or not all_rules_response.get("success"):
            print(f"Error retrieving all WAF rules for reordering. Response: {all_rules_response}")
            return

        all_rules = all_rules_response.get("result", [])
        # Sort rules by priority, providing a default value if 'priority' is missing
        all_rules_sorted = sorted(all_rules, key=lambda x: x.get('priority', 0))
        
        # Reassign priorities to ensure the new rule is last
        for i, rule in enumerate(all_rules_sorted):
            rule['priority'] = i + 1

        # Update the rules with new priorities
        update_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "PUT", all_rules_sorted)
        if update_response and update_response.get("success"):
            print(f"Successfully reordered WAF rules for domain {domain_name}.")
        else:
            print(f"Error reordering WAF rules. Response: {update_response}")
    else:
        print(f"Error adding WAF rule. Response: {response}")

##########################
def check_wordfence_rule_for_domain(domain_name):
    print(f"\nChecking for 'Wordfence' WAF custom rules in domain: {domain_name}...")

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={domain_name}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count != 1:
        print(f"Error: Zone not found or multiple zones found for {domain_name}. Bye.")
        return

    zone_id = search_results['result'][0]['id']
    zone_name = search_results['result'][0]['name']

    # Retrieve WAF custom rules for the zone
    waf_rules_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "GET")

    if not waf_rules_response or not waf_rules_response.get("success"):
        print(f"Error retrieving WAF custom rules for {zone_name}. Response: {waf_rules_response}")
        return

    waf_rules = waf_rules_response.get("result", [])

    # Check if any rule contains "Wordfence" in the title
    wordfence_rules = [rule for rule in waf_rules if "Wordfence" in rule.get("description", "")]

    if wordfence_rules:
        print(f"Domain {zone_name} has the following custom WAF rules containing 'Wordfence' in the title:")
        for rule in wordfence_rules:
            print(f"- {rule.get('description', 'No description')}")
    else:
        print(f"No custom WAF rules containing 'Wordfence' in the title found for domain {zone_name}.")

##########################
def check_zones_for_rule_per_page(rule_name):
    
    print(f"\nChecking zones for custom WAF rules containing '{rule_name}' in the title and NOT containing '443'...")

    zones = get_all_zones(page=1, per_page=1000)
    matching_zones_count = 0

    for zone in zones:
        zone_id = zone.get("id")
        zone_name = zone.get("name")

        # Retrieve WAF custom rules for the zone
        waf_rules_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules", "GET")

        if not waf_rules_response or not waf_rules_response.get("success"):
            print(f"Error retrieving WAF custom rules for {zone_name}. Response: {waf_rules_response}")
            continue

        waf_rules = waf_rules_response.get("result", [])

        # Check if any rule contains the specified rule name string in the title
        matching_rules = [rule for rule in waf_rules if rule_name in rule.get("description", "")]
        contains_443_rule = any("443" in rule.get("description", "") for rule in waf_rules)

        if matching_rules:
            matching_zones_count += 1
            if not contains_443_rule:
                print(f"\nDomain: {zone_name}")
                for rule in matching_rules:
                    print(f"- {rule.get('description', 'No description')}")

    print(f"\nFinished checking zones for custom WAF rules containing '{rule_name}' in the title and not containing '443'.")
    print(f"Number of zones with custom WAF rules containing '{rule_name}': {matching_zones_count}")

##########################
def special_feature():
    global zone_id_source, zone_id_destination

    # Verify API token
    verify_api_token()

    # Prompt for source and destination zone IDs
    '''
    zone_id_source = input("\nEnter Source Zone ID: ").strip()
    if not zone_id_source:
        print("No zone ID entered. Bye.")
        exit(0)
    '''
    # Prompt for Zone ID
    '''
    zone_id_destination = input("\nEnter Destination Zone ID: ").strip()
    if not zone_id_destination:
        print("No zone ID entered. Bye.")
        exit(0)
    '''
    # Prompt for a single domain name
    ''' 
    domain_name = input("\nEnter the domain name to check for 'Wordfence' WAF custom rules: ").strip()
    if not domain_name:
        print("No domain name entered. Bye.")
        exit(0)
    '''
    # Prompt for the rule name string
    rule_name = input("\nEnter the rule name string to search for: ").strip()
    if not rule_name:
        print("No rule name string entered. Bye.")
        exit(0)

    # Check the first 10 zones for the specified rule name string
    check_zones_for_rule_per_page(rule_name)

    # set the function you'd like to call 
    # Activate Smart Tiered Caching
    #check_smart_tiered_cache(zone_id_destination)
    # Check for Edge TTL settings
    #check_edge_ttl_for_zone(zone_id_destination)

    # Troubleshooting: Output env vars to console
    #print(f"{BEARER_TOKEN} \n{destination_account_id} \n{CLOUDFLARE_BOTO_ACCESS_KEY} \n{CLOUDFLARE_BOTO_SECRET_ACCESS_KEY}")

    # Check for 'Wordfence' WAF custom rules in the specified domain
    #check_wordfence_rule_for_domain(domain_name)

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
def check_edge_ttl_for_zone(zone_id):
    # Retrieve cache rulesets for the zone
    rulesets_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets?phase=http_request_cache_settings", "GET")

    if not rulesets_response or not rulesets_response.get("success"):
        return None

    rulesets = rulesets_response.get("result", [])

    for ruleset in rulesets:
        # Skip rulesets that are likely to produce errors
        if ruleset.get("phase") not in ["http_request_cache_settings"]:
            continue

        # Fetch the details of each ruleset
        ruleset_id = ruleset.get("id")
        ruleset_details_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}", "GET")

        if not ruleset_details_response or not ruleset_details_response.get("success"):
            continue

        ruleset_details = ruleset_details_response.get("result", {})

        for rule in ruleset_details.get("rules", []):
            action = rule.get("action")
            if action == "set_cache_settings" and "edge_ttl" in rule.get("action_parameters", {}):
                return rule.get("description", "Unnamed Rule")

    return None

##########################
def get_all_zones(page=None, per_page=50):
    zones = []
    if page is not None:
        # Fetch a specific page of zones
        response = make_api_call(f"https://api.cloudflare.com/client/v4/zones?page={page}&per_page={per_page}", "GET")
        if not response or not response.get("success"):
            print("Error retrieving zones.")
            print(response)  # Debug print
            return zones
        zones.extend(response.get("result", []))
    else:
        # Fetch all zones in a paginated manner
        current_page = 1
        while True:
            response = make_api_call(f"https://api.cloudflare.com/client/v4/zones?page={current_page}&per_page={per_page}", "GET")
            if not response or not response.get("success"):
                print("Error retrieving zones.")
                print(response)  # Debug print
                break
            zones.extend(response.get("result", []))
            if len(response.get("result", [])) < per_page:
                break  # No more pages
            current_page += 1
    return zones

##########################
def check_edge_ttl_in_cache_rules():
    choice = input("Do you want to check Cache Rules Edge TTL setting for all zones or a single domain? (all/single): ").strip().lower()

    if choice == "single":
        zone_id = input("Enter Zone ID: ").strip()
        if not zone_id:
            print("No zone ID entered. Bye.")
            return

        edge_ttl_rule_name = check_edge_ttl_for_zone(zone_id)
        if edge_ttl_rule_name:
            print(f"Zone ID {zone_id} - Active Edge TTL setting: {edge_ttl_rule_name}")
        else:
            print(f"Zone ID {zone_id} - No Edge TTL rule")
    elif choice == "all":
        print("Checking for Edge TTL setting in Cache Rules...")

        zones = get_all_zones()
        print(f"Found {len(zones)} zones.")
        
        active_edge_ttl_count = 0
        for zone in zones:
            zone_id = zone.get("id")
            zone_name = zone.get("name")

            edge_ttl_rule_name = check_edge_ttl_for_zone(zone_id)
            if edge_ttl_rule_name:
                print(f"{zone_name} - Active Edge TTL setting: {edge_ttl_rule_name}")
                active_edge_ttl_count += 1
            else:
                print(zone_name)
        
        print(f"\nTotal zones with active Edge TTL setting: {active_edge_ttl_count}")
    else:
        print("Invalid choice. Please enter 'all' or 'single'.")

##########################

def list_cache_rules_for_zone(zone_id):
    # Retrieve cache rulesets for the zone
    rulesets_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets?phase=http_request_cache_settings", "GET")

    if not rulesets_response or not rulesets_response.get("success"):
        print("Error retrieving rulesets.")
        return

    rulesets = rulesets_response.get("result", [])

    for ruleset in rulesets:
        # Skip rulesets that are likely to produce errors
        if ruleset.get("phase") not in ["http_request_cache_settings"]:
            continue

        # Fetch the details of each ruleset
        ruleset_id = ruleset.get("id")
        ruleset_details_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}", "GET")

        if not ruleset_details_response or not ruleset_details_response.get("success"):
            print(f"Error retrieving details for ruleset {ruleset_id}.")
            continue

        ruleset_details = ruleset_details_response.get("result", {})
        print(f"Ruleset: {ruleset_details.get('name', 'Unnamed Ruleset')}")

        for rule in ruleset_details.get("rules", []):
            print(f" - Rule: {rule.get('description', 'Unnamed Rule')}")

##########################
def fetch_ruleset_details(zone_id, ruleset_id):
    return make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}", "GET")

def list_cache_rules_for_all_zones(rule_name):
    zones = get_all_zones()
    print(f"Found {len(zones)} zones.")

    matching_zones = []

    for zone in zones:
        zone_id = zone.get("id")
        zone_name = zone.get("name")

        rulesets_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets?phase=http_request_cache_settings", "GET")

        if not rulesets_response or not rulesets_response.get("success"):
            continue

        rulesets = rulesets_response.get("result", [])

        for ruleset in rulesets:
            # Fetch the details of each ruleset
            ruleset_id = ruleset.get("id")
            ruleset_details_response = fetch_ruleset_details(zone_id, ruleset_id)

            if not ruleset_details_response or not ruleset_details_response.get("success"):
                continue

            ruleset_details = ruleset_details_response.get("result", {})
            rules = ruleset_details.get("rules", [])

            # Check if any rule contains the entered Cache Rule name
            for rule in rules:
                if rule_name.lower() in rule.get("description", "").lower():
                    matching_zones.append(zone_name)
                    break

    if matching_zones:
        print("Zones with matching cache rules:")
        for zone in matching_zones:
            print(f"- {zone}")
    else:
        print("No zones found with matching cache rules.")

##########################
def add_no_cache_rule(zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "name": "No Cache",
        "description": "No Cache",
        "kind": "zone",
        "phase": "http_request_cache_settings",
        "rules": [
            {
                "action": "set_cache_settings",
                "description": "No Cache",
                "expression": "true",
                "enabled": True,
                "action_parameters": {
                    "cache": False
                }
            }
        ]
    }

    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        print(f"Successfully added 'No Cache' rule to zone ID {zone_id}.")
    else:
        print(f"Error adding 'No Cache' rule: {response.status_code}, {response.text}")

##########################
def add_no_cache_rule_to_existing_ruleset(zone_id):
    # Retrieve existing rulesets for the zone
    rulesets_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets?phase=http_request_cache_settings", "GET")

    if not rulesets_response or not rulesets_response.get("success"):
        print(f"Error retrieving rulesets: {rulesets_response.get('errors')}")
        return

    rulesets = rulesets_response.get("result", [])
    if not rulesets:
        print("No existing rulesets found for the specified phase.")
        return

    # Use the first ruleset found
    ruleset_id = rulesets[0].get("id")
    ruleset_details_response = make_api_call(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}", "GET")

    if not ruleset_details_response or not ruleset_details_response.get("success"):
        print(f"Error retrieving ruleset details: {ruleset_details_response.get('errors')}")
        return

    ruleset_details = ruleset_details_response.get("result", {})
    rules = ruleset_details.get("rules", [])

    # Add the "No Cache" rule at the first position
    no_cache_rule = {
        "action": "set_cache_settings",
        "description": "No Cache",
        "expression": "true",
        "enabled": True,
        "action_parameters": {
            "bypass_cache": True
        }
    }
    rules.insert(0, no_cache_rule)

    # Update the ruleset with the new rule
    update_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "rules": rules
    }

    response = requests.put(update_url, headers=headers, json=data)

    if response.status_code == 200:
        print(f"Successfully added 'No Cache' rule to zone ID {zone_id}.")
    else:
        print(f"Error adding 'No Cache' rule: {response.status_code}, {response.text}")

##########################
def add_no_cache_rule_to_zone():
    zone_name = input("Enter Zone Domain Name: ").strip()
    if not zone_name:
        print("No domain name entered. Bye.")
        return

    # Search for the Domain Across All Zones
    search_results = make_api_call(f"https://api.cloudflare.com/client/v4/zones?name={zone_name}", "GET")

    # Process Search Results
    result_count = len(search_results.get('result', []))
    if result_count != 1:
        print(f"Error: Zone not found or multiple zones found for {zone_name}. Bye.")
        return

    zone_id = search_results['result'][0]['id']
    add_no_cache_rule_to_existing_ruleset(zone_id)

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

    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
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
        print("6] Check for Edge TTL setting in Cache Rules")
        print("   - Check all zones for Edge TTL setting in Cache Rules")
        print("7] List Cache Rules for a Zone")
        print("   - List the names of Cache Rules for a specific zone or all zones with a specific rule")
        print("8] Add 'No Cache' Rule to a Zone")
        print("   - Add a 'No Cache' rule to a specific zone")
        print("9] Add Port Firewall rule to a Zone")
        print("   - Add WAF Rule to Zone to Block if Port is not in [80 443]")
        print("10] Exit")

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
        check_edge_ttl_in_cache_rules()
    elif user_input == "7":
        choice = input("Do you want to list Cache Rules for all zones or a single domain? (all/single): ").strip().lower()
        if choice == "single":
            zone_id = input("Enter Zone ID: ").strip()
            if not zone_id:
                print("No zone ID entered. Bye.")
            else:
                list_cache_rules_for_zone(zone_id)
        elif choice == "all":
            rule_name = input("Enter Cache Rule name to look for: ").strip()
            if not rule_name:
                print("No rule name entered. Bye.")
            else:
                list_cache_rules_for_all_zones(rule_name)
        else:
            print("Invalid choice. Please enter 'all' or 'single'.")
    elif user_input == "8":
        add_no_cache_rule_to_zone()
    elif user_input == "9":
        add_port_firewall_rule_to_zone()
    elif user_input == "10":
        print("\nScript shutting down. Bye.\n")
        exit(0)
    else:
        print("\nNo valid option selected. Bye.\n")
        exit(0)

    print("\nScript completed successfully.\n")

if __name__ == "__main__":
    main_loop()
