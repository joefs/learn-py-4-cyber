"""
====================================================================
MODULE 5: LISTS - Managing Collections of Security Data 📋
====================================================================

Welcome to Module 5! You've been using lists in previous modules, but now
you'll master them completely. Lists are essential for cybersecurity work
because you're always dealing with collections: IP addresses, user accounts,
security alerts, port numbers, and more.

WHAT ARE LISTS?
Lists are ordered collections that can store multiple items. Think of them
as containers that hold related data together, like a list of authorized
users or a collection of suspicious IP addresses.

LIST OPERATIONS WE'LL COVER:
- Creating and accessing lists
- Adding and removing items
- Searching and sorting lists
- List slicing and manipulation
- Common list methods for security work
"""

# ============================================================================
# CONCEPT EXPLANATION: Creating and Accessing Lists
# ============================================================================

# Creating lists
authorized_users = ["admin", "securityteam", "manager", "analyst"]
open_ports = [22, 80, 443, 8080]
mixed_data = ["server1", 192, True, "active"]
empty_list = []

print("List Examples:")
print(f"Authorized users: {authorized_users}")
print(f"Open ports: {open_ports}")
print(f"Mixed data: {mixed_data}")
print(f"Empty list: {empty_list}")

# Accessing list items (indexing starts at 0)
print("\nAccessing List Items:") # Added newline for clarity
print(f"First user: {authorized_users[0]}")
print(f"Second user: {authorized_users[1]}")
print(f"Last user: {authorized_users[-1]}")  # Negative indexing
print(f"Second to last user: {authorized_users[-2]}")

# List length
print(f"\nNumber of authorized users: {len(authorized_users)}") # Added newline
print(f"Number of open ports: {len(open_ports)}")

# ============================================================================
# CONCEPT EXPLANATION: Adding and Removing Items
# ============================================================================

# Starting with a list of blocked IPs
blocked_ips = ["203.0.113.42", "198.51.100.1"]
print(f"\nInitial blocked IPs: {blocked_ips}") # Added newline

# Adding items
blocked_ips.append("192.0.2.146")  # Add to end
print(f"After append: {blocked_ips}")

blocked_ips.insert(1, "10.0.0.255")  # Insert at specific position
print(f"After insert: {blocked_ips}")

# Adding multiple items
new_threats = ["172.16.0.100", "192.168.1.200"]
blocked_ips.extend(new_threats)
print(f"After extend: {blocked_ips}")

# Removing items
print("\nRemoving items:") # Added newline
removed_ip = blocked_ips.pop()  # Remove and return last item
print(f"Removed last IP: {removed_ip}")
print(f"List after pop: {blocked_ips}")

blocked_ips.remove("10.0.0.255")  # Remove specific item
print(f"After removing specific IP: {blocked_ips}")

del blocked_ips[0]  # Delete by index
print(f"After deleting first item: {blocked_ips}")

# ============================================================================
# CONCEPT EXPLANATION: Searching and Sorting
# ============================================================================

# Searching in lists
security_tools = ["nmap", "wireshark", "metasploit", "burpsuite", "nessus"]
print(f"\nSecurity tools: {security_tools}") # Added newline

# Check if item exists
tool_to_find = "wireshark"
if tool_to_find in security_tools:
    print(f"✅ {tool_to_find} is available")
    position = security_tools.index(tool_to_find)
    print(f"Position of {tool_to_find}: {position}")
else:
    print(f"❌ {tool_to_find} not found")

# Counting occurrences
log_levels = ["INFO", "WARNING", "ERROR", "INFO", "CRITICAL", "INFO", "ERROR"]
print(f"\nLog levels: {log_levels}") # Added newline
print(f"INFO messages: {log_levels.count('INFO')}")
print(f"ERROR messages: {log_levels.count('ERROR')}")

# Sorting lists
vulnerability_scores_conceptual = [7.5, 9.2, 4.1, 8.8, 6.3, 9.9, 2.1] # Renamed for clarity
print(f"\nOriginal vulnerability scores: {vulnerability_scores_conceptual}") # Added newline

sorted_scores = sorted(vulnerability_scores_conceptual)  # Create new sorted list
print(f"Sorted scores (ascending): {sorted_scores}")

sorted_scores_desc = sorted(vulnerability_scores_conceptual, reverse=True)
print(f"Sorted scores (descending): {sorted_scores_desc}")

vulnerability_scores_conceptual.sort(reverse=True)  # Sort in place
print(f"Original list after in-place sort: {vulnerability_scores_conceptual}")

# ============================================================================
# CONCEPT EXPLANATION: List Slicing
# ============================================================================

# Working with network addresses
network_devices_conceptual = ["router", "switch", "firewall", "server", "workstation", "printer", "camera"] # Renamed
print(f"\nAll devices: {network_devices_conceptual}") # Added newline

# Slicing syntax: list[start:end:step]
print(f"First 3 devices: {network_devices_conceptual[:3]}")
print(f"Last 3 devices: {network_devices_conceptual[-3:]}")
print(f"Middle devices: {network_devices_conceptual[2:5]}")
print(f"Every other device: {network_devices_conceptual[::2]}")
print(f"Reversed list: {network_devices_conceptual[::-1]}")

# ============================================================================
# CONCEPT EXPLANATION: List Comprehensions (Advanced)
# ============================================================================

# Creating new lists based on existing ones
port_numbers = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995]
print(f"\nAll ports: {port_numbers}") # Added newline

# Find high-numbered ports (> 1000)
high_ports = [port for port in port_numbers if port > 1000]
print(f"High ports (>1000): {high_ports}")

# Convert to strings with descriptions
port_descriptions = [f"Port {port}" for port in port_numbers[:5]]
print(f"Port descriptions: {port_descriptions}")

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF LISTS:

1. IP ADDRESS MANAGEMENT:
   - Whitelist: authorized IP addresses
   - Blacklist: known malicious IP addresses
   - Subnet ranges: network segments to monitor
   - DHCP pools: assigned IP addresses

2. USER AND ACCESS MANAGEMENT:
   - User accounts: active, inactive, privileged users
   - Role assignments: admin, user, guest permissions
   - Access logs: login attempts, successful/failed authentications
   - Password policies: complexity requirements, history

3. SECURITY MONITORING:
   - Alert types: critical, high, medium, low priority
   - Event logs: security incidents, system events
   - Threat indicators: IOCs (Indicators of Compromise)
   - Vulnerability lists: CVE numbers, CVSS scores

4. NETWORK SECURITY:
   - Open ports: services running on systems
   - Blocked ports: restricted network access
   - Protocol monitoring: HTTP, HTTPS, SSH, FTP traffic
   - Firewall rules: allow/deny lists

5. INCIDENT RESPONSE:
   - Affected systems: compromised hosts and services
   - Evidence collection: files, logs, network captures
   - Response team: assigned personnel and roles
   - Timeline events: chronological incident details

6. CONFIGURATION MANAGEMENT:
   - Security tools: installed and configured applications
   - Policy settings: security configurations and standards
   - Patch levels: installed updates and missing patches
   - Backup schedules: data protection and recovery plans
"""

# Security incident management
incident_priorities = ["Low", "Medium", "High", "Critical"]
active_incidents = [
    "Phishing attempt from external email",
    "Suspicious login from foreign IP",
    "Malware detected on workstation-42",
    "Unauthorized access to admin panel"
]

print("\nCurrent Security Incidents:") # Added newline
for i, incident in enumerate(active_incidents):
    priority = incident_priorities[min(i, len(incident_priorities)-1)]
    print(f"[{priority}] {incident}")

# Network asset management
critical_servers = ["web-server", "database-server", "mail-server", "backup-server"]
server_status_list = [] # Renamed from server_status to avoid conflict

print("\nServer Status Check:") # Added newline
for server in critical_servers:
    # Simulate status check (in real scenario, this would ping or query the server)
    import random # Fine for conceptual example
    status = "ONLINE" if random.choice([True, False]) else "OFFLINE"
    server_status_list.append(status)
    print(f"{server}: {status}")

offline_servers = [critical_servers[i] for i in range(len(critical_servers)) if server_status_list[i] == "OFFLINE"]
if offline_servers:
    print(f"⚠️  Servers requiring attention: {offline_servers}")
else:
    print("✅ All critical servers are online")

# ============================================================================
# WARM-UP EXERCISES: Practice Using Lists
# ============================================================================

# Exercise 1: Create and print a simple list
"""
PRACTICE: Basic List Creation

Write a function `create_device_inventory()` that creates a list `devices`
with three items: "firewall", "router", "switch".
The function should return a tuple containing the list and its length.
Example: (["firewall", "router", "switch"], 3)
"""
# TODO: Implement the function create_device_inventory
def create_device_inventory():
    pass


# Exercise 2: Add item to list
"""
PRACTICE: Adding to Lists

Write a function `add_network_operator(user_list)` that takes a list of users.
It should add "operator" to the end of `user_list` using append().
The function should return the modified list.
Example: add_network_operator(["admin", "guest"]) should return ["admin", "guest", "operator"]
"""
# TODO: Implement the function add_network_operator
def add_network_operator(user_list):
    pass


# Exercise 3: Remove item from list
"""
PRACTICE: Removing from Lists

Write a function `decommission_service(service_list, service_to_remove)`
that takes a list of services and a service string to remove.
It should remove the `service_to_remove` from the `service_list` using remove().
If the service is not in the list, the list should remain unchanged.
The function should return the modified list.
Example: decommission_service(["web", "mail", "test"], "test") should return ["web", "mail"]
"""
# TODO: Implement the function decommission_service
def decommission_service(service_list, service_to_remove):
    pass


# Exercise 4: Check if item exists in list
"""
PRACTICE: Checking List Membership

Write a function `is_port_allowed(allowed_ports_list, port_to_check)`
that takes a list of allowed ports and a port number to check.
It should return True if `port_to_check` is in `allowed_ports_list`, and False otherwise.
Example: is_port_allowed([22, 80, 443], 22) should return True
"""
# TODO: Implement the function is_port_allowed
def is_port_allowed(allowed_ports_list, port_to_check):
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Asset Management System
# ============================================================================
"""
SECURITY ASSET MANAGEMENT SYSTEM

You are building a comprehensive security asset management system for your organization.
The system needs to track network devices, user accounts, security alerts, and
vulnerability assessments. You will perform a series of operations and store the
final results in specified variables.

TASK 1: NETWORK INFRASTRUCTURE TRACKING
Initial devices: ["firewall", "router", "switch", "server"]
Operations:
1. Add "intrusion_detection_system" to the end.
2. Insert "load_balancer" at index 2 (to be between "router" and "switch").
Store the final list in `final_network_devices` and its length in `final_device_count`.

TASK 2: USER ACCOUNT MANAGEMENT
Initial accounts: ["admin", "user1", "user2", "guest"]
Operations:
1. Remove "guest".
2. Add "analyst" and "manager" to the list.
Store the final list in `final_user_accounts`.
Create a boolean variable `is_admin_in_final_list` checking if "admin" is present.

TASK 3: SECURITY ALERT TRACKING
Initial alerts (strings):
- "Failed login attempt from IP address 203.0.113.42"
- "High CPU usage detected on server-01"
- "Suspicious file detected in downloads folder"
- "Firewall rule violation from internal network"
Operations:
1. Create an empty list `security_alerts_log`. Add all four initial alerts to it.
2. Create a list `formatted_initial_alerts` where each alert is prefixed by its 1-based index
   (e.g., "1: Failed login...").
3. Remove the first alert from `security_alerts_log` and store its value in `removed_alert_content`.
4. Create `formatted_remaining_alerts` similar to `formatted_initial_alerts` but for the
   updated `security_alerts_log`.

TASK 4: VULNERABILITY ASSESSMENT
Initial scores: [8.5, 6.2, 9.1, 4.3, 7.8]
Store these in `vulnerability_scores_list`.
Operations:
1. Create `sorted_vulnerability_scores` by sorting `vulnerability_scores_list` in descending order.
   (The original `vulnerability_scores_list` can be modified or a new list created).
2. Create `high_severity_vulns_list` containing scores from `sorted_vulnerability_scores` that are > 7.0.
3. Calculate the average of the original scores and store it in `average_vuln_score`.
   If the list is empty, the average should be 0.0.

TASK 5: SECURITY DASHBOARD SUMMARY DATA
Prepare these variables based on the final states from above tasks:
- `dashboard_total_devices`: (int) from `final_device_count`
- `dashboard_total_users`: (int) length of `final_user_accounts`
- `dashboard_active_alerts`: (int) length of the updated `security_alerts_log` (after removal)
- `dashboard_highest_vulnerability`: (float) the highest score from `sorted_vulnerability_scores`
                                       (or 0.0 if the list was empty).
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Network Infrastructure Tracking
# TODO: Initialize network_devices and perform operations
# final_network_devices = ?
# final_device_count = ?


# PART 2: User Account Management
# TODO: Initialize user_accounts, perform operations, check for admin
# final_user_accounts = ?
# is_admin_in_final_list = ?


# PART 3: Security Alert Tracking
# TODO: Initialize security_alerts_log, add alerts, format, remove, reformat
# security_alerts_log = ?
# formatted_initial_alerts = ?
# removed_alert_content = ?
# formatted_remaining_alerts = ?


# PART 4: Vulnerability Assessment
# TODO: Initialize vulnerability_scores_list, sort, filter, calculate average
# vulnerability_scores_list = ?
# sorted_vulnerability_scores = ?
# high_severity_vulns_list = ?
# average_vuln_score = ?


# PART 5: Security Dashboard Summary Data
# TODO: Calculate dashboard summary data points
# dashboard_total_devices = ?
# dashboard_total_users = ?
# dashboard_active_alerts = ?
# dashboard_highest_vulnerability = ?


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_lists():
    """Tests for the warm-up list functions."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0
    # Test 1
    try:
        devices, length = create_device_inventory()
        assert devices == ["firewall", "router", "switch"], "Warm-up 1: Device list incorrect"
        assert length == 3, "Warm-up 1: Device length incorrect"
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except (NameError, AssertionError, TypeError) as e: print(f"❌ Warm-up 1 FAILED: {e}")
    # Test 2
    try:
        assert add_network_operator(["admin", "guest"]) == ["admin", "guest", "operator"], "Warm-up 2: Add operator failed"
        assert add_network_operator([]) == ["operator"], "Warm-up 2: Add operator to empty list failed"
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except (NameError, AssertionError, TypeError) as e: print(f"❌ Warm-up 2 FAILED: {e}")
    # Test 3
    try:
        assert decommission_service(["web", "mail", "test", "dns"], "test") == ["web", "mail", "dns"], "Warm-up 3: Remove 'test' failed"
        assert decommission_service(["web", "mail"], "ftp") == ["web", "mail"], "Warm-up 3: Remove non-existent failed"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except (NameError, AssertionError, TypeError) as e: print(f"❌ Warm-up 3 FAILED: {e}")
    # Test 4
    try:
        assert is_port_allowed([22, 80, 443], 22) is True, "Warm-up 4: Port 22 check failed"
        assert is_port_allowed([22, 80, 443], 21) is False, "Warm-up 4: Port 21 check failed"
        print("✅ Warm-up 4 PASSED")
        passed_count += 1
    except (NameError, AssertionError, TypeError) as e: print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_exercise_asset_management():
    """Test function to verify your main exercise list operations are correct."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # TASK 1 Tests
    try:
        expected_devices = ["firewall", "router", "load_balancer", "switch", "server", "intrusion_detection_system"]
        assert final_network_devices == expected_devices, f"TASK 1: final_network_devices incorrect. Expected {expected_devices}, got {final_network_devices}"
        assert final_device_count == len(expected_devices), f"TASK 1: final_device_count incorrect. Expected {len(expected_devices)}, got {final_device_count}"
        print("✅ TASK 1 (Network Devices): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 1 (Network Devices): FAILED - {e}")
        main_passed = False

    # TASK 2 Tests
    try:
        expected_users = ["admin", "user1", "user2", "analyst", "manager"] # Order might vary if extend/append used differently, so sort for test
        assert sorted(final_user_accounts) == sorted(expected_users), f"TASK 2: final_user_accounts incorrect. Expected {expected_users} (sorted), got {sorted(final_user_accounts)}"
        assert is_admin_in_final_list is True, "TASK 2: is_admin_in_final_list should be True"
        assert "guest" not in final_user_accounts, "TASK 2: 'guest' should have been removed"
        print("✅ TASK 2 (User Accounts): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 2 (User Accounts): FAILED - {e}")
        main_passed = False

    # TASK 3 Tests
    try:
        initial_alerts_content = [
            "Failed login attempt from IP address 203.0.113.42",
            "High CPU usage detected on server-01",
            "Suspicious file detected in downloads folder",
            "Firewall rule violation from internal network"
        ]
        expected_formatted_initial = [f"{i+1}: {alert}" for i, alert in enumerate(initial_alerts_content)]
        assert formatted_initial_alerts == expected_formatted_initial, "TASK 3: formatted_initial_alerts incorrect."
        assert removed_alert_content == initial_alerts_content[0], "TASK 3: removed_alert_content incorrect."
        assert len(security_alerts_log) == 3, f"TASK 3: security_alerts_log should have 3 items after pop, got {len(security_alerts_log)}"
        expected_formatted_remaining = [f"{i+1}: {alert}" for i, alert in enumerate(initial_alerts_content[1:])] # Format remaining
        assert formatted_remaining_alerts == expected_formatted_remaining, "TASK 3: formatted_remaining_alerts incorrect."
        print("✅ TASK 3 (Security Alerts): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 3 (Security Alerts): FAILED - {e}")
        main_passed = False

    # TASK 4 Tests
    try:
        original_scores = [8.5, 6.2, 9.1, 4.3, 7.8]
        assert vulnerability_scores_list == original_scores, "TASK 4: vulnerability_scores_list was modified or not created with original values."
        expected_sorted = sorted(original_scores, reverse=True) # [9.1, 8.5, 7.8, 6.2, 4.3]
        assert sorted_vulnerability_scores == expected_sorted, f"TASK 4: sorted_vulnerability_scores incorrect. Expected {expected_sorted}, got {sorted_vulnerability_scores}"

        expected_high_sev = [9.1, 8.5, 7.8]
        assert high_severity_vulns_list == expected_high_sev, f"TASK 4: high_severity_vulns_list incorrect. Expected {expected_high_sev}, got {high_severity_vulns_list}"

        expected_avg = sum(original_scores) / len(original_scores) if original_scores else 0.0
        assert abs(average_vuln_score - expected_avg) < 0.001, f"TASK 4: average_vuln_score incorrect. Expected {expected_avg}, got {average_vuln_score}"
        print("✅ TASK 4 (Vulnerability Assessment): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 4 (Vulnerability Assessment): FAILED - {e}")
        main_passed = False

    # TASK 5 Tests
    try:
        # Re-calculate expected values based on potentially correct prior steps
        # This makes tests dependent, but reflects the exercise flow.
        # A more robust test suite would mock inputs to each task.
        expected_total_devices = len(final_network_devices) if 'final_network_devices' in globals() else 0
        expected_total_users = len(final_user_accounts) if 'final_user_accounts' in globals() else 0
        expected_active_alerts = len(security_alerts_log) if 'security_alerts_log' in globals() else 0
        expected_highest_vuln = sorted_vulnerability_scores[0] if 'sorted_vulnerability_scores' in globals() and sorted_vulnerability_scores else 0.0

        assert dashboard_total_devices == expected_total_devices, f"TASK 5: dashboard_total_devices. Expected {expected_total_devices}, Got {dashboard_total_devices}"
        assert dashboard_total_users == expected_total_users, f"TASK 5: dashboard_total_users. Expected {expected_total_users}, Got {dashboard_total_users}"
        assert dashboard_active_alerts == expected_active_alerts, f"TASK 5: dashboard_active_alerts. Expected {expected_active_alerts}, Got {dashboard_active_alerts}"
        assert abs(dashboard_highest_vulnerability - expected_highest_vuln) < 0.001, f"TASK 5: dashboard_highest_vulnerability. Expected {expected_highest_vuln}, Got {dashboard_highest_vulnerability}"
        print("✅ TASK 5 (Dashboard Summary): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 5 (Dashboard Summary): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 MAIN EXERCISE: All core logic tests passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some core logic tests failed.")
    return main_passed

def run_all_tests():
    warmup_ok = test_warmup_lists()
    main_ok = test_main_exercise_asset_management()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python lists!")
        print("Ready for Module 6: Dictionaries")
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")

# Run the tests
run_all_tests()

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Outstanding work completing Module 5! Here's what you learned:

✅ Creating and accessing lists with indexing
✅ Adding and removing items with append, insert, remove, pop
✅ Searching lists with 'in' operator and index() method
✅ Sorting lists with sort() and sorted() functions
✅ List slicing for extracting portions of data
✅ List comprehensions for creating filtered lists
✅ How to manage cybersecurity data collections effectively

CYBERSECURITY SKILLS GAINED:
- IP address and network device management
- User account and access control lists
- Security alert and incident tracking
- Vulnerability assessment and scoring
- Asset inventory and configuration management
- Log analysis and event processing

NEXT MODULE: 06_dictionaries.py
In the next module, you'll learn about dictionaries - powerful data structures
that store key-value pairs, perfect for organizing complex security information
like user profiles, system configurations, and security policies!

You're building sophisticated data management skills! 📊🔐
"""
