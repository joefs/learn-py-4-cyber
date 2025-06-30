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

# ============================================================================
# WARM-UP EXERCISES: Practice Using Lists
# ============================================================================

# Exercise 1: Create and print a simple list
"""
PRACTICE: Basic List Creation

Write a function `create_device_list()` that creates and returns a list
called `devices` with three items: "firewall", "router", "switch".
The function should also return the length of this list.
Return both the list and its length as a tuple: (list, length).
"""
# TODO: Implement the function create_device_list
def create_device_list():
    # Your code here
    pass


# Exercise 2: Add item to list
"""
PRACTICE: Adding to Lists

Write a function `add_user_to_list(users_list, new_user)` that takes a list
of users and a new user string.
It should add the `new_user` to the end of the `users_list` using append().
The function should return the modified list.
"""
# TODO: Implement the function add_user_to_list
def add_user_to_list(users_list, new_user):
    # Your code here
    pass


# Exercise 3: Remove item from list
"""
PRACTICE: Removing from Lists

Write a function `remove_service_from_list(services_list, service_to_remove)`
that takes a list of services and a service string to remove.
It should remove the `service_to_remove` from the `services_list` using remove().
If the service is not in the list, it should do nothing and return the original list.
The function should return the modified list.
"""
# TODO: Implement the function remove_service_from_list
def remove_service_from_list(services_list, service_to_remove):
    # Your code here
    pass


# Exercise 4: Check if item exists in list
"""
PRACTICE: Checking List Membership

Write a function `check_port_access(allowed_ports_list, port_to_check)`
that takes a list of allowed ports and a port number to check.
It should return True if `port_to_check` is in `allowed_ports_list`,
and False otherwise.
"""
# TODO: Implement the function check_port_access
def check_port_access(allowed_ports_list, port_to_check):
    # Your code here
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Asset Management System
# ============================================================================
"""
SECURITY ASSET MANAGEMENT SYSTEM

You are building a comprehensive security asset management system for your organization.
The system needs to track network devices, user accounts, security alerts, and
vulnerability assessments.

NETWORK INFRASTRUCTURE TRACKING:
Your network currently has these devices: firewall, router, switch, and server.
The security team is adding a new intrusion detection system and needs to insert
a load balancer between the router and switch (at position 2 of the 0-indexed list,
meaning it will be the third item).

Create a list named network_devices with the initial devices. Then:
1. Add "intrusion_detection_system" to the end of the list.
2. Insert "load_balancer" at index 2.
After these operations, this part of the exercise expects `network_devices`
to be correctly modified.

USER ACCOUNT MANAGEMENT:
The system currently has these user accounts: admin, user1, user2, and guest.
For security reasons, the guest account needs to be removed, and two new accounts
(analyst and manager) need to be added.

Create a list named user_accounts with the initial users. Then:
1. Remove "guest" from the list.
2. Add "analyst" and "manager" to the list (e.g., using extend or multiple appends).
This part of the exercise expects `user_accounts` to be correctly modified.
You will also need to create a boolean variable `is_admin_present` that is True
if "admin" is in the `user_accounts` list, and False otherwise.

SECURITY ALERT TRACKING:
Your monitoring system has detected several security incidents that need to be tracked:
- "Failed login attempt from IP address 203.0.113.42"
- "High CPU usage detected on server-01"
- "Suspicious file detected in downloads folder"
- "Firewall rule violation from internal network"

Start with an empty list named security_alerts. Then:
1. Add each of the four incidents to the list.
2. Create a variable `first_alert_removed` and store the first alert by removing it
   from `security_alerts` (e.g., using pop(0)).
This part of the exercise expects `security_alerts` to contain the remaining 3 alerts
and `first_alert_removed` to hold the one that was removed.

VULNERABILITY ASSESSMENT:
Recent vulnerability scans produced these severity scores: 8.5, 6.2, 9.1, 4.3, 7.8.
You need to prioritize remediation efforts by focusing on high-severity vulnerabilities.

Create a list named vulnerability_scores with this data. Then:
1. Sort `vulnerability_scores` in descending order (modifying the list in-place).
2. Create a new list called `high_severity_scores` containing only scores > 7.0
   from the sorted `vulnerability_scores` list (e.g., using a list comprehension).
3. Calculate the average of all scores in the original `vulnerability_scores` list
   and store it in a variable `average_score`. If the list is empty, `average_score`
   should be 0.
This part of the exercise expects `vulnerability_scores` to be sorted,
`high_severity_scores` to contain the filtered scores, and `average_score` to be correct.

SECURITY DASHBOARD SUMMARY (Data Preparation):
For a security dashboard, you need to prepare the following summary data:
- `total_devices`: The total count of network devices.
- `total_users`: The total count of user accounts.
- `active_alerts_count`: The total count of active security alerts.
- `highest_vulnerability_score`: The highest score from `vulnerability_scores`.
  If `vulnerability_scores` is empty, this should be 0.
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Network Infrastructure Tracking
# TODO: Create network_devices list and perform operations
# network_devices = ?


# PART 2: User Account Management
# TODO: Create user_accounts list, perform operations, and check for admin
# user_accounts = ?
# is_admin_present = ?


# PART 3: Security Alert Tracking
# TODO: Create security_alerts list, add alerts, and remove the first one
# security_alerts = ?
# first_alert_removed = ?


# PART 4: Vulnerability Assessment
# TODO: Create vulnerability_scores list, sort, filter, and calculate average
# vulnerability_scores = ?
# high_severity_scores = ?
# average_score = ?


# PART 5: Security Dashboard Summary Data
# TODO: Calculate summary data points
# total_devices = ?
# total_users = ?
# active_alerts_count = ?
# highest_vulnerability_score = ?


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

def test_warmup_exercises():
    """Test the warm-up exercises."""
    warmup_passed = 0
    total_warmup_tests = 4

    # Test Exercise 1
    try:
        devices, length = create_device_list()
        assert devices == ["firewall", "router", "switch"], "Exercise 1 Failed: List content"
        assert length == 3, "Exercise 1 Failed: List length"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 1 FAILED: Function 'create_device_list' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 1 FAILED: Unexpected error - {e}")

    # Test Exercise 2
    try:
        assert add_user_to_list(["admin", "guest"], "operator") == ["admin", "guest", "operator"], "Exercise 2 Failed: Test 1"
        assert add_user_to_list([], "first") == ["first"], "Exercise 2 Failed: Test 2 (empty list)"
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 2 FAILED: Function 'add_user_to_list' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 2 FAILED: Unexpected error - {e}")

    # Test Exercise 3
    try:
        assert remove_service_from_list(["web", "mail", "test", "dns"], "test") == ["web", "mail", "dns"], "Exercise 3 Failed: Test 1"
        assert remove_service_from_list(["web", "mail"], "ftp") == ["web", "mail"], "Exercise 3 Failed: Test 2 (item not in list)"
        assert remove_service_from_list([], "web") == [], "Exercise 3 Failed: Test 3 (empty list)"
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 3 FAILED: Function 'remove_service_from_list' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 3 FAILED: Unexpected error - {e}")

    # Test Exercise 4
    try:
        assert check_port_access([22, 80, 443], 22) == True, "Exercise 4 Failed: Test 1 (port exists)"
        assert check_port_access([22, 80, 443], 21) == False, "Exercise 4 Failed: Test 2 (port does not exist)"
        assert check_port_access([], 80) == False, "Exercise 4 Failed: Test 3 (empty list)"
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 4 FAILED: Function 'check_port_access' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 4 FAILED: Unexpected error - {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests


def test_main_exercise_lists():
    """Test function to verify your list operations in the main exercise are correct."""
    main_passed = True
    missing_vars = []

    def check_var(var_name):
        if var_name not in globals():
            missing_vars.append(var_name)
            return False
        return True

    # Test Network Infrastructure Tracking
    if check_var('network_devices'):
        expected_devices = ["firewall", "router", "load_balancer", "switch", "server", "intrusion_detection_system"]
        if network_devices != expected_devices:
            print(f"❌ Test FAILED: network_devices incorrect. Expected {expected_devices}, got {network_devices}")
            main_passed = False
    else: main_passed = False

    # Test User Account Management
    if check_var('user_accounts') and check_var('is_admin_present'):
        expected_users = ["admin", "user1", "user2", "analyst", "manager"]
        if user_accounts != expected_users:
            print(f"❌ Test FAILED: user_accounts incorrect. Expected {expected_users}, got {user_accounts}")
            main_passed = False
        if not is_admin_present:
            print(f"❌ Test FAILED: is_admin_present should be True.")
            main_passed = False
        if "guest" in user_accounts:
            print(f"❌ Test FAILED: 'guest' should have been removed from user_accounts.")
            main_passed = False
    else: main_passed = False

    # Test Security Alert Tracking
    if check_var('security_alerts') and check_var('first_alert_removed'):
        expected_first_alert = "Failed login attempt from IP address 203.0.113.42"
        expected_remaining_alerts = [
            "High CPU usage detected on server-01",
            "Suspicious file detected in downloads folder",
            "Firewall rule violation from internal network"
        ]
        if first_alert_removed != expected_first_alert:
            print(f"❌ Test FAILED: first_alert_removed incorrect. Expected '{expected_first_alert}', got '{first_alert_removed}'")
            main_passed = False
        if security_alerts != expected_remaining_alerts:
            print(f"❌ Test FAILED: security_alerts incorrect. Expected {expected_remaining_alerts}, got {security_alerts}")
            main_passed = False
    else: main_passed = False

    # Test Vulnerability Assessment
    if check_var('vulnerability_scores') and check_var('high_severity_scores') and check_var('average_score'):
        expected_sorted_scores = [9.1, 8.5, 7.8, 6.2, 4.3]
        expected_high_scores = [9.1, 8.5, 7.8]
        # Original scores for average: 8.5, 6.2, 9.1, 4.3, 7.8. Sum = 35.9. Avg = 35.9 / 5 = 7.18
        expected_avg_score = 7.18
        if vulnerability_scores != expected_sorted_scores: # Checks if sorting was done in-place
            print(f"❌ Test FAILED: vulnerability_scores not sorted correctly. Expected {expected_sorted_scores}, got {vulnerability_scores}")
            main_passed = False
        if high_severity_scores != expected_high_scores:
            print(f"❌ Test FAILED: high_severity_scores incorrect. Expected {expected_high_scores}, got {high_severity_scores}")
            main_passed = False
        if abs(average_score - expected_avg_score) > 0.001 : # Check float with tolerance
            print(f"❌ Test FAILED: average_score incorrect. Expected {expected_avg_score}, got {average_score}")
            main_passed = False
    else: main_passed = False

    # Test Security Dashboard Summary Data
    summary_vars = ['total_devices', 'total_users', 'active_alerts_count', 'highest_vulnerability_score']
    all_summary_vars_present = all(check_var(v) for v in summary_vars)

    if all_summary_vars_present and main_passed: # only check values if other parts passed
        if total_devices != len(network_devices): # Assuming network_devices is correct from above
             print(f"❌ Test FAILED: total_devices incorrect. Expected {len(network_devices)}, got {total_devices}")
             main_passed = False
        if total_users != len(user_accounts): # Assuming user_accounts is correct
             print(f"❌ Test FAILED: total_users incorrect. Expected {len(user_accounts)}, got {total_users}")
             main_passed = False
        if active_alerts_count != len(security_alerts): # Assuming security_alerts is correct
             print(f"❌ Test FAILED: active_alerts_count incorrect. Expected {len(security_alerts)}, got {active_alerts_count}")
             main_passed = False
        if vulnerability_scores: # Check only if list is not empty
            if highest_vulnerability_score != vulnerability_scores[0]: # Assuming sorted descending
                print(f"❌ Test FAILED: highest_vulnerability_score incorrect. Expected {vulnerability_scores[0]}, got {highest_vulnerability_score}")
                main_passed = False
        elif highest_vulnerability_score != 0: # If list is empty, score should be 0
            print(f"❌ Test FAILED: highest_vulnerability_score should be 0 for empty list, got {highest_vulnerability_score}")
            main_passed = False
    elif not all_summary_vars_present:
        main_passed = False


    if missing_vars:
        print(f"\n❌ ERROR: The following main exercise variables are not defined: {', '.join(missing_vars)}")
        return False

    if main_passed:
        print("\n✅ MAIN EXERCISE: All checks passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some checks failed. Review the messages above.")
    return main_passed


def run_all_tests():
    """Run all tests for Module 5."""
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_exercises()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    main_exercise_success = test_main_exercise_lists()

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_success:
        print("\n✅ All warm-up and main exercise tests passed!")
        print("You've successfully mastered Python lists!")
        print("Ready for Module 6: Dictionaries")
    else:
        print("\n📚 Keep practicing! Review the failed tests or checks above.")
        if not warmup_success:
            print("- Some warm-up exercises have issues.")
        if not main_exercise_success:
            print("- The main exercise has issues.")

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
