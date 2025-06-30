"""
====================================================================
MODULE 6: DICTIONARIES - Organizing Complex Security Data 🗂️
====================================================================

Welcome to Module 6! You've mastered lists for storing collections of data.
Now you'll learn about dictionaries - powerful structures that store data
as key-value pairs. Think of them as digital filing cabinets where each
piece of information has a unique label (key) for quick access.

WHAT ARE DICTIONARIES?
Dictionaries store data in key-value pairs, like a real dictionary where
words (keys) have definitions (values). They're perfect for cybersecurity
work because security data often comes in related pairs: usernames and
passwords, IP addresses and their status, systems and their configurations.

DICTIONARY OPERATIONS WE'LL COVER:
- Creating and accessing dictionaries
- Adding, updating, and removing items
- Dictionary methods and techniques
- Nested dictionaries for complex data
- Iterating through dictionaries
"""

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF DICTIONARIES:

1. USER MANAGEMENT AND ACCESS CONTROL:
   - User profiles: username -> {role, permissions, last_login, status}
   - Access logs: timestamp -> {user, action, resource, result}
   - Role definitions: role_name -> {permissions, restrictions, inheritance}

2. NETWORK AND ASSET MANAGEMENT:
   - IP mappings: IP_address -> {hostname, device_type, status, owner}
   - Device inventory: asset_id -> {type, location, configuration, vulnerabilities}
   - Port configurations: port_number -> {service, status, access_rules}

3. SECURITY MONITORING AND INCIDENTS:
   - Alert mapping: alert_id -> {timestamp, severity, description, status}
   - Threat intelligence: IOC -> {type, confidence, source, actions}
   - Incident tracking: incident_id -> {description, priority, assignee, status}

4. VULNERABILITY MANAGEMENT:
   - CVE database: CVE_id -> {score, description, affected_systems, patches}
   - System vulnerabilities: system_id -> {vulnerabilities, risk_score, patches_needed}
   - Patch management: patch_id -> {systems, installation_date, success_rate}

5. CONFIGURATION MANAGEMENT:
   - Security policies: policy_name -> {rules, enforcement, exceptions}
   - System configurations: system_id -> {security_settings, compliance_status}
   - Tool configurations: tool_name -> {settings, schedules, reporting}

6. LOG ANALYSIS AND FORENSICS:
   - Event correlation: event_id -> {timestamp, source, details, related_events}
   - User activity: user_id -> {login_times, actions, locations, anomalies}
   - System performance: metric_name -> {current, threshold, trend, alerts}
"""

# ============================================================================
# WARM-UP EXERCISES: Practice Using Dictionaries
# ============================================================================

# Exercise 1: Create a simple dictionary
"""
PRACTICE: Basic Dictionary Creation

Write a function `create_server_info()` that creates and returns a dictionary
called `server_info` with the following key-value pairs:
- "name": "web-server"
- "port": 80
- "active": True
"""
# TODO: Implement the function create_server_info
def create_server_info():
    # Your code here
    pass


# Exercise 2: Access dictionary values
"""
PRACTICE: Accessing Dictionary Values

Write a function `get_user_details(user_dict)` that takes a dictionary `user_dict`
(e.g., {"username": "admin", "role": "administrator", "logged_in": True}).
The function should return the user's username and role as a tuple: (username, role).
If a key is missing, it should use "N/A" for that value.
"""
# TODO: Implement the function get_user_details
def get_user_details(user_dict):
    # Your code here
    pass


# Exercise 3: Add new key-value pair
"""
PRACTICE: Adding to Dictionaries

Write a function `add_disk_usage(system_metrics_dict, disk_usage_value)`
that takes a dictionary `system_metrics_dict` (e.g., {"cpu": 45, "memory": 60})
and an integer `disk_usage_value`.
It should add a new key "disk" with the value `disk_usage_value` to the dictionary.
The function should return the modified dictionary.
"""
# TODO: Implement the function add_disk_usage
def add_disk_usage(system_metrics_dict, disk_usage_value):
    # Your code here
    pass


# Exercise 4: Check if key exists
"""
PRACTICE: Checking Dictionary Keys

Write a function `check_security_config(config_dict, key_to_check)`
that takes a dictionary `config_dict` (e.g., {"firewall": True, "antivirus": True})
and a `key_to_check` string.
It should return True if `key_to_check` exists in `config_dict`, and False otherwise.
"""
# TODO: Implement the function check_security_config
def check_security_config(config_dict, key_to_check):
    # Your code here
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Comprehensive Security Management System
# ============================================================================
"""
COMPREHENSIVE SECURITY MANAGEMENT DASHBOARD

You are developing a centralized security management dashboard that organizes complex
security data using structured information systems. The dashboard needs to track user
accounts, system health, and security tool configurations.

USER ACCOUNT MANAGEMENT:
Create a dictionary named `user_database`. Each key should be a username string
(e.g., "alice_admin", "bob_analyst", "charlie_guest"), and each value should be
another dictionary containing:
- "role": (string, e.g., "administrator", "analyst", "guest")
- "last_login": (string, e.g., "2023-10-01")
- "failed_attempts": (integer)
- "active": (boolean, True or False)

Populate `user_database` with:
- Alice: admin role, last login 2023-10-01, 0 failed attempts, active.
- Bob: analyst role, last login 2023-09-30, 2 failed attempts, active.
- Charlie: guest role, last login 2023-09-25, 5 failed attempts, inactive.

SYSTEM INFRASTRUCTURE MONITORING:
Create a dictionary named `system_status`. Each key should be a system name string
(e.g., "web_server", "database_server", "backup_server"), and each value should be
another dictionary containing:
- "cpu_usage": (integer, percentage)
- "memory_usage": (integer, percentage)
- "disk_usage": (integer, percentage)
- "status": (string, e.g., "healthy", "warning", "critical")

Populate `system_status` with:
- Web server: 75% CPU, 60% memory, 45% disk, "healthy" status.
- Database server: 90% CPU, 85% memory, 70% disk, "warning" status.
- Backup server: 25% CPU, 30% memory, 95% disk, "critical" status.

SECURITY TOOLS CONFIGURATION:
Create a dictionary named `security_tools`. Each key should be a tool name string
(e.g., "firewall", "antivirus", "ids"), and each value should be another
dictionary containing tool-specific information:
- Firewall: "enabled": True, "rules": 150, "last_updated": "2023-10-01", "alerts": 3
- Antivirus: "enabled": True, "definitions_date": "2023-09-30", "last_scan": "2023-10-01", "threats_found": 0
- IDS (Intrusion Detection System): "enabled": False, "sensors": 5, "last_alert_date": "2023-09-28", "total_alerts": 12

SECURITY OPERATIONS TASKS (Modify the dictionaries created above):
1.  Add a new user "david_manager" to `user_database`. David is a "manager",
    last logged in "2023-10-02", has 1 failed attempt, and is "active".
2.  Update "bob_analyst" in `user_database`: reset "failed_attempts" to 0.
3.  Check if a user "eve_hacker" exists in `user_database`. Store the result (True/False)
    in a variable `eve_hacker_exists`.
4.  Create a list `users_with_failed_logins` containing usernames of users from
    `user_database` who have `failed_attempts > 0`.
5.  Create a list `high_cpu_systems` containing names of systems from `system_status`
    with `cpu_usage > 80`.
6.  Update the "web_server" in `system_status`: change its "status" to "optimal".
7.  Calculate the `average_disk_usage` across all systems in `system_status`. If no systems, average is 0.
8.  Create a list `systems_needing_attention` from `system_status` for systems
    whose status is "warning" or "critical".
9.  Create a list `enabled_security_tools` containing names of tools from
    `security_tools` that are "enabled".
10. Find the name of the security tool with the most alerts (consider "alerts", "total_alerts", or "threats_found" - prioritize "total_alerts" if present, then "alerts", then "threats_found"). Store its name in `tool_with_most_alerts`. If no tools or no alerts, this can be an empty string or None.
11. Update the "ids" in `security_tools`: set "enabled" to True.
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: Create User Management Dictionary
# user_database = ?

# PART 2: Create System Status Dictionary
# system_status = ?

# PART 3: Create Security Tools Configuration
# security_tools = ?


# PART 4: Perform Security Operations Tasks
# Task 1: Add david_manager
# Task 2: Reset bob_analyst's failed_attempts
# Task 3: Check for eve_hacker
# eve_hacker_exists = ?
# Task 4: List users with failed logins
# users_with_failed_logins = ?
# Task 5: List high CPU systems
# high_cpu_systems = ?
# Task 6: Update web_server status
# Task 7: Calculate average disk usage
# average_disk_usage = ?
# Task 8: List systems needing attention
# systems_needing_attention = ?
# Task 9: List enabled security tools
# enabled_security_tools = ?
# Task 10: Find tool with most alerts
# tool_with_most_alerts = ?
# Task 11: Enable IDS


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

def test_warmup_exercises():
    """Test the warm-up exercises."""
    warmup_passed = 0
    total_warmup_tests = 4

    # Test Exercise 1
    try:
        expected = {"name": "web-server", "port": 80, "active": True}
        assert create_server_info() == expected, "Exercise 1 Failed"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 1 FAILED: Function 'create_server_info' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 1 FAILED: Unexpected error - {e}")

    # Test Exercise 2
    try:
        user_data = {"username": "admin", "role": "administrator", "logged_in": True}
        assert get_user_details(user_data) == ("admin", "administrator"), "Exercise 2 Failed: Test 1"
        assert get_user_details({"role": "guest"}) == ("N/A", "guest"), "Exercise 2 Failed: Test 2 (missing username)"
        assert get_user_details({}) == ("N/A", "N/A"), "Exercise 2 Failed: Test 3 (empty dict)"
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 2 FAILED: Function 'get_user_details' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 2 FAILED: Unexpected error - {e}")

    # Test Exercise 3
    try:
        metrics = {"cpu": 45, "memory": 60}
        expected = {"cpu": 45, "memory": 60, "disk": 30}
        assert add_disk_usage(metrics, 30) == expected, "Exercise 3 Failed: Test 1"
        assert add_disk_usage({}, 50) == {"disk": 50}, "Exercise 3 Failed: Test 2 (empty dict)"
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 3 FAILED: Function 'add_disk_usage' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 3 FAILED: Unexpected error - {e}")

    # Test Exercise 4
    try:
        config = {"firewall": True, "antivirus": True}
        assert check_security_config(config, "firewall") == True, "Exercise 4 Failed: Test 1 (key exists)"
        assert check_security_config(config, "backup") == False, "Exercise 4 Failed: Test 2 (key does not exist)"
        assert check_security_config({}, "firewall") == False, "Exercise 4 Failed: Test 3 (empty dict)"
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 4 FAILED: Function 'check_security_config' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 4 FAILED: Unexpected error - {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests

def test_main_exercise_dictionaries():
    """Test function to verify your dictionary operations in the main exercise are correct."""
    main_passed = True
    missing_vars = []

    def check_var(var_name, expected_type=None):
        if var_name not in globals():
            missing_vars.append(var_name)
            return False
        if expected_type and not isinstance(globals()[var_name], expected_type):
            missing_vars.append(f"{var_name} (wrong type, expected {expected_type})")
            return False
        return True

    # Initial Dictionaries
    if not check_var('user_database', dict): main_passed = False
    if not check_var('system_status', dict): main_passed = False
    if not check_var('security_tools', dict): main_passed = False

    if not main_passed: # Stop if initial dicts are missing
        print(f"❌ ERROR: Initial dictionaries not defined: {', '.join(missing_vars)}")
        return False

    # Task 1 & 2: User DB modifications
    if "david_manager" not in user_database:
        print("❌ Test FAILED: 'david_manager' not added to user_database.")
        main_passed = False
    elif user_database.get("david_manager", {}).get("role") != "manager":
        print("❌ Test FAILED: 'david_manager' has incorrect role.")
        main_passed = False
    if user_database.get("bob_analyst", {}).get("failed_attempts") != 0:
        print("❌ Test FAILED: 'bob_analyst' failed_attempts not reset.")
        main_passed = False

    # Task 3: Check eve_hacker
    if not check_var('eve_hacker_exists', bool): main_passed = False
    elif eve_hacker_exists is not False: # Should be False
        print("❌ Test FAILED: 'eve_hacker_exists' should be False.")
        main_passed = False

    # Task 4: Users with failed logins
    if not check_var('users_with_failed_logins', list): main_passed = False
    else:
        # Expected: Charlie (5), David (1) if Bob is reset
        expected_failed_users = sorted(["charlie_guest", "david_manager"])
        if sorted(users_with_failed_logins) != expected_failed_users:
            print(f"❌ Test FAILED: 'users_with_failed_logins' incorrect. Expected {expected_failed_users}, got {sorted(users_with_failed_logins)}.")
            main_passed = False

    # Task 5: High CPU systems
    if not check_var('high_cpu_systems', list): main_passed = False
    elif sorted(high_cpu_systems) != sorted(["database_server"]): # Only DB server is > 80%
        print(f"❌ Test FAILED: 'high_cpu_systems' incorrect. Expected ['database_server'], got {high_cpu_systems}.")
        main_passed = False

    # Task 6: Update web_server status
    if system_status.get("web_server", {}).get("status") != "optimal":
        print("❌ Test FAILED: 'web_server' status not updated to 'optimal'.")
        main_passed = False

    # Task 7: Average disk usage
    if not check_var('average_disk_usage', float): main_passed = False
    else:
        # disk usages: web=45, db=70, backup=95. Sum=210. Avg=70.0
        if abs(average_disk_usage - 70.0) > 0.001:
            print(f"❌ Test FAILED: 'average_disk_usage' incorrect. Expected 70.0, got {average_disk_usage}.")
            main_passed = False

    # Task 8: Systems needing attention
    if not check_var('systems_needing_attention', list): main_passed = False
    else:
        expected_attention = sorted(["database_server", "backup_server"])
        if sorted(systems_needing_attention) != expected_attention:
            print(f"❌ Test FAILED: 'systems_needing_attention' incorrect. Expected {expected_attention}, got {sorted(systems_needing_attention)}.")
            main_passed = False

    # Task 9: Enabled security tools
    if not check_var('enabled_security_tools', list): main_passed = False
    else:
        # Firewall, Antivirus are initially enabled. IDS becomes enabled in task 11.
        # Test will run after task 11 modifications.
        pass # Checked after task 11

    # Task 11: Enable IDS (must be done before testing Task 9 and 10 related to IDS)
    if security_tools.get("ids", {}).get("enabled") is not True:
        print("❌ Test FAILED: IDS 'enabled' status not updated to True.")
        main_passed = False

    # Re-check Task 9 after IDS enabling
    if main_passed and check_var('enabled_security_tools', list): # only if IDS was enabled correctly
        expected_enabled_tools = sorted(["firewall", "antivirus", "ids"])
        if sorted(enabled_security_tools) != expected_enabled_tools:
            print(f"❌ Test FAILED: 'enabled_security_tools' incorrect after IDS update. Expected {expected_enabled_tools}, got {sorted(enabled_security_tools)}.")
            main_passed = False

    # Task 10: Tool with most alerts
    if not check_var('tool_with_most_alerts', (str, type(None))): main_passed = False
    else:
        # Firewall: 3, Antivirus: 0 (threats_found), IDS: 12 (total_alerts)
        if tool_with_most_alerts != "ids":
            print(f"❌ Test FAILED: 'tool_with_most_alerts' incorrect. Expected 'ids', got '{tool_with_most_alerts}'.")
            main_passed = False

    if missing_vars:
        print(f"\n❌ ERROR: The following main exercise variables are not defined or have wrong type: {', '.join(missing_vars)}")
        return False

    if main_passed:
        print("\n✅ MAIN EXERCISE: All checks passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some checks failed. Review the messages above.")
    return main_passed

def run_all_tests():
    """Run all tests for Module 6."""
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_exercises()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    main_exercise_success = test_main_exercise_dictionaries()

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_success:
        print("\n✅ All warm-up and main exercise tests passed!")
        print("You've successfully mastered Python dictionaries!")
        print("Ready for Module 7: Functions")
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
Excellent work completing Module 6! Here's what you learned:

✅ Creating and accessing dictionaries with key-value pairs
✅ Adding, updating, and removing dictionary items
✅ Using dictionary methods: keys(), values(), items(), get()
✅ Iterating through dictionaries effectively
✅ Working with nested dictionaries for complex data
✅ Organizing cybersecurity data with structured information

CYBERSECURITY SKILLS GAINED:
- User account management and access control
- System status monitoring and alerting  
- Security tool configuration and management
- Incident tracking and response coordination
- Asset inventory and vulnerability management
- Policy and configuration management

NEXT MODULE: 07_functions.py
In the next module, you'll learn about functions - reusable blocks of code
that help you organize your cybersecurity scripts, eliminate repetition,
and build modular security tools that can be easily maintained and shared!

You're developing professional-level programming skills! 🚀🔧
"""
