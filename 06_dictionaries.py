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
# CONCEPT EXPLANATION: Creating and Accessing Dictionaries
# ============================================================================

# Creating dictionaries
user_permissions = {
    "admin": "full_access",
    "manager": "read_write",
    "analyst": "read_only",
    "guest": "no_access"
}

server_config_status = { # Renamed to avoid conflict with main exercise
    "web-server-01": "online",
    "db-server-01": "offline",
    "mail-server-01": "online",
    "backup-server-01": "maintenance"
}

vulnerability_info_conceptual = { # Renamed for clarity
    "CVE-2023-1234": {"score": 9.8, "severity": "critical"},
    "CVE-2023-5678": {"score": 6.2, "severity": "medium"},
    "CVE-2023-9012": {"score": 8.1, "severity": "high"}
}

print("Dictionary Examples:")
print(f"User permissions: {user_permissions}")
print(f"Server status (conceptual): {server_config_status}")
print(f"Vulnerability info (conceptual): {vulnerability_info_conceptual}")

# Accessing dictionary values
print("\nAccessing Dictionary Values:") # Added newline for clarity
print(f"Admin permissions: {user_permissions['admin']}")
print(f"Web server status (conceptual): {server_config_status['web-server-01']}")

# Safe access with get() method
print("\nSafe Access with get():") # Added newline
print(f"Unknown user permissions: {user_permissions.get('unknown_user', 'not_found')}")
print(f"Test server status (conceptual): {server_config_status.get('test-server', 'not_monitored')}")

# ============================================================================
# CONCEPT EXPLANATION: Adding, Updating, and Removing Items
# ============================================================================

# Starting with security alerts
security_alerts_conceptual = { # Renamed for clarity
    "2023-10-01 09:15": "Failed login attempt",
    "2023-10-01 09:20": "Suspicious file download",
    "2023-10-01 09:25": "Port scan detected"
}
print(f"\nInitial conceptual alerts: {security_alerts_conceptual}") # Added newline

# Adding new items
security_alerts_conceptual["2023-10-01 09:30"] = "Malware signature detected"
print(f"After adding conceptual alert: {security_alerts_conceptual}")

# Updating existing items
security_alerts_conceptual["2023-10-01 09:15"] = "Failed login attempt - Account locked"
print(f"After updating conceptual alert: {security_alerts_conceptual}")

# Removing items
removed_alert_conceptual = security_alerts_conceptual.pop("2023-10-01 09:20")
print(f"Removed conceptual alert: {removed_alert_conceptual}")
print(f"After conceptual removal: {security_alerts_conceptual}")

# Using del to remove items
del security_alerts_conceptual["2023-10-01 09:25"]
print(f"After conceptual del: {security_alerts_conceptual}")

# ============================================================================
# CONCEPT EXPLANATION: Dictionary Methods
# ============================================================================

# Working with firewall rules
firewall_rules_conceptual = { # Renamed
    "rule_001": {"action": "allow", "port": 80, "protocol": "tcp"},
    "rule_002": {"action": "deny", "port": 23, "protocol": "tcp"},
    "rule_003": {"action": "allow", "port": 443, "protocol": "tcp"},
    "rule_004": {"action": "deny", "port": 21, "protocol": "tcp"}
}

print("\nFirewall Rules Analysis (Conceptual):") # Added newline
print(f"All conceptual rules: {firewall_rules_conceptual}")

# Dictionary methods
print("\nDictionary Methods (Conceptual):") # Added newline
print(f"All rule names (keys): {list(firewall_rules_conceptual.keys())}")
print(f"All rule details (values): {list(firewall_rules_conceptual.values())}")
print(f"All rule items: {list(firewall_rules_conceptual.items())}")

# Checking for keys
rule_to_check_conceptual = "rule_002"
if rule_to_check_conceptual in firewall_rules_conceptual:
    print(f"✅ Rule {rule_to_check_conceptual} exists: {firewall_rules_conceptual[rule_to_check_conceptual]}")
else:
    print(f"❌ Rule {rule_to_check_conceptual} not found")

# ============================================================================
# CONCEPT EXPLANATION: Iterating Through Dictionaries
# ============================================================================

# Network device inventory
network_inventory_conceptual = { # Renamed
    "192.168.1.1": {"device": "router", "vendor": "Cisco", "model": "ISR4331"},
    "192.168.1.2": {"device": "switch", "vendor": "HP", "model": "2530-24G"},
    "192.168.1.10": {"device": "firewall", "vendor": "Fortinet", "model": "FortiGate-60E"},
    "192.168.1.100": {"device": "server", "vendor": "Dell", "model": "PowerEdge R740"}
}

# Iterate through keys
print("\nNetwork Devices by IP (Conceptual):") # Added newline
for ip_conceptual in network_inventory_conceptual: # Renamed loop var
    print(f"  {ip_conceptual}: {network_inventory_conceptual[ip_conceptual]['device']}")

# Iterate through key-value pairs
print("\nDetailed Network Inventory (Conceptual):") # Added newline
for ip_conceptual, details_conceptual in network_inventory_conceptual.items(): # Renamed loop vars
    print(f"IP: {ip_conceptual}")
    print(f"  Device: {details_conceptual['device']}")
    print(f"  Vendor: {details_conceptual['vendor']}")
    print(f"  Model: {details_conceptual['model']}")

# ============================================================================
# CONCEPT EXPLANATION: Nested Dictionaries
# ============================================================================

# Complex security configuration
security_config_conceptual = { # Renamed
    "authentication": {
        "method": "multi_factor",
        "password_policy": {
            "min_length": 12,
            "require_special": True,
            "require_numbers": True,
            "expiry_days": 90
        },
        "lockout_policy": {
            "max_attempts": 5,
            "lockout_duration": 30
        }
    },
    "network_security": {
        "firewall": {
            "enabled": True,
            "default_action": "deny",
            "logging": True
        },
        "intrusion_detection": {
            "enabled": True,
            "sensitivity": "high",
            "alert_threshold": 3
        }
    }
}

print("\nSecurity Configuration (Conceptual):") # Added newline
print(f"Authentication method: {security_config_conceptual['authentication']['method']}")
print(f"Password min length: {security_config_conceptual['authentication']['password_policy']['min_length']}")
print(f"Firewall enabled: {security_config_conceptual['network_security']['firewall']['enabled']}")
print(f"IDS sensitivity: {security_config_conceptual['network_security']['intrusion_detection']['sensitivity']}")

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

# Security incident management system
incident_database_conceptual = { # Renamed
    "INC-2023-001": {
        "title": "Phishing email campaign detected",
        "severity": "high",
        "status": "investigating",
        "assigned_to": "security_team",
        "affected_users": 15,
        "created": "2023-10-01 08:30",
        "updated": "2023-10-01 10:15"
    },
    "INC-2023-002": {
        "title": "Unauthorized access attempt",
        "severity": "critical",
        "status": "contained",
        "assigned_to": "incident_response",
        "affected_users": 1,
        "created": "2023-10-01 14:22",
        "updated": "2023-10-01 16:45"
    }
}

print("\nActive Security Incidents (Conceptual):") # Added newline
for incident_id, details in incident_database_conceptual.items():
    status_icon = "🔴" if details["severity"] == "critical" else "🟡" if details["severity"] == "high" else "🟢"
    print(f"{status_icon} {incident_id}: {details['title']}")
    print(f"   Severity: {details['severity']} | Status: {details['status']}")
    print(f"   Assigned to: {details['assigned_to']} | Users affected: {details['affected_users']}")

# Network security monitoring
network_monitoring_conceptual = { # Renamed
    "traffic_analysis": {"status": "active", "alerts": 3, "last_update": "2023-10-01 16:30"},
    "intrusion_detection": {"status": "active", "alerts": 1, "last_update": "2023-10-01 16:28"},
    "vulnerability_scan": {"status": "scheduled", "alerts": 0, "last_update": "2023-10-01 12:00"},
    "log_analysis": {"status": "active", "alerts": 7, "last_update": "2023-10-01 16:32"}
}

print("\nNetwork Security Monitoring Dashboard (Conceptual):") # Added newline
for service, info in network_monitoring_conceptual.items():
    status_icon = "✅" if info["status"] == "active" else "⏰" if info["status"] == "scheduled" else "❌"
    alert_text = f"({info['alerts']} alerts)" if info['alerts'] > 0 else ""
    print(f"{status_icon} {service.replace('_', ' ').title()}: {info['status']} {alert_text}")

# ============================================================================
# WARM-UP EXERCISES: Practice Using Dictionaries
# ============================================================================

# Exercise 1: Create a simple dictionary
"""
PRACTICE: Basic Dictionary Creation

Write a function `create_server_details()` that creates and returns a dictionary
with the following key-value pairs:
- "name": "web-server"
- "port": 80
- "active": True
"""
# TODO: Implement the function create_server_details
def create_server_details():
    pass


# Exercise 2: Access dictionary values
"""
PRACTICE: Accessing Dictionary Values

Write a function `get_user_info(user_dict)` that takes a dictionary `user_dict`
(e.g., {"username": "admin", "role": "administrator", "logged_in": True}).
The function should return a tuple containing the username and role: (username, role).
If 'username' or 'role' keys are missing, use "N/A" for the respective value.
"""
# TODO: Implement the function get_user_info
def get_user_info(user_dict):
    pass


# Exercise 3: Add new key-value pair
"""
PRACTICE: Adding to Dictionaries

Write a function `add_system_metric(metrics_dict, metric_name, metric_value)`
that takes a dictionary `metrics_dict`, a `metric_name` string, and a `metric_value`.
It should add/update the `metric_name` with `metric_value` in the dictionary.
The function should return the modified dictionary.
Example: add_system_metric({"cpu": 45}, "memory", 60) returns {"cpu": 45, "memory": 60}
"""
# TODO: Implement the function add_system_metric
def add_system_metric(metrics_dict, metric_name, metric_value):
    pass


# Exercise 4: Check if key exists
"""
PRACTICE: Checking Dictionary Keys

Write a function `is_security_feature_enabled(config_dict, feature_name)`
that takes a dictionary `config_dict` and a `feature_name` string.
It should return True if `feature_name` exists as a key in `config_dict` AND its value is True.
Otherwise, it should return False.
Example: is_security_feature_enabled({"firewall": True, "antivirus": False}, "firewall") returns True
         is_security_feature_enabled({"firewall": True, "antivirus": False}, "antivirus") returns False
         is_security_feature_enabled({"firewall": True}, "backup") returns False
"""
# TODO: Implement the function is_security_feature_enabled
def is_security_feature_enabled(config_dict, feature_name):
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Comprehensive Security Management System
# ============================================================================
"""
COMPREHENSIVE SECURITY MANAGEMENT DASHBOARD

You are developing a centralized security management dashboard that organizes complex
security data using structured information systems. The dashboard needs to track user
accounts, system health, and security tool configurations.

TASK 1: USER ACCOUNT DATABASE CREATION
Create `user_database`: a dictionary where keys are usernames (e.g., "alice_admin")
and values are dictionaries with "role", "last_login", "failed_attempts", "active" status.
Users:
- Alice: "admin" role, last login "2023-10-01", 0 failed attempts, active.
- Bob: "analyst" role, last login "2023-09-30", 2 failed attempts, active.
- Charlie: "guest" role, last login "2023-09-25", 5 failed attempts, inactive.

TASK 2: SYSTEM INFRASTRUCTURE STATUS
Create `system_status`: a dictionary where keys are system names (e.g., "web_server")
and values are dictionaries with "cpu_usage", "memory_usage", "disk_usage", "status".
Systems:
- Web server: 75% CPU, 60% memory, 45% disk, "healthy" status.
- Database server: 90% CPU, 85% memory, 70% disk, "warning" status.
- Backup server: 25% CPU, 30% memory, 95% disk, "critical" status.

TASK 3: SECURITY TOOLS CONFIGURATION
Create `security_tools`: a dictionary where keys are tool names (e.g., "firewall")
and values are dictionaries with their specific configurations.
Tools:
- Firewall: "enabled": True, "rules": 150, "last_updated": "2023-10-01", "alerts": 3
- Antivirus: "enabled": True, "definitions_date": "2023-09-30", "last_scan": "2023-10-01", "threats_found": 0
- IDS: "enabled": False, "sensors": 5, "last_alert_date": "2023-09-28", "total_alerts": 12

TASK 4: SECURITY OPERATIONS (Modify the dictionaries created above)
4.1. Add new user "david_manager" to `user_database`: "manager" role, last login "2023-10-02", 1 failed attempt, active.
4.2. Update "bob_analyst" in `user_database`: reset "failed_attempts" to 0.
4.3. Check if "eve_hacker" exists in `user_database`. Store boolean result in `eve_hacker_present`.
4.4. Create `users_needing_attention`: a list of usernames from `user_database` with `failed_attempts > 0` OR `active` is False.

TASK 5: SYSTEM MONITORING OPERATIONS
5.1. Create `high_cpu_systems_names`: a list of system names from `system_status` with `cpu_usage > 80%`.
5.2. Update "web_server" in `system_status`: change its "status" to "optimal".
5.3. Calculate `average_system_disk_usage`: average "disk_usage" of all systems. If no systems, 0.0.
5.4. Create `systems_with_issues`: a list of system names from `system_status` where status is "warning" or "critical".

TASK 6: SECURITY TOOLS ANALYSIS
6.1. Create `active_security_tools_names`: a list of names of tools from `security_tools` that are "enabled".
6.2. Find the tool with the most alerts (consider "alerts", "total_alerts", or "threats_found" - use the one that exists and is highest). Store its name in `tool_with_highest_alerts` (or None if no alerts).
6.3. Update "ids" in `security_tools`: set "enabled" to True.

TASK 7: COMPREHENSIVE SECURITY REPORT DATA
Create `security_report_data` (a dictionary) with the following keys and calculated values:
- "total_active_users": count of users where "active" is True.
- "systems_in_critical_state": count of systems with "critical" status.
- "ids_status_updated": boolean, True if IDS "enabled" is now True, False otherwise.
- "users_to_investigate_count": length of `users_needing_attention`.
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Create User Management Dictionary
# user_database = ?

# PART 2: Create System Status Dictionary
# system_status = ?

# PART 3: Create Security Tools Configuration
# security_tools = ?

# PART 4: User Management Operations
# Perform operations on user_database
# eve_hacker_present = ?
# users_needing_attention = ?

# PART 5: System Monitoring Operations
# Perform operations on system_status
# high_cpu_systems_names = ?
# average_system_disk_usage = ?
# systems_with_issues = ?

# PART 6: Security Tools Analysis
# Perform operations on security_tools
# active_security_tools_names = ?
# tool_with_highest_alerts = ?

# PART 7: Comprehensive Security Report Data
# security_report_data = ?


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_dictionaries():
    """Test the warm-up dictionary functions."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0
    # Test 1
    try:
        expected = {"name": "web-server", "port": 80, "active": True}
        assert create_server_details() == expected, "Warm-up 1 Failed"
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}")
    # Test 2
    try:
        user_data = {"username": "admin", "role": "administrator"}
        assert get_user_info(user_data) == ("admin", "administrator"), "Warm-up 2 Failed: Valid user"
        assert get_user_info({"username": "guest"}) == ("guest", "N/A"), "Warm-up 2 Failed: Missing role"
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}")
    # Test 3
    try:
        assert add_system_metric({"cpu": 45}, "memory", 60) == {"cpu": 45, "memory": 60}, "Warm-up 3 Failed: Add new"
        assert add_system_metric({"cpu": 45}, "cpu", 55) == {"cpu": 55}, "Warm-up 3 Failed: Update existing"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}")
    # Test 4
    try:
        config = {"firewall": True, "antivirus": False, "logging": True}
        assert is_security_feature_enabled(config, "firewall") is True, "Warm-up 4 Failed: firewall True"
        assert is_security_feature_enabled(config, "antivirus") is False, "Warm-up 4 Failed: antivirus False"
        assert is_security_feature_enabled(config, "backup") is False, "Warm-up 4 Failed: backup missing"
        print("✅ Warm-up 4 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_exercise_dictionaries():
    """Test function to verify your main exercise dictionary operations are correct."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # Check initial dictionary creations (existence and basic structure)
    try:
        assert isinstance(user_database, dict) and "alice_admin" in user_database
        assert isinstance(system_status, dict) and "web_server" in system_status
        assert isinstance(security_tools, dict) and "firewall" in security_tools
        print("✅ Initial Dictionaries: Basic structure OK.")
    except (NameError, AssertionError) as e:
        print(f"❌ ERROR: Initial dictionaries not defined or basic content wrong - {e}")
        return False # Critical failure

    # TASK 4 Tests
    try:
        assert "david_manager" in user_database and user_database["david_manager"]["role"] == "manager", "TASK 4.1: david_manager not added or incorrect."
        assert user_database["bob_analyst"]["failed_attempts"] == 0, "TASK 4.2: bob_analyst's failed_attempts not reset."
        assert eve_hacker_present is False, "TASK 4.3: eve_hacker_present should be False."
        # Expected: Charlie (5 failed), David (1 failed)
        expected_attention = sorted(["charlie_guest", "david_manager"])
        assert sorted(users_needing_attention) == expected_attention, f"TASK 4.4: users_needing_attention incorrect. Expected {expected_attention}, got {sorted(users_needing_attention)}."
        print("✅ TASK 4 (User Ops): PASSED")
    except (NameError, AssertionError, KeyError) as e:
        print(f"❌ TASK 4 (User Ops): FAILED - {e}")
        main_passed = False

    # TASK 5 Tests
    try:
        assert sorted(high_cpu_systems_names) == sorted(["database_server"]), "TASK 5.1: high_cpu_systems_names incorrect."
        assert system_status["web_server"]["status"] == "optimal", "TASK 5.2: web_server status not updated."
        # disk usages: web=45, db=70, backup=95. Sum=210. Avg=70.0
        assert abs(average_system_disk_usage - 70.0) < 0.001, f"TASK 5.3: average_system_disk_usage incorrect. Expected 70.0, Got {average_system_disk_usage}"
        expected_issues = sorted(["database_server", "backup_server"])
        assert sorted(systems_with_issues) == expected_issues, "TASK 5.4: systems_with_issues incorrect."
        print("✅ TASK 5 (System Monitoring): PASSED")
    except (NameError, AssertionError, KeyError, TypeError) as e:
        print(f"❌ TASK 5 (System Monitoring): FAILED - {e}")
        main_passed = False

    # TASK 6 Tests
    try:
        assert security_tools["ids"]["enabled"] is True, "TASK 6.3: IDS 'enabled' status not updated to True." # Check update first
        expected_active_tools = sorted(["firewall", "antivirus", "ids"]) # After update
        assert sorted(active_security_tools_names) == expected_active_tools, "TASK 6.1: active_security_tools_names incorrect."
        # Firewall: 3, Antivirus: 0 (threats_found), IDS: 12 (total_alerts)
        assert tool_with_highest_alerts == "ids", f"TASK 6.2: tool_with_highest_alerts incorrect. Expected 'ids', got {tool_with_highest_alerts}."
        print("✅ TASK 6 (Security Tools): PASSED")
    except (NameError, AssertionError, KeyError) as e:
        print(f"❌ TASK 6 (Security Tools): FAILED - {e}")
        main_passed = False

    # TASK 7 Tests
    try:
        assert isinstance(security_report_data, dict), "TASK 7: security_report_data should be a dictionary."
        # Expected: Alice, Bob, David are active = 3
        assert security_report_data.get("total_active_users") == 3, "TASK 7: total_active_users incorrect."
        # Expected: backup_server
        assert security_report_data.get("systems_in_critical_state") == 1, "TASK 7: systems_in_critical_state incorrect."
        assert security_report_data.get("ids_status_updated") is True, "TASK 7: ids_status_updated incorrect."
        # Expected: Charlie, David
        assert security_report_data.get("users_to_investigate_count") == 2, "TASK 7: users_to_investigate_count incorrect."
        print("✅ TASK 7 (Report Data): PASSED")
    except (NameError, AssertionError, KeyError, TypeError) as e:
        print(f"❌ TASK 7 (Report Data): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 MAIN EXERCISE: All core logic tests passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some core logic tests failed.")
    return main_passed

def run_all_tests():
    warmup_ok = test_warmup_dictionaries()
    main_ok = test_main_exercise_dictionaries()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python dictionaries!")
        print("Ready for Module 7: Functions")
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")

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
