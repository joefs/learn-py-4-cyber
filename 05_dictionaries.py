"""
====================================================================
MODULE 5: DICTIONARIES - Organizing Complex Security Data 🗂️
====================================================================

Welcome to Module 5! You've mastered lists for storing collections of data.
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

# Initialize global variables for warmup outputs
server_info_warmup1 = {}
warmup2_username = ""
warmup2_role = ""
system_warmup3_modified = {}
warmup4_firewall_exists = None
warmup4_backup_exists = None


# Exercise 1: Create a simple dictionary
"""
PRACTICE: Server Profile

You need to store basic information about a server. This information includes its name,
the port it primarily listens on, and whether it's currently active.
Specifically, the server is named "web-server", operates on port 80, and is active (True).
Represent this information as a collection of labeled data.

(Store this collection in a global variable named `server_info_warmup1` for checking.)
"""
# TODO: Create a dictionary with keys "name", "port", "active" and their respective values.
# TODO: Assign this dictionary to `server_info_warmup1`.


# Exercise 2: Access dictionary values
"""
PRACTICE: User Details Retrieval

You have a record for a user containing their username, role, and login status:
username is "admin", role is "administrator", and logged_in is True.
From this record, you need to extract the username and the role.
If a piece of information might be missing, your retrieval should gracefully
default to "N/A".

(Create a dictionary `user_warmup2` with this user's data.
Store the extracted username in `warmup2_username`.
Store the extracted role in `warmup2_role`.)
"""
# TODO: Create `user_warmup2` with "username", "role", "logged_in" keys and values.
# TODO: Access the "username" and assign it to `warmup2_username`.
# TODO: Access the "role" and assign it to `warmup2_role`. (Consider using .get() for safety, though not strictly required by test if keys are guaranteed).


# Exercise 3: Add new key-value pair
"""
PRACTICE: System Resource Monitoring Update

Your system monitoring dashboard currently tracks CPU usage (45%) and memory usage (60%).
You now also need to start tracking disk usage, which is currently at 30%.
Add this new piece of information (disk usage) to your existing system metrics.

(Start with a dictionary `system_warmup3` for CPU and memory.
Add the "disk" usage to it. Store the final, updated dictionary in
`system_warmup3_modified`.)
"""
# TODO: Create `system_warmup3` with "cpu" and "memory" usage.
# TODO: Add a new key "disk" with its value to this dictionary.
# TODO: Assign the modified dictionary to `system_warmup3_modified`.


# Exercise 4: Check if key exists
"""
PRACTICE: Configuration Verification

You have a security configuration that specifies whether the firewall is enabled (True)
and if antivirus is active (True). You need to verify two things:
1. Is there a setting for "firewall" in your configuration?
2. Is there a setting for "backup" in your configuration?
Record the true/false answers to these questions.

(Create `config_warmup4` with "firewall" and "antivirus" settings.
Store the boolean result of checking for "firewall" in `warmup4_firewall_exists`.
Store the boolean result of checking for "backup" in `warmup4_backup_exists`.)
"""
# TODO: Create `config_warmup4` with "firewall" and "antivirus" settings.
# TODO: Check if "firewall" key exists and assign result to `warmup4_firewall_exists`.
# TODO: Check if "backup" key exists and assign result to `warmup4_backup_exists`.


# ============================================================================
# YOUR MAIN EXERCISE: Build a Comprehensive Security Management System
# ============================================================================
"""
CHALLENGE: COMPREHENSIVE SECURITY MANAGEMENT DASHBOARD

You're designing a system to manage and report on various security aspects of an organization.
This involves creating structured data for user accounts, system health, and security tools,
and then performing operations and analysis on this data.

TASK 1: USER ACCOUNT DATABASE CREATION
   Establish a database (as a dictionary) for user accounts. Each username should map to
   another dictionary holding their details: "role", "last_login" date (YYYY-MM-DD string),
   number of "failed_attempts", and an "active" status (boolean).
   Populate it with:
   - Username "alice_admin": role "admin", last login "2023-10-01", 0 failed attempts, active.
   - Username "bob_analyst": role "analyst", last login "2023-09-30", 2 failed attempts, active.
   - Username "charlie_guest": role "guest", last login "2023-09-25", 5 failed attempts, inactive.
   (This entire structure should be stored in the global variable `user_database`.)

TASK 2: SYSTEM INFRASTRUCTURE STATUS
   Create a dictionary to track the status of key systems. Each system name should map to
   a dictionary detailing its "cpu_usage" (percentage), "memory_usage" (percentage),
   "disk_usage" (percentage), and overall "status" (string like "healthy", "warning", "critical").
   Include these systems:
   - "web_server": 75% CPU, 60% memory, 45% disk, status "healthy".
   - "database_server": 90% CPU, 85% memory, 70% disk, status "warning".
   - "backup_server": 25% CPU, 30% memory, 95% disk, status "critical".
   (Store this in the global variable `system_status`.)

TASK 3: SECURITY TOOLS CONFIGURATION
   Maintain a configuration inventory for security tools. Each tool name should map to
   a dictionary of its settings.
   Configure the following:
   - "firewall": "enabled" (True), "rules" (150), "last_updated" ("2023-10-01"), "alerts" (3).
   - "antivirus": "enabled" (True), "definitions_date" ("2023-09-30"), "last_scan" ("2023-10-01"), "threats_found" (0).
   - "ids" (Intrusion Detection System): "enabled" (False), "sensors" (5), "last_alert_date" ("2023-09-28"), "total_alerts" (12).
   (Store this inventory in the global variable `security_tools`.)

TASK 4: SECURITY OPERATIONS ON USER ACCOUNTS
   Perform the following updates and checks on the `user_database` created in TASK 1:
   4.1. A new user, "david_manager", joins. Add their record: role "manager", last login "2023-10-02", 1 failed attempt, active.
   4.2. "bob_analyst" successfully logged in. Update their record to show 0 "failed_attempts".
   4.3. Investigate if a user named "eve_hacker" exists in the database.
        (Store the boolean result in `main_eve_hacker_exists`.)
   4.4. Identify users requiring attention: list all usernames who have more than 0 "failed_attempts" OR are "active" is False.
        (Store this list of usernames in `main_users_needing_attention`.)

TASK 5: SYSTEM MONITORING OPERATIONS
   Using the `system_status` data from TASK 2:
   5.1. List all systems where "cpu_usage" is greater than 80%.
        (Store this list of system names in `main_high_cpu_systems`.)
   5.2. The "web_server" has been optimized. Update its "status" to "optimal".
   5.3. Calculate the average "disk_usage" across all monitored systems. If there are no systems, the average is 0.0.
        (Store this average in `main_average_disk_usage`.)
   5.4. Compile a list of systems whose status is either "warning" or "critical".
        (Store this list of system names in `main_attention_systems`.)

TASK 6: SECURITY TOOLS ANALYSIS
   Based on the `security_tools` configuration from TASK 3:
   6.1. List all security tools that are currently "enabled".
        (Store this list of tool names in `main_enabled_tools`.)
   6.2. Determine which tool has generated the most alerts. Consider the "alerts" field for the firewall,
        "threats_found" for antivirus, and "total_alerts" for IDS. If multiple tools share the max, any one is fine.
        If no tools have alerts or relevant fields, this can be None.
        (Store the name of the tool with the most alerts in `main_tool_max_alerts`.)
   6.3. The "ids" tool is now being activated. Update its configuration to set "enabled" to True.

TASK 7: COMPREHENSIVE SECURITY REPORT DATA
   Aggregate key information into a final report dictionary.
   Create `report_data_dict` with these specific keys and their corresponding values derived from the (now updated) data:
   - "total_active_users": The number of users in `user_database` who are currently "active".
   - "critical_system_count": The number of systems in `system_status` marked with "critical" status.
   - "ids_final_status_enabled": A boolean indicating if the "ids" in `security_tools` is enabled after the update in TASK 6.
   - "attention_user_count": The number of users identified in `main_users_needing_attention`.
   - "overall_system_health_string": A general assessment string ("EXCELLENT", "GOOD", or "NEEDS ATTENTION") based on this logic:
        - "EXCELLENT": If there are no critical systems, all security tools are enabled, and all users are active.
        - "GOOD": If there is at most 1 critical system AND at least 2 security tools are enabled.
        - "NEEDS ATTENTION": For all other conditions.

Ensure all results are stored in the specified global variables for automated checking.
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Create User Management Dictionary
# user_database = ?

# PART 2: Create System Status Dictionary
# system_status = ?

# PART 3: Create Security Tools Configuration
# security_tools = ?

# Initialize global variables for main exercise results from operations
main_eve_hacker_exists = None
main_users_needing_attention = []
main_high_cpu_systems = []
main_average_disk_usage = 0.0
main_attention_systems = []
main_enabled_tools = []
main_tool_max_alerts = None
report_data_dict = {}


# PART 4: User Management Operations
# Perform operations on user_database defined in PART 1
# Assign to main_eve_hacker_exists, main_users_needing_attention

# PART 5: System Monitoring Operations
# Perform operations on system_status defined in PART 2
# Assign to main_high_cpu_systems, main_average_disk_usage, main_attention_systems

# PART 6: Security Tools Analysis
# Perform operations on security_tools defined in PART 3
# Assign to main_enabled_tools, main_tool_max_alerts

# PART 7: Comprehensive Security Report Data
# Populate report_data_dict


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_dictionaries(): # Renamed from test_dictionaries
    """Test the warm-up dictionary exercises."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0
    # Test 1
    try:
        expected = {"name": "web-server", "port": 80, "active": True}
        assert server_info_warmup1 == expected, "Warmup 1 Failed"
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}")
    # Test 2
    try:
        assert warmup2_username == "admin", "Warmup 2 Failed: Username"
        assert warmup2_role == "administrator", "Warmup 2 Failed: Role"
        # Test .get() with missing key implicitly by checking default if user_warmup2 was empty
        # For a direct test of .get(), the setup would need to ensure a key is missing.
        # This test assumes user_warmup2 was created as specified.
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}")
    # Test 3
    try:
        expected_system = {"cpu": 45, "memory": 60, "disk": 30}
        assert system_warmup3_modified == expected_system, "Warmup 3 Failed"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}")
    # Test 4
    try:
        assert warmup4_firewall_exists is True, "Warmup 4 Failed: Firewall check"
        assert warmup4_backup_exists is False, "Warmup 4 Failed: Backup check"
        print("✅ Warm-up 4 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_exercise_dictionaries(): # Renamed
    """Test function to verify your main exercise dictionary operations are correct."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # Check initial dictionary creations (existence and basic structure)
    try:
        assert isinstance(user_database, dict) and "alice_admin" in user_database, "Initial user_database not correct."
        assert isinstance(system_status, dict) and "web_server" in system_status, "Initial system_status not correct."
        assert isinstance(security_tools, dict) and "firewall" in security_tools, "Initial security_tools not correct."
        print("✅ Initial Dictionaries: Basic structure OK.")
    except (NameError, AssertionError) as e:
        print(f"❌ ERROR: Initial dictionaries not defined or basic content wrong - {e}")
        return False # Critical failure

    # TASK 4 Tests
    try:
        assert "david_manager" in user_database and user_database["david_manager"]["role"] == "manager", "TASK 4.1: david_manager not added or incorrect."
        assert user_database["bob_analyst"]["failed_attempts"] == 0, "TASK 4.2: bob_analyst's failed_attempts not reset."
        assert main_eve_hacker_exists is False, "TASK 4.3: main_eve_hacker_exists should be False."
        expected_attention_users = sorted(["charlie_guest", "david_manager"]) # Charlie (inactive, 5 attempts), David (1 attempt)
        assert sorted(main_users_needing_attention) == expected_attention_users, f"TASK 4.4: main_users_needing_attention incorrect. Expected {expected_attention_users}, got {sorted(main_users_needing_attention)}."
        print("✅ TASK 4 (User Ops): PASSED")
    except (NameError, AssertionError, KeyError) as e:
        print(f"❌ TASK 4 (User Ops): FAILED - {e}")
        main_passed = False

    # TASK 5 Tests
    try:
        assert sorted(main_high_cpu_systems) == sorted(["database_server"]), "TASK 5.1: main_high_cpu_systems incorrect."
        assert system_status["web_server"]["status"] == "optimal", "TASK 5.2: web_server status not updated."
        expected_avg_disk = (45 + 70 + 95) / 3
        assert abs(main_average_disk_usage - expected_avg_disk) < 0.001, f"TASK 5.3: main_average_disk_usage incorrect. Expected {expected_avg_disk}, Got {main_average_disk_usage}"
        expected_issues_systems = sorted(["database_server", "backup_server"])
        assert sorted(main_attention_systems) == expected_issues_systems, "TASK 5.4: main_attention_systems incorrect."
        print("✅ TASK 5 (System Monitoring): PASSED")
    except (NameError, AssertionError, KeyError, TypeError) as e:
        print(f"❌ TASK 5 (System Monitoring): FAILED - {e}")
        main_passed = False

    # TASK 6 Tests
    try:
        assert security_tools["ids"]["enabled"] is True, "TASK 6.3: IDS 'enabled' status not updated to True."
        expected_active_tools_after_update = sorted(["firewall", "antivirus", "ids"])
        assert sorted(main_enabled_tools) == expected_active_tools_after_update, "TASK 6.1: main_enabled_tools incorrect."
        # Firewall: 3 alerts, Antivirus: 0 threats_found, IDS: 12 total_alerts
        assert main_tool_max_alerts == "ids", f"TASK 6.2: main_tool_max_alerts incorrect. Expected 'ids', got {main_tool_max_alerts}."
        print("✅ TASK 6 (Security Tools): PASSED")
    except (NameError, AssertionError, KeyError) as e:
        print(f"❌ TASK 6 (Security Tools): FAILED - {e}")
        main_passed = False

    # TASK 7 Tests
    try:
        assert isinstance(report_data_dict, dict), "TASK 7: report_data_dict should be a dictionary."
        # Active users: alice, bob, david = 3
        assert report_data_dict.get("total_active_users") == 3, "TASK 7: total_active_users incorrect."
        # Critical systems: backup_server = 1
        assert report_data_dict.get("systems_in_critical_state") == 1, "TASK 7: systems_in_critical_state incorrect."
        assert report_data_dict.get("ids_status_updated") is True, "TASK 7: ids_status_updated incorrect."
        # Attention users: charlie, david = 2
        assert report_data_dict.get("attention_user_count") == 2, "TASK 7: attention_user_count incorrect."
        # Based on current state: 1 critical system, 3 tools enabled, 1 inactive user (Charlie) -> NEEDS ATTENTION
        assert report_data_dict.get("overall_system_health_string") == "NEEDS ATTENTION", "TASK 7: overall_system_health_string incorrect."
        print("✅ TASK 7 (Report Data): PASSED")
    except (NameError, AssertionError, KeyError, TypeError) as e:
        print(f"❌ TASK 7 (Report Data): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 MAIN EXERCISE: All core logic tests passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some core logic tests failed.")
    return main_passed

def run_all_tests(): # Renamed
    warmup_ok = test_warmup_dictionaries()
    main_ok = test_main_exercise_dictionaries()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python dictionaries!")
        print("Ready for Module 6: Loops") # Updated to 6: Loops
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")

# Run the tests
run_all_tests() # Renamed

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

NEXT MODULE: 06_loops.py
In the next module, you'll learn about loops - the powerful feature that
lets you automate repetitive tasks like scanning multiple IP addresses,
processing log files, or checking system status across many servers!

You're developing professional-level programming skills! 🚀🔧
"""
