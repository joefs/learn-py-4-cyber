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

print("=== CREATING AND ACCESSING DICTIONARIES ===")
print()

# Creating dictionaries
user_permissions = {
    "admin": "full_access",
    "manager": "read_write",
    "analyst": "read_only",
    "guest": "no_access"
}

server_status = {
    "web-server-01": "online",
    "db-server-01": "offline",
    "mail-server-01": "online",
    "backup-server-01": "maintenance"
}

vulnerability_info = {
    "CVE-2023-1234": {"score": 9.8, "severity": "critical"},
    "CVE-2023-5678": {"score": 6.2, "severity": "medium"},
    "CVE-2023-9012": {"score": 8.1, "severity": "high"}
}

print("Dictionary Examples:")
print(f"User permissions: {user_permissions}")
print(f"Server status: {server_status}")
print(f"Vulnerability info: {vulnerability_info}")
print()

# Accessing dictionary values
print("Accessing Dictionary Values:")
print(f"Admin permissions: {user_permissions['admin']}")
print(f"Web server status: {server_status['web-server-01']}")
print()

# Safe access with get() method
print("Safe Access with get():")
print(f"Unknown user permissions: {user_permissions.get('unknown_user', 'not_found')}")
print(f"Test server status: {server_status.get('test-server', 'not_monitored')}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Adding, Updating, and Removing Items
# ============================================================================

print("=== MODIFYING DICTIONARIES ===")
print()

# Starting with security alerts
security_alerts = {
    "2023-10-01 09:15": "Failed login attempt",
    "2023-10-01 09:20": "Suspicious file download",
    "2023-10-01 09:25": "Port scan detected"
}

print(f"Initial alerts: {security_alerts}")

# Adding new items
security_alerts["2023-10-01 09:30"] = "Malware signature detected"
print(f"After adding alert: {security_alerts}")

# Updating existing items
security_alerts["2023-10-01 09:15"] = "Failed login attempt - Account locked"
print(f"After updating alert: {security_alerts}")

# Removing items
removed_alert = security_alerts.pop("2023-10-01 09:20")
print(f"Removed alert: {removed_alert}")
print(f"After removal: {security_alerts}")

# Using del to remove items
del security_alerts["2023-10-01 09:25"]
print(f"After del: {security_alerts}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Dictionary Methods
# ============================================================================

print("=== DICTIONARY METHODS ===")
print()

# Working with firewall rules
firewall_rules = {
    "rule_001": {"action": "allow", "port": 80, "protocol": "tcp"},
    "rule_002": {"action": "deny", "port": 23, "protocol": "tcp"},
    "rule_003": {"action": "allow", "port": 443, "protocol": "tcp"},
    "rule_004": {"action": "deny", "port": 21, "protocol": "tcp"}
}

print("Firewall Rules Analysis:")
print(f"All rules: {firewall_rules}")
print()

# Dictionary methods
print("Dictionary Methods:")
print(f"All rule names (keys): {list(firewall_rules.keys())}")
print(f"All rule details (values): {list(firewall_rules.values())}")
print(f"All rule items: {list(firewall_rules.items())}")
print()

# Checking for keys
rule_to_check = "rule_002"
if rule_to_check in firewall_rules:
    print(f"✅ Rule {rule_to_check} exists: {firewall_rules[rule_to_check]}")
else:
    print(f"❌ Rule {rule_to_check} not found")
print()

# ============================================================================
# CONCEPT EXPLANATION: Iterating Through Dictionaries
# ============================================================================

print("=== ITERATING THROUGH DICTIONARIES ===")
print()

# Network device inventory
network_inventory = {
    "192.168.1.1": {"device": "router", "vendor": "Cisco", "model": "ISR4331"},
    "192.168.1.2": {"device": "switch", "vendor": "HP", "model": "2530-24G"},
    "192.168.1.10": {"device": "firewall", "vendor": "Fortinet", "model": "FortiGate-60E"},
    "192.168.1.100": {"device": "server", "vendor": "Dell", "model": "PowerEdge R740"}
}

# Iterate through keys
print("Network Devices by IP:")
for ip in network_inventory:
    print(f"  {ip}: {network_inventory[ip]['device']}")
print()

# Iterate through key-value pairs
print("Detailed Network Inventory:")
for ip, details in network_inventory.items():
    print(f"IP: {ip}")
    print(f"  Device: {details['device']}")
    print(f"  Vendor: {details['vendor']}")
    print(f"  Model: {details['model']}")
    print()

# ============================================================================
# CONCEPT EXPLANATION: Nested Dictionaries
# ============================================================================

print("=== NESTED DICTIONARIES ===")
print()

# Complex security configuration
security_config = {
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

print("Security Configuration:")
print(f"Authentication method: {security_config['authentication']['method']}")
print(f"Password min length: {security_config['authentication']['password_policy']['min_length']}")
print(f"Firewall enabled: {security_config['network_security']['firewall']['enabled']}")
print(f"IDS sensitivity: {security_config['network_security']['intrusion_detection']['sensitivity']}")
print()

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

print("=== CYBERSECURITY DICTIONARY EXAMPLES ===")

# Security incident management system
incident_database = {
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

print("Active Security Incidents:")
for incident_id, details in incident_database.items():
    status_icon = "🔴" if details["severity"] == "critical" else "🟡" if details["severity"] == "high" else "🟢"
    print(f"{status_icon} {incident_id}: {details['title']}")
    print(f"   Severity: {details['severity']} | Status: {details['status']}")
    print(f"   Assigned to: {details['assigned_to']} | Users affected: {details['affected_users']}")
print()

# Network security monitoring
network_monitoring = {
    "traffic_analysis": {"status": "active", "alerts": 3, "last_update": "2023-10-01 16:30"},
    "intrusion_detection": {"status": "active", "alerts": 1, "last_update": "2023-10-01 16:28"},
    "vulnerability_scan": {"status": "scheduled", "alerts": 0, "last_update": "2023-10-01 12:00"},
    "log_analysis": {"status": "active", "alerts": 7, "last_update": "2023-10-01 16:32"}
}

print("Network Security Monitoring Dashboard:")
for service, info in network_monitoring.items():
    status_icon = "✅" if info["status"] == "active" else "⏰" if info["status"] == "scheduled" else "❌"
    alert_text = f"({info['alerts']} alerts)" if info['alerts'] > 0 else ""
    print(f"{status_icon} {service.replace('_', ' ').title()}: {info['status']} {alert_text}")
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Using Dictionaries
# ============================================================================

# Exercise 1: Create a simple dictionary
"""
PRACTICE: Basic Dictionary Creation

Your server monitoring system needs to track detailed server information.
Create a dictionary called server_info containing server details:
- "name" with value "web-server" for server identification
- "port" with value 80 for service port tracking
- "active" with value True for operational status

Display this structured server data for infrastructure management.
"""
# TODO: Create dictionary server_info and print it


# Exercise 2: Access dictionary values
"""
PRACTICE: Accessing Dictionary Values

Your user management system stores account information in structured format.
Create a dictionary user containing {"username": "admin", "role": "administrator", "logged_in": True}.
Access and display the username and role values using dictionary key lookup.
This demonstrates how to retrieve specific account details for security verification.
"""
# TODO: Create dictionary user and access username and role values


# Exercise 3: Add new key-value pair
"""
PRACTICE: Adding to Dictionaries

Your system monitoring dashboard tracks resource utilization metrics.
Create a dictionary system starting with {"cpu": 45, "memory": 60} for current usage percentages.
Add "disk": 30 to track disk utilization alongside existing metrics.
Display the updated monitoring data for comprehensive system analysis.
"""
# TODO: Create dictionary system, add "disk": 30, print updated dictionary


# Exercise 4: Check if key exists
"""
PRACTICE: Checking Dictionary Keys

Your security configuration system verifies that required protection measures are configured.
Create a dictionary config containing {"firewall": True, "antivirus": True} for security settings.
Check if "firewall" configuration exists and display appropriate status message.
Check if "backup" configuration exists and display appropriate status message.
This ensures all critical security components are properly configured.
"""
# TODO: Create dictionary config and check for "firewall" and "backup" keys


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build a Comprehensive Security Management System
# ============================================================================
"""
COMPREHENSIVE SECURITY MANAGEMENT DASHBOARD

You are developing a centralized security management dashboard that organizes complex 
security data using structured information systems. The dashboard needs to track user 
accounts, system health, and security tool configurations.

USER ACCOUNT MANAGEMENT:
Your organization has several user accounts with different access levels and activity status:

Alice (admin role) - administrator who last logged in on 2023-10-01, has 0 failed login 
attempts, and is currently active.

Bob (analyst role) - security analyst who last logged in on 2023-09-30, has 2 failed 
login attempts, and is currently active.

Charlie (guest role) - guest user who last logged in on 2023-09-25, has 5 failed login 
attempts, and is currently inactive.

Create a user database named user_database that stores each user's information including 
their role, last login date, failed attempt count, and active status.

SYSTEM INFRASTRUCTURE MONITORING:
You need to monitor three critical systems:

Web server - running at 75% CPU, 60% memory, 45% disk usage, with "healthy" status
Database server - running at 90% CPU, 85% memory, 70% disk usage, with "warning" status  
Backup server - running at 25% CPU, 30% memory, 95% disk usage, with "critical" status

Create a system status tracker named system_status that stores each system's resource 
utilization and operational status.

SECURITY TOOLS CONFIGURATION:
Your security infrastructure includes several tools:

Firewall - enabled, has 150 rules, last updated 2023-10-01, generated 3 alerts
Antivirus - enabled, definitions dated 2023-09-30, last scan 2023-10-01, found 0 threats
Intrusion Detection System - disabled, has 5 sensors, last alert 2023-09-28, 12 total alerts

Create a security tools configuration named security_tools that tracks each tool's 
operational status and key metrics.

SECURITY OPERATIONS TASKS:
1. Add a new manager user named David who logged in today with 1 failed attempt
2. Reset Bob's failed login attempts to 0 after investigation
3. Check if any unauthorized user "eve_hacker" has accessed the system
4. Generate reports on system performance, security tool status, and user activity
5. Provide an overall security assessment with recommendations
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== COMPREHENSIVE SECURITY MANAGEMENT SYSTEM ===")
print()

# PART 1: Create User Management Dictionary
# TODO: Create user_database dictionary with specified users and their details

# PART 2: Create System Status Dictionary
# TODO: Create system_status dictionary with specified systems and their metrics

# PART 3: Create Security Tools Configuration
# TODO: Create security_tools dictionary with specified tools and their configurations

print("1. USER MANAGEMENT OPERATIONS:")
print("-" * 40)
# PART 4: User Management Operations
# TODO: Add new user, update existing user, check for user, print users with failed attempts
# TODO: Add "david_manager" user to user_database
# TODO: Update bob_analyst's failed_attempts to 0
# TODO: Check if "eve_hacker" exists in user_database
# TODO: Print users with failed_attempts > 0

print("2. SYSTEM MONITORING:")
print("-" * 40)
# PART 5: System Monitoring
# TODO: Find high CPU systems, update status, calculate average disk usage, find systems needing attention
print("Systems with CPU usage > 80%:")
for system, details in system_status.items():
    if details["cpu_usage"] > 80:
        print(f"  {system}: {details['cpu_usage']}% CPU usage")

system_status["web_server"]["status"] = "optimal"

total_disk_usage = sum(details["disk_usage"] for details in system_status.values())
average_disk_usage = total_disk_usage / len(system_status)
print(f"\nAverage disk usage across all systems: {average_disk_usage:.1f}%")

print("\nSystems requiring attention:")
for system, details in system_status.items():
    if details["status"] in ["warning", "critical"]:
        print(f"  {system}: {details['status'].upper()} status")
print()

print("3. SECURITY TOOLS ANALYSIS:")
print("-" * 40)
# PART 6: Security Tools Analysis
# TODO: Check enabled tools, find tool with most alerts, update IDS, print summary
print("Enabled security tools:")
for tool, details in security_tools.items():
    if details["enabled"]:
        print(f"  ✅ {tool}")
    else:
        print(f"  ❌ {tool} (disabled)")

# Find tool with most alerts
max_alerts = 0
max_alerts_tool = ""
for tool, details in security_tools.items():
    alerts = details.get("alerts", details.get("alert_count", 0))
    if alerts > max_alerts:
        max_alerts = alerts
        max_alerts_tool = tool

print(f"\nTool with most alerts: {max_alerts_tool} ({max_alerts} alerts)")

security_tools["ids"]["enabled"] = True
print("✅ IDS has been enabled")
print()

print("4. COMPREHENSIVE SECURITY REPORT:")
print("-" * 40)
# PART 7: Security Report
# TODO: Create comprehensive security report
active_users = sum(1 for user in user_database.values() if user["active"])
inactive_users = len(user_database) - active_users

critical_systems = [system for system, details in system_status.items() if details["status"] in ["warning", "critical"]]
enabled_tools = [tool for tool, details in security_tools.items() if details["enabled"]]

print("📊 SECURITY POSTURE SUMMARY:")
print(f"   User Accounts: {active_users} active, {inactive_users} inactive")
print(f"   Critical Systems: {len(critical_systems)} requiring attention")
if critical_systems:
    print(f"      - {', '.join(critical_systems)}")
print(f"   Security Tools: {len(enabled_tools)}/{len(security_tools)} enabled")
print(f"      - Active: {', '.join(enabled_tools)}")

# Overall assessment
if len(critical_systems) == 0 and len(enabled_tools) == len(security_tools) and inactive_users == 0:
    overall_status = "EXCELLENT"
    status_icon = "🟢"
elif len(critical_systems) <= 1 and len(enabled_tools) >= 2:
    overall_status = "GOOD"
    status_icon = "🟡"
else:
    overall_status = "NEEDS ATTENTION"
    status_icon = "🔴"

print(f"\n{status_icon} Overall Security Posture: {overall_status}")

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_dictionaries():
    """Test function to verify your dictionary operations are correct."""
    
    try:
        # Test Part 1: User database creation
        expected_users = {"alice_admin", "bob_analyst", "charlie_guest", "david_manager"}
        actual_users = set(user_database.keys())
        assert actual_users == expected_users, f"user_database should have users {expected_users}, got {actual_users}"
        print("✅ Test 1 PASSED: user_database created correctly")
        
        # Test Part 2: System status creation
        expected_systems = {"web_server", "database_server", "backup_server"}
        actual_systems = set(system_status.keys())
        assert actual_systems == expected_systems, f"system_status should have systems {expected_systems}, got {actual_systems}"
        print("✅ Test 2 PASSED: system_status created correctly")
        
        # Test Part 3: Security tools creation
        expected_tools = {"firewall", "antivirus", "ids"}
        actual_tools = set(security_tools.keys())
        assert actual_tools == expected_tools, f"security_tools should have tools {expected_tools}, got {actual_tools}"
        print("✅ Test 3 PASSED: security_tools created correctly")
        
        # Test Part 4: User management operations
        assert "david_manager" in user_database, "david_manager should be added to user_database"
        assert user_database["bob_analyst"]["failed_attempts"] == 0, "bob_analyst's failed_attempts should be updated to 0"
        print("✅ Test 4 PASSED: user management operations completed")
        
        # Test Part 5: System monitoring
        assert system_status["web_server"]["status"] == "optimal", "web_server status should be updated to 'optimal'"
        print("✅ Test 5 PASSED: system monitoring operations completed")
        
        # Test Part 6: Security tools analysis
        assert security_tools["ids"]["enabled"] == True, "IDS should be enabled"
        print("✅ Test 6 PASSED: security tools analysis completed")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python dictionaries!")
        print("Ready for Module 7: Functions")
        
    except NameError as e:
        print(f"❌ ERROR: Variable not found - {e}")
        print("Make sure you've created all required dictionaries.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your dictionary operations and try again.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_dictionaries()

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
