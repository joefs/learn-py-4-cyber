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

print("=== CREATING AND ACCESSING LISTS ===")
print()

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
print()

# Accessing list items (indexing starts at 0)
print("Accessing List Items:")
print(f"First user: {authorized_users[0]}")
print(f"Second user: {authorized_users[1]}")
print(f"Last user: {authorized_users[-1]}")  # Negative indexing
print(f"Second to last user: {authorized_users[-2]}")
print()

# List length
print(f"Number of authorized users: {len(authorized_users)}")
print(f"Number of open ports: {len(open_ports)}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Adding and Removing Items
# ============================================================================

print("=== ADDING AND REMOVING ITEMS ===")
print()

# Starting with a list of blocked IPs
blocked_ips = ["203.0.113.42", "198.51.100.1"]
print(f"Initial blocked IPs: {blocked_ips}")

# Adding items
blocked_ips.append("192.0.2.146")  # Add to end
print(f"After append: {blocked_ips}")

blocked_ips.insert(1, "10.0.0.255")  # Insert at specific position
print(f"After insert: {blocked_ips}")

# Adding multiple items
new_threats = ["172.16.0.100", "192.168.1.200"]
blocked_ips.extend(new_threats)
print(f"After extend: {blocked_ips}")
print()

# Removing items
print("Removing items:")
removed_ip = blocked_ips.pop()  # Remove and return last item
print(f"Removed last IP: {removed_ip}")
print(f"List after pop: {blocked_ips}")

blocked_ips.remove("10.0.0.255")  # Remove specific item
print(f"After removing specific IP: {blocked_ips}")

del blocked_ips[0]  # Delete by index
print(f"After deleting first item: {blocked_ips}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Searching and Sorting
# ============================================================================

print("=== SEARCHING AND SORTING LISTS ===")
print()

# Searching in lists
security_tools = ["nmap", "wireshark", "metasploit", "burpsuite", "nessus"]
print(f"Security tools: {security_tools}")

# Check if item exists
tool_to_find = "wireshark"
if tool_to_find in security_tools:
    print(f"✅ {tool_to_find} is available")
    position = security_tools.index(tool_to_find)
    print(f"Position of {tool_to_find}: {position}")
else:
    print(f"❌ {tool_to_find} not found")
print()

# Counting occurrences
log_levels = ["INFO", "WARNING", "ERROR", "INFO", "CRITICAL", "INFO", "ERROR"]
print(f"Log levels: {log_levels}")
print(f"INFO messages: {log_levels.count('INFO')}")
print(f"ERROR messages: {log_levels.count('ERROR')}")
print()

# Sorting lists
vulnerability_scores = [7.5, 9.2, 4.1, 8.8, 6.3, 9.9, 2.1]
print(f"Original vulnerability scores: {vulnerability_scores}")

sorted_scores = sorted(vulnerability_scores)  # Create new sorted list
print(f"Sorted scores (ascending): {sorted_scores}")

sorted_scores_desc = sorted(vulnerability_scores, reverse=True)
print(f"Sorted scores (descending): {sorted_scores_desc}")

vulnerability_scores.sort(reverse=True)  # Sort in place
print(f"Original list after in-place sort: {vulnerability_scores}")
print()

# ============================================================================
# CONCEPT EXPLANATION: List Slicing
# ============================================================================

print("=== LIST SLICING ===")
print()

# Working with network addresses
network_devices = ["router", "switch", "firewall", "server", "workstation", "printer", "camera"]
print(f"All devices: {network_devices}")

# Slicing syntax: list[start:end:step]
print(f"First 3 devices: {network_devices[:3]}")
print(f"Last 3 devices: {network_devices[-3:]}")
print(f"Middle devices: {network_devices[2:5]}")
print(f"Every other device: {network_devices[::2]}")
print(f"Reversed list: {network_devices[::-1]}")
print()

# ============================================================================
# CONCEPT EXPLANATION: List Comprehensions (Advanced)
# ============================================================================

print("=== LIST COMPREHENSIONS ===")
print()

# Creating new lists based on existing ones
port_numbers = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995]
print(f"All ports: {port_numbers}")

# Find high-numbered ports (> 1000)
high_ports = [port for port in port_numbers if port > 1000]
print(f"High ports (>1000): {high_ports}")

# Convert to strings with descriptions
port_descriptions = [f"Port {port}" for port in port_numbers[:5]]
print(f"Port descriptions: {port_descriptions}")
print()

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

print("=== CYBERSECURITY LIST EXAMPLES ===")

# Security incident management
incident_priorities = ["Low", "Medium", "High", "Critical"]
active_incidents = [
    "Phishing attempt from external email",
    "Suspicious login from foreign IP",
    "Malware detected on workstation-42",
    "Unauthorized access to admin panel"
]

print("Current Security Incidents:")
for i, incident in enumerate(active_incidents):
    priority = incident_priorities[min(i, len(incident_priorities)-1)]
    print(f"[{priority}] {incident}")
print()

# Network asset management
critical_servers = ["web-server", "database-server", "mail-server", "backup-server"]
server_status = []

print("Server Status Check:")
for server in critical_servers:
    # Simulate status check (in real scenario, this would ping or query the server)
    import random
    status = "ONLINE" if random.choice([True, False]) else "OFFLINE"
    server_status.append(status)
    print(f"{server}: {status}")

offline_servers = [critical_servers[i] for i in range(len(critical_servers)) if server_status[i] == "OFFLINE"]
if offline_servers:
    print(f"⚠️  Servers requiring attention: {offline_servers}")
else:
    print("✅ All critical servers are online")
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Using Lists
# ============================================================================

# Exercise 1: Create and print a simple list
"""
PRACTICE: Basic List Creation

Create a list called devices with three items: "firewall", "router", "switch".
Print the list and its length.
"""
# TODO: Create list and print it


# Exercise 2: Add item to list
"""
PRACTICE: Adding to Lists

Create a list users = ["admin", "guest"].
Add "operator" to the end using append().
Print the updated list.
"""
# TODO: Create list, add item, print


# Exercise 3: Remove item from list
"""
PRACTICE: Removing from Lists

Create a list services = ["web", "mail", "test", "dns"].
Remove "test" using remove().
Print the updated list.
"""
# TODO: Create list, remove item, print


# Exercise 4: Check if item exists in list
"""
PRACTICE: Checking List Membership

Create a list allowed_ports = [22, 80, 443].
Check if port 22 is in the list and print a message.
Check if port 21 is in the list and print a message.
"""
# TODO: Create list and check membership


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

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
a load balancer between the router and switch (at position 2).

Create a list named network_devices with the initial devices, then add the new 
devices as specified. Report the updated device inventory and total count.

USER ACCOUNT MANAGEMENT:
The system currently has these user accounts: admin, user1, user2, and guest. 
For security reasons, the guest account needs to be removed, and two new accounts 
(analyst and manager) need to be added.

Create a list named user_accounts, perform the required changes, and verify that 
the admin account exists in the system.

SECURITY ALERT TRACKING:
Your monitoring system has detected several security incidents that need to be tracked:
- Failed login attempt from IP address 203.0.113.42
- High CPU usage detected on server-01
- Suspicious file detected in downloads folder  
- Firewall rule violation from internal network

Start with an empty list named security_alerts, add each incident, then process 
the alerts by displaying them with reference numbers. Remove the first alert 
after it's been addressed and show the updated alert queue.

VULNERABILITY ASSESSMENT:
Recent vulnerability scans produced these severity scores: 8.5, 6.2, 9.1, 4.3, 7.8. 
You need to prioritize remediation efforts by focusing on high-severity vulnerabilities.

Create a list named vulnerability_scores with this data. Sort the scores to identify 
the most critical vulnerabilities, filter for scores above 7.0 (high severity), 
and calculate the average score to understand overall system risk.

SECURITY DASHBOARD SUMMARY:
Generate a comprehensive summary showing the total count of network devices, 
user accounts, active security alerts, and the highest vulnerability score 
to provide management with a quick security overview.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== SECURITY ASSET MANAGEMENT SYSTEM ===")
print()

# PART 1: Create initial lists
# TODO: Create the 4 lists specified above
# Create network_devices list here

# Create user_accounts list here

# Create security_alerts list here (empty)

# Create vulnerability_scores list here


print("1. DEVICE MANAGEMENT OPERATIONS:")
print("-" * 40)
# PART 2: Device Management Operations
# TODO: Add devices and print results
# Add "intrusion_detection_system" to network_devices using append()

# Insert "load_balancer" at position 2 using insert()

# Print updated network devices and total count

print()

print("2. USER ACCOUNT MANAGEMENT:")
print("-" * 40)
# PART 3: User Account Management
# TODO: Modify user accounts and check admin presence
# Remove "guest" from user_accounts

# Add ["analyst", "manager"] to user_accounts using extend()

# Print all user accounts

# Check if "admin" is in user_accounts and print appropriate message

print()

print("3. SECURITY ALERT PROCESSING:")
print("-" * 40)
# PART 4: Security Alert Processing
# TODO: Add alerts, display with index, remove first alert
# Add the 4 security alerts using append()

# Print all alerts with index numbers using enumerate()

# Remove first alert using pop(0) and print it

# Print remaining alerts with index numbers

print()

print("4. VULNERABILITY ANALYSIS:")
print("-" * 40)
# PART 5: Vulnerability Analysis
# TODO: Sort scores, find high scores, calculate average
# Sort vulnerability_scores in descending order

# Find vulnerabilities > 7.0 using list comprehension

# Calculate and print average score

print()

print("5. SECURITY SUMMARY:")
print("-" * 40)
# PART 6: Security Summary
# TODO: Create and display summary
# Print security asset summary with counts and highest score

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_lists():
    """Test function to verify your list operations are correct."""
    
    try:
        # Test Part 1: Initial lists
        expected_devices = ["firewall", "router", "load_balancer", "switch", "server", "intrusion_detection_system"]
        assert network_devices == expected_devices, f"network_devices should be {expected_devices}, got {network_devices}"
        print("✅ Test 1 PASSED: network_devices list is correct")
        
        expected_users = ["admin", "user1", "user2", "analyst", "manager"]
        assert user_accounts == expected_users, f"user_accounts should be {expected_users}, got {user_accounts}"
        print("✅ Test 2 PASSED: user_accounts list is correct")
        
        # Test that guest was removed
        assert "guest" not in user_accounts, "guest should have been removed from user_accounts"
        print("✅ Test 3 PASSED: guest user was removed")
        
        # Test security alerts (should have 3 remaining after removing first)
        assert len(security_alerts) == 3, f"security_alerts should have 3 items, got {len(security_alerts)}"
        print("✅ Test 4 PASSED: security alerts processed correctly")
        
        # Test vulnerability scores are sorted descending
        expected_sorted = [9.1, 8.5, 7.8, 6.2, 4.3]
        assert vulnerability_scores == expected_sorted, f"vulnerability_scores should be {expected_sorted}, got {vulnerability_scores}"
        print("✅ Test 5 PASSED: vulnerability scores sorted correctly")
        
        # Test high vulnerabilities found
        expected_high = [9.1, 8.5, 7.8]
        assert high_vulnerabilities == expected_high, f"high_vulnerabilities should be {expected_high}, got {high_vulnerabilities}"
        print("✅ Test 6 PASSED: high vulnerabilities identified correctly")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python lists!")
        print("Ready for Module 6: Dictionaries")
        
    except NameError as e:
        print(f"❌ ERROR: Variable not found - {e}")
        print("Make sure you've completed all the required list operations.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your list operations and try again.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_lists()

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
