"""
====================================================================
MODULE 6: LOOPS - Automating Repetitive Tasks 🔄
====================================================================

Welcome to Module 6! You've learned to make decisions with conditional
statements and manage data with lists and dictionaries. Now you'll learn how
to automate repetitive tasks using loops - one of the most powerful features
for cybersecurity automation, especially when combined with collections of data.

WHAT ARE LOOPS?
Loops let you repeat code multiple times without writing it over and over.
Think of them as "do this task for each item in a list" or "keep doing
this until a condition is met."

TYPES OF LOOPS WE'LL COVER:
- for loops: Repeat code for each item in a sequence
- while loops: Repeat code while a condition is True
- Loop control: break and continue statements
"""

import random # Moved to top of the file

# ============================================================================
# CONCEPT EXPLANATION: Basic FOR Loops
# ============================================================================

# Loop through a list of items
ports_to_scan = [21, 22, 23, 80, 443]

print("Scanning ports:")
for port in ports_to_scan:
    print(f"Scanning port {port}...")
print("Port scan complete!")

# Loop through a range of numbers
print("\nChecking first 5 user accounts:") # Added newline for clarity
for user_id in range(1, 6):  # range(1, 6) gives us 1, 2, 3, 4, 5
    print(f"Checking user ID: {user_id}")
print("User check complete!")

# Loop through strings (each character)
password = "Secret123"
special_chars = 0

print(f"\nAnalyzing password: {password}") # Added newline
for character in password:
    if character in "!@#$%^&*()":
        special_chars += 1
print(f"Special characters found: {special_chars}")

# ============================================================================
# CONCEPT EXPLANATION: WHILE Loops
# ============================================================================

# While loop - repeat until condition becomes False
attempts = 0
max_attempts = 3
authenticated = False

print("\nSimulating login attempts:") # Added newline
while attempts < max_attempts and not authenticated:
    attempts += 1
    print(f"Login attempt #{attempts}")

    # Simulate successful login on attempt 2
    if attempts == 2:
        authenticated = True
        print("✅ Login successful!")
    else:
        print("❌ Login failed")

if not authenticated:
    print("🚨 Account locked after too many failed attempts")

# ============================================================================
# CONCEPT EXPLANATION: Loop Control (break and continue)
# ============================================================================

# Using 'break' to exit a loop early
suspicious_ips = ["192.168.1.1", "10.0.0.1", "203.0.113.42", "192.168.1.2"]
malicious_ip = "203.0.113.42"

print("\nScanning IP addresses for threats:") # Added newline
for ip in suspicious_ips:
    print(f"Checking {ip}...")
    if ip == malicious_ip:
        print(f"🚨 THREAT DETECTED: {ip} is malicious!")
        print("Stopping scan and triggering alert...")
        break  # Exit the loop immediately
    else:
        print(f"✅ {ip} is clean")

# Using 'continue' to skip the rest of the current iteration
log_entries = ["INFO: User login", "ERROR: Database error", "INFO: File saved", "WARNING: High CPU"]

print("\nProcessing log entries (skipping INFO messages):") # Added newline
for entry in log_entries:
    if entry.startswith("INFO"):
        continue  # Skip the rest of this iteration
    print(f"Processing: {entry}")

# ============================================================================
# CONCEPT EXPLANATION: Nested Loops
# ============================================================================

# Loop inside another loop
networks = ["192.168.1", "10.0.0"]
hosts_to_check = [1, 2, 3]

print("\nNetwork discovery scan:") # Added newline
for network in networks:
    print(f"Scanning network {network}.0/24:")
    for host in hosts_to_check:
        ip_address = f"{network}.{host}"
        print(f"  Pinging {ip_address}...")
    print(f"Network {network}.0/24 scan complete")

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF LOOPS:

1. NETWORK SCANNING:
   - FOR each IP in subnet: ping and check if alive
   - FOR each port in common_ports: scan for open services
   - WHILE scanning and not interrupted: continue network discovery

2. LOG FILE ANALYSIS:
   - FOR each line in log_file: analyze for suspicious patterns
   - WHILE reading log entries: count error types and security events
   - FOR each user in access_log: track login patterns

3. SECURITY MONITORING:
   - WHILE system running: monitor CPU, memory, and network usage
   - FOR each running process: check against malware signatures
   - FOR each file in directory: scan for viruses

4. USER MANAGEMENT:
   - FOR each user in database: check last login date
   - FOR each account: verify password expiration status
   - WHILE processing user list: update permissions and roles

5. INCIDENT RESPONSE:
   - FOR each affected system: isolate and analyze
   - WHILE threat active: continue monitoring and containment
   - FOR each security tool: collect logs and evidence

6. AUTOMATED SECURITY TASKS:
   - FOR each server: apply security patches
   - FOR each backup: verify integrity and restore capability
   - WHILE vulnerability scan running: process discovered issues
"""

# Automated vulnerability scanning
servers = ["web-server-1", "db-server-1", "mail-server-1"]
vulnerabilities_found = 0

print("\nStarting vulnerability scan across servers:") # Added newline
for server in servers:
    print(f"Scanning {server}...")

    # Simulate finding vulnerabilities (random for demo)
    # import random # Moved to top
    vuln_count = random.randint(0, 3)
    vulnerabilities_found += vuln_count

    if vuln_count > 0:
        print(f"  ⚠️  Found {vuln_count} vulnerabilities")
    else:
        print(f"  ✅ No vulnerabilities found")

print(f"Scan complete. Total vulnerabilities: {vulnerabilities_found}")

# Brute force detection simulation
failed_attempts_dict = {} # Renamed to avoid conflict
login_attempts_list = [ # Renamed
    ("user1", "192.168.1.100"),
    ("admin", "203.0.113.42"),
    ("admin", "203.0.113.42"),
    ("admin", "203.0.113.42"),
    ("user2", "192.168.1.101"),
    ("admin", "203.0.113.42"),
]

print("\nAnalyzing login attempts for brute force patterns:") # Added newline
for username, ip_address in login_attempts_list:
    key = f"{username}@{ip_address}"

    if key not in failed_attempts_dict:
        failed_attempts_dict[key] = 0

    failed_attempts_dict[key] += 1

    if failed_attempts_dict[key] >= 3:
        print(f"🚨 BRUTE FORCE DETECTED: {username} from {ip_address} ({failed_attempts_dict[key]} attempts)")
    else:
        print(f"Login attempt: {username} from {ip_address}")

# ============================================================================
# WARM-UP EXERCISES: Practice Using Loops
# ============================================================================

# Initialize global variables for warmup outputs
warmup1_output_list = []
warmup2_output_list = []
warmup3_output_list = []
warmup4_output_list = []

# Exercise 1: Simple for loop with range
"""
PRACTICE: Iterating System Checks

Your security script needs to perform a check on systems numbered 1, 2, and 3.
For each system number, you want to record a message indicating that the system is being checked.
The message should be "Checking system X", where X is the system number.
Collect these messages in a list.

(Store the list of check messages in the global variable `warmup1_output_list`.)
"""
# TODO: Use a for loop and the range() function to iterate from 1 to 3.
# TODO: Inside the loop, format the string "Checking system X".
# TODO: Append each formatted string to the `warmup1_output_list`.


# Exercise 2: Loop through a simple list
"""
PRACTICE: Server Inventory Check

You have a list of essential servers: "web", "mail", and "file".
Your task is to iterate through this list and, for each server, generate a message
stating "Checking [server_name] server". For example, for the "web" server,
the message would be "Checking web server". Accumulate these messages.

(Define the list of servers as `servers_warmup2`. Store the generated messages
in the global list `warmup2_output_list`.)
"""
# TODO: Create a list named `servers_warmup2` with "web", "mail", "file".
# TODO: Loop through `servers_warmup2`.
# TODO: For each server, create the specified message string.
# TODO: Append each message to `warmup2_output_list`.


# Exercise 3: Simple while loop
"""
PRACTICE: Repeated Security Scans

You need to simulate running a security scan three times.
Each scan should be identified by its sequence number (1, 2, 3).
For each scan, record a message "Security scan X", where X is the scan number.
Use a counter that starts at 1 and stops when it reaches 4.

(Collect these scan messages in the global list `warmup3_output_list`.)
"""
# TODO: Initialize a counter variable `count_warmup3` to 1.
# TODO: Use a while loop that continues as long as `count_warmup3` is less than 4.
# TODO: Inside the loop, create the "Security scan X" message.
# TODO: Append the message to `warmup3_output_list`.
# TODO: Increment `count_warmup3` in each iteration.


# Exercise 4: Loop with if condition
"""
PRACTICE: Port Status Identification

You are given a list of network ports: 22, 80, 443, and 3389.
Your script needs to check each port. If a port is 22, it's an "SSH port found".
For any other port, the message should be "Port [number] checked".
Compile a list of these status messages.

(Define the list of ports as `ports_warmup4`. Store the resulting messages
in the global list `warmup4_output_list`.)
"""
# TODO: Create a list named `ports_warmup4` with the specified ports.
# TODO: Loop through `ports_warmup4`.
# TODO: Use an if condition to check if the port is 22.
# TODO: Append the appropriate message ("SSH port found" or "Port [number] checked")
#       to `warmup4_output_list`.


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Monitoring System
# ============================================================================
"""
CHALLENGE: AUTOMATED SECURITY MONITORING SYSTEM

You are tasked with building components for an automated security monitoring system.
This system needs to perform several repetitive checks and analyses.

Initial Data Sets for Your System:
-   A list of `critical_services` that must always be running: "firewall", "antivirus", "backup", "logging".
-   A representation of currently `running_services` (use a set for this: {"firewall", "antivirus"}).
-   An `ip_whitelist` of allowed IP addresses: ["192.168.1.1", "10.0.0.1", "172.16.0.1"].
-   A log of `connection_attempts` (IP addresses that tried to connect):
    ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"].
-   A list of `recent_logins` by username: ["admin", "user1", "guest", "admin", "user2", "admin"].

Your Implementation Tasks:

TASK 1: SECURITY SERVICE MONITORING
   Go through each service defined in `critical_services`. For every service, determine if it
   is currently in the `running_services` set.
   Compile a list where each item describes a critical service and its status (e.g.,
   `{"service": "firewall", "status": "running"}` or `{"service": "backup", "status": "stopped"}`).
   (Store this list of dictionaries in the global variable `service_status_results`.)

TASK 2: IP ACCESS CONTROL VALIDATION
   Examine each IP address in the `connection_attempts` list. Check if this IP is present
   in the `ip_whitelist`.
   Create a list detailing each attempt, marking it as "allowed" or "blocked" (e.g.,
   `{"ip": "192.168.1.1", "status": "allowed"}` or `{"ip": "203.0.113.42", "status": "blocked"}`).
   (Store this list of dictionaries in the global variable `ip_validation_results`.)

TASK 3: USER LOGIN PATTERN ANALYSIS
   Analyze the `recent_logins` list.
   First, count how many times each user has logged in.
   (Store these counts in a global dictionary called `user_login_counts`, where keys are usernames
   and values are their login counts.)
   Second, identify users who have logged in more than 2 times.
   (Store a list of these high-activity usernames in the global list `high_activity_users_list`.)

TASK 4: CONTINUOUS MONITORING CYCLES
   Simulate three cycles of a continuous monitoring process.
   - In odd-numbered cycles (1st, 3rd), the system performs a "Quick security check".
   - In even-numbered cycles (2nd), it performs a "Deep security scan".
   Record the action taken in each cycle.
   (Store these action descriptions as strings in a global list called `monitoring_actions_list`,
   e.g., "Cycle 1: Quick security check", "Cycle 2: Deep security scan", etc.)

Make sure to use the globally defined initial data lists and store your final results
in the specified global variables for automated checking.
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: Define initial data lists (already provided for the main exercise)
critical_services = ["firewall", "antivirus", "backup", "logging"]
running_services = {"firewall", "antivirus"}
ip_whitelist = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
connection_attempts = ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]
recent_logins = ["admin", "user1", "guest", "admin", "user2", "admin"]

# Initialize global variables for main exercise results
service_status_results = []
ip_validation_results = []
user_login_counts = {}
high_activity_users_list = []
monitoring_actions_list = []

# PART 2: Implement loop-based logic to populate the global result variables

# TODO: TASK 1: Security Service Monitoring - Populate service_status_results


# TODO: TASK 2: IP Access Control Validation - Populate ip_validation_results


# TODO: TASK 3: User Login Pattern Analysis - Populate user_login_counts and high_activity_users_list


# TODO: TASK 4: Continuous Monitoring Cycles - Populate monitoring_actions_list


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_loops():
    """Test the warm-up exercises for loops."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0

    # Test 1
    try:
        expected1 = ["Checking system 1", "Checking system 2", "Checking system 3"]
        assert warmup1_output_list == expected1, "Warmup 1 FAILED"
        print("✅ Warm-up 1 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}. Did you assign to 'warmup1_output_list'?")

    # Test 2
    try:
        expected2 = ["Checking web server", "Checking mail server", "Checking file server"]
        # This assumes user created servers_warmup2 = ["web", "mail", "file"] in their code for Ex2
        assert warmup2_output_list == expected2, "Warmup 2 FAILED" # User needs to define servers_warmup2
        print("✅ Warm-up 2 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}. Did you assign to 'warmup2_output_list' and define 'servers_warmup2'?")

    # Test 3
    try:
        expected3 = ["Security scan 1", "Security scan 2", "Security scan 3"]
        assert warmup3_output_list == expected3, "Warmup 3 FAILED"
        print("✅ Warm-up 3 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}. Did you assign to 'warmup3_output_list'?")

    # Test 4
    try:
        expected4 = ["SSH port found", "Port 80 checked", "Port 443 checked", "Port 3389 checked"]
        # Assumes user created ports_warmup4 = [22, 80, 443, 3389]
        assert warmup4_output_list == expected4, "Warmup 4 FAILED" # User needs to define ports_warmup4
        print("✅ Warm-up 4 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 4 FAILED: {e}. Did you assign to 'warmup4_output_list' and define 'ports_warmup4'?")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_exercise_loops():
    """Test function to verify your main exercise loop implementations are correct."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # Check initial data lists are defined correctly (they are defined globally in the template)
    try:
        assert critical_services == ["firewall", "antivirus", "backup", "logging"]
        assert running_services == {"firewall", "antivirus"}
        # ... (other initial data checks are implicitly covered by testing their use)
        print("✅ Initial data lists seem OK.")
    except (NameError, AssertionError) as e:
        print(f"❌ ERROR: Initial data lists not defined correctly or have wrong values - {e}")
        return False

    # Test TASK 1: Security Service Monitoring
    try:
        expected_statuses = [
            {"service": "firewall", "status": "running"}, {"service": "antivirus", "status": "running"},
            {"service": "backup", "status": "stopped"}, {"service": "logging", "status": "stopped"}
        ]
        assert service_status_results == expected_statuses, "TASK 1: Service statuses incorrect."
        print("✅ TASK 1 (Service Statuses): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 1 (Service Statuses): FAILED - {e}. Is 'service_status_results' populated correctly?")
        main_passed = False

    # Test TASK 2: IP Access Control Validation
    try:
        expected_ip_results = [
            {"ip": "192.168.1.1", "status": "allowed"}, {"ip": "203.0.113.42", "status": "blocked"},
            {"ip": "10.0.0.1", "status": "allowed"}, {"ip": "198.51.100.1", "status": "blocked"},
            {"ip": "172.16.0.1", "status": "allowed"}
        ]
        assert ip_validation_results == expected_ip_results, "TASK 2: IP validation results incorrect."
        print("✅ TASK 2 (IP Validation): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 2 (IP Validation): FAILED - {e}. Is 'ip_validation_results' populated correctly?")
        main_passed = False

    # Test TASK 3: User Login Pattern Analysis
    try:
        expected_login_counts = {"admin": 3, "user1": 1, "guest": 1, "user2": 1}
        expected_high_activity = ["admin"]
        assert user_login_counts == expected_login_counts, "TASK 3: User login counts incorrect."
        assert sorted(high_activity_users_list) == sorted(expected_high_activity), "TASK 3: High activity users list incorrect."
        print("✅ TASK 3 (Login Patterns): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 3 (Login Patterns): FAILED - {e}. Are 'user_login_counts' and 'high_activity_users_list' populated correctly?")
        main_passed = False

    # Test TASK 4: Continuous Monitoring Cycles
    try:
        expected_actions = ["Cycle 1: Quick security check", "Cycle 2: Deep security scan", "Cycle 3: Quick security check"]
        assert monitoring_actions_list == expected_actions, "TASK 4: Monitoring cycle actions incorrect."
        print("✅ TASK 4 (Monitoring Cycles): PASSED")
    except (NameError, AssertionError) as e:
        print(f"❌ TASK 4 (Monitoring Cycles): FAILED - {e}. Is 'monitoring_actions_list' populated correctly?")
        main_passed = False

    if main_passed:
        print("\n🎉 MAIN EXERCISE: All core logic tests passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some core logic tests failed.")
    return main_passed


def run_all_tests():
    """Run all tests for Module 6."""
    warmup_ok = test_warmup_loops()
    main_ok = test_main_exercise_loops()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python loops!")
        print("Ready for Module 7: Functions") # Updated to 7
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")

# Run the tests
run_all_tests()

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Fantastic work completing Module 4! Here's what you learned:

✅ For loops to iterate through sequences and ranges
✅ While loops to repeat code based on conditions
✅ Loop control with break and continue statements
✅ Nested loops for complex iteration patterns
✅ How to automate cybersecurity tasks with loops

CYBERSECURITY SKILLS GAINED:
- Automated network scanning and discovery
- Log file analysis and pattern detection
- Security monitoring and continuous checks
- Brute force attack detection
- System health monitoring automation
- Incident response automation basics

NEXT MODULE: 07_functions.py
In the next module, you'll learn about functions - reusable blocks of code
that help you organize your cybersecurity scripts, make them more efficient,
and build modular tools for complex tasks!

You're becoming a real cybersecurity automation expert! 🤖🔒
"""
