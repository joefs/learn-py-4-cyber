"""
====================================================================
MODULE 4: LOOPS - Automating Repetitive Tasks 🔄
====================================================================

Welcome to Module 4! You've learned to make decisions with conditional
statements. Now you'll learn how to automate repetitive tasks using loops -
one of the most powerful features for cybersecurity automation.

WHAT ARE LOOPS?
Loops let you repeat code multiple times without writing it over and over.
Think of them as "do this task for each item in a list" or "keep doing
this until a condition is met."

TYPES OF LOOPS WE'LL COVER:
- for loops: Repeat code for each item in a sequence
- while loops: Repeat code while a condition is True
- Loop control: break and continue statements
"""

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
    import random # This import is fine here for a conceptual example
    vuln_count = random.randint(0, 3)
    vulnerabilities_found += vuln_count

    if vuln_count > 0:
        print(f"  ⚠️  Found {vuln_count} vulnerabilities")
    else:
        print(f"  ✅ No vulnerabilities found")

print(f"Scan complete. Total vulnerabilities: {vulnerabilities_found}")

# Brute force detection simulation
failed_attempts_dict = {} # Renamed to avoid conflict with a common variable name
login_attempts_list = [ # Renamed to avoid conflict
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

# Exercise 1: Simple for loop with range
"""
PRACTICE: Basic For Loop

Write a function `generate_system_check_messages()` that uses a for loop
to generate a list of strings. For numbers 1 through 3 (inclusive),
it should add "Checking system X" (where X is the number) to the list.
The function should return this list.
Example: ["Checking system 1", "Checking system 2", "Checking system 3"]
"""
# TODO: Implement the function generate_system_check_messages
def generate_system_check_messages():
    pass


# Exercise 2: Loop through a simple list
"""
PRACTICE: Loop Through List

Write a function `generate_server_check_messages(server_list)` that takes a
list of server names. It should return a new list where each item is
"Checking [server_name] server".
Example: generate_server_check_messages(["web", "mail"]) should return
         ["Checking web server", "Checking mail server"]
"""
# TODO: Implement the function generate_server_check_messages
def generate_server_check_messages(server_list):
    pass


# Exercise 3: Simple while loop
"""
PRACTICE: Basic While Loop

Write a function `simulate_security_scans(max_scans)` that takes an integer.
It should simulate performing security scans up to `max_scans`.
The function should return a list of strings, where each string is
"Security scan X" (X being the scan number, starting from 1 up to `max_scans`).
Example: simulate_security_scans(3) should return
         ["Security scan 1", "Security scan 2", "Security scan 3"]
"""
# TODO: Implement the function simulate_security_scans
def simulate_security_scans(max_scans):
    pass


# Exercise 4: Loop with if condition
"""
PRACTICE: Loop with Conditional

Write a function `check_ports_status(port_list)` that takes a list of port numbers.
It should return a new list containing strings describing each port.
If a port is 22, add "SSH port found".
For other ports, add "Port [number] checked".
Example: check_ports_status([22, 80, 443]) should return
         ["SSH port found", "Port 80 checked", "Port 443 checked"]
"""
# TODO: Implement the function check_ports_status
def check_ports_status(port_list):
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Monitoring System
# ============================================================================
"""
AUTOMATED SECURITY MONITORING SYSTEM

You are implementing an automated security monitoring system that performs regular
checks across multiple security domains. The system needs to process lists of data
and perform repetitive security validation tasks.

TASK 1: SECURITY SERVICE MONITORING
Define `critical_services = ["firewall", "antivirus", "backup", "logging"]`.
Define `running_services = {"firewall", "antivirus"}` (a set for efficient lookup).
Create a function `get_service_statuses(critical_services_list, services_currently_running_set)`
that returns a list of dictionaries, where each dictionary represents a service and its status:
`[{"service": "firewall", "status": "running"}, {"service": "backup", "status": "stopped"}, ...]`.

TASK 2: IP ACCESS CONTROL VALIDATION
Define `ip_whitelist = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]`.
Define `connection_attempts = ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]`.
Create a function `validate_ip_connections(whitelist, attempts_list)` that returns a list of
dictionaries: `[{"ip": "192.168.1.1", "status": "allowed"}, {"ip": "203.0.113.42", "status": "blocked"}, ...]`.

TASK 3: USER LOGIN PATTERN ANALYSIS
Define `recent_logins = ["admin", "user1", "guest", "admin", "user2", "admin"]`.
Create a function `analyze_login_patterns(logins_list)` that returns two items:
1. A dictionary `login_counts` where keys are usernames and values are their login counts.
   (e.g., `{"admin": 3, "user1": 1, ...}`)
2. A list `high_activity_users` containing usernames of users who logged in more than 2 times.

TASK 4: CONTINUOUS MONITORING CYCLES
Create a function `simulate_monitoring_cycles(num_cycles)` that simulates `num_cycles`
monitoring cycles. Odd-numbered cycles perform "Quick security check", and even-numbered
cycles perform "Deep security scan".
The function should return a list of strings describing the action for each cycle.
(e.g., `["Cycle 1: Quick security check", "Cycle 2: Deep security scan", ...]`)

You will need to call these functions with the provided data and store their results
in variables like `service_status_results`, `ip_validation_results`,
`user_login_counts`, `high_activity_users_list`, and `monitoring_actions_list`.
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: Define initial data lists
critical_services = ["firewall", "antivirus", "backup", "logging"]
running_services = {"firewall", "antivirus"} # Using a set for efficient lookup
ip_whitelist = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
connection_attempts = ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]
recent_logins = ["admin", "user1", "guest", "admin", "user2", "admin"]

# PART 2: Implement the required functions

# TODO: Implement get_service_statuses
def get_service_statuses(critical_services_list, services_currently_running_set):
    pass

# TODO: Implement validate_ip_connections
def validate_ip_connections(whitelist, attempts_list):
    pass

# TODO: Implement analyze_login_patterns
def analyze_login_patterns(logins_list):
    pass

# TODO: Implement simulate_monitoring_cycles
def simulate_monitoring_cycles(num_cycles):
    pass

# PART 3: Call functions and store results
# TODO: Call your functions here and store their results
# service_status_results = ?
# ip_validation_results = ?
# user_login_counts, high_activity_users_list = ? # Unpack results from analyze_login_patterns
# monitoring_actions_list = ?


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
        assert generate_system_check_messages() == expected1, "Warm-up 1 FAILED"
        print("✅ Warm-up 1 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}")

    # Test 2
    try:
        expected2 = ["Checking web server", "Checking mail server"]
        assert generate_server_check_messages(["web", "mail"]) == expected2, "Warm-up 2 FAILED"
        print("✅ Warm-up 2 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}")

    # Test 3
    try:
        expected3 = ["Security scan 1", "Security scan 2", "Security scan 3"]
        assert simulate_security_scans(3) == expected3, "Warm-up 3 FAILED"
        print("✅ Warm-up 3 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}")

    # Test 4
    try:
        expected4 = ["SSH port found", "Port 80 checked", "Port 3389 checked"]
        assert check_ports_status([22, 80, 3389]) == expected4, "Warm-up 4 FAILED"
        print("✅ Warm-up 4 PASSED")
        passed_count +=1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_exercise_loops():
    """Test function to verify your main exercise loop implementations are correct."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # Check initial data lists are defined correctly
    try:
        assert critical_services == ["firewall", "antivirus", "backup", "logging"]
        assert running_services == {"firewall", "antivirus"}
        assert ip_whitelist == ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        assert connection_attempts == ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]
        assert recent_logins == ["admin", "user1", "guest", "admin", "user2", "admin"]
        print("✅ Initial data lists defined correctly.")
    except (NameError, AssertionError) as e:
        print(f"❌ ERROR: Initial data lists not defined correctly or have wrong values - {e}")
        return False # Cannot proceed if data is wrong

    # Test get_service_statuses
    try:
        global service_status_results # Make it accessible for tests
        service_status_results = get_service_statuses(critical_services, running_services)
        expected_statuses = [
            {"service": "firewall", "status": "running"}, {"service": "antivirus", "status": "running"},
            {"service": "backup", "status": "stopped"}, {"service": "logging", "status": "stopped"}
        ]
        assert service_status_results == expected_statuses, "Service statuses incorrect."
        print("✅ TASK 1 (Service Statuses): PASSED")
    except (NameError, AssertionError, TypeError) as e: # Added TypeError for uncallable
        print(f"❌ TASK 1 (Service Statuses): FAILED - {e}")
        main_passed = False

    # Test validate_ip_connections
    try:
        global ip_validation_results # Make it accessible
        ip_validation_results = validate_ip_connections(ip_whitelist, connection_attempts)
        expected_ip_results = [
            {"ip": "192.168.1.1", "status": "allowed"}, {"ip": "203.0.113.42", "status": "blocked"},
            {"ip": "10.0.0.1", "status": "allowed"}, {"ip": "198.51.100.1", "status": "blocked"},
            {"ip": "172.16.0.1", "status": "allowed"}
        ]
        assert ip_validation_results == expected_ip_results, "IP validation results incorrect."
        print("✅ TASK 2 (IP Validation): PASSED")
    except (NameError, AssertionError, TypeError) as e:
        print(f"❌ TASK 2 (IP Validation): FAILED - {e}")
        main_passed = False

    # Test analyze_login_patterns
    try:
        global user_login_counts, high_activity_users_list # Make them accessible
        user_login_counts, high_activity_users_list = analyze_login_patterns(recent_logins)
        expected_login_counts = {"admin": 3, "user1": 1, "guest": 1, "user2": 1}
        expected_high_activity = ["admin"]
        assert user_login_counts == expected_login_counts, "User login counts incorrect."
        assert sorted(high_activity_users_list) == sorted(expected_high_activity), "High activity users list incorrect."
        print("✅ TASK 3 (Login Patterns): PASSED")
    except (NameError, AssertionError, TypeError, ValueError) as e: # Added ValueError for unpacking issues
        print(f"❌ TASK 3 (Login Patterns): FAILED - {e}")
        main_passed = False

    # Test simulate_monitoring_cycles
    try:
        global monitoring_actions_list # Make it accessible
        monitoring_actions_list = simulate_monitoring_cycles(3)
        expected_actions = ["Cycle 1: Quick security check", "Cycle 2: Deep security scan", "Cycle 3: Quick security check"]
        assert monitoring_actions_list == expected_actions, "Monitoring cycle actions incorrect."
        print("✅ TASK 4 (Monitoring Cycles): PASSED")
    except (NameError, AssertionError, TypeError) as e:
        print(f"❌ TASK 4 (Monitoring Cycles): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 MAIN EXERCISE: All core logic tests passed!")
    else:
        print("\n❌ MAIN EXERCISE: Some core logic tests failed.")
    return main_passed


def run_all_tests():
    """Run all tests for Module 4."""
    warmup_ok = test_warmup_loops()
    main_ok = test_main_exercise_loops()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python loops!")
        print("Ready for Module 5: Lists")
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

NEXT MODULE: 05_lists.py
In the next module, you'll dive deeper into lists - learning how to
create, modify, and manipulate collections of security data like
IP addresses, user accounts, security alerts, and system configurations!

You're becoming a real cybersecurity automation expert! 🤖🔒
"""
