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

print("=== BASIC FOR LOOPS ===")
print()

# Loop through a list of items
ports_to_scan = [21, 22, 23, 80, 443]

print("Scanning ports:")
for port in ports_to_scan:
    print(f"Scanning port {port}...")
print("Port scan complete!")
print()

# Loop through a range of numbers
print("Checking first 5 user accounts:")
for user_id in range(1, 6):  # range(1, 6) gives us 1, 2, 3, 4, 5
    print(f"Checking user ID: {user_id}")
print("User check complete!")
print()

# Loop through strings (each character)
password = "Secret123"
special_chars = 0

print(f"Analyzing password: {password}")
for character in password:
    if character in "!@#$%^&*()":
        special_chars += 1

print(f"Special characters found: {special_chars}")
print()

# ============================================================================
# CONCEPT EXPLANATION: WHILE Loops
# ============================================================================

print("=== WHILE LOOPS ===")
print()

# While loop - repeat until condition becomes False
attempts = 0
max_attempts = 3
authenticated = False

print("Simulating login attempts:")
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
print()

# ============================================================================
# CONCEPT EXPLANATION: Loop Control (break and continue)
# ============================================================================

print("=== LOOP CONTROL ===")
print()

# Using 'break' to exit a loop early
suspicious_ips = ["192.168.1.1", "10.0.0.1", "203.0.113.42", "192.168.1.2"]
malicious_ip = "203.0.113.42"

print("Scanning IP addresses for threats:")
for ip in suspicious_ips:
    print(f"Checking {ip}...")
    if ip == malicious_ip:
        print(f"🚨 THREAT DETECTED: {ip} is malicious!")
        print("Stopping scan and triggering alert...")
        break  # Exit the loop immediately
    else:
        print(f"✅ {ip} is clean")
print()

# Using 'continue' to skip the rest of the current iteration
log_entries = ["INFO: User login", "ERROR: Database error", "INFO: File saved", "WARNING: High CPU"]

print("Processing log entries (skipping INFO messages):")
for entry in log_entries:
    if entry.startswith("INFO"):
        continue  # Skip the rest of this iteration
    print(f"Processing: {entry}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Nested Loops
# ============================================================================

print("=== NESTED LOOPS ===")
print()

# Loop inside another loop
networks = ["192.168.1", "10.0.0"]
hosts_to_check = [1, 2, 3]

print("Network discovery scan:")
for network in networks:
    print(f"Scanning network {network}.0/24:")
    for host in hosts_to_check:
        ip_address = f"{network}.{host}"
        print(f"  Pinging {ip_address}...")
    print(f"Network {network}.0/24 scan complete")
print()

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

print("=== CYBERSECURITY LOOP EXAMPLES ===")

# Automated vulnerability scanning
servers = ["web-server-1", "db-server-1", "mail-server-1"]
vulnerabilities_found = 0

print("Starting vulnerability scan across servers:")
for server in servers:
    print(f"Scanning {server}...")
    
    # Simulate finding vulnerabilities (random for demo)
    import random
    vuln_count = random.randint(0, 3)
    vulnerabilities_found += vuln_count
    
    if vuln_count > 0:
        print(f"  ⚠️  Found {vuln_count} vulnerabilities")
    else:
        print(f"  ✅ No vulnerabilities found")

print(f"Scan complete. Total vulnerabilities: {vulnerabilities_found}")
print()

# Brute force detection simulation
failed_attempts = {}
login_attempts = [
    ("user1", "192.168.1.100"),
    ("admin", "203.0.113.42"),
    ("admin", "203.0.113.42"),
    ("admin", "203.0.113.42"),
    ("user2", "192.168.1.101"),
    ("admin", "203.0.113.42"),
]

print("Analyzing login attempts for brute force patterns:")
for username, ip_address in login_attempts:
    key = f"{username}@{ip_address}"
    
    if key not in failed_attempts:
        failed_attempts[key] = 0
    
    failed_attempts[key] += 1
    
    if failed_attempts[key] >= 3:
        print(f"🚨 BRUTE FORCE DETECTED: {username} from {ip_address} ({failed_attempts[key]} attempts)")
    else:
        print(f"Login attempt: {username} from {ip_address}")
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Using Loops
# ============================================================================

# Exercise 1: Simple for loop with range
"""
PRACTICE: Basic For Loop

Use a for loop to print numbers 1 through 3.
Print "Checking system" followed by the number.
"""
# TODO: Create for loop with range(1, 4)


# Exercise 2: Loop through a simple list
"""
PRACTICE: Loop Through List

Create a list called servers = ["web", "mail", "file"].
Use a for loop to print "Checking [server] server" for each one.
"""
# TODO: Create list and for loop


# Exercise 3: Simple while loop
"""
PRACTICE: Basic While Loop

Create a variable count = 1.
Use a while loop to print "Security scan" and increment count.
Stop when count reaches 4.
"""
# TODO: Create while loop


# Exercise 4: Loop with if condition
"""
PRACTICE: Loop with Conditional

Create a list ports = [22, 80, 443, 3389].
Loop through the list. If port is 22, print "SSH port found".
For other ports, print "Port [number] checked".
"""
# TODO: Create list and loop with if condition


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Monitoring System
# ============================================================================
"""
AUTOMATED SECURITY MONITORING SYSTEM

You are implementing an automated security monitoring system that performs regular 
checks across multiple security domains. The system needs to process lists of data 
and perform repetitive security validation tasks.

SECURITY SERVICE MONITORING:
Your organization relies on four critical security services: firewall, antivirus, 
backup, and logging. You need to check the status of each service. Based on current 
system information, the firewall and antivirus services are running, while the 
backup and logging services are stopped.

Create a list named critical_services containing these four service names, then 
check the status of each service and report whether it's running or stopped.

IP ACCESS CONTROL VALIDATION:
Your network has an approved whitelist of IP addresses: 192.168.1.1, 10.0.0.1, 
and 172.16.0.1. Recent connection attempts came from: 192.168.1.1, 203.0.113.42, 
10.0.0.1, 198.51.100.1, and 172.16.0.1.

Create a list named ip_whitelist for approved addresses and connection_attempts 
for the recent attempts. Validate each connection attempt against the whitelist 
and report whether it should be allowed or blocked.

USER LOGIN PATTERN ANALYSIS:
Recent login records show the following user activity: admin, user1, guest, admin, 
user2, admin. You need to analyze this data to identify users with high login activity.

Create a list named recent_logins with this data, then count how many times each 
user logged in. Flag any user who logged in more than 2 times as having high activity.

CONTINUOUS MONITORING CYCLES:
Your monitoring system runs in cycles, alternating between quick security checks 
and deep security scans. Simulate 3 monitoring cycles where odd-numbered cycles 
perform quick checks and even-numbered cycles perform deep scans.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== AUTOMATED SECURITY MONITORING SYSTEM ===")
print()

# PART 1: Create the required lists
# TODO: Create the 3 lists specified above
# Create critical_services list here

# Create ip_whitelist list here

# Create recent_logins list here


# PART 2: Security checks using loops

print("1. CRITICAL SERVICES STATUS CHECK:")
print("-" * 40)
# TODO: Service status check loop
# Write your for loop to check each service status here

print()

print("2. IP WHITELIST VALIDATION:")
print("-" * 40)
# TODO: IP whitelist validation loop
# Create connection_attempts list here

# Write your for loop to validate IP addresses here

print()

print("3. LOGIN PATTERN ANALYSIS:")
print("-" * 40)
# TODO: Login pattern analysis
# Create login_counts dictionary here

# Write your for loop to count login attempts here

# Write your for loop to print results and check for high activity here

print()

print("4. CONTINUOUS MONITORING CYCLES:")
print("-" * 40)
# TODO: Monitoring loop for 3 cycles
# Write your for loop for monitoring cycles here

print("Monitoring system check complete!")

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_loops():
    """Test function to verify your loop implementations are correct."""
    
    try:
        # Test list creation
        expected_services = ["firewall", "antivirus", "backup", "logging"]
        assert critical_services == expected_services, f"critical_services should be {expected_services}"
        print("✅ Test 1 PASSED: critical_services list is correct")
        
        expected_whitelist = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        assert ip_whitelist == expected_whitelist, f"ip_whitelist should be {expected_whitelist}"
        print("✅ Test 2 PASSED: ip_whitelist list is correct")
        
        expected_logins = ["admin", "user1", "guest", "admin", "user2", "admin"]
        assert recent_logins == expected_logins, f"recent_logins should be {expected_logins}"
        print("✅ Test 3 PASSED: recent_logins list is correct")
        
        # Test that login_counts was created correctly
        expected_counts = {"admin": 3, "user1": 1, "guest": 1, "user2": 1}
        assert login_counts == expected_counts, f"login_counts should be {expected_counts}, got {login_counts}"
        print("✅ Test 4 PASSED: login pattern analysis is correct")
        
        # Test that connection_attempts was created
        expected_attempts = ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]
        assert connection_attempts == expected_attempts, f"connection_attempts should be {expected_attempts}"
        print("✅ Test 5 PASSED: connection_attempts list is correct")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python loops!")
        print("Ready for Module 5: Lists")
        
    except NameError as e:
        print(f"❌ ERROR: Variable not found - {e}")
        print("Make sure you've created all required variables and loops.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your loop logic and variable assignments.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_loops()

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
