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

# ============================================================================
# WARM-UP EXERCISES: Practice Using Loops
# ============================================================================

# Exercise 1: Simple for loop with range
"""
PRACTICE: Basic For Loop

Write a function `generate_system_checks()` that uses a for loop to generate
a list of strings. For numbers 1 through 3, it should add
"Checking system X" (where X is the number) to the list.
The function should return this list.
Example: ["Checking system 1", "Checking system 2", "Checking system 3"]
"""
# TODO: Implement the function generate_system_checks
def generate_system_checks():
    # Your code here
    pass


# Exercise 2: Loop through a simple list
"""
PRACTICE: Loop Through List

Write a function `check_servers(server_list)` that takes a list of server names.
It should return a new list where each item is "Checking [server_name] server".
Example: check_servers(["web", "mail"]) should return
         ["Checking web server", "Checking mail server"]
"""
# TODO: Implement the function check_servers
def check_servers(server_list):
    # Your code here
    pass


# Exercise 3: Simple while loop
"""
PRACTICE: Basic While Loop

Write a function `perform_security_scans(max_scans)` that takes an integer.
It should simulate performing security scans.
The function should return a list of strings, where each string is "Security scan X"
(X being the scan number, starting from 1).
The loop should stop when the scan number reaches `max_scans`.
Example: perform_security_scans(3) should return
         ["Security scan 1", "Security scan 2", "Security scan 3"]
"""
# TODO: Implement the function perform_security_scans
def perform_security_scans(max_scans):
    # Your code here
    pass


# Exercise 4: Loop with if condition
"""
PRACTICE: Loop with Conditional

Write a function `find_ssh_ports(port_list)` that takes a list of port numbers.
It should return a new list containing strings describing each port.
If a port is 22, add "SSH port found".
For other ports, add "Port [number] checked".
Example: find_ssh_ports([22, 80, 443]) should return
         ["SSH port found", "Port 80 checked", "Port 443 checked"]
"""
# TODO: Implement the function find_ssh_ports
def find_ssh_ports(port_list):
    # Your code here
    pass


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
This part of the exercise will involve printing the status.

IP ACCESS CONTROL VALIDATION:
Your network has an approved whitelist of IP addresses: 192.168.1.1, 10.0.0.1,
and 172.16.0.1. Recent connection attempts came from: 192.168.1.1, 203.0.113.42,
10.0.0.1, 198.51.100.1, and 172.16.0.1.

Create a list named ip_whitelist for approved addresses and connection_attempts
for the recent attempts. Validate each connection attempt against the whitelist
and report whether it should be allowed or blocked by printing the result.

USER LOGIN PATTERN ANALYSIS:
Recent login records show the following user activity: admin, user1, guest, admin,
user2, admin. You need to analyze this data to identify users with high login activity.

Create a list named recent_logins with this data, then count how many times each
user logged in (store this in a dictionary called `login_counts`).
After counting, iterate through `login_counts` and print each user's count.
Flag any user who logged in more than 2 times as having high activity by printing a message.

CONTINUOUS MONITORING CYCLES:
Your monitoring system runs in cycles, alternating between quick security checks
and deep security scans. Simulate 3 monitoring cycles by printing a message for each.
Odd-numbered cycles (1, 3) perform "Quick security check".
Even-numbered cycles (2) perform "Deep security scan".
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Create the required lists
# TODO: Create the 3 lists specified above
# critical_services = ?
# ip_whitelist = ?
# recent_logins = ?


# PART 2: Security checks using loops

# --- SECURITY SERVICE MONITORING ---
# TODO: Service status check loop
# Define which services are running (e.g., a set or list for quick lookup)
# services_running = {"firewall", "antivirus"}
# Loop through critical_services and print status


# --- IP ACCESS CONTROL VALIDATION ---
# TODO: IP whitelist validation loop
# connection_attempts = ? (define this list)
# Loop through connection_attempts and print allowed/blocked status


# --- USER LOGIN PATTERN ANALYSIS ---
# TODO: Login pattern analysis
# login_counts = {} (initialize an empty dictionary)
# Loop through recent_logins to populate login_counts
# Loop through login_counts to print user counts and high activity flags


# --- CONTINUOUS MONITORING CYCLES ---
# TODO: Monitoring loop for 3 cycles (1 to 3)
# Loop 3 times, check if cycle number is odd or even to print the correct message


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

def test_warmup_exercises():
    """Test the warm-up exercises."""
    warmup_passed = 0
    total_warmup_tests = 4

    # Test Exercise 1
    try:
        expected = ["Checking system 1", "Checking system 2", "Checking system 3"]
        assert generate_system_checks() == expected, "Exercise 1 Failed"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 1 FAILED: Function 'generate_system_checks' not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up Exercise 1 FAILED: {e}")
    except Exception as e:
        print(f"❌ Warm-up Exercise 1 FAILED: Unexpected error - {e}")

    # Test Exercise 2
    try:
        expected = ["Checking web server", "Checking mail server", "Checking file server"]
        assert check_servers(["web", "mail", "file"]) == expected, "Exercise 2 Failed: Test 1"
        assert check_servers([]) == [], "Exercise 2 Failed: Test 2 (empty list)"
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 2 FAILED: Function 'check_servers' not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up Exercise 2 FAILED: {e}")
    except Exception as e:
        print(f"❌ Warm-up Exercise 2 FAILED: Unexpected error - {e}")

    # Test Exercise 3
    try:
        expected = ["Security scan 1", "Security scan 2", "Security scan 3"]
        assert perform_security_scans(3) == expected, "Exercise 3 Failed: max_scans = 3"
        assert perform_security_scans(1) == ["Security scan 1"], "Exercise 3 Failed: max_scans = 1"
        assert perform_security_scans(0) == [], "Exercise 3 Failed: max_scans = 0"
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 3 FAILED: Function 'perform_security_scans' not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up Exercise 3 FAILED: {e}")
    except Exception as e:
        print(f"❌ Warm-up Exercise 3 FAILED: Unexpected error - {e}")

    # Test Exercise 4
    try:
        expected = ["SSH port found", "Port 80 checked", "Port 443 checked", "SSH port found"]
        assert find_ssh_ports([22, 80, 443, 22]) == expected, "Exercise 4 Failed: Test 1"
        assert find_ssh_ports([100, 200]) == ["Port 100 checked", "Port 200 checked"], "Exercise 4 Failed: Test 2"
        assert find_ssh_ports([]) == [], "Exercise 4 Failed: Test 3 (empty list)"
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 4 FAILED: Function 'find_ssh_ports' not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up Exercise 4 FAILED: {e}")
    except Exception as e:
        print(f"❌ Warm-up Exercise 4 FAILED: Unexpected error - {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests


def test_main_exercise_loops():
    """Test function to verify your loop implementations in the main exercise are correct."""
    main_passed = True
    try:
        # Test list creation
        expected_services = ["firewall", "antivirus", "backup", "logging"]
        assert critical_services == expected_services, f"critical_services should be {expected_services}"

        expected_whitelist = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        assert ip_whitelist == expected_whitelist, f"ip_whitelist should be {expected_whitelist}"

        expected_logins = ["admin", "user1", "guest", "admin", "user2", "admin"]
        assert recent_logins == expected_logins, f"recent_logins should be {expected_logins}"

        # Test that connection_attempts was created
        expected_attempts = ["192.168.1.1", "203.0.113.42", "10.0.0.1", "198.51.100.1", "172.16.0.1"]
        assert connection_attempts == expected_attempts, f"connection_attempts should be {expected_attempts}"

        # Test that login_counts was created correctly
        # This assumes the user correctly implements the counting logic.
        # The problem asks to store counts in `login_counts`.
        if 'login_counts' in globals():
            expected_counts = {"admin": 3, "user1": 1, "guest": 1, "user2": 1}
            assert login_counts == expected_counts, f"login_counts dictionary not as expected. Got: {login_counts}"
        else:
            print("❌ Main Exercise Check: 'login_counts' dictionary not defined.")
            main_passed = False

        if main_passed:
            print("\n✅ MAIN EXERCISE: Initial lists and login_counts dictionary seem correct.")
            print("Reminder: For the main exercise, manually verify your printed outputs for service status, IP validation, login analysis, and monitoring cycles against the problem description.")
        else:
            print("\n❌ MAIN EXERCISE: Some initial setup (lists or login_counts dictionary) is incorrect.")

    except NameError as e:
        print(f"❌ ERROR in Main Exercise: Variable not found - {e}")
        print("Make sure you've created all required variables (critical_services, ip_whitelist, recent_logins, connection_attempts, login_counts).")
        return False # Return False on NameError
    except AssertionError as e:
        print(f"❌ TEST FAILED in Main Exercise: {e}")
        print("Check your list definitions or login_counts logic.")
        return False # Return False on AssertionError
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR in Main Exercise: {e}")
        return False # Return False on other unexpected errors

    return main_passed


def run_all_tests():
    """Run all tests for Module 4."""
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_exercises()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    # The main exercise involves print statements. We check data structures.
    # User must verify their print logic.
    main_exercise_structures_ok = test_main_exercise_loops()

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_structures_ok:
        print("\n✅ All warm-up tests passed and main exercise data structures are set up correctly.")
        print("Please ensure your main exercise loop logic prints the correct messages as per the requirements.")
        print("You've successfully practiced Python loops!")
        print("Ready for Module 5: Lists")
    else:
        print("\n📚 Keep practicing! Review the failed tests or checks above.")
        if not warmup_success:
            print("- Some warm-up exercises have issues.")
        if not main_exercise_structures_ok:
            print("- The main exercise data structure setup (lists, dictionary) has issues.")

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
