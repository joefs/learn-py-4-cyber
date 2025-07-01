"""
====================================================================
MODULE 3: CONDITIONAL STATEMENTS - Making Smart Decisions 🤔
====================================================================

Welcome to Module 3! Now that you can compare and evaluate data with operators,
you'll learn how to make your programs take different actions based on those
comparisons using conditional statements.

WHAT ARE CONDITIONAL STATEMENTS?
Conditional statements let your program make decisions. They work like this:
"IF this condition is true, THEN do this action, OTHERWISE do that action."

CONDITIONAL STATEMENTS WE'LL COVER:
- if: Execute code when a condition is True
- elif: Check additional conditions (else if)
- else: Execute code when all conditions are False
"""

# ============================================================================
# CONCEPT EXPLANATION: Basic IF Statements
# ============================================================================

# Simple if statement
failed_logins = 3
max_attempts = 5

print(f"Failed login attempts: {failed_logins}")
print(f"Maximum allowed attempts: {max_attempts}")

if failed_logins > max_attempts:
    print("🚨 ALERT: Account should be locked!")

# If statement that executes
failed_logins = 6  # Now it exceeds the limit

print(f"\nFailed login attempts: {failed_logins}") # Added newline for clarity
print(f"Maximum allowed attempts: {max_attempts}")

if failed_logins > max_attempts:
    print("🚨 ALERT: Account should be locked!")

# ============================================================================
# CONCEPT EXPLANATION: IF-ELSE Statements
# ============================================================================

# If-else provides an alternative action
firewall_status = True

print(f"\nFirewall enabled: {firewall_status}") # Added newline

if firewall_status:
    print("✅ Security status: Firewall protection active")
else:
    print("⚠️  Security status: Firewall protection disabled")

# Another if-else example
cpu_usage = 95
cpu_threshold = 90

print(f"\nCurrent CPU usage: {cpu_usage}%") # Added newline
print(f"CPU threshold: {cpu_threshold}%")

if cpu_usage > cpu_threshold:
    print("🔥 WARNING: High CPU usage detected!")
else:
    print("✅ CPU usage is within normal limits")

# ============================================================================
# CONCEPT EXPLANATION: IF-ELIF-ELSE Statements
# ============================================================================

# Multiple conditions with elif
threat_score = 7

print(f"\nCurrent threat score: {threat_score}/10") # Added newline

if threat_score >= 9:
    print("🚨 CRITICAL: Immediate action required!")
elif threat_score >= 7:
    print("⚠️  HIGH: Enhanced monitoring needed")
elif threat_score >= 5:
    print("🟡 MEDIUM: Standard monitoring")
elif threat_score >= 3:
    print("🟢 LOW: Minimal risk")
else:
    print("✅ SAFE: No significant threats")

# ============================================================================
# CONCEPT EXPLANATION: Complex Conditions
# ============================================================================

# Using logical operators in conditions
user_role = "admin"
authenticated = True
vpn_connected = False

print(f"\nUser role: {user_role}") # Added newline
print(f"Authenticated: {authenticated}")
print(f"VPN connected: {vpn_connected}")

if user_role == "admin" and authenticated:
    print("✅ Admin access granted")
    if not vpn_connected:
        print("⚠️  Warning: Admin not using VPN")
else:
    print("❌ Access denied")

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF CONDITIONAL STATEMENTS:

1. ACCESS CONTROL DECISIONS:
   - IF user is authenticated AND has proper role THEN grant access
   - IF login attempt from blacklisted IP THEN block immediately
   - IF password strength < minimum THEN require password change

2. INCIDENT RESPONSE AUTOMATION:
   - IF threat level == "CRITICAL" THEN trigger emergency response
   - IF malware detected THEN isolate system AND notify admin
   - IF unusual network activity THEN increase monitoring level

3. SYSTEM MONITORING:
   - IF CPU usage > 90% THEN send alert AND restart service
   - IF disk space < 10% THEN cleanup logs AND notify admin
   - IF service down THEN attempt restart ELSE escalate to admin

4. SECURITY POLICY ENFORCEMENT:
   - IF file extension in dangerous_list THEN quarantine file
   - IF user inactive > 30 days THEN disable account
   - IF unsuccessful logins > 5 THEN lock account for 30 minutes

5. VULNERABILITY MANAGEMENT:
   - IF patch level < required THEN schedule update
   - IF security scan finds high vulnerabilities THEN priority fix
   - IF system unpatched > 30 days THEN flag for immediate attention
"""

# Security access control example
user_ip = "203.0.113.42"
blacklisted_ips = ["203.0.113.42", "198.51.100.1"]
user_authenticated = True

print(f"\nUser IP: {user_ip}") # Added newline
print(f"User authenticated: {user_authenticated}")

if user_ip in blacklisted_ips:
    print("🚨 BLOCKED: IP address is blacklisted")
elif not user_authenticated:
    print("❌ DENIED: User not authenticated")
else:
    print("✅ ACCESS GRANTED: User cleared for entry")

# System health monitoring example
memory_usage = 85
disk_usage = 45
network_errors = 12

print("\nSystem Health Check:") # Added newline
print(f"Memory usage: {memory_usage}%")
print(f"Disk usage: {disk_usage}%")
print(f"Network errors: {network_errors}")

if memory_usage > 90:
    print("🔴 CRITICAL: Memory usage too high")
elif memory_usage > 80:
    print("🟡 WARNING: Memory usage elevated")
else:
    print("🟢 OK: Memory usage normal")

if disk_usage > 90:
    print("🔴 CRITICAL: Disk space critically low")
elif disk_usage > 75:
    print("🟡 WARNING: Disk space running low")
else:
    print("🟢 OK: Disk space sufficient")

# ============================================================================
# WARM-UP EXERCISES: Practice Using Conditionals
# ============================================================================

# Exercise 1: Simple if statement
"""
PRACTICE: Basic If Statement

Write a function `check_threat_level(threat_level)` that takes an integer.
If `threat_level` is greater than 5, it should return "High threat detected".
Otherwise, it should return "Low threat".
"""
# TODO: Implement the function check_threat_level
def check_threat_level(threat_level):
    # Your code here
    pass


# Exercise 2: If-else statement
"""
PRACTICE: If-Else Logic

Write a function `check_port_type(port)` that takes an integer.
If `port` equals 22, it should return "SSH connection".
Otherwise, it should return "Other connection".
"""
# TODO: Implement the function check_port_type
def check_port_type(port):
    # Your code here
    pass


# Exercise 3: Multiple conditions with elif
"""
PRACTICE: If-Elif-Else Logic

Write a function `evaluate_security_score(score)` that takes an integer.
If `score` is 9 or above, return "Excellent security".
If `score` is 7-8, return "Good security".
Otherwise, return "Needs improvement".
"""
# TODO: Implement the function evaluate_security_score
def evaluate_security_score(score):
    # Your code here
    pass


# Exercise 4: Combining conditions with AND
"""
PRACTICE: Conditional with AND

Write a function `check_system_readiness(admin_logged_in, system_healthy)`
that takes two boolean values.
If BOTH `admin_logged_in` AND `system_healthy` are True, return "System ready for operations".
Otherwise, return "System not ready".
"""
# TODO: Implement the function check_system_readiness
def check_system_readiness(admin_logged_in, system_healthy):
    # Your code here
    pass


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Assessment System
# ============================================================================
"""
AUTOMATED SECURITY ASSESSMENT SYSTEM

You are developing an automated security assessment tool that evaluates a computer
system's security posture and provides recommendations.

The system being assessed has the following characteristics:
- Current password length: 6 characters
- Days since last security update: 45 days
- Firewall status: Enabled
- Antivirus status: Not active
- Administrator account status: Active
- Recent failed login attempts: 8 attempts

Your assessment tool needs to evaluate four critical security areas and return a string
message for each.

PASSWORD SECURITY ASSESSMENT:
Function: `assess_password_security(password_length)`
- Passwords with 12 or more characters: return "Strong password"
- Passwords with 8-11 characters: return "Adequate password"
- Passwords with less than 8 characters: return "Weak password, requires immediate change"

SYSTEM UPDATE STATUS:
Function: `assess_system_updates(last_update_days)`
- Updated within 7 days: return "System updates are current"
- Updated within 30 days: return "System updates are acceptable"
- Not updated for over 30 days: return "System is critically outdated"

SECURITY SOFTWARE PROTECTION:
Function: `assess_software_protection(firewall_enabled, antivirus_active)`
- Both firewall and antivirus active: return "System is fully protected"
- Only one protection active: return "System is partially protected"
- Neither protection active: return "System is unprotected"

ACCOUNT SECURITY MONITORING:
Function: `assess_account_security(admin_account_active, failed_login_attempts)`
- Admin account active AND failed attempts > 5: return "Admin account under attack"
- Failed attempts > 10: return "Possible brute force attack" (this should be checked after the admin attack)
- Failed attempts > 3: return "Multiple failed attempts warning" (checked after brute force)
- Otherwise: return "Normal login activity"

You will also need to define the initial variables for the system being assessed.
Then, call your assessment functions and store their results in variables like:
`password_assessment_msg`, `update_assessment_msg`,
`software_assessment_msg`, `account_assessment_msg`.
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: Create the assessment variables
# TODO: Create the 6 initial system characteristic variables
# password_length = ?
# last_update_days = ?
# firewall_enabled = ?
# antivirus_active = ?
# admin_account_active = ?
# failed_login_attempts = ?

# PART 2: Implement the assessment functions

# TODO: Implement assess_password_security(password_length)
def assess_password_security(password_length):
    pass

# TODO: Implement assess_system_updates(last_update_days)
def assess_system_updates(last_update_days):
    pass

# TODO: Implement assess_software_protection(firewall_enabled, antivirus_active)
def assess_software_protection(firewall_enabled, antivirus_active):
    pass

# TODO: Implement assess_account_security(admin_account_active, failed_login_attempts)
def assess_account_security(admin_account_active, failed_login_attempts):
    pass

# PART 3: Call assessment functions and store results
# TODO: Call your functions with the initial variables and store results in the suggested msg variables
# password_assessment_msg = ?
# update_assessment_msg = ?
# software_assessment_msg = ?
# account_assessment_msg = ?

# (Optional) You can print these messages for your own verification during development
# print(f"Password Assessment: {password_assessment_msg}")
# print(f"System Update Assessment: {update_assessment_msg}")
# print(f"Software Protection Assessment: {software_assessment_msg}")
# print(f"Account Security Assessment: {account_assessment_msg}")

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_exercises():
    """Test the warm-up exercises."""
    print("--- Testing Warm-up Exercises ---")
    warmup_passed_count = 0

    # Test Exercise 1
    try:
        assert check_threat_level(8) == "High threat detected"
        assert check_threat_level(5) == "Low threat"
        print("✅ Warm-up 1 PASSED")
        warmup_passed_count += 1
    except AssertionError:
        print("❌ Warm-up 1 FAILED: check_threat_level logic error.")
    except NameError:
        print("❌ Warm-up 1 FAILED: check_threat_level function not defined.")

    # Test Exercise 2
    try:
        assert check_port_type(22) == "SSH connection"
        assert check_port_type(80) == "Other connection"
        print("✅ Warm-up 2 PASSED")
        warmup_passed_count += 1
    except AssertionError:
        print("❌ Warm-up 2 FAILED: check_port_type logic error.")
    except NameError:
        print("❌ Warm-up 2 FAILED: check_port_type function not defined.")

    # Test Exercise 3
    try:
        assert evaluate_security_score(10) == "Excellent security"
        assert evaluate_security_score(7) == "Good security"
        assert evaluate_security_score(5) == "Needs improvement"
        print("✅ Warm-up 3 PASSED")
        warmup_passed_count += 1
    except AssertionError:
        print("❌ Warm-up 3 FAILED: evaluate_security_score logic error.")
    except NameError:
        print("❌ Warm-up 3 FAILED: evaluate_security_score function not defined.")

    # Test Exercise 4
    try:
        assert check_system_readiness(True, True) == "System ready for operations"
        assert check_system_readiness(True, False) == "System not ready"
        assert check_system_readiness(False, True) == "System not ready"
        print("✅ Warm-up 4 PASSED")
        warmup_passed_count += 1
    except AssertionError:
        print("❌ Warm-up 4 FAILED: check_system_readiness logic error.")
    except NameError:
        print("❌ Warm-up 4 FAILED: check_system_readiness function not defined.")

    print(f"Warm-up Score: {warmup_passed_count}/4 passed.")
    return warmup_passed_count == 4


def test_main_exercise():
    """Test the main exercise conditional logic."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    # Check initial variable definitions
    expected_initial_vars = {
        "password_length": 6, "last_update_days": 45, "firewall_enabled": True,
        "antivirus_active": False, "admin_account_active": True, "failed_login_attempts": 8
    }
    for var_name, expected_value in expected_initial_vars.items():
        try:
            actual_value = globals()[var_name]
            assert actual_value == expected_value, f"Initial variable '{var_name}' has wrong value. Expected {expected_value}, got {actual_value}"
        except NameError:
            print(f"❌ Main Exercise FAILED: Initial variable '{var_name}' not defined.")
            main_passed = False
        except AssertionError as e:
            print(f"❌ Main Exercise FAILED: {e}")
            main_passed = False
    if not main_passed: return False # Stop if initial vars are wrong

    # Test assessment functions (if defined)
    assessment_functions = ["assess_password_security", "assess_system_updates", "assess_software_protection", "assess_account_security"]
    for func_name in assessment_functions:
        if func_name not in globals() or not callable(globals()[func_name]):
            print(f"❌ Main Exercise FAILED: Assessment function '{func_name}' not defined or not callable.")
            return False # Functions are critical

    # Test resulting message variables
    expected_messages = {
        "password_assessment_msg": "Weak password, requires immediate change",
        "update_assessment_msg": "System is critically outdated",
        "software_assessment_msg": "System is partially protected",
        "account_assessment_msg": "Admin account under attack"
    }
    for var_name, expected_msg in expected_messages.items():
        try:
            actual_msg = globals()[var_name]
            assert actual_msg == expected_msg, f"Assessment message variable '{var_name}' incorrect. Expected '{expected_msg}', got '{actual_msg}'"
        except NameError:
            print(f"❌ Main Exercise FAILED: Result variable '{var_name}' not defined. Make sure to call the assessment functions and store their results.")
            main_passed = False
        except AssertionError as e:
            print(f"❌ Main Exercise FAILED: {e}")
            main_passed = False

    if main_passed:
        print("✅ Main Exercise: All checks passed!")
    return main_passed

def run_all_tests():
    """Run all tests for Module 3."""
    warmup_success = test_warmup_exercises()
    main_success = test_main_exercise()

    if warmup_success and main_success:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python conditional statements!")
        print("Ready for Module 4: Loops")
    else:
        print("\n📚 Keep practicing! Complete all exercises to proceed.")
        if not warmup_success:
            print("- Review warm-up exercises.")
        if not main_success:
            print("- Review main security assessment exercise.")

# Run the tests
run_all_tests()

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Outstanding work completing Module 3! Here's what you learned:

✅ Basic if statements for simple decisions
✅ If-else statements for two-option decisions
✅ If-elif-else for multiple condition checking
✅ Complex conditions using logical operators
✅ How to build automated security assessment logic

CYBERSECURITY SKILLS GAINED:
- Automated security policy enforcement
- Intelligent threat response decisions
- System health monitoring with smart alerts
- Access control logic implementation
- Incident response automation basics

NEXT MODULE: 04_loops.py
In the next module, you'll learn about loops - the powerful feature that
lets you automate repetitive tasks like scanning multiple IP addresses,
processing log files, or checking system status across many servers!

You're building serious cybersecurity automation skills! 🛡️
"""
