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

Create a variable `threat_level_warmup1` and set it to 8.
If `threat_level_warmup1` is greater than 5, assign the string "High threat detected"
to a global variable `warmup1_output`. Otherwise, assign "Low or normal threat".
"""
# TODO: Create threat_level_warmup1 and if statement assigning to warmup1_output
# warmup1_output = "" # Initialize for testing


# Exercise 2: If-else statement
"""
PRACTICE: If-Else Logic

Create a variable `port_warmup2` and set it to 22.
If `port_warmup2` equals 22, assign "SSH connection" to a global variable
`warmup2_output`. Otherwise, assign "Other connection".
"""
# TODO: Create port_warmup2 and if-else statement assigning to warmup2_output
# warmup2_output = "" # Initialize for testing


# Exercise 3: Multiple conditions with elif
"""
PRACTICE: If-Elif-Else Logic

Create a variable `security_score_warmup3` and set it to 7.
If `security_score_warmup3` is 9 or above, assign "Excellent security" to `warmup3_output`.
Else if `security_score_warmup3` is between 7 and 8 (inclusive), assign "Good security" to `warmup3_output`.
Otherwise, assign "Needs improvement" to `warmup3_output`.
"""
# TODO: Create security_score_warmup3 and if-elif-else statement assigning to warmup3_output
# warmup3_output = "" # Initialize for testing


# Exercise 4: Combining conditions with AND
"""
PRACTICE: Conditional with AND

Create variables `admin_logged_in_warmup4 = True` and `system_healthy_warmup4 = True`.
If BOTH are True, assign "System ready for operations" to `warmup4_output`.
Otherwise, assign "System not ready" to `warmup4_output`.
"""
# TODO: Create variables and conditional with AND, assigning to warmup4_output
# warmup4_output = "" # Initialize for testing


# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Assessment System
# ============================================================================
"""
AUTOMATED SECURITY ASSESSMENT SYSTEM

You are developing an automated security assessment tool that evaluates a computer
system's security posture and provides recommendations.

The system being assessed has the following characteristics (define these variables):
- password_length = 6
- last_update_days = 45
- firewall_enabled = True
- antivirus_active = False
- admin_account_active = True
- failed_login_attempts = 8

Your task is to determine the appropriate message for each security area based on
the rules below and assign it to a corresponding global variable.

PASSWORD SECURITY ASSESSMENT:
Assign to `password_assessment_msg`:
- "Strong password" if password_length >= 12
- "Adequate password" if 8 <= password_length <= 11
- "Weak password, requires immediate change" if password_length < 8

SYSTEM UPDATE STATUS:
Assign to `update_status_msg`:
- "System updates are current" if last_update_days <= 7
- "System updates are acceptable" if 7 < last_update_days <= 30
- "System is critically outdated" if last_update_days > 30

SECURITY SOFTWARE PROTECTION:
Assign to `software_protection_msg`:
- "System is fully protected" if firewall_enabled is True AND antivirus_active is True
- "System is partially protected" if firewall_enabled is True OR antivirus_active is True (but not both)
- "System is unprotected" if neither is active

ACCOUNT SECURITY MONITORING:
Assign to `account_security_msg`:
(Order of checks matters here)
- "Admin account under attack" if admin_account_active is True AND failed_login_attempts > 5
- Else if failed_login_attempts > 10, assign "Possible brute force attack"
- Else if failed_login_attempts > 3, assign "Multiple failed attempts warning"
- Else, assign "Normal login activity"

OVERALL SECURITY RECOMMENDATION: (Optional Challenge)
Based on the messages above, assign an overall recommendation string to
`overall_recommendation_msg`. For example, if multiple areas are weak/critical,
recommend "Urgent action required across multiple areas."
If mostly good, "System posture is fair, address noted issues."
If all good/strong, "System security posture is strong."
(This part is more open-ended for the user to define their logic).
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: Define the system characteristic variables
# TODO: Define the 6 initial system characteristic variables
# password_length = 6
# ... and so on

# PART 2: Determine assessment messages and assign to global variables
# TODO: Implement conditional logic for each assessment area and assign to the respective `_msg` variables

# password_assessment_msg = "" # Initialize for testing
# update_status_msg = ""       # Initialize for testing
# software_protection_msg = "" # Initialize for testing
# account_security_msg = ""    # Initialize for testing

# (Optional Challenge)
# overall_recommendation_msg = "" # Initialize for testing


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_exercises():
    """Test the warm-up exercises."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0

    # Test Exercise 1
    try:
        # User is expected to define threat_level_warmup1 and warmup1_output
        # Simulating user code for testing:
        # threat_level_warmup1 = 8
        # if threat_level_warmup1 > 5: warmup1_output = "High threat detected"
        # else: warmup1_output = "Low or normal threat"
        assert warmup1_output == "High threat detected", "Warmup 1: threat_level = 8"

        # Test the other case (conceptually, user would change threat_level_warmup1 and rerun)
        # For testing, we assume the logic handles both.
        # A real student environment might require them to set up both test cases or we test their logic more directly.
        # For now, we'll assume the primary case (threat_level=8) is what they implement for the variable.
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except NameError:
        print("❌ Warm-up 1 FAILED: `threat_level_warmup1` or `warmup1_output` not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up 1 FAILED: {e}")

    # Test Exercise 2
    try:
        # port_warmup2 = 22
        # if port_warmup2 == 22: warmup2_output = "SSH connection"
        # else: warmup2_output = "Other connection"
        assert warmup2_output == "SSH connection", "Warmup 2: port = 22"
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except NameError:
        print("❌ Warm-up 2 FAILED: `port_warmup2` or `warmup2_output` not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up 2 FAILED: {e}")

    # Test Exercise 3
    try:
        # security_score_warmup3 = 7
        # if security_score_warmup3 >= 9: warmup3_output = "Excellent security"
        # elif security_score_warmup3 >= 7: warmup3_output = "Good security"
        # else: warmup3_output = "Needs improvement"
        assert warmup3_output == "Good security", "Warmup 3: score = 7"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except NameError:
        print("❌ Warm-up 3 FAILED: `security_score_warmup3` or `warmup3_output` not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up 3 FAILED: {e}")

    # Test Exercise 4
    try:
        # admin_logged_in_warmup4 = True
        # system_healthy_warmup4 = True
        # if admin_logged_in_warmup4 and system_healthy_warmup4: warmup4_output = "System ready for operations"
        # else: warmup4_output = "System not ready"
        assert warmup4_output == "System ready for operations", "Warmup 4: True, True"
        print("✅ Warm-up 4 PASSED")
        passed_count += 1
    except NameError:
        print("❌ Warm-up 4 FAILED: Variables for warmup 4 or `warmup4_output` not defined.")
    except AssertionError as e:
        print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 exercises completed.")
    return passed_count == 4

def test_main_exercise():
    """Test the main exercise conditional logic."""
    print("\n--- Testing Main Exercise ---")
    main_passed = True

    expected_initial_vars = {
        "password_length": 6, "last_update_days": 45, "firewall_enabled": True,
        "antivirus_active": False, "admin_account_active": True, "failed_login_attempts": 8
    }
    for var_name, expected_value in expected_initial_vars.items():
        try:
            actual_value = globals()[var_name] # Check if defined by user
            assert actual_value == expected_value, f"Initial variable '{var_name}' has wrong value. Expected {expected_value}, got {actual_value}"
        except NameError:
            print(f"❌ Main Exercise FAILED: Initial variable '{var_name}' not defined.")
            main_passed = False
        except AssertionError as e:
            print(f"❌ Main Exercise FAILED: {e}")
            main_passed = False

    if not main_passed: return False # Stop if initial vars are wrong

    expected_messages = {
        "password_assessment_msg": "Weak password, requires immediate change",
        "update_status_msg": "System is critically outdated",
        "software_protection_msg": "System is partially protected",
        "account_security_msg": "Admin account under attack"
    }
    for var_name, expected_msg in expected_messages.items():
        try:
            actual_msg = globals()[var_name] # Check if defined by user
            assert actual_msg == expected_msg, f"Assessment message variable '{var_name}' incorrect. Expected '{expected_msg}', got '{actual_msg}'"
        except NameError:
            print(f"❌ Main Exercise FAILED: Result variable '{var_name}' not defined. Make sure to implement the logic and assign to this variable.")
            main_passed = False
        except AssertionError as e:
            print(f"❌ Main Exercise FAILED: {e}")
            main_passed = False

    if main_passed:
        print("✅ Main Exercise: All required message variables correctly assigned!")
    else:
        print("❌ Main Exercise: Some message variables incorrect or not defined.")
    return main_passed

def run_all_tests(): # Renamed from test_conditionals
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
run_all_tests() # Updated call

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
